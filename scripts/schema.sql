-- ==============================================================================
-- Japan Audit Platform  監査ログDB定義（PostgreSQL 16 / TimescaleDB 任意）
--
--  1. 冪等登録       : trace_id で重複を弾く（再送しても二重登録しない）
--  2. ハッシュチェーン : 受信順（chain_seq）に SHA-256 を連鎖。先頭行ロックで直列化し、分岐させない
--  3. WORM          : UPDATE / DELETE / TRUNCATE をトリガーで拒否
--  4. 検証関数       : fn_audit_verify_chain() で改ざん・欠番・末尾削除を検出
--  5. データ最小化    : 本文は既定で保存しない（NULL）。検知明細はマスキング値のみ
-- ==============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;  -- digest() による SHA-256

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'timescaledb') THEN
        CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;
    ELSE
        RAISE NOTICE 'TimescaleDB not found: using plain PostgreSQL table.';
    END IF;
END $$;

-- ------------------------------------------------------------------------------
-- 1. 監査ログ本体
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS t_audit_access_log (
    log_id                  BIGSERIAL,
    chain_seq               BIGINT       NOT NULL,          -- 受信順の連番（トリガーが採番）
    request_timestamp       TIMESTAMPTZ  NOT NULL,          -- 業務リクエストの発生時刻（センサー側）
    received_at             TIMESTAMPTZ  NOT NULL DEFAULT clock_timestamp(),
    trace_id                VARCHAR(36)  NOT NULL,
    system_code             VARCHAR(32)  NOT NULL,
    host_name               VARCHAR(64)  NOT NULL,
    client_ip               VARCHAR(45)  NOT NULL,
    user_id                 VARCHAR(64)  NOT NULL,
    http_method             VARCHAR(10)  NOT NULL,
    request_uri             VARCHAR(1024) NOT NULL,
    query_string            TEXT,
    http_status             INTEGER      NOT NULL,
    execution_time_ms       BIGINT       NOT NULL,
    pii_detected            BOOLEAN      NOT NULL DEFAULT FALSE,
    pii_occurrences         INTEGER      NOT NULL DEFAULT 0, -- 出現回数（同じ番号2回で2）
    my_number_person_count  INTEGER      NOT NULL DEFAULT 0, -- マイナンバーの異なる値の数 ≒ 本人数
    alert_level             VARCHAR(16)  NOT NULL DEFAULT 'INFO',
    alert_reason            TEXT,
    details_digest          CHAR(64)     NOT NULL,          -- 検知明細の SHA-256（明細改ざん検出用）
    request_body            TEXT,                            -- 既定 NULL（データ最小化）
    response_body           TEXT,
    prev_record_hash        CHAR(64)     NOT NULL,
    record_hash             CHAR(64)     NOT NULL,
    CONSTRAINT pk_t_audit_access_log PRIMARY KEY (request_timestamp, log_id)
);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        PERFORM create_hypertable('t_audit_access_log', 'request_timestamp',
                                  chunk_time_interval => INTERVAL '7 days', if_not_exists => TRUE);
    END IF;
END $$;

-- TimescaleDB の一意制約は分割キー（request_timestamp）を含む必要がある
CREATE UNIQUE INDEX IF NOT EXISTS uix_audit_trace     ON t_audit_access_log (trace_id, request_timestamp);
CREATE UNIQUE INDEX IF NOT EXISTS uix_audit_chain_seq ON t_audit_access_log (chain_seq, request_timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_trace_only       ON t_audit_access_log (trace_id);
CREATE INDEX IF NOT EXISTS idx_audit_timeline         ON t_audit_access_log (request_timestamp DESC, system_code, user_id);
CREATE INDEX IF NOT EXISTS idx_audit_alerts           ON t_audit_access_log (request_timestamp DESC, alert_level)
    WHERE alert_level <> 'INFO';

-- ------------------------------------------------------------------------------
-- 2. 検知明細（マスキング値のみ）
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS t_audit_pii_detail (
    detail_id     BIGSERIAL PRIMARY KEY,
    trace_id      VARCHAR(36) NOT NULL,
    seq_no        INTEGER     NOT NULL,       -- 1ログ内の並び順（ダイジェスト計算で使用）
    pii_type      VARCHAR(32) NOT NULL,
    masked_value  VARCHAR(128) NOT NULL,
    occurred_in   VARCHAR(16) NOT NULL,       -- QUERY_STRING / REQUEST_BODY / RESPONSE_BODY
    confidence    VARCHAR(8)  NOT NULL,       -- HIGH / MEDIUM
    CONSTRAINT uq_pii_detail UNIQUE (trace_id, seq_no)
);

-- ------------------------------------------------------------------------------
-- 3. チェーンの先頭（1行だけ）。この行を FOR UPDATE でロックして挿入を直列化する
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS t_audit_chain_head (
    id         SMALLINT PRIMARY KEY CHECK (id = 1),
    last_seq   BIGINT   NOT NULL,
    last_hash  CHAR(64) NOT NULL
);
INSERT INTO t_audit_chain_head (id, last_seq, last_hash)
VALUES (1, 0, repeat('0', 64))
ON CONFLICT (id) DO NOTHING;

-- ------------------------------------------------------------------------------
-- 4. ハッシュ計算（挿入時と検証時で必ず同じ式を使うため関数に一本化）
--    時刻は UTC 固定の文字列にする（セッションの TimeZone で結果が変わらないように）
--    NULL と空文字を区別するため、NULL は 'N'、値は 'V' + 値 として連結する
-- ------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_audit_row_hash(r t_audit_access_log) RETURNS CHAR(64)
LANGUAGE sql STABLE AS $$
    SELECT encode(digest(concat_ws(chr(31),
        r.prev_record_hash,
        r.chain_seq::text,
        to_char(r.request_timestamp AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US'),
        r.trace_id, r.system_code, r.host_name, r.client_ip, r.user_id,
        r.http_method, r.request_uri, CASE WHEN r.query_string IS NULL THEN 'N' ELSE 'V' || r.query_string END,
        r.http_status::text, r.execution_time_ms::text,
        r.pii_detected::text, r.pii_occurrences::text, r.my_number_person_count::text,
        r.alert_level, CASE WHEN r.alert_reason IS NULL THEN 'N' ELSE 'V' || r.alert_reason END, r.details_digest,
        CASE WHEN r.request_body IS NULL THEN 'N' ELSE 'V' || r.request_body END, CASE WHEN r.response_body IS NULL THEN 'N' ELSE 'V' || r.response_body END
    ), 'sha256'), 'hex')
$$;

-- 明細ダイジェスト（Java 側 DetailDigest と同じ式。明細が0件なら空文字列の SHA-256）
CREATE OR REPLACE FUNCTION fn_audit_details_digest(p_trace_id VARCHAR) RETURNS CHAR(64)
LANGUAGE sql STABLE AS $$
    SELECT encode(digest(coalesce(string_agg(
               concat_ws(chr(31), seq_no::text, pii_type, masked_value, occurred_in, confidence),
               chr(30) ORDER BY seq_no), ''), 'sha256'), 'hex')
    FROM t_audit_pii_detail WHERE trace_id = p_trace_id
$$;

-- ------------------------------------------------------------------------------
-- 5. 挿入トリガー：重複を弾き、採番し、ハッシュを連鎖させる
-- ------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_audit_before_insert() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
DECLARE
    h t_audit_chain_head%ROWTYPE;
BEGIN
    -- (a) 先頭行をロック。並行する挿入はここで1件ずつに並ぶ（＝チェーンが分岐しない）
    SELECT * INTO h FROM t_audit_chain_head WHERE id = 1 FOR UPDATE;

    -- (b) 同じ trace_id が既にあれば何もしない（再送の冪等性）。
    --     ロック取得後に確認するので、同時に同じログが2本来ても片方だけが残る。
    IF EXISTS (SELECT 1 FROM t_audit_access_log WHERE trace_id = NEW.trace_id) THEN
        RETURN NULL;
    END IF;

    NEW.chain_seq        := h.last_seq + 1;
    NEW.prev_record_hash := h.last_hash;
    NEW.received_at      := clock_timestamp();
    NEW.record_hash      := fn_audit_row_hash(NEW);

    UPDATE t_audit_chain_head SET last_seq = NEW.chain_seq, last_hash = NEW.record_hash WHERE id = 1;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_before_insert ON t_audit_access_log;
CREATE TRIGGER trg_audit_before_insert
    BEFORE INSERT ON t_audit_access_log
    FOR EACH ROW EXECUTE FUNCTION fn_audit_before_insert();

-- ------------------------------------------------------------------------------
-- 6. WORM：更新・削除・全削除を拒否（監査ログは追記のみ）
-- ------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_audit_reject_change() RETURNS TRIGGER
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit log is append-only (% on % is not allowed)', TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_worm ON t_audit_access_log;
CREATE TRIGGER trg_audit_worm BEFORE UPDATE OR DELETE ON t_audit_access_log
    FOR EACH ROW EXECUTE FUNCTION fn_audit_reject_change();
DROP TRIGGER IF EXISTS trg_audit_worm_truncate ON t_audit_access_log;
CREATE TRIGGER trg_audit_worm_truncate BEFORE TRUNCATE ON t_audit_access_log
    FOR EACH STATEMENT EXECUTE FUNCTION fn_audit_reject_change();

DROP TRIGGER IF EXISTS trg_detail_worm ON t_audit_pii_detail;
CREATE TRIGGER trg_detail_worm BEFORE UPDATE OR DELETE ON t_audit_pii_detail
    FOR EACH ROW EXECUTE FUNCTION fn_audit_reject_change();
DROP TRIGGER IF EXISTS trg_detail_worm_truncate ON t_audit_pii_detail;
CREATE TRIGGER trg_detail_worm_truncate BEFORE TRUNCATE ON t_audit_pii_detail
    FOR EACH STATEMENT EXECUTE FUNCTION fn_audit_reject_change();

-- ------------------------------------------------------------------------------
-- 7. 検証関数：問題のある行だけを返す（0行なら正常）
--    検出できるもの：行の書き換え / 明細の書き換え / 連結切れ / 欠番（途中削除）/ 末尾削除
--    限界：DB管理者がトリガーを外して「全行を再計算」した場合は DB 内だけでは検出できない。
--          → コレクターが定期的に先頭ハッシュを DB の外（アンカーファイル）へ書き出して照合する。
-- ------------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION fn_audit_verify_chain()
RETURNS TABLE (chain_seq BIGINT, trace_id VARCHAR, problem TEXT)
LANGUAGE plpgsql STABLE AS $$
DECLARE
    r          t_audit_access_log%ROWTYPE;
    prev_hash  CHAR(64) := repeat('0', 64);
    expect_seq BIGINT   := 1;
    h          t_audit_chain_head%ROWTYPE;
BEGIN
    FOR r IN SELECT * FROM t_audit_access_log a ORDER BY a.chain_seq LOOP
        IF r.chain_seq <> expect_seq THEN
            chain_seq := r.chain_seq; trace_id := r.trace_id;
            problem := format('missing seq %s..%s (rows deleted?)', expect_seq, r.chain_seq - 1);
            RETURN NEXT;
        ELSIF r.prev_record_hash <> prev_hash THEN
            chain_seq := r.chain_seq; trace_id := r.trace_id;
            problem := 'prev_record_hash does not match previous row';
            RETURN NEXT;
        END IF;
        IF r.record_hash <> fn_audit_row_hash(r) THEN
            chain_seq := r.chain_seq; trace_id := r.trace_id;
            problem := 'record_hash mismatch (row content changed)';
            RETURN NEXT;
        END IF;
        IF r.details_digest <> fn_audit_details_digest(r.trace_id) THEN
            chain_seq := r.chain_seq; trace_id := r.trace_id;
            problem := 'details_digest mismatch (pii detail rows changed)';
            RETURN NEXT;
        END IF;
        prev_hash  := r.record_hash;
        expect_seq := r.chain_seq + 1;
    END LOOP;

    SELECT * INTO h FROM t_audit_chain_head WHERE id = 1;
    IF h.last_seq <> expect_seq - 1 OR h.last_hash <> prev_hash THEN
        chain_seq := h.last_seq; trace_id := NULL;
        problem := format('chain head mismatch: head=%s, last row=%s (tail rows deleted?)', h.last_seq, expect_seq - 1);
        RETURN NEXT;
    END IF;
END;
$$;

-- ------------------------------------------------------------------------------
-- 8. 権限分離の例（本番想定。アプリ用ユーザーには INSERT / SELECT だけを与える）
--    CREATE ROLE audit_writer LOGIN PASSWORD '...';
--    GRANT SELECT, INSERT ON t_audit_access_log, t_audit_pii_detail TO audit_writer;
--    GRANT SELECT ON t_audit_chain_head TO audit_writer;
--    GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO audit_writer;
--    ALTER FUNCTION fn_audit_before_insert() SECURITY DEFINER;  -- 先頭行の更新は所有者権限で
-- ------------------------------------------------------------------------------

COMMENT ON TABLE  t_audit_access_log IS 'アクセス監査ログ（追記のみ・ハッシュチェーン）';
COMMENT ON COLUMN t_audit_access_log.chain_seq IS '受信順の連番。ハッシュチェーンの順序';
COMMENT ON COLUMN t_audit_access_log.my_number_person_count IS 'マイナンバーの異なる値の数（≒本人数）';
COMMENT ON COLUMN t_audit_access_log.details_digest IS '検知明細の SHA-256。明細の改ざん検出用';
COMMENT ON TABLE  t_audit_chain_head IS 'ハッシュチェーンの先頭（直列化ロック兼 末尾削除検出用）';
