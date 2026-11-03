#!/usr/bin/env bash
# =============================================================================
# E2E 検証スクリプト：業務アプリ → 監査フィルター → コレクター → DB を実際に通して確認する
#
# 前提: docker compose up -d --build 済み（または各プロセスを手動起動済み）
# 必要: bash, curl, python3
#
#   set -a; source .env; set +a      # SENSOR_KEY / CONSOLE_PASSWORD を読み込む
#   ./scripts/e2e-verify.sh
#
# 環境変数（省略時は docker compose 前提の既定値）
#   APP_URL            業務アプリ            (http://localhost:8080)
#   COLLECTOR_URL      コレクター            (http://localhost:8081)
#   CONSOLE_USER / CONSOLE_PASSWORD           コンソール認証
#   SENSOR_KEY         直接投入テスト用
#   COLLECTOR_STOP_CMD / COLLECTOR_START_CMD  障害試験でコレクターを止める／起動するコマンド
#   RUN_TAMPER=1       改ざん検知試験も行う（DBを書き換えるため、終わったら docker compose down -v で作り直す）
#   PSQL               改ざん試験で使う psql コマンド
# =============================================================================
set -uo pipefail

APP_URL="${APP_URL:-http://localhost:8080}"
COLLECTOR_URL="${COLLECTOR_URL:-http://localhost:8081}"
CONSOLE_USER="${CONSOLE_USER:-auditor}"
CONSOLE_PASSWORD="${CONSOLE_PASSWORD:?CONSOLE_PASSWORD を設定してください（set -a; source .env; set +a）}"
SENSOR_KEY="${SENSOR_KEY:?SENSOR_KEY を設定してください}"
COLLECTOR_STOP_CMD="${COLLECTOR_STOP_CMD:-docker compose stop audit-collector}"
COLLECTOR_START_CMD="${COLLECTOR_START_CMD:-docker compose start audit-collector}"
PSQL="${PSQL:-docker compose exec -T audit-db psql -U audit_user -d auditdb -qtA}"
RUN_TAMPER="${RUN_TAMPER:-0}"

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
ng()   { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; [ $# -ge 2 ] && printf '       %s\n' "$2"; }
step() { printf '\n\033[1m[%s]\033[0m %s\n' "$1" "$2"; }

app()  { curl -s -o /tmp/e2e_body -w '%{http_code}' "$@"; }          # 業務アプリ呼び出し（本文は /tmp/e2e_body）
logs() { curl -s -u "$CONSOLE_USER:$CONSOLE_PASSWORD" "$COLLECTOR_URL/api/v1/collector/logs?limit=300"; }

# 条件（Python 式。変数 l に1件のログ）に合うログが現れるまで最大20秒待つ。見つかったログを JSON で出力
wait_log() {
  local expr="$1"
  for _ in $(seq 1 40); do
    local hit
    hit=$(logs | python3 -c "
import json,sys
try: data=json.load(sys.stdin)
except Exception: sys.exit(1)
for l in data:
    if $expr:
        print(json.dumps(l, ensure_ascii=False)); sys.exit(0)
sys.exit(1)") && { echo "$hit"; return 0; }
    sleep 0.5
  done
  return 1
}
field() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }

RUN_ID=$(date +%s)
TOK1="Authorization: Bearer demo-token-0001"
TOK2="Authorization: Bearer demo-token-0002"
TOK3="Authorization: Bearer demo-token-0003"

# -----------------------------------------------------------------------------
step 0 "起動確認"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$COLLECTOR_URL/api/v1/collector/health")" = 200 ] && ok "collector UP" || ng "collector not reachable at $COLLECTOR_URL"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$APP_URL/")" = 200 ] && ok "business app UP" || ng "app not reachable at $APP_URL"

# -----------------------------------------------------------------------------
step 1 "通常の照会：ログが届き、マイナンバーはマスキングされている"
ID=$((RUN_ID % 900000 + 1000))
code=$(app -H "$TOK1" "$APP_URL/api/v1/customers/$ID")
RAW=$(field '["myNumber"]' < /tmp/e2e_body 2>/dev/null)
[ "$code" = 200 ] && ok "業務レスポンス 200（業務側には生の番号が返る: ${RAW:0:4}…）" || ng "business status $code"
if L=$(wait_log "l['requestUri']=='/api/v1/customers/$ID' and l['userId']=='EMP_DEMO_0001'"); then
  ok "監査ログ到着（user=EMP_DEMO_0001, level=$(echo "$L" | field "['alertLevel']")）"
  echo "$L" | grep -qF "********${RAW:8:4}" && ok "マスキング値 ********${RAW:8:4} を記録" || ng "masked value not found" "$L"
  logs | grep -q "$RAW" && ng "生のマイナンバーがコレクターに存在する" || ok "生のマイナンバーはコレクターに存在しない"
else
  ng "audit log did not arrive"
fi

# -----------------------------------------------------------------------------
step 2 "大量出力：1リクエストで本人数120人 → CRITICAL"
code=$(app -H "$TOK2" "$APP_URL/api/v1/customers/export?count=120&from=$((RUN_ID % 100000 * 10))")
[ "$code" = 200 ] && ok "業務レスポンス 200" || ng "business status $code"
L=$(wait_log "l['userId']=='EMP_DEMO_0002' and l['myNumberPersonCount']==120 and l['alertLevel']=='CRITICAL'") \
  && ok "CRITICAL：$(echo "$L" | field "['alertReason']")" || ng "CRITICAL not raised for 120 persons"

# -----------------------------------------------------------------------------
step 3 "分割照会：60人×2回（同一ユーザー・10分以内）→ 2回目で CRITICAL"
app -H "$TOK3" "$APP_URL/api/v1/customers/export?count=60&from=$((RUN_ID % 100000 * 10 + 3000000))" >/dev/null
sleep 1
app -H "$TOK3" "$APP_URL/api/v1/customers/export?count=60&from=$((RUN_ID % 100000 * 10 + 6000000))" >/dev/null
L=$(wait_log "l['userId']=='EMP_DEMO_0003' and l['alertLevel']=='CRITICAL' and '分割' in (l['alertReason'] or '')") \
  && ok "CRITICAL：$(echo "$L" | field "['alertReason']")" || ng "split access not detected"

# -----------------------------------------------------------------------------
step 4 "未認証アクセスも記録される（ANONYMOUS / 401）"
code=$(app "$APP_URL/api/v1/customers/1?run=$RUN_ID")
[ "$code" = 401 ] && ok "業務は 401 を返す" || ng "expected 401, got $code"
wait_log "l['userId']=='ANONYMOUS' and l['httpStatus']==401" >/dev/null && ok "ANONYMOUS・401 として記録" || ng "anonymous access not logged"

# -----------------------------------------------------------------------------
step 5 "なりすまし：X-Forwarded-For・ユーザーヘッダーを偽装しても採用されない"
ID5=$((ID + 1))
app -H "$TOK1" -H "X-Forwarded-For: 1.2.3.4" -H "X-Authenticated-User: EMP_CEO" "$APP_URL/api/v1/customers/$ID5" >/dev/null
if L=$(wait_log "l['requestUri']=='/api/v1/customers/$ID5'"); then
  [ "$(echo "$L" | field "['userId']")" = EMP_DEMO_0001 ] && ok "ユーザーは認証結果（EMP_DEMO_0001）" || ng "user spoofed" "$L"
  [ "$(echo "$L" | field "['clientIp']")" != 1.2.3.4 ] && ok "接続元IPは実際の接続元（$(echo "$L" | field "['clientIp']")）" || ng "IP spoofed"
else
  ng "log not found"
fi

# -----------------------------------------------------------------------------
step 6 "非侵襲：200KB の本文が業務側に全部届く（旧実装は64KBで切れていた）"
head -c 200000 /dev/zero | tr '\0' 'a' > /tmp/e2e_upload
app -H "$TOK1" -H "Content-Type: text/plain" --data-binary @/tmp/e2e_upload "$APP_URL/api/v1/documents/upload" >/dev/null
got=$(field '["receivedBytes"]' < /tmp/e2e_body 2>/dev/null)
[ "$got" = 200000 ] && ok "業務側の受信バイト数 = 200000" || ng "business received $got bytes"

# -----------------------------------------------------------------------------
step 7 "コレクター認証：キー無し・誤キーは拒否"
c1=$(curl -s -o /dev/null -w '%{http_code}' -X POST -d '{}' "$COLLECTOR_URL/api/v1/collector/ingest")
c2=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'X-Audit-Sensor-Key: wrong' -d '{}' "$COLLECTOR_URL/api/v1/collector/ingest")
[ "$c1" = 401 ] && ok "キー無し → 401（旧実装は 202 で素通り）" || ng "no key -> $c1"
[ "$c2" = 401 ] && ok "誤キー → 401" || ng "wrong key -> $c2"
c3=$(curl -s -o /dev/null -w '%{http_code}' -u "$CONSOLE_USER:wrong" "$COLLECTOR_URL/api/v1/collector/logs")
[ "$c3" = 401 ] && ok "コンソールAPIも認証必須" || ng "console without auth -> $c3"

# -----------------------------------------------------------------------------
step 8 "XSS：ログ中の HTML はエスケープされて返る"
XT="xss-$RUN_ID"
curl -s -o /dev/null -X POST -H "X-Audit-Sensor-Key: $SENSOR_KEY" \
  -d "{\"traceId\":\"$XT\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"requestUri\":\"/x<img src=x onerror=alert(1)>\"}" \
  "$COLLECTOR_URL/api/v1/collector/ingest"
RAWJSON=$(logs)
echo "$RAWJSON" | grep -q '<img' && ng "raw <img> returned by API" || ok "API は \\u003c で返す（生の < を含まない）"
curl -s -u "$CONSOLE_USER:$CONSOLE_PASSWORD" -D - -o /dev/null "$COLLECTOR_URL/" | grep -qi "content-security-policy: .*script-src 'self'" \
  && ok "コンソールに CSP（インラインスクリプト禁止）" || ng "CSP header missing"

# -----------------------------------------------------------------------------
step 9 "障害試験：コレクター停止中も業務は止まらず、復旧後に欠損なく再送される"
eval "$COLLECTOR_STOP_CMD" >/dev/null 2>&1
sleep 2
OUT_IDS=""
all200=1
for i in 1 2 3 4 5; do
  oid=$((ID + 100 + i)); OUT_IDS="$OUT_IDS $oid"
  t=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' -H "$TOK1" "$APP_URL/api/v1/customers/$oid")
  [ "${t%% *}" = 200 ] || all200=0
  printf '       停止中のリクエスト %s → %s 秒\n' "$oid" "${t#* }"
done
[ $all200 = 1 ] && ok "停止中も業務レスポンスは 200" || ng "business affected during outage"
sleep 2
STATS=$(curl -s "$APP_URL/internal/audit-stats")
[ "$(echo "$STATS" | field "['spoolBytes']")" -gt 0 ] && ok "ローカル退避中: $STATS" || ng "nothing spooled" "$STATS"
eval "$COLLECTOR_START_CMD" >/dev/null 2>&1
for _ in $(seq 1 60); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "$COLLECTOR_URL/api/v1/collector/health")" = 200 ] && break; sleep 1
done
for _ in $(seq 1 60); do
  [ "$(curl -s "$APP_URL/internal/audit-stats" | field "['spoolBytes']")" = 0 ] && break; sleep 1
done
STATS=$(curl -s "$APP_URL/internal/audit-stats")
[ "$(echo "$STATS" | field "['spoolBytes']")" = 0 ] && ok "退避分を再送完了: $STATS" || ng "spool not drained" "$STATS"
missing=0
for oid in $OUT_IDS; do
  wait_log "l['requestUri']=='/api/v1/customers/$oid'" >/dev/null || missing=$((missing+1))
done
[ $missing = 0 ] && ok "停止中の5件すべてがコレクターに到着（欠損 0）" || ng "$missing logs lost"

# -----------------------------------------------------------------------------
step 10 "ハッシュチェーン検証"
curl -s -o /dev/null -X POST -u "$CONSOLE_USER:$CONSOLE_PASSWORD" "$COLLECTOR_URL/api/v1/collector/chain/anchor"
V=$(curl -s -u "$CONSOLE_USER:$CONSOLE_PASSWORD" "$COLLECTOR_URL/api/v1/collector/chain/verify")
st=$(echo "$V" | field "['status']")
case "$st" in
  OK) ok "チェーン正常（$(echo "$V" | field "['checkedRows']") 行・アンカー $(echo "$V" | field "['anchors']") 件と照合）" ;;
  UNAVAILABLE) ok "メモリ保存モードのため検証対象外" ;;
  *) ng "chain status $st" "$V" ;;
esac

if [ "$RUN_TAMPER" = 1 ]; then
  step 11 "改ざん検知（DB管理者がトリガーを外して CRITICAL を INFO に書き換える）"
  $PSQL -c "ALTER TABLE t_audit_access_log DISABLE TRIGGER trg_audit_worm" \
        -c "UPDATE t_audit_access_log SET alert_level='INFO', alert_reason=NULL WHERE alert_level='CRITICAL'" \
        -c "ALTER TABLE t_audit_access_log ENABLE TRIGGER trg_audit_worm" >/dev/null
  V=$(curl -s -u "$CONSOLE_USER:$CONSOLE_PASSWORD" "$COLLECTOR_URL/api/v1/collector/chain/verify")
  [ "$(echo "$V" | field "['status']")" = BROKEN ] && ok "改ざんを検出：$(echo "$V" | field "['problems'][0]['problem']")" || ng "tamper not detected" "$V"
  echo "       ※ DB を元に戻すには: docker compose down -v && docker compose up -d --build"
fi

# -----------------------------------------------------------------------------
step "参考" "応答時間（監査フィルターあり・20回平均）"
python3 - "$APP_URL" <<'PY'
import sys, time, urllib.request
url = sys.argv[1] + "/api/v1/customers/1"
ts = []
for _ in range(20):
    req = urllib.request.Request(url, headers={"Authorization": "Bearer demo-token-0001"})
    t = time.perf_counter(); urllib.request.urlopen(req).read(); ts.append((time.perf_counter() - t) * 1000)
ts.sort()
print(f"       平均 {sum(ts)/len(ts):.1f} ms / 中央値 {ts[len(ts)//2]:.1f} ms / 最大 {ts[-1]:.1f} ms")
PY

printf '\n結果: \033[32m%d PASS\033[0m / \033[31m%d FAIL\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
