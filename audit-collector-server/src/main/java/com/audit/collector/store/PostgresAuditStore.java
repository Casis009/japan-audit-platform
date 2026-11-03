package com.audit.collector.store;

import com.audit.collector.model.Alert;
import com.audit.collector.model.IngestRequest;
import com.audit.collector.model.LogView;

import java.sql.Array;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * PostgreSQL への保存。ハッシュ計算・採番・重複排除は DB のトリガーが行う（Java 側では計算しない）。
 * <p>
 * 接続は呼び出しごとに張る簡易実装。本番では HikariCP 等のコネクションプールを使う。
 */
public class PostgresAuditStore implements AuditStore {

    private final String url;
    private final String user;
    private final String password;

    public PostgresAuditStore(String url, String user, String password) {
        this.url = url;
        this.user = user;
        this.password = password;
    }

    private Connection connect() throws SQLException {
        return DriverManager.getConnection(url, user, password);
    }

    @Override
    public SaveResult save(IngestRequest r, Alert alert) {
        String sql = """
                INSERT INTO t_audit_access_log (
                    request_timestamp, trace_id, system_code, host_name, client_ip, user_id,
                    http_method, request_uri, query_string, http_status, execution_time_ms,
                    pii_detected, pii_occurrences, my_number_person_count, alert_level, alert_reason,
                    details_digest, request_body, response_body, chain_seq, prev_record_hash, record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '', '')
                RETURNING chain_seq
                """;
        String detailSql = """
                INSERT INTO t_audit_pii_detail (trace_id, seq_no, pii_type, masked_value, occurred_in, confidence)
                VALUES (?, ?, ?, ?, ?, ?)
                """;
        try (Connection c = connect()) {
            c.setAutoCommit(false);
            try {
                boolean inserted;
                try (PreparedStatement ps = c.prepareStatement(sql)) {
                    int i = 1;
                    ps.setTimestamp(i++, Timestamp.from(r.timestamp()));
                    ps.setString(i++, r.traceId());
                    ps.setString(i++, r.systemCode());
                    ps.setString(i++, r.hostName());
                    ps.setString(i++, r.clientIp());
                    ps.setString(i++, r.userPrincipal());
                    ps.setString(i++, r.httpMethod());
                    ps.setString(i++, r.requestUri());
                    ps.setString(i++, r.queryString());
                    ps.setInt(i++, r.httpStatus());
                    ps.setLong(i++, r.executionTimeMs());
                    ps.setBoolean(i++, r.piiDetected());
                    ps.setInt(i++, r.piiOccurrences());
                    ps.setInt(i++, r.myNumberPersonCount());
                    ps.setString(i++, alert.level().name());
                    ps.setString(i++, alert.reason());
                    ps.setString(i++, DetailDigest.of(r.details()));
                    ps.setString(i++, r.requestBody());
                    ps.setString(i, r.responseBody());
                    try (ResultSet rs = ps.executeQuery()) {
                        inserted = rs.next(); // トリガーが重複と判断すると0行（RETURNING なし）
                    }
                }
                if (!inserted) {
                    c.rollback();
                    return SaveResult.DUPLICATE; // 明細も入れない（冪等）
                }
                if (!r.details().isEmpty()) {
                    try (PreparedStatement ps = c.prepareStatement(detailSql)) {
                        for (IngestRequest.Detail d : r.details()) {
                            ps.setString(1, r.traceId());
                            ps.setInt(2, d.seqNo());
                            ps.setString(3, d.piiType());
                            ps.setString(4, d.maskedValue());
                            ps.setString(5, d.occurredIn());
                            ps.setString(6, d.confidence());
                            ps.addBatch();
                        }
                        ps.executeBatch();
                    }
                }
                c.commit();
                return SaveResult.INSERTED;
            } catch (SQLException e) {
                c.rollback();
                throw e;
            }
        } catch (SQLException e) {
            throw new StoreUnavailableException("DB save failed: " + e.getMessage(), e);
        }
    }

    @Override
    public List<LogView> recent(int limit) {
        String sql = """
                SELECT chain_seq, trace_id, request_timestamp, system_code, client_ip, user_id, http_method,
                       request_uri, http_status, execution_time_ms, pii_occurrences, my_number_person_count,
                       alert_level, alert_reason, record_hash
                FROM t_audit_access_log ORDER BY chain_seq DESC LIMIT ?
                """;
        try (Connection c = connect(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setInt(1, limit);
            List<Object[]> rows = new ArrayList<>();
            List<String> traceIds = new ArrayList<>();
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    rows.add(new Object[]{
                            rs.getLong(1), rs.getString(2), rs.getTimestamp(3).toInstant(), rs.getString(4),
                            rs.getString(5), rs.getString(6), rs.getString(7), rs.getString(8), rs.getInt(9),
                            rs.getLong(10), rs.getInt(11), rs.getInt(12), rs.getString(13), rs.getString(14),
                            rs.getString(15)});
                    traceIds.add(rs.getString(2));
                }
            }
            Map<String, List<IngestRequest.Detail>> details = loadDetails(c, traceIds);
            List<LogView> out = new ArrayList<>();
            for (Object[] o : rows) {
                out.add(new LogView((long) o[0], (String) o[1], (java.time.Instant) o[2], (String) o[3],
                        (String) o[4], (String) o[5], (String) o[6], (String) o[7], (int) o[8], (long) o[9],
                        (int) o[10], (int) o[11], (String) o[12], (String) o[13], (String) o[14],
                        details.getOrDefault((String) o[1], List.of())));
            }
            return out;
        } catch (SQLException e) {
            throw new StoreUnavailableException("DB read failed: " + e.getMessage(), e);
        }
    }

    private Map<String, List<IngestRequest.Detail>> loadDetails(Connection c, List<String> traceIds) throws SQLException {
        Map<String, List<IngestRequest.Detail>> map = new HashMap<>();
        if (traceIds.isEmpty()) {
            return map;
        }
        String sql = """
                SELECT trace_id, seq_no, pii_type, masked_value, occurred_in, confidence
                FROM t_audit_pii_detail WHERE trace_id = ANY (?) ORDER BY trace_id, seq_no
                """;
        try (PreparedStatement ps = c.prepareStatement(sql)) {
            Array arr = c.createArrayOf("varchar", traceIds.toArray());
            ps.setArray(1, arr);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    map.computeIfAbsent(rs.getString(1), k -> new ArrayList<>()).add(new IngestRequest.Detail(
                            rs.getInt(2), rs.getString(3), rs.getString(4), rs.getString(5), rs.getString(6)));
                }
            }
        }
        return map;
    }

    @Override
    public VerifyResult verify() {
        try (Connection c = connect()) {
            long count;
            try (PreparedStatement ps = c.prepareStatement("SELECT count(*) FROM t_audit_access_log");
                 ResultSet rs = ps.executeQuery()) {
                rs.next();
                count = rs.getLong(1);
            }
            List<Problem> problems = new ArrayList<>();
            try (PreparedStatement ps = c.prepareStatement("SELECT chain_seq, trace_id, problem FROM fn_audit_verify_chain()");
                 ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    long seq = rs.getLong(1);
                    problems.add(new Problem(rs.wasNull() ? null : seq, rs.getString(2), rs.getString(3)));
                }
            }
            return new VerifyResult(true, count, problems);
        } catch (SQLException e) {
            throw new StoreUnavailableException("DB verify failed: " + e.getMessage(), e);
        }
    }

    @Override
    public Optional<ChainHead> head() {
        try (Connection c = connect();
             PreparedStatement ps = c.prepareStatement("SELECT last_seq, last_hash FROM t_audit_chain_head WHERE id = 1");
             ResultSet rs = ps.executeQuery()) {
            return rs.next() ? Optional.of(new ChainHead(rs.getLong(1), rs.getString(2))) : Optional.empty();
        } catch (SQLException e) {
            throw new StoreUnavailableException("DB read failed: " + e.getMessage(), e);
        }
    }

    @Override
    public Optional<String> hashAt(long chainSeq) {
        try (Connection c = connect();
             PreparedStatement ps = c.prepareStatement("SELECT record_hash FROM t_audit_access_log WHERE chain_seq = ?")) {
            ps.setLong(1, chainSeq);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? Optional.of(rs.getString(1)) : Optional.empty();
            }
        } catch (SQLException e) {
            throw new StoreUnavailableException("DB read failed: " + e.getMessage(), e);
        }
    }

    @Override
    public boolean supportsChain() {
        return true;
    }
}
