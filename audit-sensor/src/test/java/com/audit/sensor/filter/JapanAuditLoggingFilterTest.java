package com.audit.sensor.filter;

import com.audit.rule.detector.JapanPiiDetector;
import com.audit.rule.model.DetectionResult;
import com.audit.sensor.config.AuditSensorProperties;
import com.audit.sensor.dispatcher.AuditLogDispatcher;
import com.audit.sensor.dispatcher.AuditTransport;
import com.audit.sensor.model.AuditLogPayload;
import com.audit.sensor.spool.DiskSpoolManager;
import com.audit.sensor.testsupport.FakeHttp;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JapanAuditLoggingFilterTest {

    /** 送信された JSON を記録するだけの偽コレクター。 */
    private final List<String> received = new CopyOnWriteArrayList<>();

    private AuditLogDispatcher dispatcher() throws Exception {
        String dir = Files.createTempDirectory("spool").toString();
        return new AuditLogDispatcher(100, json -> { received.add(json); return AuditTransport.Result.DELIVERED; }, new DiskSpoolManager(dir, 1_000_000), 60_000);
    }

    private AuditSensorProperties props() {
        AuditSensorProperties p = new AuditSensorProperties();
        p.setSystemCode("SYS_TEST");
        p.setTrustedProxies(Set.of("10.0.0.1"));
        return p;
    }

    private String awaitOne() throws InterruptedException {
        for (int i = 0; i < 100 && received.isEmpty(); i++) Thread.sleep(20);
        assertEquals(1, received.size());
        return received.get(0);
    }

    @Test
    @DisplayName("レスポンス中のマイナンバーはマスキングされ、生値は送信データに含まれない")
    void masksBeforeSending() throws Exception {
        try (var d = dispatcher()) {
            var filter = new JapanAuditLoggingFilter(props(), d, new JapanPiiDetector());
            var req = new FakeHttp.Request("");
            req.principal = () -> "EMP_TEST_1";
            var res = new FakeHttp.Response();
            FilterChain chain = (rq, rs) -> rs.getWriter().write("{\"myNumber\":\"123456789018\",\"m2\":\"1234-5678-9018\"}");

            filter.doFilter(req, res, chain);

            assertTrue(res.sentText().contains("123456789018"), "client must get the original response");
            String json = awaitOne();
            assertFalse(json.contains("123456789018"));
            assertTrue(json.contains("********9018"));
            assertTrue(json.contains("\"myNumberPersonCount\":1"), json);   // 同一番号2回 → 本人数1
            assertTrue(json.contains("\"piiOccurrences\":2"), json);
            assertTrue(json.contains("\"userPrincipal\":\"EMP_TEST_1\""));
            assertTrue(json.contains("\"responseBody\":null"), "body must not be sent by default (data minimization)");
        }
    }

    @Test
    @DisplayName("【なりすまし対策】信頼していない接続元の X-Forwarded-For・ユーザーヘッダーは無視")
    void ignoresSpoofableHeadersFromUntrustedClients() throws Exception {
        try (var d = dispatcher()) {
            var filter = new JapanAuditLoggingFilter(props(), d, new JapanPiiDetector());
            var req = new FakeHttp.Request("");
            req.remoteAddr = "203.0.113.9";
            req.headers.put("X-Forwarded-For", "1.2.3.4");
            req.headers.put("X-Authenticated-User", "EMP_CEO");

            filter.doFilter(req, new FakeHttp.Response(), (rq, rs) -> { });

            String json = awaitOne();
            assertTrue(json.contains("\"clientIp\":\"203.0.113.9\""), json);
            assertTrue(json.contains("\"userPrincipal\":\"ANONYMOUS\""), json);
        }
    }

    @Test
    @DisplayName("信頼済みプロキシ経由なら X-Forwarded-For とユーザーヘッダーを採用")
    void honorsTrustedProxy() throws Exception {
        try (var d = dispatcher()) {
            var filter = new JapanAuditLoggingFilter(props(), d, new JapanPiiDetector());
            var req = new FakeHttp.Request("");
            req.remoteAddr = "10.0.0.1";
            req.headers.put("X-Forwarded-For", "198.51.100.7, 10.0.0.1");
            req.headers.put("X-Authenticated-User", "EMP_GW_USER");

            filter.doFilter(req, new FakeHttp.Response(), (rq, rs) -> { });

            String json = awaitOne();
            assertTrue(json.contains("\"clientIp\":\"198.51.100.7\""), json);
            assertTrue(json.contains("\"userPrincipal\":\"EMP_GW_USER\""), json);
        }
    }

    @Test
    @DisplayName("業務で例外が起きても例外はそのまま上へ、監査ログは status=500 で残る")
    void businessExceptionPropagatesAndIsAudited() throws Exception {
        try (var d = dispatcher()) {
            var filter = new JapanAuditLoggingFilter(props(), d, new JapanPiiDetector());
            assertThrows(IllegalStateException.class, () ->
                    filter.doFilter(new FakeHttp.Request(""), new FakeHttp.Response(), (rq, rs) -> {
                        throw new IllegalStateException("boom");
                    }));
            assertTrue(awaitOne().contains("\"httpStatus\":500"));
        }
    }

    @Test
    @DisplayName("【フェイルオープン】検知処理が壊れても業務レスポンスは正常に返る")
    void auditFailureDoesNotBreakBusiness() throws Exception {
        try (var d = dispatcher()) {
            JapanPiiDetector broken = new JapanPiiDetector() {
                @Override
                public DetectionResult scanAndMask(String text) {
                    throw new RuntimeException("detector crashed");
                }
            };
            var filter = new JapanAuditLoggingFilter(props(), d, broken);
            var res = new FakeHttp.Response();

            filter.doFilter(new FakeHttp.Request(""), res, (rq, rs) -> rs.getWriter().write("OK"));

            assertEquals("OK", res.sentText());
        }
    }

    @Test
    @DisplayName("送信ペイロードは1行のJSON（改行を含む値もエスケープ）")
    void payloadIsSingleLine() {
        var p = new AuditLogPayload("t", null, "S", "h", "ip", "u", "GET", "/a\nb", null, 200, 1,
                false, 0, 0, List.of(), "x\"y\n", null);
        String json = p.toJson();
        assertFalse(json.contains("\n"));
        assertTrue(json.contains("\"requestUri\":\"/a\\nb\""));
    }
}
