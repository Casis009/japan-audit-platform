package com.audit.collector.web;

import com.audit.collector.config.CollectorConfig;
import com.audit.collector.store.InMemoryAuditStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Duration;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 実際に HTTP サーバーを起動して叩く（保存先はメモリ）。 */
class CollectorServerTest {

    private static final String KEY = "test-sensor-key-0123456789";
    private static final String BODY = "{\"traceId\":\"t-%s\",\"timestamp\":\"2026-11-03T02:00:00Z\",\"userPrincipal\":\"EMP_X\","
            + "\"requestUri\":\"/a<img src=x onerror=alert(1)>\",\"piiOccurrences\":0}";

    private final HttpClient http = HttpClient.newHttpClient();

    private static int freePort() throws Exception {
        try (ServerSocket s = new ServerSocket(0)) {
            return s.getLocalPort();
        }
    }

    private CollectorServer start(int port) throws Exception {
        var cfg = new CollectorConfig(port, "memory", "", "", "", KEY, "auditor", "pw", 100, Duration.ofMinutes(10),
                Files.createTempFile("anchors", ".jsonl"), Duration.ofHours(1), 1_000_000);
        var s = new CollectorServer(cfg, new InMemoryAuditStore(100));
        s.start();
        return s;
    }

    private HttpResponse<String> post(int port, String key, String body) throws Exception {
        var b = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/v1/collector/ingest"))
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (key != null) b.header("X-Audit-Sensor-Key", key);
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> get(int port, String path, boolean auth) throws Exception {
        var b = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path));
        if (auth) {
            b.header("Authorization", "Basic " + Base64.getEncoder().encodeToString("auditor:pw".getBytes(StandardCharsets.UTF_8)));
        }
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    @DisplayName("【回帰】キー無し・誤キーは401、正しいキーで202、同じログの再送は200(DUPLICATE)")
    void ingestAuthAndIdempotency() throws Exception {
        int port = freePort();
        var s = start(port);
        try {
            assertEquals(401, post(port, null, BODY.formatted("1")).statusCode());
            assertEquals(401, post(port, "wrong", BODY.formatted("1")).statusCode());
            assertEquals(202, post(port, KEY, BODY.formatted("1")).statusCode());
            var dup = post(port, KEY, BODY.formatted("1"));
            assertEquals(200, dup.statusCode());
            assertTrue(dup.body().contains("DUPLICATE"));
            assertEquals(400, post(port, KEY, "{broken").statusCode());
        } finally {
            s.stop();
        }
    }

    @Test
    @DisplayName("【回帰】コンソールAPIは認証必須、ログ中の HTML はエスケープされて返る")
    void consoleRequiresAuthAndEscapes() throws Exception {
        int port = freePort();
        var s = start(port);
        try {
            post(port, KEY, BODY.formatted("2"));
            assertEquals(401, get(port, "/api/v1/collector/logs", false).statusCode());
            assertEquals(401, get(port, "/", false).statusCode());
            var logs = get(port, "/api/v1/collector/logs", true);
            assertEquals(200, logs.statusCode());
            assertFalse(logs.body().contains("<img"), logs.body());
            assertTrue(logs.body().contains("\\u003cimg"));
            var page = get(port, "/", true);
            assertTrue(page.headers().firstValue("Content-Security-Policy").orElse("").contains("script-src 'self'"));
            assertFalse(page.body().contains("innerHTML"));
            assertFalse(get(port, "/console.js", true).body().contains("innerHTML ="));
        } finally {
            s.stop();
        }
    }
}
