package com.audit.sensor.dispatcher;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * JDK 標準の HttpClient でコレクターへ POST する実装。
 * センサーキーは {@code X-Audit-Sensor-Key} ヘッダーで送る（本番では mTLS と併用する想定）。
 */
public class HttpCollectorTransport implements AuditTransport {

    private static final Logger log = Logger.getLogger(HttpCollectorTransport.class.getName());

    private final HttpClient client;
    private final URI uri;
    private final String sensorKey;
    private final Duration timeout;

    public HttpCollectorTransport(String collectorUrl, String sensorKey, long timeoutMs) {
        this.uri = URI.create(collectorUrl);
        this.sensorKey = sensorKey == null ? "" : sensorKey;
        this.timeout = Duration.ofMillis(timeoutMs);
        this.client = HttpClient.newBuilder().connectTimeout(timeout).build();
    }

    @Override
    public Result send(String json) {
        try {
            HttpRequest req = HttpRequest.newBuilder(uri)
                    .timeout(timeout)
                    .header("Content-Type", "application/json; charset=UTF-8")
                    .header("X-Audit-Sensor-Key", sensorKey)
                    .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8))
                    .build();
            int code = client.send(req, HttpResponse.BodyHandlers.discarding()).statusCode();
            if (code / 100 == 2) {
                return Result.DELIVERED;
            }
            if (code == 400 || code == 413) {
                log.warning("[AuditTransport] collector rejected the record permanently: HTTP " + code);
                return Result.REJECTED;
            }
            log.warning("[AuditTransport] collector returned HTTP " + code + " (will retry)");
            return Result.RETRY;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Result.RETRY;
        } catch (Exception e) {
            log.log(Level.FINE, "[AuditTransport] collector unreachable: " + e);
            return Result.RETRY;
        }
    }
}
