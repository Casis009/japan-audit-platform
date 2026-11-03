package com.audit.collector.web;

import com.audit.collector.config.CollectorConfig;
import com.audit.collector.json.MiniJson;
import com.audit.collector.model.IngestRequest;
import com.audit.collector.security.Credentials;
import com.audit.collector.service.AlertEvaluator;
import com.audit.collector.service.ChainAnchorService;
import com.audit.collector.service.IngestionService;
import com.audit.collector.store.AuditStore;
import com.audit.collector.store.InMemoryAuditStore;
import com.audit.collector.store.PostgresAuditStore;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 監査ログ収集サーバー（JDK 標準 HttpServer ＋ 仮想スレッド）。
 *
 * <pre>
 *  POST /api/v1/collector/ingest        センサーキー必須。202=新規 / 200=重複（冪等）/ 400=不正 / 401=認証NG / 503=保存不可
 *  GET  /api/v1/collector/logs          Basic 認証。直近ログ（マスキング済み）
 *  GET  /api/v1/collector/chain/verify  Basic 認証。ハッシュチェーン＋アンカー照合の結果
 *  POST /api/v1/collector/chain/anchor  Basic 認証。アンカーを今すぐ記録
 *  GET  /api/v1/collector/health        認証なし
 *  GET  /  , /console.js                Basic 認証。監査コンソール
 * </pre>
 * 503 を返すのが重要：DB に書けなかったのに 2xx を返すと、センサーは「届いた」と判断して退避しないため、ログが消える。
 */
public final class CollectorServer {

    private static final Logger log = Logger.getLogger(CollectorServer.class.getName());
    private static final String CSP =
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'";

    private final CollectorConfig cfg;
    private final IngestionService ingestion;
    private final ChainAnchorService anchors;
    private HttpServer server;

    public CollectorServer(CollectorConfig cfg, AuditStore store) {
        this.cfg = cfg;
        this.ingestion = new IngestionService(store, new AlertEvaluator(cfg.personThreshold(), cfg.alertWindow()));
        this.anchors = new ChainAnchorService(store, cfg.anchorFile());
    }

    public static void main(String[] args) throws IOException {
        CollectorConfig cfg = CollectorConfig.fromEnv(System.getenv());
        AuditStore store = "memory".equalsIgnoreCase(cfg.storage())
                ? new InMemoryAuditStore(10_000)
                : new PostgresAuditStore(cfg.dbUrl(), cfg.dbUser(), cfg.dbPassword());
        new CollectorServer(cfg, store).start();
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(cfg.port()), 0);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.createContext("/api/v1/collector/ingest", safe(this::ingest));
        server.createContext("/api/v1/collector/logs", safe(console(this::logs)));
        server.createContext("/api/v1/collector/chain/verify", safe(console(this::verify)));
        server.createContext("/api/v1/collector/chain/anchor", safe(console(this::anchor)));
        server.createContext("/api/v1/collector/health", safe(ex -> send(ex, 200, "application/json", "{\"status\":\"UP\"}")));
        server.createContext("/console.js", safe(console(ex -> send(ex, 200, "text/javascript; charset=UTF-8", ConsoleAssets.JS))));
        server.createContext("/", safe(console(this::page)));
        server.start();

        Thread.ofVirtual().name("chain-anchor").start(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    Thread.sleep(cfg.anchorInterval().toMillis());
                    anchors.anchorNow();
                } catch (InterruptedException e) {
                    return;
                } catch (Exception e) {
                    log.log(Level.FINE, "[Anchor] skipped: " + e.getMessage());
                }
            }
        });
        log.info("[Collector] listening on :" + cfg.port() + " storage=" + cfg.storage()
                + (cfg.consolePassword().isEmpty() ? " (console disabled: CONSOLE_PASSWORD not set)" : ""));
    }

    public void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    // ---------------------------------------------------------------- handlers

    private void ingest(HttpExchange ex) throws IOException {
        if (!"POST".equals(ex.getRequestMethod())) {
            send(ex, 405, "application/json", "{\"error\":\"METHOD_NOT_ALLOWED\"}");
            return;
        }
        if (!Credentials.sensorKeyMatches(ex.getRequestHeaders().getFirst("X-Audit-Sensor-Key"), cfg.sensorKey())) {
            send(ex, 401, "application/json", "{\"error\":\"UNAUTHORIZED\"}");
            return;
        }
        byte[] body;
        try (InputStream in = ex.getRequestBody()) {
            body = in.readNBytes(cfg.maxRequestBytes() + 1);
        }
        if (body.length > cfg.maxRequestBytes()) {
            send(ex, 413, "application/json", "{\"error\":\"PAYLOAD_TOO_LARGE\"}");
            return;
        }
        IngestRequest req;
        try {
            req = IngestRequest.fromJson(new String(body, StandardCharsets.UTF_8));
        } catch (IllegalArgumentException | MiniJson.JsonException e) {
            send(ex, 400, "application/json", "{\"error\":\"BAD_REQUEST\",\"message\":" + MiniJson.quote(e.getMessage()) + "}");
            return;
        }
        try {
            IngestionService.Outcome o = ingestion.ingest(req);
            boolean dup = o.result() == AuditStore.SaveResult.DUPLICATE;
            send(ex, dup ? 200 : 202, "application/json",
                    "{\"status\":" + MiniJson.quote(dup ? "DUPLICATE" : "ACCEPTED")
                            + ",\"traceId\":" + MiniJson.quote(req.traceId())
                            + ",\"alertLevel\":" + MiniJson.quote(o.alert().level().name()) + "}");
        } catch (AuditStore.StoreUnavailableException e) {
            log.warning("[Collector] store unavailable -> 503 (sensor will spool and retry): " + e.getMessage());
            send(ex, 503, "application/json", "{\"error\":\"STORE_UNAVAILABLE\"}");
        }
    }

    private void logs(HttpExchange ex) throws IOException {
        int limit = 100;
        String q = ex.getRequestURI().getQuery();
        if (q != null && q.startsWith("limit=")) {
            try {
                limit = Math.max(1, Math.min(1000, Integer.parseInt(q.substring(6))));
            } catch (NumberFormatException ignored) {
                // 既定値のまま
            }
        }
        send(ex, 200, "application/json; charset=UTF-8", JsonViews.logs(ingestion.store().recent(limit)));
    }

    private void verify(HttpExchange ex) throws IOException {
        AuditStore.VerifyResult v = ingestion.store().verify();
        ChainAnchorService.AnchorCheck a = v.available() ? anchors.check() : new ChainAnchorService.AnchorCheck(0, java.util.List.of());
        send(ex, 200, "application/json; charset=UTF-8", JsonViews.verify(v, a));
    }

    private void anchor(HttpExchange ex) throws IOException {
        if (!"POST".equals(ex.getRequestMethod())) {
            send(ex, 405, "application/json", "{\"error\":\"METHOD_NOT_ALLOWED\"}");
            return;
        }
        var a = anchors.anchorNow();
        send(ex, 200, "application/json", a.map(x -> "{\"seq\":" + x.seq() + ",\"hash\":" + MiniJson.quote(x.hash()) + "}")
                .orElse("{\"seq\":null}"));
    }

    private void page(HttpExchange ex) throws IOException {
        if (!"/".equals(ex.getRequestURI().getPath())) {
            send(ex, 404, "text/plain; charset=UTF-8", "Not Found");
            return;
        }
        send(ex, 200, "text/html; charset=UTF-8", ConsoleAssets.HTML);
    }

    // ---------------------------------------------------------------- plumbing

    private HttpHandler console(HttpHandler next) {
        return ex -> {
            if (cfg.consolePassword().isEmpty()) {
                send(ex, 503, "text/plain; charset=UTF-8", "console disabled: set CONSOLE_PASSWORD");
                return;
            }
            if (!Credentials.basicAuthMatches(ex.getRequestHeaders().getFirst("Authorization"),
                    cfg.consoleUser(), cfg.consolePassword())) {
                ex.getResponseHeaders().set("WWW-Authenticate", "Basic realm=\"audit-console\", charset=\"UTF-8\"");
                send(ex, 401, "text/plain; charset=UTF-8", "Unauthorized");
                return;
            }
            next.handle(ex);
        };
    }

    private static HttpHandler safe(HttpHandler h) {
        return ex -> {
            try {
                h.handle(ex);
            } catch (AuditStore.StoreUnavailableException e) {
                send(ex, 503, "application/json", "{\"error\":\"STORE_UNAVAILABLE\"}");
            } catch (Exception e) {
                log.log(Level.WARNING, "[Collector] handler error", e);
                try {
                    send(ex, 500, "application/json", "{\"error\":\"INTERNAL\"}");
                } catch (IOException ignored) {
                    // 既に応答済み
                }
            } finally {
                ex.close();
            }
        };
    }

    static void send(HttpExchange ex, int code, String type, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        var h = ex.getResponseHeaders();
        h.set("Content-Type", type);
        h.set("X-Content-Type-Options", "nosniff");
        h.set("Cache-Control", "no-store");
        h.set("Content-Security-Policy", CSP);
        ex.sendResponseHeaders(code, b.length == 0 ? -1 : b.length);
        if (b.length > 0) {
            try (OutputStream os = ex.getResponseBody()) {
                os.write(b);
            }
        }
    }
}
