package com.audit.demo;

import com.audit.demo.adapter.ExchangeRequest;
import com.audit.demo.adapter.ExchangeResponse;
import com.audit.rule.mynumber.MyNumberModulus11Validator;
import com.audit.sensor.config.AuditSensorFactory;
import com.audit.sensor.config.AuditSensorProperties;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 監査センサーを組み込んだ「架空の顧客管理システム」（デモ用の業務アプリ）。
 *
 * <pre>
 *  クライアント ─▶ [アダプター：認証] ─▶ [監査フィルター] ─▶ 業務処理
 *                                           └─(非同期)─▶ コレクター
 * </pre>
 * 業務処理（{@link #business}）は監査のことを一切知らない。フィルターを1つ挟むだけで監査ログが取れる＝非侵襲。
 * <p>
 * データはすべて架空：氏名「架空 太郎n」、電話「000-xxxx-xxxx」（000 は実在しない局番）、
 * メール「@example.com」、マイナンバーはチェックディジットだけ正しい架空番号。
 */
public final class DemoBusinessApplication {

    private static final Logger log = Logger.getLogger(DemoBusinessApplication.class.getName());

    /** デモ用の認証トークン → 社員ID（本番では IdP / SSO が行う）。 */
    private static final Map<String, String> DEMO_TOKENS = Map.of(
            "demo-token-0001", "EMP_DEMO_0001",
            "demo-token-0002", "EMP_DEMO_0002",
            "demo-token-0003", "EMP_DEMO_0003");

    private DemoBusinessApplication() {
    }

    public static void main(String[] args) throws IOException {
        Map<String, String> env = new HashMap<>(System.getenv());
        env.putIfAbsent("AUDIT_SYSTEM_CODE", "SYS_DEMO_CUSTOMER");
        AuditSensorProperties props = AuditSensorProperties.fromEnv(env);
        AuditSensorFactory.AuditSensor sensor = AuditSensorFactory.create(props);
        int port = Integer.parseInt(env.getOrDefault("APP_PORT", "8080"));

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());

        // 業務API：監査フィルターを通す
        server.createContext("/api/", ex -> {
            try {
                ExchangeRequest req = new ExchangeRequest(ex);
                ExchangeResponse res = new ExchangeResponse(ex);
                authenticate(req); // コンテナ側の認証（Bearer トークン）
                FilterChain business = (rq, rs) -> business((HttpServletRequest) rq, (HttpServletResponse) rs);
                try {
                    sensor.filter().doFilter(req, res, business);
                } catch (Exception e) {
                    log.log(Level.WARNING, "business error", e);
                    res.reset();
                    res.setStatus(500);
                    res.setContentType("application/json");
                    res.getWriter().write("{\"error\":\"INTERNAL\"}");
                }
                res.commit();
            } finally {
                ex.close();
            }
        });

        // 運用確認用（監査対象外）：センサーの送信状況
        server.createContext("/internal/audit-stats", ex -> {
            var d = sensor.dispatcher();
            var s = d.getSpool();
            String json = String.format(
                    "{\"sent\":%d,\"queue\":%d,\"spooledTotal\":%d,\"spoolBytes\":%d,\"resent\":%d,\"rejected\":%d,\"dropped\":%d,\"overflow\":%d}",
                    d.getSentCount(), d.getQueueSize(), s.getSpooledCount(), s.getSpooledBytes(),
                    s.getResentCount(), s.getRejectedCount(), s.getDroppedCount(), d.getOverflowCount());
            reply(ex, 200, "application/json", json);
        });

        server.createContext("/", ex -> {
            if (!"/".equals(ex.getRequestURI().getPath())) {
                reply(ex, 404, "text/plain; charset=UTF-8", "Not Found");
                return;
            }
            reply(ex, 200, "text/html; charset=UTF-8", DemoPage.HTML);
        });

        Runtime.getRuntime().addShutdownHook(new Thread(sensor::close)); // 停止時はキューを退避してから終わる
        server.start();
        log.info("[DemoApp] listening on :" + port + " system=" + props.getSystemCode() + " collector=" + props.getCollectorUrl());
    }

    private static void authenticate(ExchangeRequest req) {
        String auth = req.getHeader("Authorization");
        if (auth != null && auth.startsWith("Bearer ")) {
            String user = DEMO_TOKENS.get(auth.substring(7).trim());
            if (user != null) {
                req.setUserPrincipal(() -> user);
            }
        }
    }

    // ------------------------------------------------------------------ 業務処理（監査を意識しない）

    static void business(HttpServletRequest req, HttpServletResponse res) throws IOException {
        res.setContentType("application/json");
        if (req.getUserPrincipal() == null) {
            res.setStatus(401);
            res.getWriter().write("{\"error\":\"UNAUTHORIZED\"}");
            return;
        }
        String path = req.getRequestURI();
        String method = req.getMethod();

        if ("GET".equals(method) && path.matches("/api/v1/customers/\\d+")) {
            int id = Integer.parseInt(path.substring(path.lastIndexOf('/') + 1));
            res.getWriter().write(customerJson(id));
        } else if ("GET".equals(method) && "/api/v1/customers/export".equals(path)) {
            int count = parseCount(req.getParameter("count"));
            int from = parseCount(req.getParameter("from"));
            StringBuilder sb = new StringBuilder("{\"customers\":[");
            for (int i = 0; i < count; i++) {
                if (i > 0) sb.append(',');
                sb.append(customerJson(Math.max(1, from) + i));
            }
            res.getWriter().write(sb.append("]}").toString());
        } else if ("POST".equals(method) && "/api/v1/customers/register".equals(path)) {
            String body = readAll(req.getInputStream());
            res.setStatus(201);
            res.getWriter().write("{\"status\":\"REGISTERED\",\"receivedBytes\":" + body.getBytes(StandardCharsets.UTF_8).length + "}");
        } else if ("POST".equals(method) && "/api/v1/documents/upload".equals(path)) {
            // 大きな本文が業務側に「全部」届くことを確認するためのエンドポイント
            long n = 0;
            byte[] buf = new byte[8192];
            InputStream in = req.getInputStream();
            int r;
            while ((r = in.read(buf)) != -1) n += r;
            res.getWriter().write("{\"status\":\"UPLOADED\",\"receivedBytes\":" + n + "}");
        } else {
            res.setStatus(404);
            res.getWriter().write("{\"error\":\"NOT_FOUND\"}");
        }
    }

    /** 架空の顧客1件。マイナンバーはチェックディジットだけ正しい架空番号。 */
    static String customerJson(int id) {
        String myNumber = MyNumberModulus11Validator.generateValidMyNumber(String.format("9%010d", id));
        return String.format(
                "{\"customerId\":%d,\"name\":\"架空 太郎%d\",\"myNumber\":\"%s\",\"phone\":\"000-%04d-%04d\",\"email\":\"user%d@example.com\"}",
                id, id, myNumber, id / 10000 % 10000, id % 10000, id);
    }

    private static int parseCount(String v) {
        try {
            return v == null ? 1 : Math.max(0, Math.min(1000, Integer.parseInt(v)));
        } catch (NumberFormatException e) {
            return 1;
        }
    }

    private static String readAll(InputStream in) throws IOException {
        return new String(in.readAllBytes(), StandardCharsets.UTF_8);
    }

    private static void reply(HttpExchange ex, int code, String type, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", type);
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(b);
        }
    }
}
