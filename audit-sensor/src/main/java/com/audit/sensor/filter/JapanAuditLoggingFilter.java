package com.audit.sensor.filter;

import com.audit.rule.detector.JapanPiiDetector;
import com.audit.rule.model.DetectedItem;
import com.audit.rule.model.DetectionResult;
import com.audit.rule.model.PiiType;
import com.audit.sensor.config.AuditSensorProperties;
import com.audit.sensor.dispatcher.AuditLogDispatcher;
import com.audit.sensor.model.AuditLogPayload;
import com.audit.sensor.wrapper.AuditContentCachingRequestWrapper;
import com.audit.sensor.wrapper.AuditContentCachingResponseWrapper;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.security.Principal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 業務アプリの前段に置く監査ログ収集フィルター。
 *
 * <h2>設計原則</h2>
 * <ul>
 *   <li><b>非侵襲</b>：業務側の本文・レスポンスは1バイトも変えない（コピーは上限付きで別に取る）。</li>
 *   <li><b>フェイルオープン</b>：監査処理で起きた例外は握りつぶして記録だけし、業務レスポンスには影響させない。</li>
 *   <li><b>マスキングしてから外に出す</b>：個人情報はこのフィルター内でマスキングし、生値はプロセス外へ出さない。</li>
 *   <li><b>Who・Where は信頼できる情報源からだけ取る</b>：
 *       リクエスト本文や任意ヘッダーの自己申告は採用しない（なりすまし防止）。</li>
 * </ul>
 */
public class JapanAuditLoggingFilter implements Filter {

    private static final Logger log = Logger.getLogger(JapanAuditLoggingFilter.class.getName());

    private final AuditSensorProperties props;
    private final AuditLogDispatcher dispatcher;
    private final JapanPiiDetector detector;

    public JapanAuditLoggingFilter(AuditSensorProperties props, AuditLogDispatcher dispatcher, JapanPiiDetector detector) {
        this.props = props;
        this.dispatcher = dispatcher;
        this.detector = detector;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (!props.isEnabled()
                || !(request instanceof HttpServletRequest httpReq)
                || !(response instanceof HttpServletResponse httpRes)) {
            chain.doFilter(request, response);
            return;
        }

        long startNanos = System.nanoTime();
        Instant startedAt = Instant.now();
        var req = new AuditContentCachingRequestWrapper(httpReq, props.getMaxCaptureBytes());
        var res = new AuditContentCachingResponseWrapper(httpRes, props.getMaxCaptureBytes());

        boolean businessFailed = false;
        try {
            chain.doFilter(req, res);
        } catch (IOException | ServletException | RuntimeException e) {
            businessFailed = true;
            throw e; // 業務の例外はそのまま上へ（監査は記録だけする）
        } finally {
            try {
                long ms = (System.nanoTime() - startNanos) / 1_000_000;
                int status = businessFailed && res.getStatus() < 400 ? 500 : res.getStatus();
                dispatcher.dispatch(buildPayload(req, res, status, ms, startedAt));
            } catch (Exception auditError) {
                // フェイルオープン：監査側の失敗は業務に波及させない
                log.log(Level.WARNING, "[AuditFilter] audit processing failed (business response unaffected)", auditError);
            }
        }
    }

    AuditLogPayload buildPayload(AuditContentCachingRequestWrapper req, AuditContentCachingResponseWrapper res,
                                 int status, long ms, Instant startedAt) {
        String query = req.getQueryString();
        String reqBody = req.getCapturedBody();
        String resBody = res.getCapturedBody();

        List<AuditLogPayload.Detail> details = new ArrayList<>();
        Set<String> myNumbers = new HashSet<>();
        int occurrences = 0;

        if (props.isMaskPii()) {
            DetectionResult q = detector.scanAndMask(query);
            DetectionResult rq = detector.scanAndMask(reqBody);
            DetectionResult rs = detector.scanAndMask(resBody);
            occurrences += addDetails(q, "QUERY_STRING", details, myNumbers);
            occurrences += addDetails(rq, "REQUEST_BODY", details, myNumbers);
            occurrences += addDetails(rs, "RESPONSE_BODY", details, myNumbers);
            query = q.maskedText();
            reqBody = rq.maskedText();
            resBody = rs.maskedText();
        }

        return new AuditLogPayload(
                UUID.randomUUID().toString(),
                startedAt,
                props.getSystemCode(),
                props.getHostName(),
                resolveClientIp(req),
                resolvePrincipal(req),
                req.getMethod(),
                req.getRequestURI(),
                query,
                status,
                ms,
                occurrences > 0,
                occurrences,
                myNumbers.size(),
                details,
                props.isSendBody() ? reqBody : null,
                props.isSendBody() ? resBody : null
        );
    }

    private static int addDetails(DetectionResult r, String where, List<AuditLogPayload.Detail> out, Set<String> myNumbers) {
        for (DetectedItem it : r.items()) {
            out.add(new AuditLogPayload.Detail(it.type().name(), it.maskedValue(), where, it.confidence().name()));
            if (it.type() == PiiType.MY_NUMBER && it.rawValue() != null) {
                myNumbers.add(it.rawValue().replace("-", "")); // 本人数カウント用（プロセス外には出さない）
            }
        }
        return r.occurrenceCount();
    }

    /**
     * Who の決定。
     * 1) コンテナ／業務アプリの認証結果（getUserPrincipal）
     * 2) 信頼済みプロキシ（認証ゲートウェイ）から来た場合に限り、そのユーザーヘッダー
     * 3) どちらもなければ ANONYMOUS（特定の社員番号で埋めない）
     */
    String resolvePrincipal(HttpServletRequest req) {
        Principal p = req.getUserPrincipal();
        if (p != null && p.getName() != null && !p.getName().isBlank()) {
            return p.getName();
        }
        if (isFromTrustedProxy(req)) {
            String h = req.getHeader(props.getTrustedUserHeader());
            if (h != null && !h.isBlank()) {
                return h.trim();
            }
        }
        return "ANONYMOUS";
    }

    /**
     * Where の決定。X-Forwarded-For は誰でも書けるヘッダーなので、
     * 信頼済みプロキシから来たときだけ採用する（それ以外は接続元アドレス）。
     */
    String resolveClientIp(HttpServletRequest req) {
        String remote = req.getRemoteAddr();
        if (isFromTrustedProxy(req)) {
            String xff = req.getHeader("X-Forwarded-For");
            if (xff != null && !xff.isBlank()) {
                return xff.split(",")[0].trim();
            }
        }
        return remote != null ? remote : "unknown";
    }

    private boolean isFromTrustedProxy(HttpServletRequest req) {
        String remote = req.getRemoteAddr();
        return remote != null && props.getTrustedProxies().contains(remote);
    }
}
