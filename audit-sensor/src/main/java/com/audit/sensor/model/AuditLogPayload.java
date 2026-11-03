package com.audit.sensor.model;

import java.time.Instant;
import java.util.List;

/**
 * センサー → コレクターへ送る監査ログ1件（JSON 1行 = 1件）。
 * <p>
 * 6何原則：Who=userPrincipal / When=timestamp / Where=clientIp・systemCode /
 * Whom=details（誰の情報か＝マスキング値） / What=requestUri・httpMethod / How=httpStatus・executionTimeMs
 * <p>
 * 生の個人情報は持たない。details はすべてマスキング済みの値。
 */
public record AuditLogPayload(
        String traceId,
        Instant timestamp,
        String systemCode,
        String hostName,
        String clientIp,
        String userPrincipal,
        String httpMethod,
        String requestUri,
        String queryString,
        int httpStatus,
        long executionTimeMs,
        boolean piiDetected,
        int piiOccurrences,
        int myNumberPersonCount,
        List<Detail> details,
        String requestBody,
        String responseBody
) {

    /** 検知明細（マスキング済み）。occurredIn は REQUEST_BODY / RESPONSE_BODY / QUERY_STRING。 */
    public record Detail(String piiType, String maskedValue, String occurredIn, String confidence) {
    }

    public AuditLogPayload {
        details = details == null ? List.of() : List.copyOf(details);
    }

    public String toJson() {
        StringBuilder sb = new StringBuilder(256);
        sb.append('{');
        str(sb, "traceId", traceId).append(',');
        str(sb, "timestamp", timestamp == null ? null : timestamp.toString()).append(',');
        str(sb, "systemCode", systemCode).append(',');
        str(sb, "hostName", hostName).append(',');
        str(sb, "clientIp", clientIp).append(',');
        str(sb, "userPrincipal", userPrincipal).append(',');
        str(sb, "httpMethod", httpMethod).append(',');
        str(sb, "requestUri", requestUri).append(',');
        str(sb, "queryString", queryString).append(',');
        sb.append("\"httpStatus\":").append(httpStatus).append(',');
        sb.append("\"executionTimeMs\":").append(executionTimeMs).append(',');
        sb.append("\"piiDetected\":").append(piiDetected).append(',');
        sb.append("\"piiOccurrences\":").append(piiOccurrences).append(',');
        sb.append("\"myNumberPersonCount\":").append(myNumberPersonCount).append(',');
        sb.append("\"details\":[");
        for (int i = 0; i < details.size(); i++) {
            Detail d = details.get(i);
            if (i > 0) sb.append(',');
            sb.append('{');
            str(sb, "piiType", d.piiType()).append(',');
            str(sb, "maskedValue", d.maskedValue()).append(',');
            str(sb, "occurredIn", d.occurredIn()).append(',');
            str(sb, "confidence", d.confidence());
            sb.append('}');
        }
        sb.append("],");
        str(sb, "requestBody", requestBody).append(',');
        str(sb, "responseBody", responseBody);
        sb.append('}');
        return sb.toString();
    }

    private static StringBuilder str(StringBuilder sb, String key, String value) {
        sb.append('"').append(key).append("\":");
        if (value == null) {
            return sb.append("null");
        }
        sb.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.append('"');
    }
}
