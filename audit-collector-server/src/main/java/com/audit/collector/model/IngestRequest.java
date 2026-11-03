package com.audit.collector.model;

import com.audit.collector.json.MiniJson;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * センサーから受け取る監査ログ1件。{@link #fromJson(String)} で入力検証まで行う。
 * <p>
 * 方針：足りない項目を「それらしい値」で埋めない。
 * 旧実装はユーザーが無いと特定の社員番号で埋めていたため、無関係の社員に操作が紐付いていた。
 */
public record IngestRequest(
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

    public record Detail(int seqNo, String piiType, String maskedValue, String occurredIn, String confidence) {
    }

    public IngestRequest {
        details = List.copyOf(details);
    }

    public static IngestRequest fromJson(String json) {
        Map<String, Object> m = MiniJson.parseObject(json);

        String traceId = required(m, "traceId", 36);
        Instant ts;
        try {
            ts = Instant.parse(required(m, "timestamp", 40));
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException("timestamp must be ISO-8601 (e.g. 2026-11-03T02:00:00Z)");
        }

        List<Detail> details = new ArrayList<>();
        Object rawDetails = m.get("details");
        if (rawDetails instanceof List<?> list) {
            if (list.size() > 10_000) {
                throw new IllegalArgumentException("too many details");
            }
            int seq = 1;
            for (Object o : list) {
                if (!(o instanceof Map<?, ?> d)) {
                    throw new IllegalArgumentException("details[] must be objects");
                }
                details.add(new Detail(seq++,
                        str(d, "piiType", 32, "UNKNOWN"),
                        str(d, "maskedValue", 128, ""),
                        str(d, "occurredIn", 16, "UNKNOWN"),
                        str(d, "confidence", 8, "MEDIUM")));
            }
        }

        int occurrences = intVal(m, "piiOccurrences", details.size());
        int persons = intVal(m, "myNumberPersonCount", 0);
        if (occurrences < 0 || persons < 0) {
            throw new IllegalArgumentException("counts must be >= 0");
        }

        return new IngestRequest(
                traceId,
                ts,
                str(m, "systemCode", 32, "SYS_UNKNOWN"),
                str(m, "hostName", 64, "unknown"),
                str(m, "clientIp", 45, "unknown"),
                str(m, "userPrincipal", 64, "ANONYMOUS"),
                str(m, "httpMethod", 10, "UNKNOWN"),
                str(m, "requestUri", 1024, "/"),
                str(m, "queryString", 4096, null),
                intVal(m, "httpStatus", 0),
                longVal(m, "executionTimeMs", 0),
                Boolean.TRUE.equals(m.get("piiDetected")) || occurrences > 0,
                occurrences,
                persons,
                details,
                str(m, "requestBody", 1_000_000, null),
                str(m, "responseBody", 1_000_000, null));
    }

    private static String required(Map<String, Object> m, String key, int max) {
        String v = str(m, key, max, null);
        if (v == null || v.isBlank()) {
            throw new IllegalArgumentException(key + " is required");
        }
        return v;
    }

    private static String str(Map<?, ?> m, String key, int max, String def) {
        Object v = m.get(key);
        if (v == null) {
            return def;
        }
        if (!(v instanceof String s)) {
            throw new IllegalArgumentException(key + " must be a string");
        }
        if (s.length() > max) {
            throw new IllegalArgumentException(key + " is too long (max " + max + ")");
        }
        return s;
    }

    private static int intVal(Map<String, Object> m, String key, int def) {
        Object v = m.get(key);
        if (v == null) return def;
        if (!(v instanceof BigDecimal n)) throw new IllegalArgumentException(key + " must be a number");
        try {
            return n.intValueExact();
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException(key + " must be an integer");
        }
    }

    private static long longVal(Map<String, Object> m, String key, long def) {
        Object v = m.get(key);
        if (v == null) return def;
        if (!(v instanceof BigDecimal n)) throw new IllegalArgumentException(key + " must be a number");
        try {
            return n.longValueExact();
        } catch (ArithmeticException e) {
            throw new IllegalArgumentException(key + " must be an integer");
        }
    }
}
