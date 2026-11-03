package com.audit.collector.model;

import java.time.Instant;
import java.util.List;

/** 画面・API に返す監査ログ1件（マスキング済みの値だけを含む）。 */
public record LogView(
        long chainSeq,
        String traceId,
        Instant timestamp,
        String systemCode,
        String clientIp,
        String userId,
        String httpMethod,
        String requestUri,
        int httpStatus,
        long executionTimeMs,
        int piiOccurrences,
        int myNumberPersonCount,
        String alertLevel,
        String alertReason,
        String recordHash,
        List<IngestRequest.Detail> details
) {
}
