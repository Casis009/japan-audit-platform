package com.audit.collector.service;

import com.audit.collector.model.Alert;
import com.audit.collector.model.IngestRequest;
import com.audit.collector.store.AuditStore;

import java.util.logging.Logger;

/** 受信 → 警戒判定 → 保存 → （新規なら）分割照会の集計に反映。 */
public class IngestionService {

    private static final Logger log = Logger.getLogger(IngestionService.class.getName());

    private final AuditStore store;
    private final AlertEvaluator evaluator;

    public IngestionService(AuditStore store, AlertEvaluator evaluator) {
        this.store = store;
        this.evaluator = evaluator;
    }

    public record Outcome(AuditStore.SaveResult result, Alert alert) {
    }

    /** @throws AuditStore.StoreUnavailableException 保存できなかった（呼び出し元は 503 を返す） */
    public Outcome ingest(IngestRequest r) {
        Alert alert = evaluator.evaluate(r);
        AuditStore.SaveResult result = store.save(r, alert);
        if (result == AuditStore.SaveResult.INSERTED) {
            evaluator.record(r);
            if (alert.level() == Alert.Level.CRITICAL) {
                // 生の個人情報はログに出さない（ここにあるのはマスキング済みの値と件数だけ）
                log.warning(String.format("[ALERT][CRITICAL] trace=%s system=%s user=%s ip=%s uri=%s reason=%s",
                        r.traceId(), r.systemCode(), r.userPrincipal(), r.clientIp(), r.requestUri(), alert.reason()));
            }
        }
        return new Outcome(result, alert);
    }

    public AuditStore store() {
        return store;
    }
}
