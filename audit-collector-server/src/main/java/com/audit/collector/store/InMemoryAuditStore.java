package com.audit.collector.store;

import com.audit.collector.model.Alert;
import com.audit.collector.model.IngestRequest;
import com.audit.collector.model.LogView;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * DB なしで動かすためのメモリ保存（デモ・単体テスト用）。
 * 再起動で消え、改ざん防止（ハッシュチェーン）も持たない。画面には「検証不可」と表示する。
 */
public class InMemoryAuditStore implements AuditStore {

    private final Map<String, LogView> byTrace = new LinkedHashMap<>();
    private final int capacity;
    private long seq;

    public InMemoryAuditStore(int capacity) {
        this.capacity = capacity;
    }

    @Override
    public synchronized SaveResult save(IngestRequest r, Alert a) {
        if (byTrace.containsKey(r.traceId())) {
            return SaveResult.DUPLICATE;
        }
        byTrace.put(r.traceId(), new LogView(++seq, r.traceId(), r.timestamp(), r.systemCode(), r.clientIp(),
                r.userPrincipal(), r.httpMethod(), r.requestUri(), r.httpStatus(), r.executionTimeMs(),
                r.piiOccurrences(), r.myNumberPersonCount(), a.level().name(), a.reason(), null, r.details()));
        if (byTrace.size() > capacity) {
            byTrace.remove(byTrace.keySet().iterator().next());
        }
        return SaveResult.INSERTED;
    }

    @Override
    public synchronized List<LogView> recent(int limit) {
        List<LogView> all = new ArrayList<>(byTrace.values());
        List<LogView> out = new ArrayList<>();
        for (int i = all.size() - 1; i >= 0 && out.size() < limit; i--) {
            out.add(all.get(i));
        }
        return out;
    }

    @Override
    public VerifyResult verify() {
        return new VerifyResult(false, 0, List.of());
    }

    @Override
    public Optional<ChainHead> head() {
        return Optional.empty();
    }

    @Override
    public Optional<String> hashAt(long chainSeq) {
        return Optional.empty();
    }

    @Override
    public boolean supportsChain() {
        return false;
    }
}
