package com.audit.collector.store;

import com.audit.collector.model.Alert;
import com.audit.collector.model.IngestRequest;
import com.audit.collector.model.LogView;

import java.util.List;
import java.util.Optional;

/** 監査ログの保存先。PostgreSQL 版と、DB なしで動かすためのメモリ版がある。 */
public interface AuditStore {

    enum SaveResult { INSERTED, DUPLICATE }

    /** @throws StoreUnavailableException 保存できなかった（呼び出し元は 503 を返し、センサーに再送させる） */
    SaveResult save(IngestRequest req, Alert alert);

    List<LogView> recent(int limit);

    /** ハッシュチェーンの検証結果（問題のある行の一覧。空なら正常）。 */
    VerifyResult verify();

    Optional<ChainHead> head();

    /** 指定した連番の行の record_hash（アンカー照合用）。 */
    Optional<String> hashAt(long chainSeq);

    boolean supportsChain();

    record ChainHead(long seq, String hash) {
    }

    record Problem(Long chainSeq, String traceId, String problem) {
    }

    record VerifyResult(boolean available, long checkedRows, List<Problem> problems) {
        public boolean ok() {
            return available && problems.isEmpty();
        }
    }

    class StoreUnavailableException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public StoreUnavailableException(String msg, Throwable cause) {
            super(msg, cause);
        }
    }
}
