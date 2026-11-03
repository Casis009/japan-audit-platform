package com.audit.sensor.dispatcher;

/**
 * 監査ログ1件（JSON 1行）をコレクターへ届ける手段。
 * テストでは偽物に差し替えられるようにインタフェースにしている。
 */
@FunctionalInterface
public interface AuditTransport {

    /** 送信結果。 */
    enum Result {
        /** 受け付けられた（新規・重複とも）。 */
        DELIVERED,
        /** 一時的な失敗（停止・タイムアウト・5xx・認証設定ミス）。退避して後で再送する。 */
        RETRY,
        /**
         * 恒久的な拒否（電文不正 400 / 大きすぎ 413）。何度送っても通らないので、
         * 再送の列から外して別ファイル（rejected.jsonl）に残す。
         * これをしないと、1件の不正電文が後ろに並んだ正常なログの再送まで止めてしまう。
         */
        REJECTED
    }

    /** 例外は投げない。 */
    Result send(String json);
}
