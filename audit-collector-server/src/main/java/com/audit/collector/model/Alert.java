package com.audit.collector.model;

/**
 * 監査ログに付ける警戒レベル。
 * <p>
 * 注意：ここで付けるのは「人が確認すべき兆候」の印であり、法的な判断（漏えい等報告の要否）ではない。
 * 報告要否は事実関係を確認したうえで担当者が判断する。
 */
public record Alert(Level level, String reason) {

    public enum Level { INFO, WARN, CRITICAL }

    public static Alert info() {
        return new Alert(Level.INFO, null);
    }
}
