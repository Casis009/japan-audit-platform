package com.audit.rule.model;

/**
 * 検知した個人情報1件。
 * <p>
 * {@code rawValue} は「本人数（重複除外）」の算出にだけ使い、ログ・送信データには絶対に出さない。
 * そのため {@link #toString()} を上書きし、誤ってログ出力されても生値が漏れないようにしている。
 */
public record DetectedItem(
        PiiType type,
        String rawValue,
        String maskedValue,
        int startIndex,
        int endIndex,
        Confidence confidence
) {

    /** 検知の確からしさ。 */
    public enum Confidence {
        /** 直前に「マイナンバー」「myNumber」等のキーワードがあり、チェックディジットも一致。 */
        HIGH,
        /** チェックディジットは一致するが、文脈キーワードがない（注文番号等の偶然一致の可能性あり）。 */
        MEDIUM
    }

    @Override
    public String toString() {
        return "DetectedItem[type=" + type + ", masked=" + maskedValue + ", confidence=" + confidence
                + ", range=" + startIndex + "-" + endIndex + "]";
    }
}
