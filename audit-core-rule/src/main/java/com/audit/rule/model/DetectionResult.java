package com.audit.rule.model;

import java.util.List;
import java.util.Objects;

/**
 * 1つのテキスト（リクエスト本文・レスポンス本文など）に対する検知結果。
 *
 * @param items      重複区間を除いた検知項目（出現順）
 * @param maskedText 検知箇所をマスキングしたテキスト
 */
public record DetectionResult(List<DetectedItem> items, String maskedText) {

    public DetectionResult {
        items = List.copyOf(items);
    }

    public static DetectionResult empty(String originalText) {
        return new DetectionResult(List.of(), originalText);
    }

    public boolean containsPii() {
        return !items.isEmpty();
    }

    /** 出現回数（同じ番号が2回出れば2件）。 */
    public int occurrenceCount() {
        return items.size();
    }

    /**
     * 指定種別の「異なる値」の数。
     * マイナンバーは1人1番号なので、MY_NUMBER の値の種類数 ≒ 本人数として扱える。
     */
    public long distinctCount(PiiType type) {
        return items.stream()
                .filter(i -> i.type() == type)
                .map(DetectedItem::rawValue)
                .filter(Objects::nonNull)
                .map(v -> v.replace("-", ""))
                .distinct()
                .count();
    }
}
