package com.audit.rule.model;

/**
 * 日本の個人情報保護法およびPマーク（JIS Q 15001）基準に基づく識別対象の個人特定情報種別。
 */
public enum PiiType {
    MY_NUMBER("個人番号（マイナンバー）", "12桁。モジュラス11アルゴリズムによる検証"),
    CORPORATE_NUMBER("法人番号", "13桁。モジュラス9アルゴリズムによる検証"),
    PENSION_NUMBER("基礎年金番号", "4桁-6桁（計10桁）"),
    DRIVER_LICENSE("運転免許証番号", "12桁。公安委員会コード＋年号＋連番"),
    PASSPORT("旅券（パスポート）番号", "アルファベット2桁＋数字7桁"),
    PHONE_JP("日本国内電話番号", "市外局番/携帯プレフィックス＋ハイフン"),
    EMAIL("メールアドレス", "RFC 5322準拠");

    private final String title;
    private final String description;

    PiiType(String title, String description) {
        this.title = title;
        this.description = description;
    }

    public String getTitle() {
        return title;
    }

    public String getDescription() {
        return description;
    }
}
