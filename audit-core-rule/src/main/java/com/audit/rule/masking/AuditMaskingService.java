package com.audit.rule.masking;

import com.audit.rule.model.PiiType;

/**
 * Pマーク（JIS Q 15001）および日本企業向けセキュリティ要件に準拠したマスキング処理サービス。
 */
public final class AuditMaskingService {

    private AuditMaskingService() {
    }

    public static String mask(PiiType type, String rawValue) {
        if (rawValue == null || rawValue.isEmpty()) {
            return rawValue;
        }

        return switch (type) {
            case MY_NUMBER -> maskMyNumber(rawValue);
            case CORPORATE_NUMBER -> maskCorporateNumber(rawValue);
            case PENSION_NUMBER -> maskPensionNumber(rawValue);
            case DRIVER_LICENSE -> maskDriverLicense(rawValue);
            case PASSPORT -> maskPassport(rawValue);
            case PHONE_JP -> maskPhone(rawValue);
            case EMAIL -> maskEmail(rawValue);
        };
    }

    /**
     * マイナンバーのマスキング：
     * 例: "123456789018" -> "********9018" (下4桁のみ残し、特定を防止)
     */
    public static String maskMyNumber(String raw) {
        String clean = raw.replace("-", "");
        if (clean.length() == 12) {
            return "********" + clean.substring(8);
        }
        return "************";
    }

    public static String maskCorporateNumber(String raw) {
        String clean = raw.replace("-", "");
        if (clean.length() == 13) {
            return clean.substring(0, 1) + "***********" + clean.substring(12);
        }
        return "*************";
    }

    /**
     * 基礎年金番号 (4桁-6桁)：
     * 例: "1234-567890" -> "****-**7890"
     */
    public static String maskPensionNumber(String raw) {
        if (raw.contains("-")) {
            String[] parts = raw.split("-");
            if (parts.length == 2 && parts[1].length() >= 4) {
                return "****-**" + parts[1].substring(parts[1].length() - 4);
            }
        }
        return "****-******";
    }

    public static String maskDriverLicense(String raw) {
        String clean = raw.replace("-", "");
        if (clean.length() == 12) {
            return clean.substring(0, 2) + "********" + clean.substring(10);
        }
        return "************";
    }

    public static String maskPassport(String raw) {
        if (raw.length() >= 4) {
            return raw.substring(0, 2) + "*****" + raw.substring(raw.length() - 2);
        }
        return "*******";
    }

    /**
     * 電話番号：先頭（局番）と末尾4桁を残し、中間を伏せる。ハイフンの位置は元の形式を保つ。
     * 例: "090-1234-5678" -> "090-****-5678"、"09012345678" -> "090****5678"
     */
    public static String maskPhone(String raw) {
        String[] parts = raw.split("-");
        if (parts.length == 3) {
            return parts[0] + "-" + "*".repeat(parts[1].length()) + "-" + parts[2];
        }
        String clean = raw.replace("-", "");
        if (clean.length() >= 8) {
            return clean.substring(0, 3) + "****" + clean.substring(clean.length() - 4);
        }
        return "***-****-****";
    }

    public static String maskEmail(String raw) {
        int atIndex = raw.indexOf('@');
        if (atIndex >= 1) {
            return raw.charAt(0) + "***" + raw.substring(atIndex);
        }
        return "***@***.***";
    }
}
