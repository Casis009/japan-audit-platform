package com.audit.rule.corporate;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * 日本の法人番号（13桁）の検証器。
 * <p>
 * 根拠法令：行政手続における特定の個人を識別するための番号の利用等に関する法律第39条、
 * および法人番号の指定等に関する省令（平成26年財務省令第85号）第3条
 * <p>
 * アルゴリズム（モジュラス9）：
 * 1桁目（最上位桁：検査数字）の計算式：
 * <ul>
 *   <li>2〜13桁目を末尾（右）から順に P_1, P_2, ..., P_12 とする。</li>
 *   <li>各桁の重み係数 Q_n：
 *     <ul>
 *       <li>n が奇数（1, 3, 5, 7, 9, 11）のとき：Q_n = 1</li>
 *       <li>n が偶数（2, 4, 6, 8, 10, 12）のとき：Q_n = 2</li>
 *     </ul>
 *   </li>
 *   <li>S = &sum; (P_n &times; Q_n) (n=1..12)</li>
 *   <li>余り R = S mod 9</li>
 *   <li>検査数字（1桁目） = 9 - R</li>
 * </ul>
 */
public final class CorporateNumberValidator {

    private static final Pattern DIGITS_13_PATTERN = Pattern.compile("^\\d{13}$");

    private CorporateNumberValidator() {
    }

    public static boolean isValid(String candidate) {
        if (candidate == null) {
            return false;
        }

        String sanitized = candidate.replace("-", "").trim();
        if (!DIGITS_13_PATTERN.matcher(sanitized).matches()) {
            return false;
        }

        int actualCheckDigit = sanitized.charAt(0) - '0';
        String remaining12Digits = sanitized.substring(1);
        int expectedCheckDigit = calculateCheckDigit(remaining12Digits);

        return actualCheckDigit == expectedCheckDigit;
    }

    public static int calculateCheckDigit(String remaining12Digits) {
        Objects.requireNonNull(remaining12Digits, "remaining12Digits must not be null");
        if (remaining12Digits.length() != 12) {
            throw new IllegalArgumentException("Length must be 12, but was " + remaining12Digits.length());
        }

        int sum = 0;
        // P_n: 末尾(12번째)부터 역순(n = 1..12)
        for (int n = 1; n <= 12; n++) {
            int charIndex = 12 - n;
            int p_n = remaining12Digits.charAt(charIndex) - '0';
            if (p_n < 0 || p_n > 9) {
                throw new IllegalArgumentException("Invalid digit at " + charIndex);
            }

            int q_n = (n % 2 == 1) ? 1 : 2;
            sum += p_n * q_n;
        }

        int remainder = sum % 9;
        return 9 - remainder;
    }
}
