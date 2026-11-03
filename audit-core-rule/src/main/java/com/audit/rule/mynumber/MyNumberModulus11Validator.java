package com.audit.rule.mynumber;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * 日本のマイナンバー（個人番号：12桁）の仕様検証およびチェックディジット検証器。
 * <p>
 * 根拠法令：行政手続における特定の個人を識別するための番号の利用等に関する法律施行令
 * （平成26年政令第155号）第8条
 * <p>
 * アルゴリズム（モジュラス11 / Modulus 11）：
 * 12桁目（検査数字：Check Digit）の計算式：
 * <ul>
 *   <li>1〜11桁目を末尾（右）から順に P_1, P_2, ..., P_11 とする。</li>
 *   <li>各桁の重み係数 Q_n：
 *     <ul>
 *       <li>1 &le; n &le; 6 のとき：Q_n = n + 1 （重み: 2, 3, 4, 5, 6, 7）</li>
 *       <li>7 &le; n &le; 11 のとき：Q_n = n - 5 （重み: 2, 3, 4, 5, 6）</li>
 *     </ul>
 *   </li>
 *   <li>S = &sum; (P_n &times; Q_n) (n=1..11)</li>
 *   <li>余り R = S mod 11</li>
 *   <li>R &le; 1 のとき：検査数字 = 0</li>
 *   <li>R &gt; 1 のとき：検査数字 = 11 - R</li>
 * </ul>
 */
public final class MyNumberModulus11Validator {

    private static final Pattern DIGITS_12_PATTERN = Pattern.compile("^\\d{12}$");

    private MyNumberModulus11Validator() {
        // 인스턴스화 방지
    }

    /**
     * 入力された文字列が日本の正規マイナンバー（12桁）であるかをモジュラス11アルゴリズムにより厳格検証する。
     *
     * @param candidate 検証対象文字列（ハイフン付き・なし両対応）
     * @return 正当なマイナンバーである場合 true、チェックサム不一致・桁数不正時は false
     */
    public static boolean isValid(String candidate) {
        if (candidate == null) {
            return false;
        }

        String sanitized = candidate.replace("-", "").trim();

        if (!DIGITS_12_PATTERN.matcher(sanitized).matches()) {
            return false;
        }

        // 12桁すべて同一数字（000000000000等）のダミー番号を排除
        if (isAllSameDigits(sanitized)) {
            return false;
        }

        int expectedCheckDigit = calculateCheckDigit(sanitized.substring(0, 11));
        int actualCheckDigit = sanitized.charAt(11) - '0';

        return expectedCheckDigit == actualCheckDigit;
    }

    /**
     * マイナンバー先頭11桁からモジュラス11による検査数字（Check Digit）を算出する。
     *
     * @param first11Digits 先頭11桁の数字文字列
     * @return 12桁目の検査数字（0〜9）
     */
    public static int calculateCheckDigit(String first11Digits) {
        Objects.requireNonNull(first11Digits, "first11Digits must not be null");
        if (first11Digits.length() != 11) {
            throw new IllegalArgumentException("Length of first 11 digits must be 11, but got: " + first11Digits.length());
        }

        int sum = 0;
        // P_n: 右（11桁目）から左（1桁目）への逆順インデックス (n = 1..11)
        for (int n = 1; n <= 11; n++) {
            int charIndex = 11 - n;
            int p_n = first11Digits.charAt(charIndex) - '0';
            if (p_n < 0 || p_n > 9) {
                throw new IllegalArgumentException("Invalid digit at index " + charIndex);
            }

            int q_n = (n <= 6) ? (n + 1) : (n - 5);
            sum += p_n * q_n;
        }

        int remainder = sum % 11;
        if (remainder <= 1) {
            return 0;
        } else {
            return 11 - remainder;
        }
    }

    /**
     * 任意11桁の数値から正当なマイナンバー12桁文字列を生成する（テスト・シミュレーション用）。
     */
    public static String generateValidMyNumber(String first11Digits) {
        int cd = calculateCheckDigit(first11Digits);
        return first11Digits + cd;
    }

    private static boolean isAllSameDigits(String s) {
        char first = s.charAt(0);
        for (int i = 1; i < s.length(); i++) {
            if (s.charAt(i) != first) {
                return false;
            }
        }
        return true;
    }
}
