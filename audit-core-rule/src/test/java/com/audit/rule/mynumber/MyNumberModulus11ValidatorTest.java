package com.audit.rule.mynumber;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MyNumberModulus11ValidatorTest {

    @Test
    @DisplayName("手計算した検査用数字と一致する（12345678901 → 8）")
    void checkDigitMatchesHandCalculation() {
        // P(右から)=1,0,9,8,7,6,5,4,3,2,1 / Q=2,3,4,5,6,7,2,3,4,5,6
        // Σ=2+0+36+40+42+42+10+12+12+10+6=212, 212 mod 11 = 3 → 11-3 = 8
        assertEquals(8, MyNumberModulus11Validator.calculateCheckDigit("12345678901"));
        assertTrue(MyNumberModulus11Validator.isValid("123456789018"));
    }

    @Test
    @DisplayName("ハイフン区切り（4-4-4）でも検証できる")
    void acceptsHyphenatedForm() {
        assertTrue(MyNumberModulus11Validator.isValid("1234-5678-9018"));
    }

    @Test
    @DisplayName("検査用数字が違えば不正")
    void rejectsWrongCheckDigit() {
        assertFalse(MyNumberModulus11Validator.isValid("123456789019"));
    }

    @Test
    @DisplayName("余りが0か1のときは検査用数字0")
    void remainderZeroOrOneGivesZero() {
        // 11桁を総当たりして余り≦1のケースを探し、検査用数字が0になることを確認
        boolean found = false;
        for (int i = 0; i < 2000 && !found; i++) {
            String first11 = String.format("%011d", i * 7919L);
            int sum = 0;
            for (int n = 1; n <= 11; n++) {
                int p = first11.charAt(11 - n) - '0';
                sum += p * (n <= 6 ? n + 1 : n - 5);
            }
            if (sum % 11 <= 1) {
                assertEquals(0, MyNumberModulus11Validator.calculateCheckDigit(first11));
                found = true;
            }
        }
        assertTrue(found, "remainder<=1 case should exist in the search range");
    }

    @Test
    @DisplayName("桁数違い・数字以外・全桁同一は不正")
    void rejectsMalformed() {
        assertFalse(MyNumberModulus11Validator.isValid(null));
        assertFalse(MyNumberModulus11Validator.isValid("12345"));
        assertFalse(MyNumberModulus11Validator.isValid("1234567890181"));
        assertFalse(MyNumberModulus11Validator.isValid("12345678901a"));
        assertFalse(MyNumberModulus11Validator.isValid("000000000000"));
    }

    @Test
    @DisplayName("11桁以外を渡すと例外")
    void calculateRejectsWrongLength() {
        assertThrows(IllegalArgumentException.class, () -> MyNumberModulus11Validator.calculateCheckDigit("123"));
    }
}
