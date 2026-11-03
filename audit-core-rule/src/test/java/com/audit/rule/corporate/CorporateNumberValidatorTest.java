package com.audit.rule.corporate;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CorporateNumberValidatorTest {

    @Test
    @DisplayName("公開されている法人番号（国税庁：7000012050002）を正しく検証できる")
    void validatesPublicCorporateNumber() {
        // 下12桁 000012050002、右から P=2,0,0,0,5,0,2,1,0,0,0,0 / Q=1,2,1,2,...
        // Σ=2+5+2+2=11 → 11 mod 9 = 2 → 9-2 = 7（先頭の検査用数字）
        assertEquals(7, CorporateNumberValidator.calculateCheckDigit("000012050002"));
        assertTrue(CorporateNumberValidator.isValid("7000012050002"));
    }

    @Test
    @DisplayName("先頭の検査用数字が違えば不正")
    void rejectsWrongCheckDigit() {
        assertFalse(CorporateNumberValidator.isValid("8000012050002"));
        assertFalse(CorporateNumberValidator.isValid("700001205000"));
    }
}
