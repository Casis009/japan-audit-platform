package com.audit.rule.detector;

import com.audit.rule.model.DetectedItem;
import com.audit.rule.model.DetectionResult;
import com.audit.rule.model.PiiType;
import com.audit.rule.mynumber.MyNumberModulus11Validator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JapanPiiDetectorTest {

    private final JapanPiiDetector detector = new JapanPiiDetector();

    @Test
    @DisplayName("myNumber キーの値は確度 HIGH でマスキングされる")
    void keywordContextGivesHighConfidence() {
        DetectionResult r = detector.scanAndMask("{\"myNumber\":\"123456789018\"}");
        assertEquals("{\"myNumber\":\"********9018\"}", r.maskedText());
        assertEquals(DetectedItem.Confidence.HIGH, r.items().get(0).confidence());
    }

    @Test
    @DisplayName("文脈のない12桁（注文番号など）は MEDIUM。安全側でマスキングはする")
    void noContextGivesMediumButStillMasks() {
        String orderNo = MyNumberModulus11Validator.generateValidMyNumber("20261103000");
        DetectionResult r = detector.scanAndMask("{\"orderNo\":\"" + orderNo + "\"}");
        assertEquals(1, r.occurrenceCount());
        assertEquals(DetectedItem.Confidence.MEDIUM, r.items().get(0).confidence());
        assertFalse(r.maskedText().contains(orderNo));
    }

    @Test
    @DisplayName("13桁以上の数字の一部を12桁として誤検知しない")
    void doesNotMatchInsideLongerNumbers() {
        DetectionResult r = detector.scanAndMask("id=91234567890181");
        assertEquals(0, r.distinctCount(PiiType.MY_NUMBER));
    }

    @Test
    @DisplayName("電話番号はハイフンの形を保ってマスキング")
    void phoneMaskKeepsFormat() {
        DetectionResult r = detector.scanAndMask("tel: 090-1234-5678");
        assertEquals("tel: 090-****-5678", r.maskedText());
    }

    @Test
    @DisplayName("メールはローカル部の先頭1文字だけ残す")
    void emailMasked() {
        DetectionResult r = detector.scanAndMask("mail=taro@example.com");
        assertEquals("mail=t***@example.com", r.maskedText());
    }

    @Test
    @DisplayName("同じ番号が2回出ても本人数は1（出現回数は2）")
    void distinctCountsPersons() {
        DetectionResult r = detector.scanAndMask("a=123456789018, b=1234-5678-9018");
        assertEquals(2, r.occurrenceCount());
        assertEquals(1, r.distinctCount(PiiType.MY_NUMBER));
    }

    @Test
    @DisplayName("数字も@もない文字列はファストパスで即返却")
    void fastPathForTextWithoutDigits() {
        assertFalse(JapanPiiDetector.mayContainPii("こんにちは、世界"));
        assertFalse(detector.scanAndMask("hello world").containsPii());
    }

    @Test
    @DisplayName("toString に生の個人情報が出ない（ログ誤出力対策）")
    void toStringDoesNotLeakRawValue() {
        DetectionResult r = detector.scanAndMask("myNumber=123456789018");
        assertFalse(r.items().get(0).toString().contains("123456789018"));
    }

    @Test
    @DisplayName("【限界の記録】ランダムな12桁の約1割はモジュラス11を通る（誤検知ゼロではない）")
    void randomFalsePositiveRateIsAboutTenPercent() {
        Random rnd = new Random(42);
        int n = 200_000, pass = 0;
        for (int i = 0; i < n; i++) {
            StringBuilder sb = new StringBuilder().append(1 + rnd.nextInt(9));
            for (int j = 0; j < 11; j++) sb.append(rnd.nextInt(10));
            if (MyNumberModulus11Validator.isValid(sb.toString())) pass++;
        }
        double rate = pass * 100.0 / n;
        assertTrue(rate > 8 && rate < 12, "observed " + rate + "%");
    }
}
