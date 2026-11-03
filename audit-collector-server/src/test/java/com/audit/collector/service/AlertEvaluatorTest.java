package com.audit.collector.service;

import com.audit.collector.model.Alert;
import com.audit.collector.model.IngestRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AlertEvaluatorTest {

    private static IngestRequest req(String user, Instant at, int persons) {
        List<IngestRequest.Detail> d = persons > 0
                ? List.of(new IngestRequest.Detail(1, "MY_NUMBER", "********0001", "RESPONSE_BODY", "HIGH"))
                : List.of();
        return new IngestRequest("t-" + System.nanoTime(), at, "S", "h", "ip", user, "GET", "/x", null, 200, 1,
                persons > 0, persons, persons, d, null, null);
    }

    @Test
    @DisplayName("「100人を超える」なので 100人ちょうどは CRITICAL にしない（以上ではなく超）")
    void exactlyHundredIsNotCritical() {
        var e = new AlertEvaluator(100, Duration.ofMinutes(10));
        assertEquals(Alert.Level.WARN, e.evaluate(req("u1", Instant.now(), 100)).level());
        assertEquals(Alert.Level.CRITICAL, e.evaluate(req("u2", Instant.now(), 101)).level());
    }

    @Test
    @DisplayName("60人×2回に分けても、10分以内の累計で CRITICAL")
    void splitAccessIsDetected() {
        var e = new AlertEvaluator(100, Duration.ofMinutes(10));
        Instant t = Instant.parse("2026-11-03T00:00:00Z");
        IngestRequest first = req("u1", t, 60);
        assertEquals(Alert.Level.WARN, e.evaluate(first).level());
        e.record(first);
        assertEquals(Alert.Level.CRITICAL, e.evaluate(req("u1", t.plusSeconds(60), 60)).level());
    }

    @Test
    @DisplayName("窓（10分）の外の照会は累計に入れない／別ユーザーとは合算しない")
    void windowAndUserAreRespected() {
        var e = new AlertEvaluator(100, Duration.ofMinutes(10));
        Instant t = Instant.parse("2026-11-03T00:00:00Z");
        e.record(req("u1", t, 60));
        assertEquals(Alert.Level.WARN, e.evaluate(req("u1", t.plus(Duration.ofMinutes(11)), 60)).level());
        assertEquals(Alert.Level.WARN, e.evaluate(req("u2", t.plusSeconds(10), 60)).level());
    }

    @Test
    @DisplayName("再送された重複は record しないので二重に数えない")
    void evaluateAloneDoesNotAccumulate() {
        var e = new AlertEvaluator(100, Duration.ofMinutes(10));
        Instant t = Instant.parse("2026-11-03T00:00:00Z");
        IngestRequest r = req("u1", t, 60);
        e.evaluate(r);
        e.evaluate(r); // 重複として保存されなかった想定（record しない）
        assertEquals(Alert.Level.WARN, e.evaluate(req("u1", t.plusSeconds(5), 30)).level());
    }

    @Test
    @DisplayName("個人情報なしは INFO")
    void noPiiIsInfo() {
        var e = new AlertEvaluator(100, Duration.ofMinutes(10));
        assertEquals(Alert.Level.INFO, e.evaluate(req("u1", Instant.now(), 0)).level());
    }
}
