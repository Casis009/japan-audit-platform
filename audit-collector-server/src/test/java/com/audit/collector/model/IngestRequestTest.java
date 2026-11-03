package com.audit.collector.model;

import com.audit.collector.json.MiniJson;
import com.audit.collector.security.Credentials;
import com.audit.collector.store.DetailDigest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IngestRequestTest {

    private static final String SENSOR_JSON = """
            {"traceId":"6f1c2c1e-0000-4000-8000-000000000001","timestamp":"2026-11-03T02:00:00Z",
             "systemCode":"SYS_DEMO","hostName":"was-1","clientIp":"10.0.0.5","userPrincipal":"EMP_DEMO_0001",
             "httpMethod":"GET","requestUri":"/api/v1/customers/1","queryString":null,"httpStatus":200,
             "executionTimeMs":12,"piiDetected":true,"piiOccurrences":1,"myNumberPersonCount":1,
             "details":[{"piiType":"MY_NUMBER","maskedValue":"********0001","occurredIn":"RESPONSE_BODY","confidence":"HIGH"}],
             "requestBody":null,"responseBody":null}
            """;

    @Test
    @DisplayName("センサーの送信形式をそのまま読める")
    void parsesSensorPayload() {
        IngestRequest r = IngestRequest.fromJson(SENSOR_JSON);
        assertEquals("EMP_DEMO_0001", r.userPrincipal());
        assertEquals(1, r.details().size());
        assertEquals(1, r.details().get(0).seqNo());
        assertEquals(1, r.myNumberPersonCount());
    }

    @Test
    @DisplayName("【回帰】ユーザーが無いときは特定の社員番号で埋めず ANONYMOUS")
    void missingUserBecomesAnonymous() {
        IngestRequest r = IngestRequest.fromJson("{\"traceId\":\"t1\",\"timestamp\":\"2026-11-03T02:00:00Z\"}");
        assertEquals("ANONYMOUS", r.userPrincipal());
    }

    @Test
    @DisplayName("必須項目なし・時刻の形式違い・型違い・長すぎる値は拒否")
    void rejectsInvalid() {
        assertThrows(IllegalArgumentException.class, () -> IngestRequest.fromJson("{\"timestamp\":\"2026-11-03T02:00:00Z\"}"));
        assertThrows(IllegalArgumentException.class, () -> IngestRequest.fromJson("{\"traceId\":\"t\",\"timestamp\":\"yesterday\"}"));
        assertThrows(IllegalArgumentException.class, () -> IngestRequest.fromJson("{\"traceId\":\"t\",\"timestamp\":\"2026-11-03T02:00:00Z\",\"httpStatus\":\"200\"}"));
        assertThrows(IllegalArgumentException.class, () -> IngestRequest.fromJson("{\"traceId\":\"" + "x".repeat(37) + "\",\"timestamp\":\"2026-11-03T02:00:00Z\"}"));
        assertThrows(MiniJson.JsonException.class, () -> IngestRequest.fromJson("not json"));
    }

    @Test
    @DisplayName("【回帰】センサーキー：ヘッダー無し・空・不一致はすべて拒否")
    void sensorKeyMustMatch() {
        String key = "0123456789abcdef0123";
        assertFalse(Credentials.sensorKeyMatches(null, key));   // 旧実装ではここが素通りだった
        assertFalse(Credentials.sensorKeyMatches("", key));
        assertFalse(Credentials.sensorKeyMatches("wrong", key));
        assertTrue(Credentials.sensorKeyMatches(key, key));
        assertFalse(Credentials.sensorKeyMatches(key, ""));     // サーバー側未設定なら誰も通さない
    }

    @Test
    @DisplayName("明細なしのダイジェストは空文字列の SHA-256（DB 側の式と同じ）")
    void digestOfNoDetails() {
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", DetailDigest.of(List.of()));
    }
}
