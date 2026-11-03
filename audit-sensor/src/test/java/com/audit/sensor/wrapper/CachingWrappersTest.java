package com.audit.sensor.wrapper;

import com.audit.sensor.testsupport.FakeHttp;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CachingWrappersTest {

    @Test
    @DisplayName("【回帰】上限(64KB)を超える本文でも業務側には全バイト届く")
    void largeRequestBodyIsNotTruncatedForBusiness() throws Exception {
        byte[] big = new byte[200_000];
        Arrays.fill(big, (byte) 'a');
        var req = new AuditContentCachingRequestWrapper(new FakeHttp.Request(big), 65_536);

        byte[] seenByBusiness = req.getInputStream().readAllBytes();

        assertEquals(200_000, seenByBusiness.length);
        assertEquals(65_536, req.getCapturedBody().length());
        assertTrue(req.isCaptureTruncated());
    }

    @Test
    @DisplayName("小さい本文は丸ごと監査用にコピーされる")
    void smallBodyCapturedWhole() throws Exception {
        var req = new AuditContentCachingRequestWrapper(new FakeHttp.Request("{\"a\":1}"), 65_536);
        req.getReader().readLine();
        assertEquals("{\"a\":1}", req.getCapturedBody());
        assertFalse(req.isCaptureTruncated());
    }

    @Test
    @DisplayName("レスポンスはクライアントへ全部流れ、監査用コピーだけが上限で止まる")
    void responseTeeSendsEverything() throws Exception {
        var raw = new FakeHttp.Response();
        var res = new AuditContentCachingResponseWrapper(raw, 10);
        res.getWriter().write("0123456789ABCDEFGHIJ");
        res.flushBuffer();
        assertEquals("0123456789ABCDEFGHIJ", raw.sentText());
        assertEquals("0123456789", res.getCapturedBody());
        assertTrue(res.isCaptureTruncated());
    }
}
