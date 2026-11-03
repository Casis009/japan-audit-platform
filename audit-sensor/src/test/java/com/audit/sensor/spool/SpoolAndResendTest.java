package com.audit.sensor.spool;

import com.audit.sensor.dispatcher.AuditLogDispatcher;
import com.audit.sensor.dispatcher.AuditTransport.Result;
import com.audit.sensor.model.AuditLogPayload;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SpoolAndResendTest {

    private static AuditLogPayload payload(int i) {
        return new AuditLogPayload("trace-" + i, Instant.now(), "S", "h", "ip", "u", "GET", "/x", null, 200, 1,
                false, 0, 0, List.of(), null, null);
    }

    @Test
    @DisplayName("コレクター停止中は退避し、復旧後の再送で全件届く（欠損なし）")
    void spoolsDuringOutageAndResendsAfterRecovery() throws Exception {
        AtomicBoolean collectorUp = new AtomicBoolean(false);
        List<String> delivered = new CopyOnWriteArrayList<>();
        var spool = new DiskSpoolManager(Files.createTempDirectory("spool").toString(), 1_000_000);

        try (var d = new AuditLogDispatcher(100, json -> collectorUp.get() && delivered.add(json) ? Result.DELIVERED : Result.RETRY, spool, 60_000)) {
            for (int i = 0; i < 20; i++) d.dispatch(payload(i));
            for (int i = 0; i < 100 && spool.getSpooledCount() < 20; i++) Thread.sleep(20);
            assertEquals(20, spool.getSpooledCount());
            assertEquals(0, delivered.size());

            collectorUp.set(true);
            assertEquals(20, d.resendNow());

            assertEquals(20, delivered.size());
            assertFalse(spool.hasPending());
            for (int i = 0; i < 20; i++) {
                final int n = i;
                assertTrue(delivered.stream().anyMatch(j -> j.contains("\"traceId\":\"trace-" + n + "\"")));
            }
        }
    }

    @Test
    @DisplayName("再送の途中で失敗したら、未送信分だけが残り次回に続きから送る")
    void partialResendKeepsRemaining() throws Exception {
        var spool = new DiskSpoolManager(Files.createTempDirectory("spool").toString(), 1_000_000);
        for (int i = 0; i < 10; i++) spool.spool(payload(i).toJson());

        AtomicInteger budget = new AtomicInteger(4); // 4件目まで成功、その後失敗
        assertEquals(4, spool.drain(json -> budget.getAndDecrement() > 0 ? Result.DELIVERED : Result.RETRY));
        assertTrue(spool.hasPending());

        assertEquals(6, spool.drain(json -> Result.DELIVERED));
        assertFalse(spool.hasPending());
        assertEquals(10, spool.getResentCount());
    }

    @Test
    @DisplayName("退避の上限を超えたら捨てて件数を数える（ディスクを溢れさせない）")
    void dropsWhenSpoolLimitReached() throws Exception {
        String line = payload(0).toJson();
        var spool = new DiskSpoolManager(Files.createTempDirectory("spool").toString(), line.length() * 3L + 3);
        for (int i = 0; i < 5; i++) spool.spool(line);
        assertEquals(3, spool.getSpooledCount());
        assertEquals(2, spool.getDroppedCount());
    }

    @Test
    @DisplayName("複数スレッドから同時に退避しても行が混ざらない")
    void concurrentSpoolWritesStayLineAligned() throws Exception {
        var spool = new DiskSpoolManager(Files.createTempDirectory("spool").toString(), 50_000_000);
        Thread[] ts = new Thread[8];
        for (int t = 0; t < ts.length; t++) {
            final int base = t * 1000;
            ts[t] = Thread.ofVirtual().start(() -> {
                for (int i = 0; i < 200; i++) spool.spool(payload(base + i).toJson());
            });
        }
        for (Thread t : ts) t.join();
        List<String> got = new CopyOnWriteArrayList<>();
        assertEquals(1600, spool.drain(json -> json.startsWith("{") && json.endsWith("}") && got.add(json) ? Result.DELIVERED : Result.RETRY));
        assertEquals(1600, got.size());
    }

    @Test
    @DisplayName("恒久的に拒否された1件（400）は rejected へ移し、後続の再送を止めない")
    void poisonRecordDoesNotBlockQueue() throws Exception {
        var spool = new DiskSpoolManager(Files.createTempDirectory("spool").toString(), 1_000_000);
        for (int i = 0; i < 5; i++) spool.spool(payload(i).toJson());

        List<String> delivered = new CopyOnWriteArrayList<>();
        int n = spool.drain(json -> json.contains("trace-2") ? Result.REJECTED : (delivered.add(json) ? Result.DELIVERED : Result.RETRY));

        assertEquals(4, n);
        assertEquals(1, spool.getRejectedCount());
        assertFalse(spool.hasPending());
        assertTrue(Files.exists(spool.getSpoolDir().resolve("rejected.jsonl")));
    }
}
