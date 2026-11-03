package com.audit.sensor.dispatcher;

import com.audit.sensor.model.AuditLogPayload;
import com.audit.sensor.spool.DiskSpoolManager;

import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 監査ログの非同期送信係。
 *
 * <pre>
 *  業務スレッド ──offer()──▶ [キュー(上限付き)] ──▶ 送信スレッド(仮想スレッド) ──▶ コレクター
 *        │ キュー満杯                                   │ 送信失敗
 *        └──────────────▶ ディスク退避 ◀────────────────┘
 *                               │
 *                 再送スレッド(一定間隔) ──▶ コレクター（復旧後）
 * </pre>
 *
 * <ul>
 *   <li>業務スレッドは {@code offer()} するだけで即座に戻る（待たない）。</li>
 *   <li><b>サーキットブレーカー</b>：送信に失敗したら一定時間はコレクターを叩かず直接退避する。
 *       落ちているコレクターに毎回タイムアウトまで待つと、キューが詰まるため。</li>
 *   <li>再送スレッドが定期的に退避分を送り直す。コレクターは traceId で重複排除するので、二重送信しても安全。</li>
 * </ul>
 */
public final class AuditLogDispatcher implements AutoCloseable {

    private static final Logger log = Logger.getLogger(AuditLogDispatcher.class.getName());

    private final BlockingQueue<AuditLogPayload> queue;
    private final AuditTransport transport;
    private final DiskSpoolManager spool;
    private final long retryAfterMs;

    private final AtomicBoolean running = new AtomicBoolean(true);
    private final AtomicLong sentCount = new AtomicLong();
    private final AtomicLong overflowCount = new AtomicLong();
    private volatile long circuitOpenUntil = 0;

    private final Thread sender;
    private final Thread resender;

    public AuditLogDispatcher(int queueCapacity, AuditTransport transport, DiskSpoolManager spool, long retryAfterMs) {
        this.queue = new ArrayBlockingQueue<>(queueCapacity > 0 ? queueCapacity : 5000);
        this.transport = transport;
        this.spool = spool;
        this.retryAfterMs = retryAfterMs;
        this.sender = Thread.ofVirtual().name("audit-sender").start(this::sendLoop);
        this.resender = Thread.ofVirtual().name("audit-resender").start(this::resendLoop);
    }

    /** 業務スレッドから呼ばれる。絶対にブロックしない。 */
    public void dispatch(AuditLogPayload payload) {
        if (!running.get() || !queue.offer(payload)) {
            overflowCount.incrementAndGet();
            spool.spool(payload.toJson());
        }
    }

    private void sendLoop() {
        while (running.get() || !queue.isEmpty()) {
            try {
                AuditLogPayload p = queue.poll(200, TimeUnit.MILLISECONDS);
                if (p != null) {
                    deliver(p.toJson());
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                log.log(Level.WARNING, "[AuditDispatcher] unexpected error in sender", e);
            }
        }
    }

    private void deliver(String json) {
        if (System.currentTimeMillis() < circuitOpenUntil) {
            spool.spool(json); // ブレーカー作動中：コレクターを叩かずに退避
            return;
        }
        switch (transport.send(json)) {
            case DELIVERED -> sentCount.incrementAndGet();
            case REJECTED -> spool.reject(json); // 再送しても通らないので別ファイルへ
            case RETRY -> {
                circuitOpenUntil = System.currentTimeMillis() + retryAfterMs;
                log.warning("[AuditDispatcher] collector unavailable -> spooling, retry after " + retryAfterMs + "ms");
                spool.spool(json);
            }
        }
    }

    private void resendLoop() {
        while (running.get()) {
            try {
                Thread.sleep(retryAfterMs);
                resendNow();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                log.log(Level.WARNING, "[AuditDispatcher] resend error", e);
            }
        }
    }

    /** 退避分の再送を今すぐ試みる（テスト・運用コマンド用にも公開）。 */
    public int resendNow() {
        if (!spool.hasPending()) {
            return 0;
        }
        int n = spool.drain(transport);
        if (n > 0) {
            circuitOpenUntil = 0; // 届いた＝コレクター復旧
            log.info("[AuditDispatcher] resent " + n + " spooled records");
        }
        return n;
    }

    public long getSentCount() { return sentCount.get(); }
    public long getOverflowCount() { return overflowCount.get(); }
    public int getQueueSize() { return queue.size(); }
    public DiskSpoolManager getSpool() { return spool; }

    /** 停止時：キューに残った分は送るか退避してから終わる（消さない）。 */
    @Override
    public void close() {
        running.set(false);
        resender.interrupt();
        try {
            sender.join(5000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        AuditLogPayload p;
        while ((p = queue.poll()) != null) {
            spool.spool(p.toJson());
        }
    }
}
