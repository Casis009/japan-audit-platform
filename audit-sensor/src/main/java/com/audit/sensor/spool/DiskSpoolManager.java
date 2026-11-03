package com.audit.sensor.spool;

import com.audit.sensor.dispatcher.AuditTransport;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * コレクターに届けられなかった監査ログをローカルディスクへ退避し、復旧後に再送する。
 *
 * <h2>ファイルの流れ</h2>
 * <pre>
 *  書き込み:  current.jsonl に1行ずつ追記（JSON 1行 = 1件、マスキング済み）
 *  再送開始:  current.jsonl を pending-&lt;時刻&gt;.jsonl へ原子的にリネーム（以後の書き込みは新しい current へ）
 *  再送:      pending を先頭行から送信。全件成功 → 削除 / 途中で失敗 → 未送信分だけ残して次回へ
 * </pre>
 * リネームしてから読むので、「書きながら読む」競合が起きない。
 * 同じ行を2回送ってもコレクター側が traceId で重複排除する（冪等）ので、途中失敗からの再開で二重登録にならない。
 *
 * <h2>上限</h2>
 * 合計サイズが上限を超えたら新しい行は捨てて件数だけ数える（ディスク溢れで業務サーバーを止めない＝フェイルオープン）。
 */
public class DiskSpoolManager {

    private static final Logger log = Logger.getLogger(DiskSpoolManager.class.getName());
    private static final String CURRENT = "current.jsonl";
    private static final String PENDING_PREFIX = "pending-";
    /** コレクターに恒久的に拒否されたログ（調査用に残す。再送はしない）。 */
    private static final String REJECTED = "rejected.jsonl";

    private final Path dir;
    private final long maxBytes;
    private final Object writeLock = new Object();
    private final Object drainLock = new Object();

    private final AtomicLong spooledBytes = new AtomicLong();
    private final AtomicLong spooledCount = new AtomicLong();
    private final AtomicLong resentCount = new AtomicLong();
    private final AtomicLong droppedCount = new AtomicLong();
    private final AtomicLong rejectedCount = new AtomicLong();
    private long pendingSeq;

    public DiskSpoolManager(String spoolPath, long maxBytes) {
        this.dir = Paths.get(spoolPath != null ? spoolPath : System.getProperty("java.io.tmpdir"), "audit-spool");
        this.maxBytes = maxBytes;
        try {
            Files.createDirectories(dir);
            spooledBytes.set(directorySize());
            log.info("[AuditSpool] spool dir: " + dir.toAbsolutePath() + " (existing " + spooledBytes.get() + " bytes)");
        } catch (IOException e) {
            log.log(Level.SEVERE, "[AuditSpool] cannot create spool dir " + dir, e);
        }
    }

    /** 1件を退避する。書けなかった／上限超過なら false（件数は droppedCount に記録）。 */
    public boolean spool(String jsonLine) {
        byte[] line = (jsonLine + "\n").getBytes(StandardCharsets.UTF_8);
        synchronized (writeLock) { // 複数スレッドの行が混ざらないように直列化
            if (spooledBytes.get() + line.length > maxBytes) {
                long d = droppedCount.incrementAndGet();
                log.warning("[AuditSpool] spool limit reached, record dropped (total dropped=" + d + ")");
                return false;
            }
            try {
                Files.write(dir.resolve(CURRENT), line,
                        StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND);
                spooledBytes.addAndGet(line.length);
                spooledCount.incrementAndGet();
                return true;
            } catch (IOException e) {
                long d = droppedCount.incrementAndGet();
                log.log(Level.WARNING, "[AuditSpool] write failed, record dropped (total dropped=" + d + ")", e);
                return false;
            }
        }
    }

    /** コレクターに恒久的に拒否されたログを rejected.jsonl に残す（再送対象外）。 */
    public void reject(String jsonLine) {
        rejectedCount.incrementAndGet();
        synchronized (writeLock) {
            try {
                Files.write(dir.resolve(REJECTED), (jsonLine + "\n").getBytes(StandardCharsets.UTF_8),
                        StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND);
            } catch (IOException e) {
                log.log(Level.WARNING, "[AuditSpool] cannot write rejected record", e);
            }
        }
    }

    /**
     * 退避済みのログを再送する。
     *
     * @return 今回再送できた件数
     */
    public int drain(AuditTransport transport) {
        synchronized (drainLock) {
            rotateCurrent();
            int sent = 0;
            for (Path pending : pendingFiles()) {
                int r = drainFile(pending, transport);
                if (r < 0) {
                    return sent + (-r - 1); // 途中で失敗。残りは次回
                }
                sent += r;
            }
            return sent;
        }
    }

    /** @return 全件成功なら送信件数、途中失敗なら -(送信件数+1) */
    private int drainFile(Path file, AuditTransport transport) {
        List<String> lines;
        try {
            lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            log.log(Level.WARNING, "[AuditSpool] cannot read " + file, e);
            return -1;
        }
        int ok = 0;
        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            if (line.isBlank()) {
                continue;
            }
            AuditTransport.Result r = transport.send(line);
            if (r == AuditTransport.Result.REJECTED) {
                reject(line); // 不正な1件で後続を止めない
                continue;
            }
            if (r == AuditTransport.Result.RETRY) {
                keepRemaining(file, lines.subList(i, lines.size()));
                resentCount.addAndGet(ok);
                return -(ok + 1);
            }
            ok++;
        }
        try {
            long size = Files.size(file);
            Files.delete(file);
            spooledBytes.addAndGet(-size);
        } catch (IOException e) {
            log.log(Level.WARNING, "[AuditSpool] cannot delete " + file, e);
        }
        resentCount.addAndGet(ok);
        return ok;
    }

    private void keepRemaining(Path file, List<String> remaining) {
        try {
            long before = Files.size(file);
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            Files.write(tmp, remaining, StandardCharsets.UTF_8);
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            spooledBytes.addAndGet(Files.size(file) - before);
        } catch (IOException e) {
            log.log(Level.WARNING, "[AuditSpool] cannot rewrite " + file, e);
        }
    }

    private void rotateCurrent() {
        synchronized (writeLock) {
            Path cur = dir.resolve(CURRENT);
            try {
                if (Files.exists(cur) && Files.size(cur) > 0) {
                    String name = String.format("%s%d-%06d.jsonl", PENDING_PREFIX, System.currentTimeMillis(), pendingSeq++);
                    Files.move(cur, dir.resolve(name), StandardCopyOption.ATOMIC_MOVE);
                }
            } catch (IOException e) {
                log.log(Level.WARNING, "[AuditSpool] rotate failed", e);
            }
        }
    }

    private List<Path> pendingFiles() {
        List<Path> files = new ArrayList<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir, PENDING_PREFIX + "*.jsonl")) {
            ds.forEach(files::add);
        } catch (IOException e) {
            log.log(Level.WARNING, "[AuditSpool] cannot list " + dir, e);
        }
        files.sort(null); // ファイル名＝時刻順
        return files;
    }

    private long directorySize() throws IOException {
        long total = 0;
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir, "*.jsonl")) {
            for (Path p : ds) {
                if (!p.getFileName().toString().equals(REJECTED)) {
                    total += Files.size(p);
                }
            }
        }
        return total;
    }

    public boolean hasPending() {
        return spooledBytes.get() > 0;
    }

    public Path getSpoolDir() { return dir; }
    public long getSpooledBytes() { return spooledBytes.get(); }
    public long getSpooledCount() { return spooledCount.get(); }
    public long getResentCount() { return resentCount.get(); }
    public long getDroppedCount() { return droppedCount.get(); }
    public long getRejectedCount() { return rejectedCount.get(); }
}
