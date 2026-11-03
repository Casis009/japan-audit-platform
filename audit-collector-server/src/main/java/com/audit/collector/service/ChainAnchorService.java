package com.audit.collector.service;

import com.audit.collector.json.MiniJson;
import com.audit.collector.store.AuditStore;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * ハッシュチェーンの「アンカー」を DB の外に残す。
 *
 * <h2>なぜ必要か</h2>
 * DB 管理者（スーパーユーザー）はトリガーを外し、行を書き換えたうえで以降のハッシュを全部計算し直せる。
 * そうされると DB の中だけで検証しても「正常」に見えてしまう。
 * そこで一定間隔で「この時点の最後の連番とハッシュ」を DB の外（このファイル）へ追記しておき、
 * 検証時に「過去に記録したハッシュと、今の DB のその連番のハッシュが一致するか」を照合する。
 * <p>
 * 本番では、このファイルを別サーバー・WORM ストレージ（S3 Object Lock 等）・タイムスタンプ局へ送ると効果が高い。
 */
public class ChainAnchorService {

    private static final Logger log = Logger.getLogger(ChainAnchorService.class.getName());

    private final AuditStore store;
    private final Path file;
    private long lastAnchoredSeq = -1;

    public record Anchor(long seq, String hash, Instant at) {
    }

    public record AnchorCheck(int anchors, List<String> problems) {
    }

    public ChainAnchorService(AuditStore store, Path file) {
        this.store = store;
        this.file = file;
    }

    /** 先頭が進んでいれば1行追記する。 */
    public synchronized Optional<Anchor> anchorNow() {
        if (!store.supportsChain()) {
            return Optional.empty();
        }
        Optional<AuditStore.ChainHead> head = store.head();
        if (head.isEmpty() || head.get().seq() == 0 || head.get().seq() == lastAnchoredSeq) {
            return Optional.empty();
        }
        Anchor a = new Anchor(head.get().seq(), head.get().hash(), Instant.now());
        String line = "{\"seq\":" + a.seq() + ",\"hash\":" + MiniJson.quote(a.hash())
                + ",\"at\":" + MiniJson.quote(a.at().toString()) + "}\n";
        try {
            if (file.getParent() != null) {
                Files.createDirectories(file.getParent());
            }
            Files.writeString(file, line, StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            lastAnchoredSeq = a.seq();
            return Optional.of(a);
        } catch (IOException e) {
            log.log(Level.WARNING, "[Anchor] cannot write " + file, e);
            return Optional.empty();
        }
    }

    /** 記録済みアンカーと現在の DB を照合する。 */
    public AnchorCheck check() {
        List<String> problems = new ArrayList<>();
        List<Anchor> anchors = load(problems);
        for (Anchor a : anchors) {
            Optional<String> now = store.hashAt(a.seq());
            if (now.isEmpty()) {
                problems.add("anchor seq " + a.seq() + ": row no longer exists");
            } else if (!now.get().equals(a.hash())) {
                problems.add("anchor seq " + a.seq() + ": hash differs from anchor recorded at " + a.at()
                        + " (chain was rewritten)");
            }
        }
        return new AnchorCheck(anchors.size(), problems);
    }

    private List<Anchor> load(List<String> problems) {
        List<Anchor> out = new ArrayList<>();
        if (!Files.exists(file)) {
            return out;
        }
        try {
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                if (line.isBlank()) continue;
                try {
                    Map<String, Object> m = MiniJson.parseObject(line);
                    out.add(new Anchor(((BigDecimal) m.get("seq")).longValueExact(), (String) m.get("hash"),
                            Instant.parse((String) m.get("at"))));
                } catch (RuntimeException e) {
                    problems.add("unreadable anchor line: " + e.getMessage());
                }
            }
        } catch (IOException e) {
            problems.add("cannot read anchor file: " + e.getMessage());
        }
        return out;
    }
}
