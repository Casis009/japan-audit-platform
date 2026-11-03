package com.audit.collector.service;

import com.audit.collector.model.Alert;
import com.audit.collector.model.IngestRequest;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 監査ログから警戒レベルを判定する。
 *
 * <h2>閾値の根拠</h2>
 * 番号法 第29条の4・同条に基づく委員会規則 第2条は、特定個人情報の漏えい等で
 * 「本人の数が100人を<b>超える</b>」事態を報告対象としている。これを参考に、社内監視の閾値を
 * 「本人数 100人超（&gt; 100）」とした。数えるのは出現回数ではなく<b>異なるマイナンバーの数（≒本人数）</b>。
 * <p>
 * なお個人情報保護法 第26条（施行規則 第7条）の「人数」基準は 1,000人超であり、100人ではない。
 *
 * <h2>2つの検知</h2>
 * <ol>
 *   <li>1リクエストで本人数が閾値超 → CRITICAL</li>
 *   <li>同じユーザーの直近 {@code window} 内の本人数の累計が閾値超 → CRITICAL（99人ずつに分けて取得する回避への対策）</li>
 * </ol>
 * 累計はリクエストごとの人数を足すため、同じ人を何度も見ると多めに数える（安全側＝見逃しより過検知を選ぶ）。
 * 状態はメモリ上にあるため、再起動で消え、複数台構成では共有されない（本番では DB 集計かストリーム処理に置き換える）。
 */
public class AlertEvaluator {

    private final int personThreshold;
    private final Duration window;
    private final Map<String, Deque<long[]>> perUser = new ConcurrentHashMap<>();

    public AlertEvaluator(int personThreshold, Duration window) {
        this.personThreshold = personThreshold;
        this.window = window;
    }

    public Alert evaluate(IngestRequest r) {
        int persons = r.myNumberPersonCount();
        if (persons > personThreshold) {
            return new Alert(Alert.Level.CRITICAL, String.format(
                    "特定個人情報の大量照会：1リクエストで本人数 %d 人（閾値 %d 人超）", persons, personThreshold));
        }

        if (persons > 0) {
            long sum = windowSum(r.userPrincipal(), r.timestamp()) + persons;
            if (sum > personThreshold) {
                return new Alert(Alert.Level.CRITICAL, String.format(
                        "分割照会の疑い：%s の直近%d分の本人数累計 %d 人（閾値 %d 人超）",
                        r.userPrincipal(), window.toMinutes(), sum, personThreshold));
            }
        }

        if (r.piiDetected()) {
            Set<String> types = new LinkedHashSet<>();
            r.details().forEach(d -> types.add(d.piiType()));
            return new Alert(Alert.Level.WARN, "個人情報を含む照会：" + String.join(",", types));
        }
        return Alert.info();
    }

    /**
     * 新規登録が確定したログだけを窓に記録する（再送の重複を二重に数えないため、登録後に呼ぶ）。
     */
    public void record(IngestRequest r) {
        if (r.myNumberPersonCount() <= 0) {
            return;
        }
        Deque<long[]> q = perUser.computeIfAbsent(r.userPrincipal(), k -> new ArrayDeque<>());
        synchronized (q) {
            q.addLast(new long[]{r.timestamp().toEpochMilli(), r.myNumberPersonCount()});
        }
    }

    private long windowSum(String user, Instant at) {
        Deque<long[]> q = perUser.get(user);
        if (q == null) {
            return 0;
        }
        synchronized (q) {
            long now = at.toEpochMilli();
            long from = now - window.toMillis();
            long sum = 0;
            var it = q.iterator();
            while (it.hasNext()) {
                long[] e = it.next();
                if (e[0] < from - window.toMillis()) {
                    it.remove(); // 十分古いものは捨てる（再送で少し古いログが来ても判定できるよう余裕を持たせる）
                } else if (e[0] >= from && e[0] <= now) {
                    sum += e[1];
                }
            }
            return sum;
        }
    }
}
