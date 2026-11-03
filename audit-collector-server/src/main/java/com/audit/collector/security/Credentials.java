package com.audit.collector.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * 認証まわり。
 *
 * <h2>旧実装の欠陥</h2>
 * <pre>if (key != null &amp;&amp; !key.isBlank() &amp;&amp; !expected.equals(key)) → 401</pre>
 * この条件だと「ヘッダーを付けない」場合はチェック自体が飛ばされ、誰でもログを登録できた（実測で 202）。
 * 新実装は「一致したときだけ通す」書き方にし、比較は所要時間が一致長に依存しない定数時間比較にする。
 */
public final class Credentials {

    private Credentials() {
    }

    /** センサーキーの照合。null・空・不一致はすべて拒否。 */
    public static boolean sensorKeyMatches(String presented, String expected) {
        if (presented == null || expected == null || expected.isEmpty()) {
            return false;
        }
        return MessageDigest.isEqual(
                presented.getBytes(StandardCharsets.UTF_8),
                expected.getBytes(StandardCharsets.UTF_8));
    }

    /** 監査コンソール用の Basic 認証。 */
    public static boolean basicAuthMatches(String authorizationHeader, String user, String password) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Basic ")
                || user == null || password == null || password.isEmpty()) {
            return false;
        }
        String decoded;
        try {
            decoded = new String(Base64.getDecoder().decode(authorizationHeader.substring(6).trim()), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return false;
        }
        String expected = user + ":" + password;
        return MessageDigest.isEqual(decoded.getBytes(StandardCharsets.UTF_8), expected.getBytes(StandardCharsets.UTF_8));
    }
}
