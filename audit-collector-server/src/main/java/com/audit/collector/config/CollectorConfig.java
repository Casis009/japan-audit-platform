package com.audit.collector.config;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;

/** コレクターの設定（すべて環境変数から読む。秘密情報の既定値は持たない）。 */
public record CollectorConfig(
        int port,
        String storage,          // postgres | memory
        String dbUrl,
        String dbUser,
        String dbPassword,
        String sensorKey,
        String consoleUser,
        String consolePassword,
        int personThreshold,
        Duration alertWindow,
        Path anchorFile,
        Duration anchorInterval,
        int maxRequestBytes
) {

    public static CollectorConfig fromEnv(Map<String, String> env) {
        String sensorKey = env.getOrDefault("SENSOR_KEY", "");
        if (sensorKey.length() < 16) {
            throw new IllegalStateException(
                    "SENSOR_KEY must be set (16+ chars). Example: export SENSOR_KEY=$(openssl rand -hex 24)");
        }
        String host = env.getOrDefault("DB_HOST", "localhost");
        String port = env.getOrDefault("DB_PORT", "5432");
        String name = env.getOrDefault("DB_NAME", "auditdb");
        return new CollectorConfig(
                Integer.parseInt(env.getOrDefault("COLLECTOR_PORT", "8081")),
                env.getOrDefault("COLLECTOR_STORAGE", "postgres"),
                "jdbc:postgresql://" + host + ":" + port + "/" + name,
                env.getOrDefault("DB_USER", "audit_user"),
                env.getOrDefault("DB_PASSWORD", ""),
                sensorKey,
                env.getOrDefault("CONSOLE_USER", "auditor"),
                env.getOrDefault("CONSOLE_PASSWORD", ""),
                Integer.parseInt(env.getOrDefault("ALERT_PERSON_THRESHOLD", "100")),
                Duration.ofMinutes(Long.parseLong(env.getOrDefault("ALERT_WINDOW_MINUTES", "10"))),
                Path.of(env.getOrDefault("ANCHOR_FILE", "./data/chain-anchors.jsonl")),
                Duration.ofSeconds(Long.parseLong(env.getOrDefault("ANCHOR_INTERVAL_SECONDS", "60"))),
                Integer.parseInt(env.getOrDefault("MAX_REQUEST_BYTES", String.valueOf(2 * 1024 * 1024))));
    }
}
