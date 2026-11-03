package com.audit.sensor.config;

import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 監査センサーの設定値。
 * <p>
 * Spring Boot の {@code @ConfigurationProperties} に相当するが、本プロジェクトは依存ライブラリなしで
 * 動かすため、環境変数から読む {@link #fromEnv(Map)} を用意している。
 */
public class AuditSensorProperties {

    private boolean enabled = true;
    private String systemCode = "SYS_UNKNOWN";
    private String hostName = "localhost";
    private String collectorUrl = "http://localhost:8081/api/v1/collector/ingest";
    private String sensorKey = "";
    private String spoolPath = null;
    private int maxQueueSize = 5000;
    /** 監査用にコピーする本文の上限（業務データは削らない）。 */
    private int maxCaptureBytes = 65536;
    /**
     * マスキング済み本文をコレクターへ送るか。既定は false（データ最小化）。
     * 氏名・住所は形式で検知できないため、本文を送ると監査DBに平文の個人情報が残りうる。
     */
    private boolean sendBody = false;
    private boolean maskPii = true;
    /** この IP から来たときだけ X-Forwarded-For / 認証済みユーザーヘッダーを信用する。 */
    private Set<String> trustedProxies = Set.of();
    /** 前段の認証ゲートウェイが付与するユーザーヘッダー名（信頼済みプロキシ経由のときだけ採用）。 */
    private String trustedUserHeader = "X-Authenticated-User";
    /** スプール（ローカル退避）の上限。超えたら破棄して件数を数える（業務は止めない）。 */
    private long maxSpoolBytes = 100L * 1024 * 1024;
    private long resendIntervalMs = 5000;
    private long sendTimeoutMs = 2000;

    public static AuditSensorProperties fromEnv(Map<String, String> env) {
        AuditSensorProperties p = new AuditSensorProperties();
        p.enabled = Boolean.parseBoolean(env.getOrDefault("AUDIT_ENABLED", "true"));
        p.systemCode = env.getOrDefault("AUDIT_SYSTEM_CODE", p.systemCode);
        p.hostName = env.getOrDefault("HOSTNAME", p.hostName);
        p.collectorUrl = env.getOrDefault("COLLECTOR_URL", p.collectorUrl);
        p.sensorKey = env.getOrDefault("SENSOR_KEY", "");
        p.spoolPath = env.getOrDefault("SPOOL_PATH", null);
        p.maxQueueSize = Integer.parseInt(env.getOrDefault("AUDIT_MAX_QUEUE", "5000"));
        p.maxCaptureBytes = Integer.parseInt(env.getOrDefault("AUDIT_MAX_CAPTURE_BYTES", "65536"));
        p.sendBody = Boolean.parseBoolean(env.getOrDefault("AUDIT_SEND_BODY", "false"));
        p.trustedProxies = Arrays.stream(env.getOrDefault("AUDIT_TRUSTED_PROXIES", "").split(","))
                .map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toUnmodifiableSet());
        p.maxSpoolBytes = Long.parseLong(env.getOrDefault("AUDIT_MAX_SPOOL_BYTES", String.valueOf(p.maxSpoolBytes)));
        p.resendIntervalMs = Long.parseLong(env.getOrDefault("AUDIT_RESEND_INTERVAL_MS", "5000"));
        return p;
    }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public String getSystemCode() { return systemCode; }
    public void setSystemCode(String systemCode) { this.systemCode = systemCode; }

    public String getHostName() { return hostName; }
    public void setHostName(String hostName) { this.hostName = hostName; }

    public String getCollectorUrl() { return collectorUrl; }
    public void setCollectorUrl(String collectorUrl) { this.collectorUrl = collectorUrl; }

    public String getSensorKey() { return sensorKey; }
    public void setSensorKey(String sensorKey) { this.sensorKey = sensorKey; }

    public String getSpoolPath() { return spoolPath; }
    public void setSpoolPath(String spoolPath) { this.spoolPath = spoolPath; }

    public int getMaxQueueSize() { return maxQueueSize; }
    public void setMaxQueueSize(int maxQueueSize) { this.maxQueueSize = maxQueueSize; }

    public int getMaxCaptureBytes() { return maxCaptureBytes; }
    public void setMaxCaptureBytes(int maxCaptureBytes) { this.maxCaptureBytes = maxCaptureBytes; }

    public boolean isSendBody() { return sendBody; }
    public void setSendBody(boolean sendBody) { this.sendBody = sendBody; }

    public boolean isMaskPii() { return maskPii; }
    public void setMaskPii(boolean maskPii) { this.maskPii = maskPii; }

    public Set<String> getTrustedProxies() { return trustedProxies; }
    public void setTrustedProxies(Set<String> trustedProxies) { this.trustedProxies = Set.copyOf(trustedProxies); }

    public String getTrustedUserHeader() { return trustedUserHeader; }
    public void setTrustedUserHeader(String trustedUserHeader) { this.trustedUserHeader = trustedUserHeader; }

    public long getMaxSpoolBytes() { return maxSpoolBytes; }
    public void setMaxSpoolBytes(long maxSpoolBytes) { this.maxSpoolBytes = maxSpoolBytes; }

    public long getResendIntervalMs() { return resendIntervalMs; }
    public void setResendIntervalMs(long resendIntervalMs) { this.resendIntervalMs = resendIntervalMs; }

    public long getSendTimeoutMs() { return sendTimeoutMs; }
    public void setSendTimeoutMs(long sendTimeoutMs) { this.sendTimeoutMs = sendTimeoutMs; }
}
