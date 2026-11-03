package com.audit.sensor.config;

import com.audit.rule.detector.JapanPiiDetector;
import com.audit.sensor.dispatcher.AuditLogDispatcher;
import com.audit.sensor.dispatcher.HttpCollectorTransport;
import com.audit.sensor.filter.JapanAuditLoggingFilter;
import com.audit.sensor.spool.DiskSpoolManager;

/**
 * 設定から監査センサー一式（フィルター・送信係・退避）を組み立てる。
 * <p>
 * Spring Boot なら AutoConfiguration が行う「部品の組み立て」を、ここでは手書きしている。
 * 業務アプリ側は {@code AuditSensorFactory.create(props).filter()} をフィルターチェーンに1つ足すだけで済む。
 */
public final class AuditSensorFactory {

    private AuditSensorFactory() {
    }

    public record AuditSensor(JapanAuditLoggingFilter filter, AuditLogDispatcher dispatcher) implements AutoCloseable {
        @Override
        public void close() {
            dispatcher.close();
        }
    }

    public static AuditSensor create(AuditSensorProperties props) {
        if (props.getSensorKey() == null || props.getSensorKey().isBlank()) {
            throw new IllegalStateException("SENSOR_KEY is not set (collector will reject unauthenticated logs)");
        }
        DiskSpoolManager spool = new DiskSpoolManager(props.getSpoolPath(), props.getMaxSpoolBytes());
        HttpCollectorTransport transport =
                new HttpCollectorTransport(props.getCollectorUrl(), props.getSensorKey(), props.getSendTimeoutMs());
        AuditLogDispatcher dispatcher =
                new AuditLogDispatcher(props.getMaxQueueSize(), transport, spool, props.getResendIntervalMs());
        JapanAuditLoggingFilter filter = new JapanAuditLoggingFilter(props, dispatcher, new JapanPiiDetector());
        return new AuditSensor(filter, dispatcher);
    }
}
