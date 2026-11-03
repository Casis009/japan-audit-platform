package com.audit.sensor.wrapper;

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * 本文の「監査用コピー」を上限付きで保持する小さなバッファ。
 * <p>
 * 重要：上限を超えた分は <b>コピーしないだけ</b> で、業務側（Controller・クライアント）へのデータは
 * 1バイトも削らない。旧実装は上限で業務データ自体を切り捨てていたため、ここで責務を分離した。
 */
final class BoundedCapture {

    private final ByteArrayOutputStream buf = new ByteArrayOutputStream();
    private final int limit;
    private long totalBytes;

    BoundedCapture(int limit) {
        this.limit = Math.max(0, limit);
    }

    void write(int b) {
        totalBytes++;
        if (buf.size() < limit) {
            buf.write(b);
        }
    }

    void write(byte[] b, int off, int len) {
        if (len <= 0) {
            return;
        }
        totalBytes += len;
        int room = limit - buf.size();
        if (room > 0) {
            buf.write(b, off, Math.min(room, len));
        }
    }

    /** 実際に流れたバイト数（上限とは無関係）。 */
    long totalBytes() {
        return totalBytes;
    }

    boolean truncated() {
        return totalBytes > buf.size();
    }

    String asString(String encoding) {
        Charset cs = StandardCharsets.UTF_8;
        if (encoding != null && Charset.isSupported(encoding)) {
            cs = Charset.forName(encoding);
        }
        return new String(buf.toByteArray(), cs);
    }
}
