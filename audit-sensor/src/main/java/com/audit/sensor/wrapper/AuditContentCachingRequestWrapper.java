package com.audit.sensor.wrapper;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * リクエスト本文を「業務側が読んだ分だけ」横取りしてコピーするラッパー（Read-Through 方式）。
 *
 * <h2>旧実装の問題と修正</h2>
 * 旧実装はコンストラクタで本文を先読みし、上限（64KB）で切った本文を業務側に渡していた。
 * そのため 200KB の本文を送ると Controller には 64KB しか届かず、業務データが壊れていた（実測で再現）。
 * <p>
 * 新実装は先読みしない。業務側が {@code getInputStream()} で読んだバイトを素通しし、
 * そのうち先頭の上限分だけを監査用にコピーする。Spring の ContentCachingRequestWrapper と同じ考え方。
 * <p>
 * トレードオフ：業務側が本文を読まなかった場合、監査用コピーも空になる（GET 等では本文が無いので実害は小さい）。
 */
public class AuditContentCachingRequestWrapper extends HttpServletRequestWrapper {

    private final BoundedCapture capture;
    private ServletInputStream stream;
    private BufferedReader reader;

    public AuditContentCachingRequestWrapper(HttpServletRequest request, int captureLimitBytes) {
        super(request);
        this.capture = new BoundedCapture(captureLimitBytes);
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
        if (stream == null) {
            stream = new TeeInputStream(super.getInputStream(), capture);
        }
        return stream;
    }

    @Override
    public BufferedReader getReader() throws IOException {
        if (reader == null) {
            reader = new BufferedReader(new InputStreamReader(getInputStream(), charset()));
        }
        return reader;
    }

    /** 監査用にコピーした本文（上限まで）。 */
    public String getCapturedBody() {
        return capture.asString(getCharacterEncoding());
    }

    public boolean isCaptureTruncated() {
        return capture.truncated();
    }

    private Charset charset() {
        String enc = getCharacterEncoding();
        return (enc != null && Charset.isSupported(enc)) ? Charset.forName(enc) : StandardCharsets.UTF_8;
    }

    private static final class TeeInputStream extends ServletInputStream {
        private final ServletInputStream in;
        private final BoundedCapture capture;

        TeeInputStream(ServletInputStream in, BoundedCapture capture) {
            this.in = in;
            this.capture = capture;
        }

        @Override
        public int read() throws IOException {
            int b = in.read();
            if (b != -1) {
                capture.write(b);
            }
            return b;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            int n = in.read(b, off, len);
            if (n > 0) {
                capture.write(b, off, n);
            }
            return n;
        }

        @Override
        public boolean isFinished() {
            return in.isFinished();
        }

        @Override
        public boolean isReady() {
            return in.isReady();
        }

        @Override
        public void setReadListener(ReadListener listener) {
            in.setReadListener(listener);
        }
    }
}
