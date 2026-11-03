package com.audit.sensor.wrapper;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * レスポンス本文をクライアントへそのまま流しつつ（Tee）、先頭の上限分だけ監査用にコピーするラッパー。
 * クライアントへの送信は一切待たせない・削らない。
 */
public class AuditContentCachingResponseWrapper extends HttpServletResponseWrapper {

    private final BoundedCapture capture;
    private ServletOutputStream stream;
    private PrintWriter writer;

    public AuditContentCachingResponseWrapper(HttpServletResponse response, int captureLimitBytes) {
        super(response);
        this.capture = new BoundedCapture(captureLimitBytes);
    }

    @Override
    public ServletOutputStream getOutputStream() throws IOException {
        if (writer != null) {
            throw new IllegalStateException("getWriter() has already been called");
        }
        if (stream == null) {
            stream = new TeeOutputStream(super.getOutputStream(), capture);
        }
        return stream;
    }

    @Override
    public PrintWriter getWriter() throws IOException {
        if (stream != null && writer == null) {
            throw new IllegalStateException("getOutputStream() has already been called");
        }
        if (writer == null) {
            ServletOutputStream tee = new TeeOutputStream(super.getOutputStream(), capture);
            writer = new PrintWriter(new OutputStreamWriter(tee, charset()), false);
        }
        return writer;
    }

    @Override
    public void flushBuffer() throws IOException {
        if (writer != null) {
            writer.flush();
        } else if (stream != null) {
            stream.flush();
        }
        super.flushBuffer();
    }

    /** 監査用にコピーした本文（上限まで）。 */
    public String getCapturedBody() {
        if (writer != null) {
            writer.flush();
        }
        return capture.asString(getCharacterEncoding());
    }

    public boolean isCaptureTruncated() {
        return capture.truncated();
    }

    private Charset charset() {
        String enc = getCharacterEncoding();
        return (enc != null && Charset.isSupported(enc)) ? Charset.forName(enc) : StandardCharsets.UTF_8;
    }

    private static final class TeeOutputStream extends ServletOutputStream {
        private final ServletOutputStream out;
        private final BoundedCapture capture;

        TeeOutputStream(ServletOutputStream out, BoundedCapture capture) {
            this.out = out;
            this.capture = capture;
        }

        @Override
        public void write(int b) throws IOException {
            out.write(b);
            capture.write(b);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            out.write(b, off, len);
            capture.write(b, off, len);
        }

        @Override
        public void flush() throws IOException {
            out.flush();
        }

        @Override
        public void close() throws IOException {
            out.close();
        }

        @Override
        public boolean isReady() {
            return out.isReady();
        }

        @Override
        public void setWriteListener(WriteListener listener) {
            out.setWriteListener(listener);
        }
    }
}
