package com.audit.demo.adapter;

import com.sun.net.httpserver.HttpExchange;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletResponse;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

/**
 * HttpServletResponse を HttpExchange へ書き出すアダプター。
 * 簡単のため本文はメモリにためて、{@link #commit()} でまとめて送る（Content-Length 付き）。
 */
public class ExchangeResponse implements HttpServletResponse {

    private final HttpExchange ex;
    private final ByteArrayOutputStream body = new ByteArrayOutputStream();
    private int status = 200;
    private String contentType;
    private String encoding = "UTF-8";
    private ServletOutputStream stream;
    private PrintWriter writer;
    private boolean committed;

    public ExchangeResponse(HttpExchange ex) {
        this.ex = ex;
    }

    /** 業務処理の後に1回だけ呼び、クライアントへ送信する。 */
    public void commit() throws IOException {
        if (committed) return;
        if (writer != null) writer.flush();
        committed = true;
        if (contentType != null) {
            String ct = contentType.contains("charset") ? contentType : contentType + "; charset=" + encoding;
            ex.getResponseHeaders().set("Content-Type", ct);
        }
        byte[] b = body.toByteArray();
        ex.sendResponseHeaders(status, b.length == 0 ? -1 : b.length);
        if (b.length > 0) {
            try (OutputStream os = ex.getResponseBody()) {
                os.write(b);
            }
        }
    }

    @Override
    public ServletOutputStream getOutputStream() {
        if (stream == null) {
            stream = new ServletOutputStream() {
                @Override public void write(int b) { body.write(b); }
                @Override public void write(byte[] b, int off, int len) { body.write(b, off, len); }
                @Override public boolean isReady() { return true; }
                @Override public void setWriteListener(WriteListener l) { throw new UnsupportedOperationException(); }
            };
        }
        return stream;
    }

    @Override
    public PrintWriter getWriter() {
        if (writer == null) {
            writer = new PrintWriter(new OutputStreamWriter(getOutputStream(), StandardCharsets.UTF_8));
        }
        return writer;
    }

    @Override public String getCharacterEncoding() { return encoding; }
    @Override public void setCharacterEncoding(String charset) { this.encoding = charset; }
    @Override public String getContentType() { return contentType; }
    @Override public void setContentType(String type) { this.contentType = type; }
    @Override public void setContentLength(int len) { /* commit() で計算する */ }
    @Override public void setBufferSize(int size) { }
    @Override public int getBufferSize() { return body.size(); }
    @Override public void flushBuffer() { /* commit() で送る */ }
    @Override public void reset() { body.reset(); status = 200; }
    @Override public boolean isCommitted() { return committed; }
    @Override public int getStatus() { return status; }
    @Override public void setStatus(int sc) { this.status = sc; }
    @Override public void setHeader(String name, String value) { ex.getResponseHeaders().set(name, value); }
    @Override public void addHeader(String name, String value) { ex.getResponseHeaders().add(name, value); }
    @Override public String getHeader(String name) { return ex.getResponseHeaders().getFirst(name); }
}
