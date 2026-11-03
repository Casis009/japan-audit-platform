package com.audit.sensor.testsupport;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

/** テスト用の最小限の HttpServletRequest / HttpServletResponse。 */
public final class FakeHttp {

    private FakeHttp() {
    }

    public static final class Request implements HttpServletRequest {
        public String method = "GET";
        public String uri = "/";
        public String query;
        public String remoteAddr = "10.0.0.5";
        public Principal principal;
        public final Map<String, String> headers = new HashMap<>();
        private final ByteArrayInputStream body;
        private ServletInputStream stream;

        public Request(byte[] body) {
            this.body = new ByteArrayInputStream(body);
        }

        public Request(String body) {
            this(body.getBytes(StandardCharsets.UTF_8));
        }

        @Override public String getMethod() { return method; }
        @Override public String getRequestURI() { return uri; }
        @Override public StringBuffer getRequestURL() { return new StringBuffer("http://test" + uri); }
        @Override public String getQueryString() { return query; }
        @Override public String getHeader(String name) { return headers.get(name); }
        @Override public Principal getUserPrincipal() { return principal; }
        @Override public String getContextPath() { return ""; }
        @Override public Object getAttribute(String name) { return null; }
        @Override public void setAttribute(String name, Object o) { }
        @Override public String getCharacterEncoding() { return "UTF-8"; }
        @Override public void setCharacterEncoding(String env) { }
        @Override public int getContentLength() { return -1; }
        @Override public long getContentLengthLong() { return -1; }
        @Override public String getContentType() { return "application/json"; }
        @Override public String getParameter(String name) { return null; }
        @Override public String getRemoteAddr() { return remoteAddr; }
        @Override public String getRemoteHost() { return remoteAddr; }
        @Override public int getRemotePort() { return 50000; }

        @Override
        public ServletInputStream getInputStream() {
            if (stream == null) {
                stream = new ServletInputStream() {
                    @Override public int read() { return body.read(); }
                    @Override public int read(byte[] b, int off, int len) { return body.read(b, off, len); }
                    @Override public boolean isFinished() { return body.available() == 0; }
                    @Override public boolean isReady() { return true; }
                    @Override public void setReadListener(ReadListener l) { }
                };
            }
            return stream;
        }

        @Override
        public BufferedReader getReader() {
            return new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
        }
    }

    public static final class Response implements HttpServletResponse {
        public final ByteArrayOutputStream sent = new ByteArrayOutputStream();
        public int status = 200;
        private ServletOutputStream stream;
        private PrintWriter writer;

        public String sentText() {
            if (writer != null) writer.flush();
            return sent.toString(StandardCharsets.UTF_8);
        }

        @Override
        public ServletOutputStream getOutputStream() {
            if (stream == null) {
                stream = new ServletOutputStream() {
                    @Override public void write(int b) { sent.write(b); }
                    @Override public void write(byte[] b, int off, int len) { sent.write(b, off, len); }
                    @Override public boolean isReady() { return true; }
                    @Override public void setWriteListener(WriteListener l) { }
                };
            }
            return stream;
        }

        @Override
        public PrintWriter getWriter() {
            if (writer == null) writer = new PrintWriter(new OutputStreamWriter(getOutputStream(), StandardCharsets.UTF_8));
            return writer;
        }

        @Override public String getCharacterEncoding() { return "UTF-8"; }
        @Override public String getContentType() { return "application/json"; }
        @Override public void setCharacterEncoding(String charset) { }
        @Override public void setContentLength(int len) { }
        @Override public void setContentType(String type) { }
        @Override public void setBufferSize(int size) { }
        @Override public int getBufferSize() { return 0; }
        @Override public void flushBuffer() { if (writer != null) writer.flush(); }
        @Override public void reset() { sent.reset(); }
        @Override public boolean isCommitted() { return false; }
        @Override public int getStatus() { return status; }
        @Override public void setStatus(int sc) { status = sc; }
        @Override public void setHeader(String name, String value) { }
        @Override public void addHeader(String name, String value) { }
        @Override public String getHeader(String name) { return null; }
    }
}
