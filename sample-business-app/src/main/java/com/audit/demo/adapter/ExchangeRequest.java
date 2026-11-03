package com.audit.demo.adapter;

import com.sun.net.httpserver.HttpExchange;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

/**
 * JDK の HttpExchange を HttpServletRequest として見せるアダプター。
 * 本物のサーブレットコンテナ（Tomcat 等）が行う変換を、デモ用に最小限で再現している。
 */
public class ExchangeRequest implements HttpServletRequest {

    private final HttpExchange ex;
    private final Map<String, Object> attributes = new HashMap<>();
    private Principal principal;
    private ServletInputStream stream;
    private String encoding;

    public ExchangeRequest(HttpExchange ex) {
        this.ex = ex;
    }

    /** コンテナ（ここではアダプター）が認証した結果を設定する。 */
    public void setUserPrincipal(Principal principal) {
        this.principal = principal;
    }

    @Override public Principal getUserPrincipal() { return principal; }
    @Override public String getMethod() { return ex.getRequestMethod(); }
    @Override public String getRequestURI() { return ex.getRequestURI().getRawPath(); }
    @Override public StringBuffer getRequestURL() { return new StringBuffer("http://" + ex.getLocalAddress().getHostString() + ":" + ex.getLocalAddress().getPort() + getRequestURI()); }
    @Override public String getQueryString() { return ex.getRequestURI().getRawQuery(); }
    @Override public String getHeader(String name) { return ex.getRequestHeaders().getFirst(name); }
    @Override public String getContextPath() { return ""; }
    @Override public Object getAttribute(String name) { return attributes.get(name); }
    @Override public void setAttribute(String name, Object o) { attributes.put(name, o); }
    @Override public void setCharacterEncoding(String env) { this.encoding = env; }
    @Override public String getContentType() { return getHeader("Content-Type"); }
    @Override public String getRemoteAddr() { return ex.getRemoteAddress().getAddress().getHostAddress(); }
    @Override public String getRemoteHost() { return ex.getRemoteAddress().getHostString(); }
    @Override public int getRemotePort() { return ex.getRemoteAddress().getPort(); }

    @Override
    public String getCharacterEncoding() {
        if (encoding != null) return encoding;
        String ct = getContentType();
        if (ct != null) {
            for (String part : ct.split(";")) {
                String p = part.trim();
                if (p.toLowerCase().startsWith("charset=")) return p.substring(8).replace("\"", "");
            }
        }
        return null;
    }

    @Override
    public long getContentLengthLong() {
        String v = getHeader("Content-Length");
        try {
            return v == null ? -1 : Long.parseLong(v);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    @Override
    public int getContentLength() {
        long l = getContentLengthLong();
        return l > Integer.MAX_VALUE ? -1 : (int) l;
    }

    @Override
    public String getParameter(String name) {
        String q = getQueryString();
        if (q == null) return null;
        for (String kv : q.split("&")) {
            int i = kv.indexOf('=');
            String k = URLDecoder.decode(i < 0 ? kv : kv.substring(0, i), StandardCharsets.UTF_8);
            if (k.equals(name)) {
                return i < 0 ? "" : URLDecoder.decode(kv.substring(i + 1), StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    @Override
    public ServletInputStream getInputStream() {
        if (stream == null) {
            InputStream in = ex.getRequestBody();
            stream = new ServletInputStream() {
                private boolean finished;
                @Override public int read() throws IOException { int b = in.read(); finished = b == -1; return b; }
                @Override public int read(byte[] b, int off, int len) throws IOException { int n = in.read(b, off, len); finished = n == -1; return n; }
                @Override public boolean isFinished() { return finished; }
                @Override public boolean isReady() { return true; }
                @Override public void setReadListener(ReadListener l) { throw new UnsupportedOperationException("async IO not supported"); }
            };
        }
        return stream;
    }

    @Override
    public BufferedReader getReader() {
        String enc = getCharacterEncoding();
        Charset cs = enc != null && Charset.isSupported(enc) ? Charset.forName(enc) : StandardCharsets.UTF_8;
        return new BufferedReader(new InputStreamReader(getInputStream(), cs));
    }
}
