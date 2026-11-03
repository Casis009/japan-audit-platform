package jakarta.servlet.http;

import jakarta.servlet.ServletInputStream;
import java.io.BufferedReader;
import java.io.IOException;

public class HttpServletRequestWrapper implements HttpServletRequest {
    private HttpServletRequest request;

    public HttpServletRequestWrapper(HttpServletRequest request) {
        if (request == null) throw new IllegalArgumentException("Request cannot be null");
        this.request = request;
    }

    public HttpServletRequest getRequest() { return this.request; }

    @Override public Object getAttribute(String name) { return request.getAttribute(name); }
    @Override public void setAttribute(String name, Object o) { request.setAttribute(name, o); }
    @Override public String getCharacterEncoding() { return request.getCharacterEncoding(); }
    @Override public void setCharacterEncoding(String env) throws java.io.UnsupportedEncodingException { request.setCharacterEncoding(env); }
    @Override public int getContentLength() { return request.getContentLength(); }
    @Override public long getContentLengthLong() { return request.getContentLengthLong(); }
    @Override public String getContentType() { return request.getContentType(); }
    @Override public ServletInputStream getInputStream() throws IOException { return request.getInputStream(); }
    @Override public String getParameter(String name) { return request.getParameter(name); }
    @Override public BufferedReader getReader() throws IOException { return request.getReader(); }
    @Override public String getRemoteAddr() { return request.getRemoteAddr(); }
    @Override public String getRemoteHost() { return request.getRemoteHost(); }
    @Override public int getRemotePort() { return request.getRemotePort(); }
    @Override public String getMethod() { return request.getMethod(); }
    @Override public String getRequestURI() { return request.getRequestURI(); }
    @Override public StringBuffer getRequestURL() { return request.getRequestURL(); }
    @Override public String getQueryString() { return request.getQueryString(); }
    @Override public String getHeader(String name) { return request.getHeader(name); }
    @Override public java.security.Principal getUserPrincipal() { return request.getUserPrincipal(); }
    @Override public String getContextPath() { return request.getContextPath(); }
}
