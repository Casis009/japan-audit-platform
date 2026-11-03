package jakarta.servlet.http;

import jakarta.servlet.ServletOutputStream;
import java.io.IOException;
import java.io.PrintWriter;

public class HttpServletResponseWrapper implements HttpServletResponse {
    private HttpServletResponse response;

    public HttpServletResponseWrapper(HttpServletResponse response) {
        if (response == null) throw new IllegalArgumentException("Response cannot be null");
        this.response = response;
    }

    public HttpServletResponse getResponse() { return this.response; }

    @Override public String getCharacterEncoding() { return response.getCharacterEncoding(); }
    @Override public String getContentType() { return response.getContentType(); }
    @Override public ServletOutputStream getOutputStream() throws IOException { return response.getOutputStream(); }
    @Override public PrintWriter getWriter() throws IOException { return response.getWriter(); }
    @Override public void setCharacterEncoding(String charset) { response.setCharacterEncoding(charset); }
    @Override public void setContentLength(int len) { response.setContentLength(len); }
    @Override public void setContentType(String type) { response.setContentType(type); }
    @Override public void setBufferSize(int size) { response.setBufferSize(size); }
    @Override public int getBufferSize() { return response.getBufferSize(); }
    @Override public void flushBuffer() throws IOException { response.flushBuffer(); }
    @Override public void reset() { response.reset(); }
    @Override public boolean isCommitted() { return response.isCommitted(); }
    @Override public int getStatus() { return response.getStatus(); }
    @Override public void setStatus(int sc) { response.setStatus(sc); }
    @Override public void setHeader(String name, String value) { response.setHeader(name, value); }
    @Override public void addHeader(String name, String value) { response.addHeader(name, value); }
    @Override public String getHeader(String name) { return response.getHeader(name); }
}
