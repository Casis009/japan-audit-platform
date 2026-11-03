package jakarta.servlet;

import java.io.BufferedReader;
import java.io.IOException;

public interface ServletRequest {
    Object getAttribute(String name);
    void setAttribute(String name, Object o);
    String getCharacterEncoding();
    void setCharacterEncoding(String env) throws java.io.UnsupportedEncodingException;
    int getContentLength();
    long getContentLengthLong();
    String getContentType();
    ServletInputStream getInputStream() throws IOException;
    String getParameter(String name);
    BufferedReader getReader() throws IOException;
    String getRemoteAddr();
    String getRemoteHost();
    int getRemotePort();
}
