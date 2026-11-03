package jakarta.servlet.http;

import jakarta.servlet.ServletResponse;

public interface HttpServletResponse extends ServletResponse {
    int getStatus();
    void setStatus(int sc);
    void setHeader(String name, String value);
    void addHeader(String name, String value);
    String getHeader(String name);
}
