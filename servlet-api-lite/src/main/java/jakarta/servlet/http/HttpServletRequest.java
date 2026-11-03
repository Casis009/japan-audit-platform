package jakarta.servlet.http;

import jakarta.servlet.ServletRequest;

public interface HttpServletRequest extends ServletRequest {
    String getMethod();
    String getRequestURI();
    StringBuffer getRequestURL();
    String getQueryString();
    String getHeader(String name);
    java.security.Principal getUserPrincipal();
    String getContextPath();
}
