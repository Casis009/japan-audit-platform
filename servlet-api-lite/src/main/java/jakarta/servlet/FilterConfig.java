package jakarta.servlet;

public interface FilterConfig {
    String getFilterName();
    String getInitParameter(String name);
}
