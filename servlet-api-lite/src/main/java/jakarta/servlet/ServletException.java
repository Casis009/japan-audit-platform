package jakarta.servlet;

public class ServletException extends Exception {
    private static final long serialVersionUID = 1L;
    public ServletException() { super(); }
    public ServletException(String message) { super(message); }
    public ServletException(String message, Throwable rootCause) { super(message, rootCause); }
    public ServletException(Throwable rootCause) { super(rootCause); }
}
