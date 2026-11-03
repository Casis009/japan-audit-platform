package jakarta.servlet;

import java.io.IOException;
import java.io.PrintWriter;

public interface ServletResponse {
    String getCharacterEncoding();
    String getContentType();
    ServletOutputStream getOutputStream() throws IOException;
    PrintWriter getWriter() throws IOException;
    void setCharacterEncoding(String charset);
    void setContentLength(int len);
    void setContentType(String type);
    void setBufferSize(int size);
    int getBufferSize();
    void flushBuffer() throws IOException;
    void reset();
    boolean isCommitted();
}
