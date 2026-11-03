package jakarta.servlet;

import java.io.OutputStream;

public abstract class ServletOutputStream extends OutputStream {
    protected ServletOutputStream() {}
    public abstract boolean isReady();
    public abstract void setWriteListener(WriteListener writeListener);
}
