package jakarta.servlet;

import java.io.InputStream;

public abstract class ServletInputStream extends InputStream {
    protected ServletInputStream() {}
    public abstract boolean isFinished();
    public abstract boolean isReady();
    public abstract void setReadListener(ReadListener readListener);
}
