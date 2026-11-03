package jakarta.servlet;

import java.io.IOException;

public interface ReadListener extends java.util.EventListener {
    void onDataAvailable() throws IOException;
    void onAllDataRead() throws IOException;
    void onError(Throwable t);
}
