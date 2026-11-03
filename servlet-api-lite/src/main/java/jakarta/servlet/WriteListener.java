package jakarta.servlet;

import java.io.IOException;

public interface WriteListener extends java.util.EventListener {
    void onWritePossible() throws IOException;
    void onError(Throwable t);
}
