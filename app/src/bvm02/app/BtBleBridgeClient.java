package bvm02.app;

import android.net.LocalSocket;
import android.net.LocalSocketAddress;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Abstract UNIX domain socket client ({@code @bvm02_ble}) connecting {@code bvm02.app}
 * directly to {@code bvm02.hook.BtBleBridgeServer} running inside {@code com.android.bluetooth}.
 *
 * Supports both one-shot diagnostic queries ({@code PING}, {@code CAPS}, {@code BRIDGE_STATUS})
 * and full-duplex asynchronous BLE GATT sessions ({@code STREAM_SESSION}).
 */
public final class BtBleBridgeClient {

    public static final String SOCKET_NAME = "bvm02_ble";
    public static final String GEN5W_SOCKET_NAME = "gen5w_ble";
    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static final int TIMEOUT_MS = 2500;

    public static final class BridgeResponse {
        public final boolean connected;
        public final List<String> lines;
        public final String error;

        public BridgeResponse(boolean connected, List<String> lines, String error) {
            this.connected = connected;
            this.lines = lines;
            this.error = error;
        }
    }

    public interface StreamListener {
        void onSessionReady(String bannerLine);
        void onSessionLine(String line);
        void onSessionClosed(String reason);
    }

    public static final class StreamSession {
        private final StreamListener listener;
        private final AtomicBoolean open = new AtomicBoolean(false);
        private final AtomicBoolean closed = new AtomicBoolean(false);
        private final List<String> txQueue = new ArrayList<String>();
        private final Object txLock = new Object();
        private volatile LocalSocket socket;

        StreamSession(StreamListener listener) {
            this.listener = listener;
        }

        void start() {
            Thread readerThread = new Thread(new Runnable() {
                @Override
                public void run() {
                    runSessionIo();
                }
            }, "Bvm02BridgeRx");
            readerThread.setDaemon(true);
            readerThread.start();
        }

        public boolean isOpen() {
            return open.get() && !closed.get();
        }

        public void sendLine(String cmd) {
            if (cmd == null || closed.get()) return;
            synchronized (txLock) {
                if (txQueue.size() < 96) {
                    txQueue.add(cmd);
                    txLock.notifyAll();
                }
            }
        }

        public void close() {
            if (!closed.compareAndSet(false, true)) return;
            open.set(false);
            synchronized (txLock) {
                txQueue.clear();
                txQueue.add("QUIT");
                txLock.notifyAll();
            }
            LocalSocket s = socket;
            if (s != null) {
                try { s.shutdownInput(); } catch (Throwable ignored) {}
                try { s.close(); } catch (Throwable ignored) {}
            }
        }

        private void runSessionIo() {
            LocalSocket sock = null;
            Thread writerThread = null;
            String closeReason = "EOF";
            try {
                sock = connectBridgeSocket();
                sock.setSoTimeout(4000);
                this.socket = sock;

                final OutputStream os = sock.getOutputStream();
                os.write("STREAM_SESSION BVM02\n".getBytes(UTF8));
                os.flush();

                BufferedReader br = new BufferedReader(new InputStreamReader(sock.getInputStream(), UTF8));
                String first = br.readLine();
                if (first == null) {
                    closeReason = "Empty handshake from @bvm02_ble";
                    return;
                }
                if (!first.startsWith("OK STREAM_READY")) {
                    closeReason = first;
                    return;
                }

                sock.setSoTimeout(0);
                open.set(true);

                writerThread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        runWriterLoop(os);
                    }
                }, "Bvm02BridgeTx");
                writerThread.setDaemon(true);
                writerThread.start();

                if (listener != null) {
                    listener.onSessionReady(first);
                }

                String line;
                while (!closed.get() && (line = br.readLine()) != null) {
                    if (listener != null && !line.isEmpty()) {
                        listener.onSessionLine(line);
                    }
                }
            } catch (Throwable t) {
                if (!closed.get()) {
                    closeReason = t.getClass().getSimpleName() + ": " + t.getMessage();
                } else {
                    closeReason = "CLOSED";
                }
            } finally {
                open.set(false);
                closed.set(true);
                synchronized (txLock) {
                    txLock.notifyAll();
                }
                if (sock != null) {
                    try { sock.close(); } catch (Throwable ignored) {}
                }
                if (listener != null) {
                    listener.onSessionClosed(closeReason);
                }
            }
        }

        private void runWriterLoop(OutputStream os) {
            try {
                while (true) {
                    String nextCmd;
                    synchronized (txLock) {
                        while (txQueue.isEmpty() && !closed.get()) {
                            txLock.wait(1000L);
                        }
                        if (txQueue.isEmpty()) {
                            break;
                        }
                        nextCmd = txQueue.remove(0);
                    }
                    os.write((nextCmd + "\n").getBytes(UTF8));
                    os.flush();
                    if ("QUIT".equals(nextCmd)) {
                        break;
                    }
                }
            } catch (Throwable ignored) {}
        }
    }

    private BtBleBridgeClient() {}

    public static StreamSession openStreamSession(StreamListener listener) {
        StreamSession session = new StreamSession(listener);
        session.start();
        return session;
    }

    static LocalSocket connectBridgeSocket() throws Exception {
        LocalSocket s1 = new LocalSocket();
        try {
            s1.connect(new LocalSocketAddress(SOCKET_NAME, LocalSocketAddress.Namespace.ABSTRACT));
            return s1;
        } catch (Throwable firstErr) {
            try { s1.close(); } catch (Throwable ignored) {}
            LocalSocket s2 = new LocalSocket();
            s2.connect(new LocalSocketAddress(GEN5W_SOCKET_NAME, LocalSocketAddress.Namespace.ABSTRACT));
            return s2;
        }
    }

    public static BridgeResponse sendCommand(String command) {
        List<String> lines = new ArrayList<String>();
        LocalSocket sock = null;
        try {
            sock = connectBridgeSocket();
            sock.setSoTimeout(TIMEOUT_MS);

            OutputStream os = sock.getOutputStream();
            os.write((command + "\n").getBytes(UTF8));
            os.flush();

            BufferedReader br = new BufferedReader(new InputStreamReader(sock.getInputStream(), UTF8));
            String line;
            while ((line = br.readLine()) != null && lines.size() < 200) {
                if ("END".equals(line)) {
                    break;
                }
                lines.add(line);
            }
            return new BridgeResponse(true, lines, null);
        } catch (Throwable t) {
            return new BridgeResponse(false, lines, t.getClass().getSimpleName() + ": " + t.getMessage());
        } finally {
            if (sock != null) {
                try { sock.close(); } catch (Throwable ignored) {}
            }
        }
    }
}
