package bvm02.app;

import android.net.LocalSocket;
import android.net.LocalSocketAddress;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

/**
 * Abstract UNIX domain socket client ({@code @bvm02_ble}) connecting {@code bvm02.app}
 * directly to {@code bvm02.hook.BtBleBridgeServer} running inside {@code com.android.bluetooth}.
 */
public final class BtBleBridgeClient {

    public static final String SOCKET_NAME = "bvm02_ble";
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

    private BtBleBridgeClient() {}

    public static BridgeResponse sendCommand(String command) {
        List<String> lines = new ArrayList<String>();
        LocalSocket sock = null;
        try {
            sock = new LocalSocket();
            sock.connect(new LocalSocketAddress(SOCKET_NAME, LocalSocketAddress.Namespace.ABSTRACT));
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
