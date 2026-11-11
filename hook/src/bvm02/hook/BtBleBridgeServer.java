package bvm02.hook;

import android.net.Credentials;
import android.net.LocalServerSocket;
import android.net.LocalSocket;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import hmgapi.hook.LoadedApp;
import hmgapi.hook.ModContext;

/**
 * Lightweight, zero-disk-I/O abstract UNIX domain socket server ({@code @bvm02_ble})
 * running strictly inside {@code com.android.bluetooth}.
 */
public final class BtBleBridgeServer {

    public static final String SOCKET_NAME = "bvm02_ble";
    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static final AtomicBoolean STARTED = new AtomicBoolean(false);
    private static volatile boolean modEnabled = true;

    private BtBleBridgeServer() {}

    public static void setModEnabled(boolean enabled) {
        modEnabled = enabled;
        if (!enabled) {
            BleGattSessionManager.getInstance().onModDisabled();
            BtNativeBridge.shutdown();
        }
    }

    public static void startIfNeeded(final ModContext mod, final LoadedApp app) {
        if (!STARTED.compareAndSet(false, true)) {
            return;
        }
        modEnabled = (mod == null) || mod.enabled();
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                runAcceptLoop(mod, app);
            }
        }, "Bvm02BleBridge");
        t.setDaemon(true);
        t.setPriority(Thread.NORM_PRIORITY - 1);
        t.start();
    }

    private static void runAcceptLoop(final ModContext mod, final LoadedApp app) {
        LocalServerSocket server = null;
        try {
            server = new LocalServerSocket(SOCKET_NAME);
            if (mod != null) {
                mod.log("BtBleBridgeServer v" + BtHookEntry.HOOK_VERSION + " listening on abstract @" + SOCKET_NAME
                        + " in " + (app != null ? app.processName : "com.android.bluetooth"));
            }
            while (true) {
                final LocalSocket client = server.accept();
                if (client == null) continue;
                Thread clientThread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            handleClient(mod, app, client);
                        } catch (Throwable clientErr) {
                            if (mod != null) {
                                mod.log("BtBleBridgeServer client err: " + clientErr);
                            }
                        } finally {
                            try { client.close(); } catch (Throwable ignored) {}
                        }
                    }
                }, "Bvm02BleClient");
                clientThread.setDaemon(true);
                clientThread.start();
            }
        } catch (Throwable bindErr) {
            STARTED.set(false);
            if (mod != null) {
                mod.log("BtBleBridgeServer bind @" + SOCKET_NAME + " failed: " + bindErr);
            }
        } finally {
            if (server != null) {
                try { server.close(); } catch (Throwable ignored) {}
            }
        }
    }

    private static void handleClient(ModContext mod, LoadedApp app, LocalSocket client) throws Exception {
        client.setSoTimeout(2500);
        Credentials creds = client.getPeerCredentials();
        int uid = (creds != null) ? creds.getUid() : -1;
        if (uid < 0 || (uid != 0 && uid != 1000 && uid != 1002 && uid < 10000)) {
            return;
        }

        BufferedReader reader = new BufferedReader(new InputStreamReader(client.getInputStream(), UTF8));
        OutputStream os = client.getOutputStream();
        String cmd = reader.readLine();
        if (cmd == null) {
            return;
        }
        cmd = cmd.trim();
        boolean isEnabled = modEnabled && (mod == null || mod.enabled());

        if ("STREAM_SESSION".equals(cmd)) {
            if (!isEnabled) {
                os.write("ERR MOD_DISABLED\n".getBytes(UTF8));
                os.flush();
                return;
            }
            if (!BtNativeBridge.ensureInitialized(mod, app)) {
                String status = BtNativeBridge.describeStatus(mod, app);
                os.write(("ERR BRIDGE_INIT_FAILED " + status + "\n").getBytes(UTF8));
                os.flush();
                return;
            }
            client.setSoTimeout(0);
            BleGattSessionManager.getInstance().runStreamSession(mod, reader, os);
            return;
        }

        StringBuilder resp = new StringBuilder(512);
        if ("PING".equals(cmd)) {
            resp.append("OK PONG version=")
                    .append(BtHookEntry.HOOK_VERSION)
                    .append(" pid=")
                    .append(android.os.Process.myPid())
                    .append(" uid=")
                    .append(android.os.Process.myUid())
                    .append(" enabled=")
                    .append(isEnabled)
                    .append('\n');
        } else if ("BRIDGE_STATUS".equals(cmd)) {
            if (!isEnabled) {
                resp.append("BRIDGE: status=MOD_DISABLED\n");
            } else {
                resp.append("BRIDGE: ").append(BtNativeBridge.describeStatus(mod, app)).append('\n');
            }
        } else if ("CAPS".equals(cmd)) {
            if (!isEnabled) {
                resp.append("CAPS: status=MOD_DISABLED\n");
            } else {
                List<String> lines = BtMemInspector.inspectLiveCapabilities(mod);
                for (int i = 0; i < lines.size(); i++) {
                    resp.append("CAPS: ").append(lines.get(i)).append('\n');
                }
                resp.append("CAPS: jni_bridge=").append(BtNativeBridge.describeStatus(mod, app)).append('\n');
            }
        } else {
            resp.append("ERR UNKNOWN_CMD\n");
        }
        resp.append("END\n");
        os.write(resp.toString().getBytes(UTF8));
        os.flush();
    }
}
