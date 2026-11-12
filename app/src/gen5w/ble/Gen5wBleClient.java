package gen5w.ble;

import android.net.LocalSocket;
import android.net.LocalSocketAddress;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * General-purpose Bluetooth Low Energy Central & Scanner client SDK for Gen5W head units
 * (Android 4.4.2 KitKat, API 19).
 *
 * Connects to {@code @gen5w_ble} (or {@code @bvm02_ble} fallback) in {@code com.android.bluetooth}
 * with zero BVM02-specific assumptions. Supports concurrent BLE connections (`MULTICONN 1`),
 * optional ATT MTU negotiation (`REQUEST_MTU`), long characteristic reads (`READ_LONG_CHAR`),
 * and per-device notification routing.
 */
public final class Gen5wBleClient {

    public static final String PRIMARY_SOCKET = "gen5w_ble";
    public static final String FALLBACK_SOCKET = "bvm02_ble";
    private static final Charset UTF8 = Charset.forName("UTF-8");

    public interface LineChannel {
        void sendLine(String line);
        void close();
    }

    public interface Listener {
        void onSessionReady(String serverVersion);
        void onScanStateChanged(boolean scanning, String error);
        void onAdvertisement(String mac, int addrType, int rssi, Gen5wBleAdvRecord record);
        void onConnecting(String mac);
        void onConnected(String mac, Map<String, Integer> charPropsByUuid);
        void onDisconnected(String mac, int status, String reason);
        void onMtuChanged(String mac, int mtu, String error);
        void onCharacteristicRead(String mac, String uuid, byte[] value, String error);
        void onCharacteristicChanged(String mac, String uuid, byte[] value);
        void onCharacteristicWrite(String mac, String uuid, String error);
        void onSessionClosed(String reason);
    }

    public static abstract class SimpleListener implements Listener {
        @Override public void onSessionReady(String serverVersion) {}
        @Override public void onScanStateChanged(boolean scanning, String error) {}
        @Override public void onAdvertisement(String mac, int addrType, int rssi, Gen5wBleAdvRecord record) {}
        @Override public void onConnecting(String mac) {}
        @Override public void onConnected(String mac, Map<String, Integer> charPropsByUuid) {}
        @Override public void onDisconnected(String mac, int status, String reason) {}
        @Override public void onMtuChanged(String mac, int mtu, String error) {}
        @Override public void onCharacteristicRead(String mac, String uuid, byte[] value, String error) {}
        @Override public void onCharacteristicChanged(String mac, String uuid, byte[] value) {}
        @Override public void onCharacteristicWrite(String mac, String uuid, String error) {}
        @Override public void onSessionClosed(String reason) {}
    }

    private final Listener listener;
    private final AtomicBoolean open = new AtomicBoolean(false);
    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final List<String> txQueue = new ArrayList<String>();
    private final Object txLock = new Object();
    private volatile LocalSocket socket;
    private volatile LineChannel customChannel;

    public Gen5wBleClient(Listener listener) {
        this.listener = listener;
    }

    /**
     * Opens an asynchronous {@code STREAM_SESSION GENERIC} connection to {@code @gen5w_ble}
     * (falling back to {@code @bvm02_ble} if needed) and enables {@code MULTICONN 1}.
     */
    public void connectBridge() {
        if (open.get() || closed.get()) return;
        Thread rx = new Thread(new Runnable() {
            @Override
            public void run() {
                runSocketLoop();
            }
        }, "Gen5wBleClientRx");
        rx.setDaemon(true);
        rx.start();
    }

    /**
     * Attaches an in-memory {@link LineChannel} (used for deterministic JVM unit testing).
     */
    public void attachCustomChannel(LineChannel channel) {
        this.customChannel = channel;
        this.open.set(true);
        sendRaw("MULTICONN 1");
    }

    public boolean isBridgeOpen() {
        return open.get() && !closed.get();
    }

    public void startScan() {
        sendRaw("SCAN_START");
    }

    public void stopScan() {
        sendRaw("SCAN_STOP");
    }

    public void connectDevice(String mac) {
        connectDevice(mac, -1, "*");
    }

    public void connectDevice(String mac, int addrTypeHint, String serviceFilter) {
        if (mac == null) return;
        String cleanMac = mac.trim().toUpperCase(Locale.US);
        String filter = (serviceFilter == null || serviceFilter.trim().isEmpty()) ? "*" : serviceFilter.trim();
        sendRaw("CONNECT " + cleanMac + " " + addrTypeHint + " " + filter);
    }

    public void disconnectDevice(String mac) {
        if (mac == null || mac.trim().isEmpty()) {
            sendRaw("DISCONNECT ALL");
        } else {
            sendRaw("@" + mac.trim().toUpperCase(Locale.US) + " DISCONNECT");
        }
    }

    public void requestMtu(String mac, int desiredMtu) {
        sendTargeted(mac, "REQUEST_MTU " + desiredMtu);
    }

    public void setMaxServerMtu(String mac, int maxMtu) {
        sendTargeted(mac, "SET_MAX_MTU " + maxMtu);
    }

    public void protectCharacteristic(String mac, String uuid) {
        sendTargeted(mac, "PROTECT_CHAR " + Gen5wBleAdvRecord.normalizeUuid(uuid));
    }

    public void enableNotifications(String mac, String uuid) {
        sendTargeted(mac, "ENABLE_NOTIFY " + Gen5wBleAdvRecord.normalizeUuid(uuid));
    }

    public void disableNotifications(String mac, String uuid) {
        sendTargeted(mac, "DISABLE_NOTIFY " + Gen5wBleAdvRecord.normalizeUuid(uuid));
    }

    public void readCharacteristic(String mac, String uuid) {
        sendTargeted(mac, "READ_CHAR " + Gen5wBleAdvRecord.normalizeUuid(uuid));
    }

    public void readCharacteristicBlob(String mac, String uuid, int offset) {
        sendTargeted(mac, "READ_BLOB " + Gen5wBleAdvRecord.normalizeUuid(uuid) + " " + offset);
    }

    public void readLongCharacteristic(String mac, String uuid) {
        sendTargeted(mac, "READ_LONG_CHAR " + Gen5wBleAdvRecord.normalizeUuid(uuid));
    }

    public void writeCharacteristic(String mac, String uuid, byte[] payload, boolean withoutResponse) {
        String verb = withoutResponse ? "WRITE_CHAR_NR " : "WRITE_CHAR ";
        String hex = (payload == null || payload.length == 0) ? "-" : bytesToHex(payload);
        sendTargeted(mac, verb + Gen5wBleAdvRecord.normalizeUuid(uuid) + " " + hex);
    }

    public void close() {
        if (!closed.compareAndSet(false, true)) return;
        open.set(false);
        LineChannel ch = customChannel;
        if (ch != null) {
            try { ch.sendLine("QUIT"); } catch (Throwable ignored) {}
            try { ch.close(); } catch (Throwable ignored) {}
            return;
        }
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

    public void handleServerLine(String rawLine) {
        if (rawLine == null) return;
        String line = rawLine.trim();
        if (line.isEmpty()) return;

        if (line.startsWith("OK STREAM_READY")) {
            String ver = "unknown";
            int idx = line.indexOf("version=");
            if (idx >= 0) ver = line.substring(idx + 8).trim();
            if (listener != null) listener.onSessionReady(ver);
            return;
        }

        String mac = "";
        if (line.startsWith("@")) {
            int sp = line.indexOf(' ');
            if (sp > 1) {
                mac = line.substring(1, sp).toUpperCase(Locale.US);
                line = line.substring(sp + 1).trim();
            }
        }

        String[] p = line.split("\\s+");
        if (p.length == 0) return;
        String head = p[0];

        if ("SCAN_STATE".equals(head) && p.length >= 2) {
            boolean on = "1".equals(p[1]);
            String err = (p.length >= 3) ? p[2] : null;
            if (listener != null) listener.onScanStateChanged(on, err);
            return;
        }
        if ("ADV".equals(head) && p.length >= 5) {
            int addrType = parseIntSafe(p[2], 0);
            int rssi = parseIntSafe(p[3], -100);
            byte[] ad = hexToBytes(p[4]);
            if (listener != null) {
                listener.onAdvertisement(p[1], addrType, rssi, Gen5wBleAdvRecord.parse(ad));
            }
            return;
        }
        if ("CONN_STATE".equals(head) && p.length >= 3) {
            String st = p[1];
            String devMac = p[2];
            if ("CONNECTING".equals(st)) {
                if (listener != null) listener.onConnecting(devMac);
            } else if ("DISCONNECTED".equals(st)) {
                int code = 0;
                String reason = "DISCONNECTED";
                for (int i = 3; i < p.length; i++) {
                    if (p[i].startsWith("status=")) code = parseIntSafe(p[i].substring(7), 0);
                    else if (p[i].startsWith("reason=")) reason = p[i].substring(7);
                }
                if (listener != null) listener.onDisconnected(devMac, code, reason);
            }
            return;
        }
        if ("GATT_READY".equals(head) && p.length >= 3) {
            Map<String, Integer> specs = parseGattReadySpecs(p[2]);
            if (listener != null) listener.onConnected(p[1], specs);
            return;
        }
        if ("CHAR_NOTIFY".equals(head) && p.length >= 3) {
            byte[] val = hexToBytes(p[2]);
            if (listener != null && val != null) {
                listener.onCharacteristicChanged(mac, p[1], val);
            }
            return;
        }
        if ("OP_OK".equals(head) && p.length >= 2) {
            String op = p[1];
            if ("REQUEST_MTU".equals(op) && p.length >= 3) {
                if (listener != null) listener.onMtuChanged(mac, parseIntSafe(p[2], 23), null);
            } else if (("READ_CHAR".equals(op) || "READ_LONG_CHAR".equals(op)) && p.length >= 4) {
                if (listener != null) listener.onCharacteristicRead(mac, p[2], hexToBytes(p[3]), null);
            } else if ("READ_BLOB".equals(op) && p.length >= 5) {
                if (listener != null) listener.onCharacteristicRead(mac, p[2], hexToBytes(p[4]), null);
            } else if (("WRITE_CHAR".equals(op) || "WRITE_CHAR_NR".equals(op)) && p.length >= 3) {
                if (listener != null) listener.onCharacteristicWrite(mac, p[2], null);
            }
            return;
        }
        if ("OP_ERR".equals(head) && p.length >= 3) {
            String op = p[1];
            if ("REQUEST_MTU".equals(op)) {
                if (listener != null) listener.onMtuChanged(mac, 23, p[2]);
            } else if (("READ_CHAR".equals(op) || "READ_LONG_CHAR".equals(op) || "READ_BLOB".equals(op))
                    && p.length >= 4) {
                if (listener != null) listener.onCharacteristicRead(mac, p[2], null, p[3]);
            } else if (("WRITE_CHAR".equals(op) || "WRITE_CHAR_NR".equals(op)) && p.length >= 4) {
                if (listener != null) listener.onCharacteristicWrite(mac, p[2], p[3]);
            }
        }
    }

    private void sendTargeted(String mac, String cmd) {
        if (mac != null && !mac.trim().isEmpty()) {
            sendRaw("@" + mac.trim().toUpperCase(Locale.US) + " " + cmd);
        } else {
            sendRaw(cmd);
        }
    }

    private void sendRaw(String line) {
        if (line == null || closed.get()) return;
        LineChannel ch = customChannel;
        if (ch != null) {
            ch.sendLine(line);
            return;
        }
        synchronized (txLock) {
            if (txQueue.size() < 128) {
                txQueue.add(line);
                txLock.notifyAll();
            }
        }
    }

    private void runSocketLoop() {
        LocalSocket sock = null;
        String closeReason = "EOF";
        try {
            sock = connectEitherEndpoint();
            sock.setSoTimeout(4000);
            this.socket = sock;

            final OutputStream os = sock.getOutputStream();
            os.write("STREAM_SESSION GENERIC\n".getBytes(UTF8));
            os.flush();

            BufferedReader br = new BufferedReader(new InputStreamReader(sock.getInputStream(), UTF8));
            String banner = br.readLine();
            if (banner == null || !banner.startsWith("OK STREAM_READY")) {
                closeReason = (banner != null) ? banner : "EMPTY_HANDSHAKE";
                return;
            }

            sock.setSoTimeout(0);
            open.set(true);

            Thread writer = new Thread(new Runnable() {
                @Override
                public void run() {
                    runWriterLoop(os);
                }
            }, "Gen5wBleClientTx");
            writer.setDaemon(true);
            writer.start();

            sendRaw("MULTICONN 1");
            handleServerLine(banner);

            String line;
            while (!closed.get() && (line = br.readLine()) != null) {
                handleServerLine(line);
            }
        } catch (Throwable t) {
            closeReason = closed.get() ? "CLOSED" : (t.getClass().getSimpleName() + ": " + t.getMessage());
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

    private static LocalSocket connectEitherEndpoint() throws Exception {
        LocalSocket s1 = new LocalSocket();
        try {
            s1.connect(new LocalSocketAddress(PRIMARY_SOCKET, LocalSocketAddress.Namespace.ABSTRACT));
            return s1;
        } catch (Throwable firstErr) {
            try { s1.close(); } catch (Throwable ignored) {}
            LocalSocket s2 = new LocalSocket();
            s2.connect(new LocalSocketAddress(FALLBACK_SOCKET, LocalSocketAddress.Namespace.ABSTRACT));
            return s2;
        }
    }

    private void runWriterLoop(OutputStream os) {
        try {
            while (true) {
                String cmd;
                synchronized (txLock) {
                    while (txQueue.isEmpty() && !closed.get()) {
                        txLock.wait(1000L);
                    }
                    if (txQueue.isEmpty()) break;
                    cmd = txQueue.remove(0);
                }
                os.write((cmd + "\n").getBytes(UTF8));
                os.flush();
                if ("QUIT".equals(cmd)) break;
            }
        } catch (Throwable ignored) {}
    }

    public static Map<String, Integer> parseGattReadySpecs(String csv) {
        Map<String, Integer> map = new LinkedHashMap<String, Integer>();
        if (csv == null || csv.isEmpty() || "none".equals(csv)) {
            return Collections.unmodifiableMap(map);
        }
        String[] entries = csv.split(",");
        for (int i = 0; i < entries.length; i++) {
            int colon = entries[i].indexOf(':');
            if (colon > 0 && colon + 1 < entries[i].length()) {
                String u = Gen5wBleAdvRecord.normalizeUuid(entries[i].substring(0, colon));
                try {
                    int props = Integer.parseInt(entries[i].substring(colon + 1), 16);
                    map.put(u, Integer.valueOf(props));
                } catch (NumberFormatException ignored) {}
            }
        }
        return Collections.unmodifiableMap(map);
    }

    public static String bytesToHex(byte[] b) {
        if (b == null || b.length == 0) return "";
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (int i = 0; i < b.length; i++) {
            int v = b[i] & 0xFF;
            if (v < 0x10) sb.append('0');
            sb.append(Integer.toHexString(v));
        }
        return sb.toString();
    }

    public static byte[] hexToBytes(String hex) {
        if (hex == null) return new byte[0];
        String s = hex.trim();
        if ("-".equals(s) || s.isEmpty()) return new byte[0];
        if ((s.length() & 1) != 0) return null;
        int n = s.length() / 2;
        byte[] out = new byte[n];
        try {
            for (int i = 0; i < n; i++) {
                out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
            }
            return out;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static int parseIntSafe(String s, int fallback) {
        try {
            return Integer.parseInt(s.trim());
        } catch (Throwable t) {
            return fallback;
        }
    }
}
