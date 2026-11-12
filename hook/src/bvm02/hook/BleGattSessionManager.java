package bvm02.hook;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import hmgapi.hook.ModContext;

/**
 * Coexistence-safe, multi-client, multi-connection Bluetooth 4.x HCI LE Scanner,
 * L2CAP Fragmenter/Reassembler, and General-Purpose ATT/GATT Central running inside
 * {@code com.android.bluetooth} over {@link BtNativeBridge}.
 *
 * Designed specifically for Gen5W head units where {@code GattService} is manifest-disabled
 * and {@code bplus.default.so} is compiled with {@code BLE_INCLUDED=FALSE}, while preserving
 * 100% of simultaneous Classic Bluetooth ({@code HFP} / {@code A2DP}) traffic.
 *
 * Supports:
 * - Concurrent IPC stream clients across {@code @gen5w_ble} (generic GATT discovery) and
 *   {@code @bvm02_ble} (BVM02 backwards-compatible defaults).
 * - Multiple simultaneous BLE peripheral connections (up to {@link #MAX_CONCURRENT_CONNECTIONS}),
 *   both across separate apps and within a single app via {@code MULTICONN 1} + {@code @<MAC>}.
 * - Optional ATT MTU negotiation ({@code REQUEST_MTU} / {@code SET_MAX_MTU} up to 517 bytes),
 *   automatic outbound LE ACL fragmentation across 27-byte BT 4.0 controller buffers, and
 *   ATT long attribute reads ({@code READ_BLOB} / {@code READ_LONG_CHAR}).
 */
public final class BleGattSessionManager implements BtNativeBridge.PacketSink {

    private static final Charset UTF8 = Charset.forName("UTF-8");

    public static final int MAX_CONCURRENT_CONNECTIONS        = 4;
    public static final int DEFAULT_ATT_MTU                   = 23;
    public static final int MAX_SUPPORTED_ATT_MTU             = 517;
    public static final int DEFAULT_LE_ACL_MAX_LEN            = 27;
    public static final int MAX_REASSEMBLED_L2CAP_LEN         = 520;

    // HCI Opcodes
    public static final int HCI_DISCONNECT                    = 0x0406;
    public static final int HCI_SET_EVENT_MASK                = 0x0C01;
    public static final int HCI_WRITE_LE_HOST_SUPPORT         = 0x0C6D;
    public static final int HCI_LE_SET_EVENT_MASK             = 0x2001;
    public static final int HCI_LE_READ_BUFFER_SIZE           = 0x2002;
    public static final int HCI_LE_SET_SCAN_PARAMETERS        = 0x200B;
    public static final int HCI_LE_SET_SCAN_ENABLE            = 0x200C;
    public static final int HCI_LE_CREATE_CONNECTION          = 0x200D;
    public static final int HCI_LE_CREATE_CONNECTION_CANCEL   = 0x200E;
    public static final int HCI_LE_CONNECTION_UPDATE          = 0x2013;

    // L2CAP Fixed CIDs
    public static final int L2CAP_CID_ATT                     = 0x0004;
    public static final int L2CAP_CID_LE_SIGNALING            = 0x0005;

    // ATT Opcodes
    public static final int ATT_ERROR_RSP                     = 0x01;
    public static final int ATT_EXCHANGE_MTU_REQ              = 0x02;
    public static final int ATT_EXCHANGE_MTU_RSP              = 0x03;
    public static final int ATT_FIND_INFO_REQ                 = 0x04;
    public static final int ATT_FIND_INFO_RSP                 = 0x05;
    public static final int ATT_READ_BY_TYPE_REQ              = 0x08;
    public static final int ATT_READ_BY_TYPE_RSP              = 0x09;
    public static final int ATT_READ_REQ                      = 0x0A;
    public static final int ATT_READ_RSP                      = 0x0B;
    public static final int ATT_READ_BLOB_REQ                 = 0x0C;
    public static final int ATT_READ_BLOB_RSP                 = 0x0D;
    public static final int ATT_READ_BY_GROUP_TYPE_REQ        = 0x10;
    public static final int ATT_READ_BY_GROUP_TYPE_RSP        = 0x11;
    public static final int ATT_WRITE_REQ                     = 0x12;
    public static final int ATT_WRITE_RSP                     = 0x13;
    public static final int ATT_HANDLE_VALUE_NTF              = 0x1B;
    public static final int ATT_HANDLE_VALUE_IND              = 0x1D;
    public static final int ATT_HANDLE_VALUE_CFM              = 0x1E;
    public static final int ATT_WRITE_CMD                     = 0x52;

    public interface LineEmitter {
        void emitLine(String line);
    }

    public static final class AdvReportItem {
        public final int eventType;
        public final int addrType;
        public final String mac;
        public final byte[] data;
        public final int rssi;

        public AdvReportItem(int eventType, int addrType, String mac, byte[] data, int rssi) {
            this.eventType = eventType;
            this.addrType = addrType;
            this.mac = mac;
            this.data = data;
            this.rssi = rssi;
        }
    }

    public static final class DiscoveredChar {
        public final String shortUuid;
        public final int declHandle;
        public final int valHandle;
        public final int props;
        public int endHandle;
        public int cccdHandle;
        public volatile boolean notifySubscribed;

        public DiscoveredChar(String shortUuid, int declHandle, int valHandle, int props) {
            this.shortUuid = shortUuid;
            this.declHandle = declHandle;
            this.valHandle = valHandle;
            this.props = props;
            this.endHandle = valHandle;
            this.cccdHandle = 0;
            this.notifySubscribed = false;
        }
    }

    public static final class ClientSession {
        public final int sessionId;
        public final LineEmitter emitter;
        public final boolean genericDefault;
        volatile OutputStream socketOut;
        volatile boolean active = true;
        volatile boolean multiConnMode = false;
        volatile boolean scanning = false;
        volatile boolean cancelConnectRequested = false;
        volatile int defaultServerMtu = DEFAULT_ATT_MTU;
        volatile String primaryMac = "";
        final Map<String, LeConnection> ownedByMac = new LinkedHashMap<String, LeConnection>();

        ClientSession(int sessionId, LineEmitter emitter, boolean genericDefault, OutputStream socketOut) {
            this.sessionId = sessionId;
            this.emitter = emitter;
            this.genericDefault = genericDefault;
            this.socketOut = socketOut;
        }

        void emitRaw(String line) {
            if (!active || emitter == null) return;
            emitter.emitLine(line);
        }

        void emitForConn(String mac, String body) {
            if (!active || emitter == null) return;
            if (multiConnMode && mac != null && !mac.isEmpty()) {
                emitter.emitLine("@" + mac + " " + body);
            } else {
                emitter.emitLine(body);
            }
        }
    }

    private static final class LeConnection {
        final int handle;
        final String mac;
        final ClientSession owner;
        final Object attLock = new Object();
        final Map<String, DiscoveredChar> charByUuid = new LinkedHashMap<String, DiscoveredChar>();
        final Map<Integer, DiscoveredChar> charByValHandle = new LinkedHashMap<Integer, DiscoveredChar>();
        final Set<String> protectedWriteUuids = new HashSet<String>();

        volatile boolean closed = false;
        volatile int attMtu = DEFAULT_ATT_MTU;
        volatile int preferredServerMtu = DEFAULT_ATT_MTU;

        // Per-handle L2CAP reassembly state (protected by hciLock)
        ByteArrayOutputStream l2capReassembly = null;
        int l2capExpectedLen = 0;
        int l2capCurrentCid = 0;

        // Per-handle synchronous ATT request/response waiter (protected by attLock)
        boolean attAwaitingResponse = false;
        byte[] pendingAttResponse = null;

        LeConnection(int handle, String mac, ClientSession owner, int initialServerMtu) {
            this.handle = handle;
            this.mac = mac;
            this.owner = owner;
            this.preferredServerMtu = clampMtu(initialServerMtu);
        }
    }

    private static final class CachedAdvState {
        int addrType;
        byte[] advData = new byte[0];
        byte[] scanRspData = new byte[0];
        long updatedMs;
    }

    private static final BleGattSessionManager INSTANCE =
            new BleGattSessionManager(BtNativeBridge.getLiveTransport());

    static {
        BtNativeBridge.setPacketSink(INSTANCE);
    }

    public static BleGattSessionManager getInstance() {
        return INSTANCE;
    }

    private final BtNativeBridge.Transport transport;
    private final Object hciLock = new Object();
    private final Object scanOpLock = new Object();
    private final Object connectOpLock = new Object();
    private final AtomicInteger nextSessionId = new AtomicInteger(1);

    private final List<ClientSession> activeSessions = new CopyOnWriteArrayList<ClientSession>();
    private final Map<LineEmitter, ClientSession> directSessions =
            new LinkedHashMap<LineEmitter, ClientSession>();

    // Active BLE connections indexed by handle and MAC (protected by hciLock)
    private final Map<Integer, LeConnection> connectionsByHandle =
            new LinkedHashMap<Integer, LeConnection>();
    private final Map<String, LeConnection> connectionsByMac =
            new LinkedHashMap<String, LeConnection>();

    // Cached advertising address types & merged AD payloads across scans
    private final Map<String, CachedAdvState> advCache = new LinkedHashMap<String, CachedAdvState>();

    // HCI synchronous command waiter state (protected by hciLock)
    private int waitingOpcode = -1;
    private byte[] completedCmdEvent = null;
    private int cmdStatusValue = -1;

    // Controller & shared LE ACL credit state
    private boolean controllerInitialized = false;
    private int controllerLeAclMaxLen = DEFAULT_LE_ACL_MAX_LEN;
    private int maxLeAclCredits = 2;
    private int inflightLeAclPkts = 0;
    private volatile boolean hardwareScanning = false;
    private volatile boolean connectInProgress = false;
    private byte[] pendingLeConnEvent = null;

    public BleGattSessionManager(BtNativeBridge.Transport transport) {
        this.transport = transport;
    }

    public String describeActiveSessions() {
        int sessCount = activeSessions.size();
        StringBuilder sb = new StringBuilder(128);
        sb.append("sessions=").append(sessCount);
        synchronized (hciLock) {
            sb.append(" connections=").append(connectionsByHandle.size())
                    .append('/').append(MAX_CONCURRENT_CONNECTIONS)
                    .append(" leAclMaxLen=").append(controllerLeAclMaxLen)
                    .append(" credits=").append(maxLeAclCredits - inflightLeAclPkts)
                    .append('/').append(maxLeAclCredits)
                    .append(" hwScan=").append(hardwareScanning);
            if (!connectionsByHandle.isEmpty()) {
                sb.append(" links=[");
                boolean first = true;
                for (LeConnection c : connectionsByHandle.values()) {
                    if (!first) sb.append(',');
                    first = false;
                    sb.append(c.mac)
                            .append("@0x").append(Integer.toHexString(c.handle))
                            .append("(mtu=").append(c.attMtu).append(')');
                }
                sb.append(']');
            }
        }
        return sb.toString();
    }

    public void onModDisabled() {
        List<ClientSession> snapshot = new ArrayList<ClientSession>(activeSessions);
        for (int i = 0; i < snapshot.size(); i++) {
            ClientSession s = snapshot.get(i);
            s.cancelConnectRequested = true;
            s.scanning = false;
        }
        synchronized (hciLock) {
            hciLock.notifyAll();
        }
        for (int i = 0; i < snapshot.size(); i++) {
            teardownSession(snapshot.get(i));
        }
        synchronized (directSessions) {
            directSessions.clear();
        }
        transport.setFilterState(false, BtNativeBridge.HANDLE_OP_CLEAR_ALL);
    }

    /**
     * Backwards-compatible entry point (defaults to BVM02 profile rules).
     */
    public void runStreamSession(final ModContext mod, BufferedReader reader, final OutputStream os) {
        runStreamSession(mod, reader, os, false);
    }

    /**
     * Runs a full-duplex persistent BLE control & notification stream over {@code @gen5w_ble}
     * ({@code genericDefault = true}) or {@code @bvm02_ble} ({@code genericDefault = false}).
     * Multiple client sessions can run concurrently without preempting one another.
     */
    public void runStreamSession(
            final ModContext mod,
            BufferedReader reader,
            final OutputStream os,
            final boolean genericDefault) {
        final Object writeLock = new Object();
        final ClientSession[] sessionRef = new ClientSession[1];
        final LineEmitter emitter = new LineEmitter() {
            @Override
            public void emitLine(String line) {
                synchronized (writeLock) {
                    ClientSession s = sessionRef[0];
                    if (s == null || !s.active) return;
                    try {
                        os.write((line + "\n").getBytes(UTF8));
                        os.flush();
                    } catch (Throwable ignored) {}
                }
            }
        };

        final ClientSession session = new ClientSession(
                nextSessionId.getAndIncrement(), emitter, genericDefault, os);
        sessionRef[0] = session;
        activeSessions.add(session);
        transport.setFilterState(true, BtNativeBridge.HANDLE_OP_KEEP);

        final List<String> cmdQueue = new ArrayList<String>();
        final Object queueLock = new Object();
        final boolean[] readerDone = new boolean[]{false};

        Thread worker = new Thread(new Runnable() {
            @Override
            public void run() {
                while (true) {
                    String cmdLine;
                    synchronized (queueLock) {
                        while (cmdQueue.isEmpty() && !readerDone[0]) {
                            try {
                                queueLock.wait(500L);
                            } catch (InterruptedException ie) {
                                return;
                            }
                        }
                        if (cmdQueue.isEmpty() && readerDone[0]) {
                            break;
                        }
                        cmdLine = cmdQueue.remove(0);
                    }
                    try {
                        executeSessionCommand(mod, session, cmdLine);
                    } catch (Throwable cmdErr) {
                        if (mod != null) {
                            mod.log("BleGattSessionManager cmd err (" + cmdLine + "): " + cmdErr);
                        }
                        session.emitRaw("ERR CMD_EXCEPTION " + sanitizeToken(cmdErr.getMessage()));
                    }
                }
            }
        }, "Gen5wBleSession-" + session.sessionId);
        worker.setDaemon(true);
        worker.start();

        session.emitRaw("OK STREAM_READY version=" + BtHookEntry.HOOK_VERSION);

        try {
            String raw;
            while ((raw = reader.readLine()) != null) {
                String trimmed = raw.trim();
                if (trimmed.isEmpty()) continue;
                if ("QUIT".equals(trimmed)) {
                    session.cancelConnectRequested = true;
                    synchronized (hciLock) {
                        hciLock.notifyAll();
                    }
                    wakeAllSessionAttLocks(session);
                    break;
                }
                if (trimmed.equals("DISCONNECT") || trimmed.endsWith(" DISCONNECT")
                        || trimmed.startsWith("DISCONNECT ")) {
                    session.cancelConnectRequested = true;
                    synchronized (hciLock) {
                        hciLock.notifyAll();
                    }
                    wakeAllSessionAttLocks(session);
                }
                synchronized (queueLock) {
                    if (cmdQueue.size() < 128) {
                        cmdQueue.add(trimmed);
                        queueLock.notifyAll();
                    }
                }
            }
        } catch (Throwable ignored) {
        } finally {
            session.cancelConnectRequested = true;
            synchronized (hciLock) {
                hciLock.notifyAll();
            }
            wakeAllSessionAttLocks(session);
            synchronized (queueLock) {
                readerDone[0] = true;
                cmdQueue.clear();
                queueLock.notifyAll();
            }
            try {
                worker.join(2500L);
            } catch (InterruptedException ignored) {}

            teardownSession(session);
        }
    }

    /**
     * Creates an in-process session handle (used by unit tests and embedded callers).
     */
    public ClientSession openDirectSession(LineEmitter emitter, boolean genericDefault) {
        ClientSession s = new ClientSession(
                nextSessionId.getAndIncrement(), emitter, genericDefault, null);
        activeSessions.add(s);
        synchronized (directSessions) {
            if (emitter != null) {
                directSessions.put(emitter, s);
            }
        }
        transport.setFilterState(true, BtNativeBridge.HANDLE_OP_KEEP);
        return s;
    }

    public void closeDirectSession(ClientSession session) {
        if (session == null) return;
        synchronized (directSessions) {
            if (session.emitter != null && directSessions.get(session.emitter) == session) {
                directSessions.remove(session.emitter);
            }
        }
        teardownSession(session);
    }

    /**
     * Backwards-compatible command entry point (auto-associates a BVM02-mode {@link ClientSession}
     * with {@code emitter} if not already opened).
     */
    public void executeSessionCommand(ModContext mod, String line, LineEmitter emitter) {
        ClientSession session;
        synchronized (directSessions) {
            session = directSessions.get(emitter);
            if (session == null || !session.active) {
                session = new ClientSession(
                        nextSessionId.getAndIncrement(), emitter, false, null);
                directSessions.put(emitter, session);
                activeSessions.add(session);
                transport.setFilterState(true, BtNativeBridge.HANDLE_OP_KEEP);
            }
        }
        executeSessionCommand(mod, session, line);
    }

    public void executeSessionCommand(ModContext mod, ClientSession session, String line) {
        if (session == null || line == null) return;
        String trimmed = line.trim();
        if (trimmed.isEmpty()) return;
        String[] rawParts = trimmed.split("\\s+");
        if (rawParts.length == 0) return;

        String explicitMac = null;
        String[] parts = rawParts;
        if (rawParts[0].startsWith("@") && rawParts[0].length() > 1) {
            explicitMac = rawParts[0].substring(1).toUpperCase(Locale.US);
            if (rawParts.length < 2) {
                session.emitRaw("ERR MISSING_CMD_AFTER_TARGET");
                return;
            }
            parts = new String[rawParts.length - 1];
            System.arraycopy(rawParts, 1, parts, 0, parts.length);
        }

        String verb = parts[0];

        if ("PING".equals(verb)) {
            session.emitRaw("PONG");
            return;
        }
        if ("MULTICONN".equals(verb)) {
            boolean en = parts.length < 2 || !"0".equals(parts[1]);
            session.multiConnMode = en;
            session.emitRaw("OP_OK MULTICONN " + (en ? "1" : "0"));
            return;
        }
        if ("SET_MAX_MTU".equals(verb) && parts.length >= 2) {
            int mtu = parsePositiveInt(parts[1], DEFAULT_ATT_MTU);
            int clamped = clampMtu(mtu);
            session.defaultServerMtu = clamped;
            LeConnection active = resolveSessionConnection(session, explicitMac);
            if (active != null) {
                active.preferredServerMtu = clamped;
            }
            session.emitForConn(explicitMac, "OP_OK SET_MAX_MTU " + clamped);
            return;
        }
        if ("SCAN_START".equals(verb)) {
            startBleScan(mod, session);
            return;
        }
        if ("SCAN_STOP".equals(verb)) {
            stopBleScan(mod, session, true);
            return;
        }
        if ("CONNECT".equals(verb) && parts.length >= 2) {
            String mac = parts[1].toUpperCase(Locale.US);
            int addrTypeHint = -1;
            if (parts.length >= 3) {
                try {
                    addrTypeHint = Integer.parseInt(parts[2]);
                } catch (NumberFormatException ignored) {}
            }
            String serviceFilter = null;
            if (parts.length >= 4) {
                serviceFilter = parts[3];
            }
            connectAndDiscover(mod, session, mac, addrTypeHint, serviceFilter);
            return;
        }
        if ("DISCONNECT".equals(verb)) {
            String target = explicitMac;
            if (target == null && parts.length >= 2) {
                target = parts[1].toUpperCase(Locale.US);
            }
            if ("ALL".equals(target) || "*".equals(target)) {
                disconnectAllSessionLinks(session, true, "USER_REQUESTED");
            } else {
                LeConnection conn = resolveSessionConnection(session, target);
                if (conn != null) {
                    disconnectConnection(conn, true, "USER_REQUESTED");
                } else if (target != null && !target.isEmpty()) {
                    session.emitForConn(target, "CONN_STATE DISCONNECTED " + target + " status=0 reason=NOT_CONNECTED");
                }
            }
            return;
        }
        if ("REQUEST_MTU".equals(verb) && parts.length >= 2) {
            int desiredMtu = parsePositiveInt(parts[1], DEFAULT_ATT_MTU);
            handleRequestMtu(session, explicitMac, desiredMtu);
            return;
        }
        if ("PROTECT_CHAR".equals(verb) && parts.length >= 2) {
            String uuid = normalizeUuidKey(parts[1]);
            handleProtectChar(session, explicitMac, uuid);
            return;
        }
        if ("ENABLE_NOTIFY".equals(verb) && parts.length >= 2) {
            String uuid = normalizeUuidKey(parts[1]);
            handleEnableNotify(session, explicitMac, uuid);
            return;
        }
        if ("DISABLE_NOTIFY".equals(verb) && parts.length >= 2) {
            String uuid = normalizeUuidKey(parts[1]);
            handleDisableNotify(session, explicitMac, uuid);
            return;
        }
        if ("READ_CHAR".equals(verb) && parts.length >= 2) {
            String uuid = normalizeUuidKey(parts[1]);
            handleReadChar(session, explicitMac, uuid);
            return;
        }
        if ("READ_BLOB".equals(verb) && parts.length >= 3) {
            String uuid = normalizeUuidKey(parts[1]);
            int offset = parsePositiveInt(parts[2], 0);
            handleReadBlob(session, explicitMac, uuid, offset);
            return;
        }
        if ("READ_LONG_CHAR".equals(verb) && parts.length >= 2) {
            String uuid = normalizeUuidKey(parts[1]);
            handleReadLongChar(session, explicitMac, uuid);
            return;
        }
        if ("WRITE_CHAR".equals(verb) && parts.length >= 3) {
            String uuid = normalizeUuidKey(parts[1]);
            byte[] payload = hexToBytes(parts[2]);
            handleWriteChar(session, explicitMac, uuid, payload, false);
            return;
        }
        if ("WRITE_CHAR_NR".equals(verb) && parts.length >= 3) {
            String uuid = normalizeUuidKey(parts[1]);
            byte[] payload = hexToBytes(parts[2]);
            handleWriteChar(session, explicitMac, uuid, payload, true);
            return;
        }

        session.emitForConn(explicitMac, "ERR UNKNOWN_SESSION_CMD " + sanitizeToken(verb));
    }

    // ================= SESSION & CONNECTION LIFECYCLE =================

    private void wakeAllSessionAttLocks(ClientSession session) {
        List<LeConnection> list;
        synchronized (session.ownedByMac) {
            list = new ArrayList<LeConnection>(session.ownedByMac.values());
        }
        for (int i = 0; i < list.size(); i++) {
            LeConnection c = list.get(i);
            synchronized (c.attLock) {
                c.attLock.notifyAll();
            }
        }
    }

    private void teardownSession(ClientSession session) {
        if (session == null) return;
        session.active = false;
        session.scanning = false;
        session.cancelConnectRequested = true;
        activeSessions.remove(session);

        syncHardwareScanState(null);
        disconnectAllSessionLinks(session, false, "SESSION_CLOSED");

        OutputStream out = session.socketOut;
        session.socketOut = null;
        if (out != null) {
            try { out.close(); } catch (Throwable ignored) {}
        }

        boolean anyLeft = !activeSessions.isEmpty();
        int remainingConns;
        synchronized (hciLock) {
            remainingConns = connectionsByHandle.size();
        }
        if (!anyLeft && remainingConns == 0) {
            transport.setFilterState(false, BtNativeBridge.HANDLE_OP_CLEAR_ALL);
        }
    }

    private LeConnection resolveSessionConnection(ClientSession session, String explicitMac) {
        synchronized (session.ownedByMac) {
            if (explicitMac != null && !explicitMac.isEmpty()) {
                return session.ownedByMac.get(explicitMac);
            }
            if (!session.primaryMac.isEmpty()) {
                LeConnection primary = session.ownedByMac.get(session.primaryMac);
                if (primary != null) return primary;
            }
            if (!session.ownedByMac.isEmpty()) {
                return session.ownedByMac.values().iterator().next();
            }
            return null;
        }
    }

    private void refreshSessionPrimaryMac(ClientSession session) {
        synchronized (session.ownedByMac) {
            if (session.ownedByMac.containsKey(session.primaryMac)) {
                return;
            }
            String last = "";
            for (String m : session.ownedByMac.keySet()) {
                last = m;
            }
            session.primaryMac = last;
        }
    }

    // ================= CONTROLLER INIT, SHARED SCAN & MULTI-CONNECT =================

    private boolean ensureControllerLeReady(ModContext mod) {
        transport.setFilterState(true, BtNativeBridge.HANDLE_OP_KEEP);
        if (controllerInitialized) {
            return true;
        }

        // 1. HCI_Set_Event_Mask (0x0C01): keep all Classic BR/EDR bits (0..55) + enable Bit 61 (LE Meta Event)
        byte[] evMask = new byte[]{
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x20
        };
        byte[] r1 = sendHciCmdSync(HCI_SET_EVENT_MASK, evMask, 1500L);
        if (r1 == null) {
            if (mod != null) mod.log("HCI_Set_Event_Mask timed out");
            return false;
        }

        // 2. HCI_Write_LE_Host_Support (0x0C6D): LE_Supported_Host=1, Simultaneous_LE_Host=1
        sendHciCmdSync(HCI_WRITE_LE_HOST_SUPPORT, new byte[]{0x01, 0x01}, 1200L);

        // 3. HCI_LE_Set_Event_Mask (0x2001): bits 0..4 (Conn Complete, Adv Report, Conn Update, Remote Feat, LTK)
        byte[] leMask = new byte[]{0x1F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        sendHciCmdSync(HCI_LE_SET_EVENT_MASK, leMask, 1200L);

        // 4. HCI_LE_Read_Buffer_Size (0x2002)
        byte[] bufRsp = sendHciCmdSync(HCI_LE_READ_BUFFER_SIZE, new byte[0], 1200L);
        if (bufRsp != null && bufRsp.length >= 9 && (bufRsp[5] & 0xFF) == 0) {
            int lePktLen = u16le(bufRsp, 6);
            int leNumPkts = bufRsp[8] & 0xFF;
            controllerLeAclMaxLen = (lePktLen >= DEFAULT_LE_ACL_MAX_LEN) ? lePktLen : DEFAULT_LE_ACL_MAX_LEN;
            if (leNumPkts > 0) {
                maxLeAclCredits = Math.min(leNumPkts, 4);
            } else {
                maxLeAclCredits = 2; // Shared BR/EDR ACL pool: cap conservatively to protect A2DP
            }
            if (mod != null) {
                mod.log("Controller LE ready: leAclLen=" + controllerLeAclMaxLen + " (raw=" + lePktLen
                        + ") leNumPkts=" + leNumPkts + " creditCap=" + maxLeAclCredits);
            }
        }

        controllerInitialized = true;
        return true;
    }

    private boolean anySessionWantsScan() {
        for (int i = 0; i < activeSessions.size(); i++) {
            ClientSession s = activeSessions.get(i);
            if (s.active && s.scanning) {
                return true;
            }
        }
        return false;
    }

    private void startBleScan(ModContext mod, ClientSession session) {
        if (!ensureControllerLeReady(mod)) {
            session.emitRaw("SCAN_STATE 0 ERR_CONTROLLER_INIT");
            return;
        }
        synchronized (scanOpLock) {
            session.scanning = true;
            if (connectInProgress) {
                // Scan will automatically resume as soon as the in-flight connection attempt finishes
                session.emitRaw("SCAN_STATE 1");
                return;
            }
            if (hardwareScanning) {
                session.emitRaw("SCAN_STATE 1");
                return;
            }
            String err = enableHardwareScanLocked();
            if (err != null) {
                session.scanning = false;
                session.emitRaw("SCAN_STATE 0 " + err);
            } else {
                session.emitRaw("SCAN_STATE 1");
            }
        }
    }

    private void stopBleScan(ModContext mod, ClientSession session, boolean emitReply) {
        synchronized (scanOpLock) {
            session.scanning = false;
            if (!anySessionWantsScan() && hardwareScanning) {
                sendHciCmdSync(HCI_LE_SET_SCAN_ENABLE, new byte[]{0x00, 0x00}, 1000L);
                hardwareScanning = false;
            }
        }
        if (emitReply) {
            session.emitRaw("SCAN_STATE 0");
        }
    }

    private void syncHardwareScanState(ModContext mod) {
        synchronized (scanOpLock) {
            boolean want = anySessionWantsScan() && !connectInProgress;
            if (want && !hardwareScanning) {
                if (ensureControllerLeReady(mod)) {
                    enableHardwareScanLocked();
                }
            } else if (!want && hardwareScanning) {
                sendHciCmdSync(HCI_LE_SET_SCAN_ENABLE, new byte[]{0x00, 0x00}, 1000L);
                hardwareScanning = false;
            }
        }
    }

    private String enableHardwareScanLocked() {
        // Cleanly clear any stale scan state first
        sendHciCmdSync(HCI_LE_SET_SCAN_ENABLE, new byte[]{0x00, 0x00}, 800L);

        // Active scan, 60ms interval (0x0060), 20ms window (0x0020 = 33% duty cycle for A2DP coexistence)
        byte[] scanParams = new byte[]{
                0x01,       // Active scanning (requests SCAN_RSP for Complete Local Name)
                0x60, 0x00, // LE_Scan_Interval = 96 * 0.625ms = 60ms
                0x20, 0x00, // LE_Scan_Window   = 32 * 0.625ms = 20ms
                0x00,       // Own_Address_Type = Public (0x00)
                0x00        // Scanning_Filter_Policy = Accept all (0x00)
        };
        byte[] paramRsp = sendHciCmdSync(HCI_LE_SET_SCAN_PARAMETERS, scanParams, 1200L);
        if (paramRsp == null || paramRsp.length < 6 || (paramRsp[5] & 0xFF) != 0) {
            int st = (paramRsp != null && paramRsp.length >= 6) ? (paramRsp[5] & 0xFF) : -1;
            hardwareScanning = false;
            return "ERR_SCAN_PARAMS_" + st;
        }

        // Enable scan with Filter_Duplicates=0x00 so SCAN_RSP updates always arrive
        byte[] enRsp = sendHciCmdSync(HCI_LE_SET_SCAN_ENABLE, new byte[]{0x01, 0x00}, 1200L);
        if (enRsp == null || enRsp.length < 6 || (enRsp[5] & 0xFF) != 0) {
            int st = (enRsp != null && enRsp.length >= 6) ? (enRsp[5] & 0xFF) : -1;
            hardwareScanning = false;
            return "ERR_SCAN_ENABLE_" + st;
        }

        hardwareScanning = true;
        return null;
    }

    private void connectAndDiscover(
            ModContext mod,
            ClientSession session,
            String mac,
            int addrTypeHint,
            String explicitServiceFilter) {
        byte[] macLe = parseMacToLittleEndian(mac);
        if (macLe == null) {
            session.emitForConn(mac, "CONN_STATE DISCONNECTED " + mac + " status=255 reason=INVALID_MAC");
            return;
        }
        if (!ensureControllerLeReady(mod)) {
            session.emitForConn(mac, "CONN_STATE DISCONNECTED " + mac + " status=254 reason=ERR_CONTROLLER_INIT");
            return;
        }

        // In legacy single-connection mode, stop this session's scan & close its previous link first
        if (!session.multiConnMode) {
            stopBleScan(mod, session, false);
            disconnectAllSessionLinks(session, false, null);
        } else {
            // If this session already owns a link to the exact same MAC, close that stale link first
            LeConnection sameMacOwn;
            synchronized (session.ownedByMac) {
                sameMacOwn = session.ownedByMac.get(mac);
            }
            if (sameMacOwn != null) {
                disconnectConnection(sameMacOwn, false, null);
            }
        }

        synchronized (hciLock) {
            LeConnection existingOther = connectionsByMac.get(mac);
            if (existingOther != null && !existingOther.closed) {
                session.emitForConn(mac, "CONN_STATE DISCONNECTED " + mac + " status=253 reason=ALREADY_CONNECTED");
                return;
            }
            if (connectionsByHandle.size() >= MAX_CONCURRENT_CONNECTIONS) {
                session.emitForConn(mac, "CONN_STATE DISCONNECTED " + mac + " status=252 reason=MAX_CONNECTIONS_REACHED");
                return;
            }
        }

        int[] candidateAddrTypes;
        if (addrTypeHint == 0 || addrTypeHint == 1) {
            candidateAddrTypes = new int[]{addrTypeHint};
        } else {
            Integer cached = getCachedAddrType(mac);
            if (cached != null) {
                int primary = cached.intValue();
                candidateAddrTypes = new int[]{primary, primary == 0 ? 1 : 0};
            } else {
                candidateAddrTypes = new int[]{0, 1};
            }
        }

        session.cancelConnectRequested = false;
        session.emitForConn(mac, "CONN_STATE CONNECTING " + mac);

        LeConnection established = null;
        synchronized (connectOpLock) {
            connectInProgress = true;
            try {
                // Pause hardware scan while controller initiator state machine runs
                synchronized (scanOpLock) {
                    if (hardwareScanning) {
                        sendHciCmdSync(HCI_LE_SET_SCAN_ENABLE, new byte[]{0x00, 0x00}, 800L);
                        hardwareScanning = false;
                    }
                }

                byte[] connEvt = null;
                int lastStatus = -1;
                for (int attempt = 0; attempt < candidateAddrTypes.length; attempt++) {
                    if (session.cancelConnectRequested || !session.active) {
                        session.emitForConn(mac, "CONN_STATE DISCONNECTED " + mac + " status=0 reason=CANCELED");
                        return;
                    }
                    int peerAddrType = candidateAddrTypes[attempt];
                    long waitMs = (candidateAddrTypes.length == 1) ? 9500L : 5500L;

                    synchronized (hciLock) {
                        pendingLeConnEvent = null;
                    }

                    byte[] createParams = buildLeCreateConnParams(macLe, peerAddrType);
                    int cmdStatus = sendHciCmdStatusSync(HCI_LE_CREATE_CONNECTION, createParams, 1500L);
                    if (cmdStatus != 0) {
                        lastStatus = cmdStatus;
                        if (cmdStatus == 0x0C) {
                            sendHciCmdSync(HCI_LE_CREATE_CONNECTION_CANCEL, new byte[0], 1000L);
                        }
                        continue;
                    }

                    long deadline = System.currentTimeMillis() + waitMs;
                    synchronized (hciLock) {
                        while (pendingLeConnEvent == null && !session.cancelConnectRequested && session.active) {
                            long rem = deadline - System.currentTimeMillis();
                            if (rem <= 0L) break;
                            try {
                                hciLock.wait(rem);
                            } catch (InterruptedException ie) {
                                break;
                            }
                        }
                        connEvt = pendingLeConnEvent;
                        pendingLeConnEvent = null;
                    }

                    if (connEvt != null) {
                        int st = connEvt[3] & 0xFF;
                        lastStatus = st;
                        if (st == 0) {
                            break;
                        }
                        connEvt = null;
                    } else {
                        sendHciCmdSync(HCI_LE_CREATE_CONNECTION_CANCEL, new byte[0], 1000L);
                        synchronized (hciLock) {
                            if (pendingLeConnEvent == null) {
                                try { hciLock.wait(350L); } catch (InterruptedException ignored) {}
                            }
                            if (pendingLeConnEvent != null && (pendingLeConnEvent[3] & 0xFF) == 0) {
                                connEvt = pendingLeConnEvent;
                            }
                            pendingLeConnEvent = null;
                        }
                        if (connEvt != null) {
                            break;
                        }
                        lastStatus = 133;
                    }
                }

                if (session.cancelConnectRequested || !session.active) {
                    if (connEvt != null && (connEvt[3] & 0xFF) == 0) {
                        int h = u16le(connEvt, 4) & 0x0FFF;
                        sendDisconnectCmd(h);
                    }
                    session.emitForConn(mac, "CONN_STATE DISCONNECTED " + mac + " status=0 reason=CANCELED");
                    return;
                }

                if (connEvt == null || (connEvt[3] & 0xFF) != 0) {
                    session.emitForConn(mac, "CONN_STATE DISCONNECTED " + mac
                            + " status=" + lastStatus + " reason=CONNECT_TIMEOUT");
                    return;
                }

                int handle = u16le(connEvt, 4) & 0x0FFF;
                established = new LeConnection(handle, mac, session, session.defaultServerMtu);
                String resolvedFilter = resolveServiceFilter(session, explicitServiceFilter);
                if (!session.genericDefault && "fff0".equals(resolvedFilter)) {
                    established.protectedWriteUuids.add("fff1");
                }

                synchronized (hciLock) {
                    connectionsByHandle.put(Integer.valueOf(handle), established);
                    connectionsByMac.put(mac, established);
                }
                synchronized (session.ownedByMac) {
                    session.ownedByMac.put(mac, established);
                    session.primaryMac = mac;
                }
                transport.setFilterState(true, handle);

                if (mod != null) {
                    mod.log("BLE connected to " + mac + " handle=0x" + Integer.toHexString(handle)
                            + " session=" + session.sessionId + " filter=" + resolvedFilter);
                }
                session.emitForConn(mac, String.format(Locale.US, "CONN_STATE DISCOVERING %s handle=0x%04x",
                        mac, Integer.valueOf(handle)));
            } finally {
                connectInProgress = false;
                syncHardwareScanState(mod);
            }
        }

        if (established == null || established.closed) {
            return;
        }

        // Brief settle window before ATT service discovery (matches KitKat Broadcom peripheral timing)
        sleepQuietly(150L);
        if (established.closed) {
            return;
        }

        String resolvedFilter = resolveServiceFilter(session, explicitServiceFilter);
        discoverGattTable(established, resolvedFilter);
    }

    private static String resolveServiceFilter(ClientSession session, String explicitFilter) {
        if (explicitFilter != null && !explicitFilter.trim().isEmpty()) {
            String f = explicitFilter.trim().toLowerCase(Locale.US);
            if ("*".equals(f) || "all".equals(f)) {
                return "*";
            }
            return normalizeUuidKey(f);
        }
        return session.genericDefault ? "*" : "fff0";
    }

    private void disconnectAllSessionLinks(ClientSession session, boolean emitEvent, String reason) {
        List<LeConnection> list;
        synchronized (session.ownedByMac) {
            list = new ArrayList<LeConnection>(session.ownedByMac.values());
        }
        for (int i = 0; i < list.size(); i++) {
            disconnectConnection(list.get(i), emitEvent, reason);
        }
    }

    private void disconnectConnection(LeConnection conn, boolean emitEvent, String reason) {
        if (conn == null) return;
        boolean wasOpen = false;
        synchronized (hciLock) {
            if (!conn.closed) {
                conn.closed = true;
                wasOpen = true;
                connectionsByHandle.remove(Integer.valueOf(conn.handle));
                if (connectionsByMac.get(conn.mac) == conn) {
                    connectionsByMac.remove(conn.mac);
                }
                conn.l2capReassembly = null;
                conn.l2capExpectedLen = 0;
                if (connectionsByHandle.isEmpty()) {
                    inflightLeAclPkts = 0;
                }
                hciLock.notifyAll();
            }
        }
        synchronized (conn.owner.ownedByMac) {
            if (conn.owner.ownedByMac.get(conn.mac) == conn) {
                conn.owner.ownedByMac.remove(conn.mac);
            }
        }
        refreshSessionPrimaryMac(conn.owner);

        synchronized (conn.attLock) {
            conn.charByUuid.clear();
            conn.charByValHandle.clear();
            conn.attLock.notifyAll();
        }

        if (wasOpen && conn.handle >= 0 && conn.handle <= 0x0EFF) {
            // Keep C filter tracking briefly so Disconnection_Complete (0x05) is consumed cleanly
            sendDisconnectCmd(conn.handle);
            sleepQuietly(180L);
            transport.setFilterState(true, BtNativeBridge.encodeUntrackHandle(conn.handle));
        }

        if (emitEvent && wasOpen) {
            conn.owner.emitForConn(conn.mac, "CONN_STATE DISCONNECTED " + conn.mac + " status=0 reason="
                    + (reason != null ? reason : "DISCONNECTED"));
        }
    }

    private void sendDisconnectCmd(int handle) {
        byte[] discParams = new byte[]{
                (byte) (handle & 0xFF),
                (byte) ((handle >> 8) & 0x0F),
                0x13 // Remote User Terminated Connection
        };
        sendHciCmdSync(HCI_DISCONNECT, discParams, 800L);
    }

    // ================= ATT / GATT CENTRAL DISCOVERY & OPERATIONS =================

    private boolean discoverGattTable(LeConnection conn, String serviceFilter) {
        synchronized (conn.attLock) {
            conn.charByUuid.clear();
            conn.charByValHandle.clear();
        }

        boolean wildcard = "*".equals(serviceFilter);
        int targetSvcStart = 0;
        int targetSvcEnd = 0;

        // 1. Discover Primary Services (UUID 0x2800) via ATT_READ_BY_GROUP_TYPE_REQ (0x10)
        int curStart = 0x0001;
        int guard = 0;
        while (curStart <= 0xFFFF && guard++ < 48) {
            byte[] req = new byte[]{
                    (byte) ATT_READ_BY_GROUP_TYPE_REQ,
                    (byte) (curStart & 0xFF), (byte) ((curStart >> 8) & 0xFF),
                    (byte) 0xFF, (byte) 0xFF,
                    0x00, 0x28
            };
            byte[] rsp = transactAtt(conn, req, 3000L);
            if (rsp == null) {
                disconnectConnection(conn, true, "ATT_SVC_DISCOVERY_TIMEOUT");
                return false;
            }
            int op = rsp[0] & 0xFF;
            if (op == ATT_ERROR_RSP) {
                break; // 0x0A Attribute Not Found -> end of primary services
            }
            if (op != ATT_READ_BY_GROUP_TYPE_RSP || rsp.length < 4) {
                break;
            }
            int itemLen = rsp[1] & 0xFF;
            if (itemLen != 6 && itemLen != 20) {
                break;
            }
            int lastEnd = curStart;
            for (int pos = 2; pos + itemLen <= rsp.length; pos += itemLen) {
                int sHandle = u16le(rsp, pos);
                int eHandle = u16le(rsp, pos + 2);
                String svcUuid = decodeAttUuid(rsp, pos + 4, itemLen - 4);
                conn.owner.emitForConn(conn.mac, String.format(Locale.US, "GATT_SVC %s %04x %04x",
                        svcUuid, Integer.valueOf(sHandle), Integer.valueOf(eHandle)));
                if (!wildcard && serviceFilter.equals(svcUuid)) {
                    targetSvcStart = sHandle;
                    targetSvcEnd = eHandle;
                }
                if (eHandle > lastEnd) {
                    lastEnd = eHandle;
                }
            }
            if (lastEnd >= 0xFFFF || lastEnd < curStart) {
                break;
            }
            curStart = lastEnd + 1;
        }

        int searchStart = (!wildcard && targetSvcStart > 0 && targetSvcEnd >= targetSvcStart)
                ? targetSvcStart : 0x0001;
        int searchEnd = (!wildcard && targetSvcStart > 0 && targetSvcEnd >= targetSvcStart)
                ? targetSvcEnd : 0xFFFF;

        // 2. Discover Characteristics (UUID 0x2803) via ATT_READ_BY_TYPE_REQ (0x08)
        List<DiscoveredChar> discovered = new ArrayList<DiscoveredChar>();
        curStart = searchStart;
        guard = 0;
        while (curStart <= searchEnd && guard++ < 128) {
            byte[] req = new byte[]{
                    (byte) ATT_READ_BY_TYPE_REQ,
                    (byte) (curStart & 0xFF), (byte) ((curStart >> 8) & 0xFF),
                    (byte) (searchEnd & 0xFF), (byte) ((searchEnd >> 8) & 0xFF),
                    0x03, 0x28
            };
            byte[] rsp = transactAtt(conn, req, 3000L);
            if (rsp == null) {
                disconnectConnection(conn, true, "ATT_CHAR_DISCOVERY_TIMEOUT");
                return false;
            }
            int op = rsp[0] & 0xFF;
            if (op == ATT_ERROR_RSP) {
                break;
            }
            if (op != ATT_READ_BY_TYPE_RSP || rsp.length < 4) {
                break;
            }
            int itemLen = rsp[1] & 0xFF;
            if (itemLen != 7 && itemLen != 21) {
                break;
            }
            int maxHandleSeen = curStart;
            for (int pos = 2; pos + itemLen <= rsp.length; pos += itemLen) {
                int declHandle = u16le(rsp, pos);
                int props = rsp[pos + 2] & 0xFF;
                int valHandle = u16le(rsp, pos + 3);
                String charUuid = decodeAttUuid(rsp, pos + 5, itemLen - 5);
                discovered.add(new DiscoveredChar(charUuid, declHandle, valHandle, props));
                int stepHandle = Math.max(declHandle, valHandle);
                if (stepHandle > maxHandleSeen) {
                    maxHandleSeen = stepHandle;
                }
            }
            if (maxHandleSeen >= searchEnd || maxHandleSeen >= 0xFFFF) {
                break;
            }
            curStart = maxHandleSeen + 1;
        }

        for (int i = 0; i < discovered.size(); i++) {
            DiscoveredChar c = discovered.get(i);
            c.endHandle = (i + 1 < discovered.size())
                    ? Math.max(c.valHandle, discovered.get(i + 1).declHandle - 1)
                    : Math.max(c.valHandle, searchEnd);
            synchronized (conn.attLock) {
                conn.charByUuid.put(c.shortUuid, c);
                conn.charByValHandle.put(Integer.valueOf(c.valHandle), c);
            }
            conn.owner.emitForConn(conn.mac, String.format(Locale.US, "GATT_CHAR %s %02x %04x %04x",
                    c.shortUuid, Integer.valueOf(c.props),
                    Integer.valueOf(c.valHandle), Integer.valueOf(c.endHandle)));
        }

        boolean serviceSatisfied;
        StringBuilder specCsv = new StringBuilder();
        synchronized (conn.attLock) {
            if (wildcard) {
                serviceSatisfied = true;
            } else if ("fff0".equals(serviceFilter)) {
                serviceSatisfied = (targetSvcStart > 0)
                        || conn.charByUuid.containsKey("fff2")
                        || conn.charByUuid.containsKey("fff4")
                        || conn.charByUuid.containsKey("fff1");
            } else {
                serviceSatisfied = (targetSvcStart > 0) || conn.charByUuid.containsKey(serviceFilter);
            }
            for (DiscoveredChar c : conn.charByUuid.values()) {
                if (specCsv.length() > 0) specCsv.append(',');
                specCsv.append(c.shortUuid)
                        .append(':')
                        .append(String.format(Locale.US, "%02x", Integer.valueOf(c.props)));
            }
        }

        if (!serviceSatisfied) {
            String reason = "fff0".equals(serviceFilter)
                    ? "MISSING_SERVICE_FFF0"
                    : ("MISSING_SERVICE_" + serviceFilter.toUpperCase(Locale.US));
            disconnectConnection(conn, true, reason);
            return false;
        }

        conn.owner.emitForConn(conn.mac,
                "GATT_READY " + conn.mac + " " + (specCsv.length() > 0 ? specCsv.toString() : "none"));
        return true;
    }

    private void handleRequestMtu(ClientSession session, String explicitMac, int desiredMtu) {
        LeConnection conn = resolveSessionConnection(session, explicitMac);
        if (conn == null || conn.closed) {
            session.emitForConn(explicitMac, "OP_ERR REQUEST_MTU NOT_CONNECTED");
            return;
        }
        int clamped = clampMtu(desiredMtu);
        conn.preferredServerMtu = clamped;
        byte[] req = new byte[]{
                (byte) ATT_EXCHANGE_MTU_REQ,
                (byte) (clamped & 0xFF),
                (byte) ((clamped >> 8) & 0xFF)
        };
        byte[] rsp = transactAtt(conn, req, 2500L);
        if (rsp == null) {
            session.emitForConn(conn.mac, "OP_ERR REQUEST_MTU TIMEOUT");
            return;
        }
        int op = rsp[0] & 0xFF;
        if (op == ATT_EXCHANGE_MTU_RSP && rsp.length >= 3) {
            int serverRxMtu = u16le(rsp, 1);
            int effective = Math.max(DEFAULT_ATT_MTU, Math.min(clamped, serverRxMtu));
            conn.attMtu = effective;
            session.emitForConn(conn.mac, "OP_OK REQUEST_MTU " + effective);
        } else if (op == ATT_ERROR_RSP && rsp.length >= 5) {
            conn.attMtu = DEFAULT_ATT_MTU;
            session.emitForConn(conn.mac, "OP_ERR REQUEST_MTU ATT_ERR_0x"
                    + Integer.toHexString(rsp[4] & 0xFF));
        } else {
            session.emitForConn(conn.mac, "OP_ERR REQUEST_MTU UNEXPECTED_RSP");
        }
    }

    private void handleProtectChar(ClientSession session, String explicitMac, String uuid) {
        LeConnection conn = resolveSessionConnection(session, explicitMac);
        if (conn == null || conn.closed) {
            session.emitForConn(explicitMac, "OP_ERR PROTECT_CHAR " + uuid + " NOT_CONNECTED");
            return;
        }
        synchronized (conn.attLock) {
            conn.protectedWriteUuids.add(uuid);
        }
        session.emitForConn(conn.mac, "OP_OK PROTECT_CHAR " + uuid);
    }

    private void handleEnableNotify(ClientSession session, String explicitMac, String shortUuid) {
        LeConnection conn = resolveSessionConnection(session, explicitMac);
        if (conn == null || conn.closed) {
            session.emitForConn(explicitMac, "OP_ERR ENABLE_NOTIFY " + shortUuid + " NOT_CONNECTED");
            return;
        }
        DiscoveredChar ch;
        synchronized (conn.attLock) {
            ch = conn.charByUuid.get(shortUuid);
        }
        if (ch == null) {
            session.emitForConn(conn.mac, "OP_ERR ENABLE_NOTIFY " + shortUuid + " CHAR_NOT_FOUND");
            return;
        }

        ensureCccdDiscovered(conn, ch);

        if (ch.cccdHandle == 0) {
            ch.notifySubscribed = true;
            session.emitForConn(conn.mac, "OP_OK ENABLE_NOTIFY " + shortUuid);
            return;
        }

        boolean indicateOnly = ((ch.props & 0x20) != 0) && ((ch.props & 0x10) == 0);
        byte[] writeCccd = new byte[]{
                (byte) ATT_WRITE_REQ,
                (byte) (ch.cccdHandle & 0xFF),
                (byte) ((ch.cccdHandle >> 8) & 0xFF),
                (byte) (indicateOnly ? 0x02 : 0x01),
                0x00
        };
        byte[] rsp = transactAtt(conn, writeCccd, 2500L);
        if (rsp != null && (rsp[0] & 0xFF) == ATT_WRITE_RSP) {
            ch.notifySubscribed = true;
            session.emitForConn(conn.mac, "OP_OK ENABLE_NOTIFY " + shortUuid);
        } else {
            session.emitForConn(conn.mac, "OP_ERR ENABLE_NOTIFY " + shortUuid + " CCCD_WRITE_FAILED");
        }
    }

    private void handleDisableNotify(ClientSession session, String explicitMac, String shortUuid) {
        LeConnection conn = resolveSessionConnection(session, explicitMac);
        if (conn == null || conn.closed) {
            session.emitForConn(explicitMac, "OP_ERR DISABLE_NOTIFY " + shortUuid + " NOT_CONNECTED");
            return;
        }
        DiscoveredChar ch;
        synchronized (conn.attLock) {
            ch = conn.charByUuid.get(shortUuid);
        }
        if (ch == null) {
            session.emitForConn(conn.mac, "OP_ERR DISABLE_NOTIFY " + shortUuid + " CHAR_NOT_FOUND");
            return;
        }

        ensureCccdDiscovered(conn, ch);
        ch.notifySubscribed = false;

        if (ch.cccdHandle == 0) {
            session.emitForConn(conn.mac, "OP_OK DISABLE_NOTIFY " + shortUuid);
            return;
        }

        byte[] writeCccd = new byte[]{
                (byte) ATT_WRITE_REQ,
                (byte) (ch.cccdHandle & 0xFF),
                (byte) ((ch.cccdHandle >> 8) & 0xFF),
                0x00,
                0x00
        };
        byte[] rsp = transactAtt(conn, writeCccd, 2500L);
        if (rsp != null && (rsp[0] & 0xFF) == ATT_WRITE_RSP) {
            session.emitForConn(conn.mac, "OP_OK DISABLE_NOTIFY " + shortUuid);
        } else {
            session.emitForConn(conn.mac, "OP_ERR DISABLE_NOTIFY " + shortUuid + " CCCD_WRITE_FAILED");
        }
    }

    private void ensureCccdDiscovered(LeConnection conn, DiscoveredChar ch) {
        if (ch.cccdHandle != 0 || ch.valHandle >= ch.endHandle) {
            return;
        }
        int startH = ch.valHandle + 1;
        int endH = Math.min(ch.endHandle, ch.valHandle + 6);
        byte[] findReq = new byte[]{
                (byte) ATT_FIND_INFO_REQ,
                (byte) (startH & 0xFF), (byte) ((startH >> 8) & 0xFF),
                (byte) (endH & 0xFF), (byte) ((endH >> 8) & 0xFF)
        };
        byte[] findRsp = transactAtt(conn, findReq, 2500L);
        if (findRsp != null && (findRsp[0] & 0xFF) == ATT_FIND_INFO_RSP && findRsp.length >= 6) {
            int fmt = findRsp[1] & 0xFF;
            int pairLen = (fmt == 1) ? 4 : ((fmt == 2) ? 18 : 0);
            if (pairLen > 0) {
                for (int pos = 2; pos + pairLen <= findRsp.length; pos += pairLen) {
                    int descHandle = u16le(findRsp, pos);
                    String descUuid = decodeAttUuid(findRsp, pos + 2, pairLen - 2);
                    if ("2902".equals(descUuid)) {
                        ch.cccdHandle = descHandle;
                        break;
                    }
                }
            }
        }
    }

    private void handleReadChar(ClientSession session, String explicitMac, String shortUuid) {
        LeConnection conn = resolveSessionConnection(session, explicitMac);
        if (conn == null || conn.closed) {
            session.emitForConn(explicitMac, "OP_ERR READ_CHAR " + shortUuid + " NOT_CONNECTED");
            return;
        }
        DiscoveredChar ch;
        synchronized (conn.attLock) {
            ch = conn.charByUuid.get(shortUuid);
        }
        if (ch == null) {
            session.emitForConn(conn.mac, "OP_ERR READ_CHAR " + shortUuid + " CHAR_NOT_FOUND");
            return;
        }
        byte[] req = new byte[]{
                (byte) ATT_READ_REQ,
                (byte) (ch.valHandle & 0xFF),
                (byte) ((ch.valHandle >> 8) & 0xFF)
        };
        byte[] rsp = transactAtt(conn, req, 2500L);
        if (rsp == null) {
            session.emitForConn(conn.mac, "OP_ERR READ_CHAR " + shortUuid + " TIMEOUT");
            return;
        }
        int op = rsp[0] & 0xFF;
        if (op == ATT_READ_RSP) {
            byte[] val = new byte[rsp.length - 1];
            if (val.length > 0) {
                System.arraycopy(rsp, 1, val, 0, val.length);
            }
            session.emitForConn(conn.mac,
                    "OP_OK READ_CHAR " + shortUuid + " " + (val.length > 0 ? bytesToHex(val) : "-"));
        } else if (op == ATT_ERROR_RSP && rsp.length >= 5) {
            session.emitForConn(conn.mac, "OP_ERR READ_CHAR " + shortUuid + " ATT_ERR_0x"
                    + Integer.toHexString(rsp[4] & 0xFF));
        } else {
            session.emitForConn(conn.mac, "OP_ERR READ_CHAR " + shortUuid + " UNEXPECTED_RSP");
        }
    }

    private void handleReadBlob(ClientSession session, String explicitMac, String shortUuid, int offset) {
        LeConnection conn = resolveSessionConnection(session, explicitMac);
        if (conn == null || conn.closed) {
            session.emitForConn(explicitMac, "OP_ERR READ_BLOB " + shortUuid + " NOT_CONNECTED");
            return;
        }
        if (offset < 0 || offset > 0xFFFF) {
            session.emitForConn(conn.mac, "OP_ERR READ_BLOB " + shortUuid + " INVALID_OFFSET");
            return;
        }
        DiscoveredChar ch;
        synchronized (conn.attLock) {
            ch = conn.charByUuid.get(shortUuid);
        }
        if (ch == null) {
            session.emitForConn(conn.mac, "OP_ERR READ_BLOB " + shortUuid + " CHAR_NOT_FOUND");
            return;
        }
        byte[] req = new byte[]{
                (byte) ATT_READ_BLOB_REQ,
                (byte) (ch.valHandle & 0xFF),
                (byte) ((ch.valHandle >> 8) & 0xFF),
                (byte) (offset & 0xFF),
                (byte) ((offset >> 8) & 0xFF)
        };
        byte[] rsp = transactAtt(conn, req, 2500L);
        if (rsp == null) {
            session.emitForConn(conn.mac, "OP_ERR READ_BLOB " + shortUuid + " TIMEOUT");
            return;
        }
        int op = rsp[0] & 0xFF;
        if (op == ATT_READ_BLOB_RSP) {
            byte[] val = new byte[rsp.length - 1];
            if (val.length > 0) {
                System.arraycopy(rsp, 1, val, 0, val.length);
            }
            session.emitForConn(conn.mac, "OP_OK READ_BLOB " + shortUuid + " " + offset + " "
                    + (val.length > 0 ? bytesToHex(val) : "-"));
        } else if (op == ATT_ERROR_RSP && rsp.length >= 5) {
            session.emitForConn(conn.mac, "OP_ERR READ_BLOB " + shortUuid + " ATT_ERR_0x"
                    + Integer.toHexString(rsp[4] & 0xFF));
        } else {
            session.emitForConn(conn.mac, "OP_ERR READ_BLOB " + shortUuid + " UNEXPECTED_RSP");
        }
    }

    private void handleReadLongChar(ClientSession session, String explicitMac, String shortUuid) {
        LeConnection conn = resolveSessionConnection(session, explicitMac);
        if (conn == null || conn.closed) {
            session.emitForConn(explicitMac, "OP_ERR READ_LONG_CHAR " + shortUuid + " NOT_CONNECTED");
            return;
        }
        DiscoveredChar ch;
        synchronized (conn.attLock) {
            ch = conn.charByUuid.get(shortUuid);
        }
        if (ch == null) {
            session.emitForConn(conn.mac, "OP_ERR READ_LONG_CHAR " + shortUuid + " CHAR_NOT_FOUND");
            return;
        }

        byte[] firstReq = new byte[]{
                (byte) ATT_READ_REQ,
                (byte) (ch.valHandle & 0xFF),
                (byte) ((ch.valHandle >> 8) & 0xFF)
        };
        byte[] rsp = transactAtt(conn, firstReq, 2500L);
        if (rsp == null) {
            session.emitForConn(conn.mac, "OP_ERR READ_LONG_CHAR " + shortUuid + " TIMEOUT");
            return;
        }
        int op = rsp[0] & 0xFF;
        if (op == ATT_ERROR_RSP && rsp.length >= 5) {
            session.emitForConn(conn.mac, "OP_ERR READ_LONG_CHAR " + shortUuid + " ATT_ERR_0x"
                    + Integer.toHexString(rsp[4] & 0xFF));
            return;
        }
        if (op != ATT_READ_RSP) {
            session.emitForConn(conn.mac, "OP_ERR READ_LONG_CHAR " + shortUuid + " UNEXPECTED_RSP");
            return;
        }

        ByteArrayOutputStream acc = new ByteArrayOutputStream(128);
        int chunkLen = rsp.length - 1;
        if (chunkLen > 0) {
            acc.write(rsp, 1, chunkLen);
        }

        int expectedFullChunk = Math.max(22, conn.attMtu - 1);
        int guard = 0;
        while (chunkLen >= expectedFullChunk && acc.size() < 512 && guard++ < 32) {
            int offset = acc.size();
            byte[] blobReq = new byte[]{
                    (byte) ATT_READ_BLOB_REQ,
                    (byte) (ch.valHandle & 0xFF),
                    (byte) ((ch.valHandle >> 8) & 0xFF),
                    (byte) (offset & 0xFF),
                    (byte) ((offset >> 8) & 0xFF)
            };
            byte[] blobRsp = transactAtt(conn, blobReq, 2500L);
            if (blobRsp == null) {
                session.emitForConn(conn.mac, "OP_ERR READ_LONG_CHAR " + shortUuid + " TIMEOUT");
                return;
            }
            int bop = blobRsp[0] & 0xFF;
            if (bop == ATT_ERROR_RSP && blobRsp.length >= 5) {
                int attErr = blobRsp[4] & 0xFF;
                // 0x0B = Attribute Not Long, 0x07 = Invalid Offset -> return accumulated bytes cleanly
                if (attErr == 0x0B || attErr == 0x07) {
                    break;
                }
                session.emitForConn(conn.mac, "OP_ERR READ_LONG_CHAR " + shortUuid + " ATT_ERR_0x"
                        + Integer.toHexString(attErr));
                return;
            }
            if (bop != ATT_READ_BLOB_RSP) {
                break;
            }
            chunkLen = blobRsp.length - 1;
            if (chunkLen > 0) {
                int copy = Math.min(chunkLen, 512 - acc.size());
                acc.write(blobRsp, 1, copy);
            }
            expectedFullChunk = Math.max(22, conn.attMtu - 1);
        }

        byte[] fullVal = acc.toByteArray();
        session.emitForConn(conn.mac, "OP_OK READ_LONG_CHAR " + shortUuid + " "
                + (fullVal.length > 0 ? bytesToHex(fullVal) : "-"));
    }

    private void handleWriteChar(
            ClientSession session,
            String explicitMac,
            String shortUuid,
            byte[] payload,
            boolean preferNoResponse) {
        String opName = preferNoResponse ? "WRITE_CHAR_NR" : "WRITE_CHAR";
        LeConnection conn = resolveSessionConnection(session, explicitMac);
        if (conn == null || conn.closed) {
            session.emitForConn(explicitMac, "OP_ERR " + opName + " " + shortUuid + " NOT_CONNECTED");
            return;
        }
        boolean isProtected;
        synchronized (conn.attLock) {
            isProtected = conn.protectedWriteUuids.contains(shortUuid);
        }
        if (isProtected) {
            String reason = "fff1".equals(shortUuid)
                    ? "FORBIDDEN_READ_ONLY_FFF1"
                    : ("PROTECTED_CHAR_" + shortUuid.toUpperCase(Locale.US));
            session.emitForConn(conn.mac, "OP_ERR " + opName + " " + shortUuid + " " + reason);
            return;
        }
        if (payload == null) {
            session.emitForConn(conn.mac, "OP_ERR " + opName + " " + shortUuid + " INVALID_HEX");
            return;
        }
        DiscoveredChar ch;
        synchronized (conn.attLock) {
            ch = conn.charByUuid.get(shortUuid);
        }
        if (ch == null) {
            session.emitForConn(conn.mac, "OP_ERR " + opName + " " + shortUuid + " CHAR_NOT_FOUND");
            return;
        }

        int maxPayload = Math.max(20, conn.attMtu - 3);
        int len = Math.min(payload.length, maxPayload);
        boolean canWriteReq = (ch.props & 0x08) != 0;
        boolean canWriteCmd = (ch.props & 0x04) != 0;
        boolean useWriteReq;
        if (preferNoResponse) {
            useWriteReq = !canWriteCmd && canWriteReq;
        } else {
            useWriteReq = canWriteReq || !canWriteCmd;
        }

        byte[] pdu = new byte[3 + len];
        pdu[0] = (byte) (useWriteReq ? ATT_WRITE_REQ : ATT_WRITE_CMD);
        pdu[1] = (byte) (ch.valHandle & 0xFF);
        pdu[2] = (byte) ((ch.valHandle >> 8) & 0xFF);
        if (len > 0) {
            System.arraycopy(payload, 0, pdu, 3, len);
        }

        if (!useWriteReq) {
            boolean ok = sendL2capPdu(conn.handle, L2CAP_CID_ATT, pdu, 2500L);
            session.emitForConn(conn.mac, ok
                    ? ("OP_OK " + opName + " " + shortUuid)
                    : ("OP_ERR " + opName + " " + shortUuid + " ACL_TX_FAILED"));
            return;
        }

        byte[] rsp = transactAtt(conn, pdu, 3000L);
        if (rsp != null && (rsp[0] & 0xFF) == ATT_WRITE_RSP) {
            session.emitForConn(conn.mac, "OP_OK " + opName + " " + shortUuid);
        } else if (rsp != null && (rsp[0] & 0xFF) == ATT_ERROR_RSP && rsp.length >= 5) {
            session.emitForConn(conn.mac, "OP_ERR " + opName + " " + shortUuid + " ATT_ERR_0x"
                    + Integer.toHexString(rsp[4] & 0xFF));
        } else {
            session.emitForConn(conn.mac, "OP_ERR " + opName + " " + shortUuid + " TIMEOUT");
        }
    }

    private byte[] transactAtt(LeConnection conn, byte[] attReq, long timeoutMs) {
        if (conn == null || conn.closed) return null;
        synchronized (conn.attLock) {
            if (conn.closed) return null;
            conn.pendingAttResponse = null;
            conn.attAwaitingResponse = true;
        }
        if (!sendL2capPdu(conn.handle, L2CAP_CID_ATT, attReq, timeoutMs)) {
            synchronized (conn.attLock) {
                conn.attAwaitingResponse = false;
            }
            return null;
        }
        long deadline = System.currentTimeMillis() + timeoutMs;
        synchronized (conn.attLock) {
            try {
                while (conn.pendingAttResponse == null
                        && !conn.closed
                        && !conn.owner.cancelConnectRequested
                        && conn.owner.active) {
                    long rem = deadline - System.currentTimeMillis();
                    if (rem <= 0L) break;
                    conn.attLock.wait(rem);
                }
                return conn.pendingAttResponse;
            } catch (InterruptedException ie) {
                return null;
            } finally {
                conn.attAwaitingResponse = false;
                conn.pendingAttResponse = null;
            }
        }
    }

    // ================= HCI & L2CAP PACKET FRAMING / FRAGMENTATION / DISPATCH =================

    private byte[] sendHciCmdSync(int opcode, byte[] params, long timeoutMs) {
        byte[] pkt = buildHciCommandPacket(opcode, params);
        synchronized (hciLock) {
            waitingOpcode = opcode;
            completedCmdEvent = null;
            cmdStatusValue = -1;
            if (!transport.sendHciCommand(pkt)) {
                waitingOpcode = -1;
                return null;
            }
            long deadline = System.currentTimeMillis() + timeoutMs;
            while (completedCmdEvent == null) {
                long rem = deadline - System.currentTimeMillis();
                if (rem <= 0L) break;
                try {
                    hciLock.wait(rem);
                } catch (InterruptedException ie) {
                    break;
                }
            }
            byte[] res = completedCmdEvent;
            waitingOpcode = -1;
            completedCmdEvent = null;
            return res;
        }
    }

    private int sendHciCmdStatusSync(int opcode, byte[] params, long timeoutMs) {
        byte[] pkt = buildHciCommandPacket(opcode, params);
        synchronized (hciLock) {
            waitingOpcode = opcode;
            completedCmdEvent = null;
            cmdStatusValue = -1;
            if (!transport.sendHciCommand(pkt)) {
                waitingOpcode = -1;
                return -1;
            }
            long deadline = System.currentTimeMillis() + timeoutMs;
            while (cmdStatusValue < 0 && completedCmdEvent == null) {
                long rem = deadline - System.currentTimeMillis();
                if (rem <= 0L) break;
                try {
                    hciLock.wait(rem);
                } catch (InterruptedException ie) {
                    break;
                }
            }
            int st = cmdStatusValue;
            if (st < 0 && completedCmdEvent != null && completedCmdEvent.length >= 6) {
                st = completedCmdEvent[5] & 0xFF;
            }
            waitingOpcode = -1;
            completedCmdEvent = null;
            cmdStatusValue = -1;
            return st;
        }
    }

    private boolean sendL2capPdu(int handle, int cid, byte[] l2capPayload, long creditWaitMs) {
        if (handle < 0 || handle > 0x0EFF) {
            return false;
        }
        int maxAclData;
        synchronized (hciLock) {
            maxAclData = controllerLeAclMaxLen;
        }
        List<byte[]> fragments = fragmentL2capIntoAclPackets(handle, cid, l2capPayload, maxAclData);
        long deadline = System.currentTimeMillis() + creditWaitMs;

        for (int i = 0; i < fragments.size(); i++) {
            synchronized (hciLock) {
                while (connectionsByHandle.containsKey(Integer.valueOf(handle))
                        && inflightLeAclPkts >= maxLeAclCredits) {
                    long rem = deadline - System.currentTimeMillis();
                    if (rem <= 0L) return false;
                    try {
                        hciLock.wait(rem);
                    } catch (InterruptedException ie) {
                        return false;
                    }
                }
                LeConnection conn = connectionsByHandle.get(Integer.valueOf(handle));
                if (conn == null || conn.closed) {
                    return false;
                }
                inflightLeAclPkts++;
            }

            boolean ok = transport.sendLeAcl(fragments.get(i));
            if (!ok) {
                synchronized (hciLock) {
                    if (inflightLeAclPkts > 0) inflightLeAclPkts--;
                    hciLock.notifyAll();
                }
                return false;
            }
        }
        return true;
    }

    @Override
    public void onHciEvent(byte[] ev) {
        if (ev == null || ev.length < 2) return;
        int evCode = ev[0] & 0xFF;

        // Command_Complete (0x0E)
        if (evCode == 0x0E && ev.length >= 6) {
            int opcode = u16le(ev, 3);
            synchronized (hciLock) {
                if (opcode == waitingOpcode) {
                    completedCmdEvent = ev;
                    hciLock.notifyAll();
                }
            }
            return;
        }

        // Command_Status (0x0F)
        if (evCode == 0x0F && ev.length >= 6) {
            int status = ev[2] & 0xFF;
            int opcode = u16le(ev, 4);
            synchronized (hciLock) {
                if (opcode == waitingOpcode) {
                    cmdStatusValue = status;
                    hciLock.notifyAll();
                }
            }
            return;
        }

        // Number_Of_Completed_Packets (0x13)
        if (evCode == 0x13 && ev.length >= 3) {
            int numH = ev[2] & 0xFF;
            synchronized (hciLock) {
                if (!connectionsByHandle.isEmpty() && 3 + numH * 4 <= ev.length) {
                    boolean changed = false;
                    for (int i = 0; i < numH; i++) {
                        int h = u16le(ev, 3 + i * 4) & 0x0FFF;
                        int completed = u16le(ev, 5 + i * 4);
                        if (completed > 0 && connectionsByHandle.containsKey(Integer.valueOf(h))) {
                            inflightLeAclPkts = Math.max(0, inflightLeAclPkts - completed);
                            changed = true;
                        }
                    }
                    if (changed) {
                        hciLock.notifyAll();
                    }
                }
            }
            return;
        }

        // Disconnection_Complete (0x05)
        if (evCode == 0x05 && ev.length >= 6) {
            int st = ev[2] & 0xFF;
            int h = u16le(ev, 3) & 0x0FFF;
            int reason = ev[5] & 0xFF;
            LeConnection dropped = null;
            synchronized (hciLock) {
                if (st == 0) {
                    dropped = connectionsByHandle.remove(Integer.valueOf(h));
                    if (dropped != null) {
                        dropped.closed = true;
                        if (connectionsByMac.get(dropped.mac) == dropped) {
                            connectionsByMac.remove(dropped.mac);
                        }
                        dropped.l2capReassembly = null;
                        dropped.l2capExpectedLen = 0;
                        if (connectionsByHandle.isEmpty()) {
                            inflightLeAclPkts = 0;
                        }
                        hciLock.notifyAll();
                    }
                }
            }
            if (dropped != null) {
                transport.setFilterState(true, BtNativeBridge.encodeUntrackHandle(h));
                synchronized (dropped.owner.ownedByMac) {
                    if (dropped.owner.ownedByMac.get(dropped.mac) == dropped) {
                        dropped.owner.ownedByMac.remove(dropped.mac);
                    }
                }
                refreshSessionPrimaryMac(dropped.owner);
                synchronized (dropped.attLock) {
                    dropped.charByUuid.clear();
                    dropped.charByValHandle.clear();
                    dropped.attLock.notifyAll();
                }
                dropped.owner.emitForConn(dropped.mac, "CONN_STATE DISCONNECTED " + dropped.mac
                        + " status=" + reason + " reason=REMOTE_DISCONNECT_0x"
                        + Integer.toHexString(reason));
            }
            return;
        }

        // LE Meta Event (0x3E)
        if (evCode == 0x3E && ev.length >= 3) {
            int sub = ev[2] & 0xFF;
            if (sub == 0x02) { // LE_Advertising_Report
                List<AdvReportItem> reports = parseLeAdvertisingReports(ev);
                for (int i = 0; i < reports.size(); i++) {
                    AdvReportItem r = reports.get(i);
                    byte[] merged = updateAdvCacheAndMerge(r);
                    String advLine = "ADV " + r.mac + " " + r.addrType + " " + r.rssi + " "
                            + (merged.length > 0 ? bytesToHex(merged) : "-");
                    for (int sIdx = 0; sIdx < activeSessions.size(); sIdx++) {
                        ClientSession s = activeSessions.get(sIdx);
                        if (s.active && s.scanning) {
                            s.emitRaw(advLine);
                        }
                    }
                }
            } else if ((sub == 0x01 && ev.length >= 19) || (sub == 0x0A && ev.length >= 19)) {
                synchronized (hciLock) {
                    pendingLeConnEvent = ev;
                    hciLock.notifyAll();
                }
            }
        }
    }

    @Override
    public void onLeAcl(byte[] acl) {
        if (acl == null || acl.length < 4) return;
        int handle = u16le(acl, 0) & 0x0FFF;
        int pbFlag = (acl[1] >> 4) & 0x03;
        int aclLen = u16le(acl, 2);
        if (4 + aclLen > acl.length) {
            aclLen = acl.length - 4;
        }
        if (aclLen <= 0) return;

        LeConnection conn;
        int completedCid = -1;
        byte[] completedPdu = null;

        synchronized (hciLock) {
            conn = connectionsByHandle.get(Integer.valueOf(handle));
            if (conn == null || conn.closed) return;

            if (pbFlag == 0x02 || pbFlag == 0x00) {
                if (aclLen < 4) return;
                int l2capLen = u16le(acl, 4);
                int cid = u16le(acl, 6);
                int avail = aclLen - 4;
                if (avail >= l2capLen) {
                    completedCid = cid;
                    completedPdu = new byte[l2capLen];
                    System.arraycopy(acl, 8, completedPdu, 0, l2capLen);
                    conn.l2capReassembly = null;
                    conn.l2capExpectedLen = 0;
                } else if (l2capLen <= MAX_REASSEMBLED_L2CAP_LEN) {
                    conn.l2capReassembly = new ByteArrayOutputStream(l2capLen);
                    conn.l2capReassembly.write(acl, 8, avail);
                    conn.l2capExpectedLen = l2capLen;
                    conn.l2capCurrentCid = cid;
                } else {
                    conn.l2capReassembly = null;
                    conn.l2capExpectedLen = 0;
                }
            } else if (pbFlag == 0x01 && conn.l2capReassembly != null) {
                conn.l2capReassembly.write(acl, 4, aclLen);
                if (conn.l2capReassembly.size() >= conn.l2capExpectedLen) {
                    byte[] full = conn.l2capReassembly.toByteArray();
                    completedCid = conn.l2capCurrentCid;
                    completedPdu = new byte[conn.l2capExpectedLen];
                    System.arraycopy(full, 0, completedPdu, 0, conn.l2capExpectedLen);
                    conn.l2capReassembly = null;
                    conn.l2capExpectedLen = 0;
                }
            }
        }

        if (completedPdu != null) {
            handleCompleteL2capSdu(conn, completedCid, completedPdu);
        }
    }

    private void handleCompleteL2capSdu(final LeConnection conn, int cid, byte[] pdu) {
        if (conn == null || conn.closed || pdu.length == 0) return;

        if (cid == L2CAP_CID_LE_SIGNALING) {
            // L2CAP Connection Parameter Update Request (0x12) from peripheral
            if ((pdu[0] & 0xFF) == 0x12 && pdu.length >= 12) {
                byte identifier = pdu[1];
                final int minInt = u16le(pdu, 4);
                final int maxInt = u16le(pdu, 6);
                final int latency = u16le(pdu, 8);
                final int timeout = u16le(pdu, 10);

                // Accept (0x0000) on CID 0x0005
                byte[] rsp = new byte[]{0x13, identifier, 0x02, 0x00, 0x00, 0x00};
                sendL2capPdu(conn.handle, L2CAP_CID_LE_SIGNALING, rsp, 500L);

                if (minInt >= 6 && maxInt >= minInt && maxInt <= 3200 && timeout >= 10 && timeout <= 3200) {
                    byte[] upd = new byte[]{
                            (byte) (conn.handle & 0xFF), (byte) ((conn.handle >> 8) & 0x0F),
                            (byte) (minInt & 0xFF), (byte) ((minInt >> 8) & 0xFF),
                            (byte) (maxInt & 0xFF), (byte) ((maxInt >> 8) & 0xFF),
                            (byte) (latency & 0xFF), (byte) ((latency >> 8) & 0xFF),
                            (byte) (timeout & 0xFF), (byte) ((timeout >> 8) & 0xFF),
                            0x00, 0x00, 0x00, 0x00
                    };
                    transport.sendHciCommand(buildHciCommandPacket(HCI_LE_CONNECTION_UPDATE, upd));
                }
            }
            return;
        }

        if (cid != L2CAP_CID_ATT) {
            return;
        }

        int attOp = pdu[0] & 0xFF;
        if (attOp == ATT_EXCHANGE_MTU_REQ && pdu.length >= 3) {
            int peerRxMtu = u16le(pdu, 1);
            int ourMaxMtu = conn.preferredServerMtu;
            conn.attMtu = Math.max(DEFAULT_ATT_MTU, Math.min(peerRxMtu, ourMaxMtu));
            sendL2capPdu(conn.handle, L2CAP_CID_ATT, new byte[]{
                    (byte) ATT_EXCHANGE_MTU_RSP,
                    (byte) (ourMaxMtu & 0xFF),
                    (byte) ((ourMaxMtu >> 8) & 0xFF)
            }, 500L);
            return;
        }

        if (attOp == ATT_HANDLE_VALUE_NTF || attOp == ATT_HANDLE_VALUE_IND) {
            if (attOp == ATT_HANDLE_VALUE_IND) {
                sendL2capPdu(conn.handle, L2CAP_CID_ATT, new byte[]{(byte) ATT_HANDLE_VALUE_CFM}, 500L);
            }
            if (pdu.length >= 3) {
                int valHandle = u16le(pdu, 1);
                DiscoveredChar ch;
                synchronized (conn.attLock) {
                    ch = conn.charByValHandle.get(Integer.valueOf(valHandle));
                }
                // Suppress unsolicited notifications (e.g., BVM02 FW v1.14 10 Hz Battery Service 0x0027)
                // unless the client session explicitly enabled notifications on this characteristic.
                if (ch == null || !ch.notifySubscribed) {
                    return;
                }
                byte[] val = new byte[pdu.length - 3];
                if (val.length > 0) {
                    System.arraycopy(pdu, 3, val, 0, val.length);
                }
                conn.owner.emitForConn(conn.mac,
                        "CHAR_NOTIFY " + ch.shortUuid + " " + (val.length > 0 ? bytesToHex(val) : "-"));
            }
            return;
        }

        synchronized (conn.attLock) {
            if (conn.attAwaitingResponse) {
                conn.pendingAttResponse = pdu;
                conn.attLock.notifyAll();
            }
        }
    }

    // ================= PURE STATIC CODECS (HOST-UNIT-TESTABLE) =================

    public static int clampMtu(int mtu) {
        if (mtu < DEFAULT_ATT_MTU) return DEFAULT_ATT_MTU;
        if (mtu > MAX_SUPPORTED_ATT_MTU) return MAX_SUPPORTED_ATT_MTU;
        return mtu;
    }

    public static byte[] buildHciCommandPacket(int opcode, byte[] params) {
        int plen = (params != null) ? params.length : 0;
        byte[] out = new byte[3 + plen];
        out[0] = (byte) (opcode & 0xFF);
        out[1] = (byte) ((opcode >> 8) & 0xFF);
        out[2] = (byte) (plen & 0xFF);
        if (plen > 0) {
            System.arraycopy(params, 0, out, 3, plen);
        }
        return out;
    }

    public static byte[] buildLeCreateConnParams(byte[] peerMacLe6, int peerAddrType) {
        byte[] p = new byte[25];
        p[0] = 0x60; p[1] = 0x00; // Scan_Interval = 60ms
        p[2] = 0x30; p[3] = 0x00; // Scan_Window = 30ms
        p[4] = 0x00;              // Initiator_Filter_Policy = Peer address
        p[5] = (byte) (peerAddrType & 0x01);
        System.arraycopy(peerMacLe6, 0, p, 6, 6);
        p[12] = 0x00;             // Own_Address_Type = Public
        p[13] = 0x18; p[14] = 0x00; // Conn_Interval_Min = 24 * 1.25ms = 30ms
        p[15] = 0x28; p[16] = 0x00; // Conn_Interval_Max = 40 * 1.25ms = 50ms
        p[17] = 0x00; p[18] = 0x00; // Conn_Latency = 0
        p[19] = (byte) 0x90; p[20] = 0x01; // Supervision_Timeout = 400 * 10ms = 4.0s
        p[21] = 0x00; p[22] = 0x00; // Minimum_CE_Length
        p[23] = 0x00; p[24] = 0x00; // Maximum_CE_Length
        return p;
    }

    public static byte[] wrapLeAclL2cap(int connHandle, int cid, byte[] l2capPayload) {
        int payLen = (l2capPayload != null) ? l2capPayload.length : 0;
        int aclDataLen = 4 + payLen;
        byte[] acl = new byte[4 + aclDataLen];
        acl[0] = (byte) (connHandle & 0xFF);
        acl[1] = (byte) ((connHandle >> 8) & 0x0F); // PB=00 (First non-automatically-flushable packet), BC=00
        acl[2] = (byte) (aclDataLen & 0xFF);
        acl[3] = (byte) ((aclDataLen >> 8) & 0xFF);
        acl[4] = (byte) (payLen & 0xFF);
        acl[5] = (byte) ((payLen >> 8) & 0xFF);
        acl[6] = (byte) (cid & 0xFF);
        acl[7] = (byte) ((cid >> 8) & 0xFF);
        if (payLen > 0) {
            System.arraycopy(l2capPayload, 0, acl, 8, payLen);
        }
        return acl;
    }

    /**
     * Fragments an L2CAP SDU across one or more HCI LE ACL Data Packets respecting the
     * controller's {@code LE_ACL_Data_Packet_Length} (typically 27 bytes on BT 4.0 controllers).
     * First packet carries {@code PB=0x00} (start non-auto-flushable), continuation packets carry {@code PB=0x01}.
     */
    public static List<byte[]> fragmentL2capIntoAclPackets(
            int connHandle,
            int cid,
            byte[] l2capPayload,
            int maxAclDataLen) {
        int effMax = Math.max(8, maxAclDataLen);
        int payLen = (l2capPayload != null) ? l2capPayload.length : 0;
        int totalL2cap = 4 + payLen;
        List<byte[]> out = new ArrayList<byte[]>((totalL2cap + effMax - 1) / effMax);

        if (totalL2cap <= effMax) {
            out.add(wrapLeAclL2cap(connHandle, cid, l2capPayload));
            return out;
        }

        byte[] l2capFrame = new byte[totalL2cap];
        l2capFrame[0] = (byte) (payLen & 0xFF);
        l2capFrame[1] = (byte) ((payLen >> 8) & 0xFF);
        l2capFrame[2] = (byte) (cid & 0xFF);
        l2capFrame[3] = (byte) ((cid >> 8) & 0xFF);
        if (payLen > 0) {
            System.arraycopy(l2capPayload, 0, l2capFrame, 4, payLen);
        }

        int offset = 0;
        while (offset < totalL2cap) {
            int chunkLen = Math.min(effMax, totalL2cap - offset);
            byte[] acl = new byte[4 + chunkLen];
            acl[0] = (byte) (connHandle & 0xFF);
            int pbBits = (offset == 0) ? 0x00 : 0x10; // PB=00 first fragment, PB=01 continuation fragment
            acl[1] = (byte) (((connHandle >> 8) & 0x0F) | pbBits);
            acl[2] = (byte) (chunkLen & 0xFF);
            acl[3] = (byte) ((chunkLen >> 8) & 0xFF);
            System.arraycopy(l2capFrame, offset, acl, 4, chunkLen);
            out.add(acl);
            offset += chunkLen;
        }
        return out;
    }

    public static List<AdvReportItem> parseLeAdvertisingReports(byte[] hciEvt) {
        List<AdvReportItem> list = new ArrayList<AdvReportItem>();
        if (hciEvt == null || hciEvt.length < 4) return list;
        if ((hciEvt[0] & 0xFF) != 0x3E || (hciEvt[2] & 0xFF) != 0x02) return list;

        int numReports = hciEvt[3] & 0xFF;
        int pos = 4;
        for (int i = 0; i < numReports; i++) {
            if (pos + 9 > hciEvt.length) break;
            int evtType = hciEvt[pos] & 0xFF;
            int addrType = hciEvt[pos + 1] & 0xFF;
            String mac = formatMacLittleEndian(hciEvt, pos + 2);
            int dataLen = hciEvt[pos + 8] & 0xFF;
            if (pos + 9 + dataLen + 1 > hciEvt.length) break;
            byte[] ad = new byte[dataLen];
            if (dataLen > 0) {
                System.arraycopy(hciEvt, pos + 9, ad, 0, dataLen);
            }
            int rssi = (int) hciEvt[pos + 9 + dataLen]; // signed dBm byte
            list.add(new AdvReportItem(evtType, addrType, mac, ad, rssi));
            pos += 10 + dataLen;
        }
        return list;
    }

    public synchronized byte[] updateAdvCacheAndMerge(AdvReportItem item) {
        long now = System.currentTimeMillis();
        CachedAdvState st = advCache.get(item.mac);
        if (st == null) {
            if (advCache.size() >= 128) {
                String oldestKey = advCache.keySet().iterator().next();
                advCache.remove(oldestKey);
            }
            st = new CachedAdvState();
            advCache.put(item.mac, st);
        } else if (now - st.updatedMs > 15000L) {
            st.advData = new byte[0];
            st.scanRspData = new byte[0];
        }
        st.addrType = item.addrType;
        st.updatedMs = now;

        if (item.eventType == 0x04) { // SCAN_RSP
            st.scanRspData = trimTrailingZeroAdPadding(item.data);
        } else {
            st.advData = trimTrailingZeroAdPadding(item.data);
        }

        int len1 = st.advData.length;
        int len2 = Math.min(st.scanRspData.length, Math.max(0, 62 - len1));
        byte[] merged = new byte[Math.min(62, len1 + len2)];
        int copy1 = Math.min(len1, merged.length);
        System.arraycopy(st.advData, 0, merged, 0, copy1);
        if (len2 > 0 && copy1 + len2 <= merged.length) {
            System.arraycopy(st.scanRspData, 0, merged, copy1, len2);
        }
        return merged;
    }

    private synchronized Integer getCachedAddrType(String mac) {
        CachedAdvState st = advCache.get(mac);
        return (st != null) ? Integer.valueOf(st.addrType) : null;
    }

    public static byte[] trimTrailingZeroAdPadding(byte[] ad) {
        if (ad == null || ad.length == 0) return new byte[0];
        int pos = 0;
        while (pos < ad.length) {
            int fieldLen = ad[pos] & 0xFF;
            if (fieldLen == 0) break;
            if (pos + 1 + fieldLen > ad.length) {
                pos = ad.length;
                break;
            }
            pos += 1 + fieldLen;
        }
        byte[] out = new byte[pos];
        System.arraycopy(ad, 0, out, 0, pos);
        return out;
    }

    public static String decodeAttUuid(byte[] buf, int off, int len) {
        if (len == 2 && off + 2 <= buf.length) {
            int u16 = u16le(buf, off);
            return String.format(Locale.US, "%04x", Integer.valueOf(u16));
        }
        if (len == 16 && off + 16 <= buf.length) {
            // Check Bluetooth Base UUID: 0000xxxx-0000-1000-8000-00805f9b34fb (stored little-endian in ATT)
            byte[] baseLe = new byte[]{
                    (byte) 0xFB, 0x34, (byte) 0x9B, 0x5F, (byte) 0x80, 0x00,
                    0x00, (byte) 0x80, 0x00, 0x10, 0x00, 0x00
            };
            boolean isBtBase = (buf[off + 14] == 0x00 && buf[off + 15] == 0x00);
            for (int i = 0; isBtBase && i < 12; i++) {
                if (buf[off + i] != baseLe[i]) {
                    isBtBase = false;
                }
            }
            if (isBtBase) {
                int u16 = u16le(buf, off + 12);
                return String.format(Locale.US, "%04x", Integer.valueOf(u16));
            }
            StringBuilder sb = new StringBuilder(36);
            for (int i = 15; i >= 0; i--) {
                sb.append(String.format(Locale.US, "%02x", Integer.valueOf(buf[off + i] & 0xFF)));
                if (i == 12 || i == 10 || i == 8 || i == 6) sb.append('-');
            }
            return sb.toString();
        }
        return "0000";
    }

    public static String normalizeUuidKey(String raw) {
        if (raw == null) return "";
        String s = raw.trim().toLowerCase(Locale.US);
        if (s.startsWith("0x")) {
            s = s.substring(2);
        }
        if (s.length() == 36 && s.startsWith("0000") && s.endsWith("-0000-1000-8000-00805f9b34fb")) {
            return s.substring(4, 8);
        }
        return s;
    }

    public static byte[] parseMacToLittleEndian(String mac) {
        if (mac == null) return null;
        String[] parts = mac.trim().split(":");
        if (parts.length != 6) return null;
        byte[] le = new byte[6];
        try {
            for (int i = 0; i < 6; i++) {
                if (parts[i].length() != 2) return null;
                le[5 - i] = (byte) Integer.parseInt(parts[i], 16);
            }
            return le;
        } catch (NumberFormatException nfe) {
            return null;
        }
    }

    public static String formatMacLittleEndian(byte[] b, int off) {
        return String.format(Locale.US, "%02X:%02X:%02X:%02X:%02X:%02X",
                Integer.valueOf(b[off + 5] & 0xFF),
                Integer.valueOf(b[off + 4] & 0xFF),
                Integer.valueOf(b[off + 3] & 0xFF),
                Integer.valueOf(b[off + 2] & 0xFF),
                Integer.valueOf(b[off + 1] & 0xFF),
                Integer.valueOf(b[off] & 0xFF));
    }

    public static int u16le(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8);
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
        if (hex == null) return null;
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

    private static int parsePositiveInt(String raw, int fallback) {
        if (raw == null) return fallback;
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException nfe) {
            return fallback;
        }
    }

    private static String sanitizeToken(String s) {
        if (s == null || s.isEmpty()) return "unknown";
        return s.replace('\n', '_').replace('\r', '_').replace(' ', '_');
    }

    private static void sleepQuietly(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException ignored) {}
    }
}
