package bvm02.hook;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import hmgapi.hook.ModContext;

/**
 * Coexistence-safe Bluetooth 4.x HCI LE Scanner, L2CAP Reassembler, and ATT/GATT Central
 * running inside {@code com.android.bluetooth} over {@link BtNativeBridge}.
 *
 * Designed specifically for Gen5W head units where {@code GattService} is manifest-disabled
 * and {@code bplus.default.so} is compiled with {@code BLE_INCLUDED=FALSE}, while preserving
 * 100% of simultaneous Classic Bluetooth ({@code HFP} / {@code A2DP}) traffic.
 */
public final class BleGattSessionManager implements BtNativeBridge.PacketSink {

    private static final Charset UTF8 = Charset.forName("UTF-8");

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

        public DiscoveredChar(String shortUuid, int declHandle, int valHandle, int props) {
            this.shortUuid = shortUuid;
            this.declHandle = declHandle;
            this.valHandle = valHandle;
            this.props = props;
            this.endHandle = valHandle;
            this.cccdHandle = 0;
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
    private final Object attLock = new Object();
    private final Object sessionSwapLock = new Object();

    // Cached advertising address types & merged AD payloads across scans
    private final Map<String, CachedAdvState> advCache = new LinkedHashMap<String, CachedAdvState>();

    //HCI synchronous waiter state
    private int waitingOpcode = -1;
    private byte[] completedCmdEvent = null;
    private int cmdStatusValue = -1;

    // Connection / Scan state
    private boolean controllerInitialized = false;
    private int maxLeAclCredits = 2;
    private int inflightLeAclPkts = 0;
    private volatile boolean scanning = false;
    private volatile boolean cancelConnectRequested = false;
    private volatile int activeConnHandle = -1;
    private volatile String activeConnMac = "";
    private byte[] pendingLeConnEvent = null;

    // L2CAP reassembly buffer for activeConnHandle
    private ByteArrayOutputStream l2capReassembly = null;
    private int l2capExpectedLen = 0;
    private int l2capCurrentCid = 0;

    // ATT synchronous waiter & discovered GATT characteristics
    private boolean attAwaitingResponse = false;
    private byte[] pendingAttResponse = null;
    private final Map<String, DiscoveredChar> charByUuid = new LinkedHashMap<String, DiscoveredChar>();
    private final Map<Integer, DiscoveredChar> charByValHandle = new LinkedHashMap<Integer, DiscoveredChar>();

    // Active stream session output emitter
    private volatile LineEmitter activeEmitter = null;
    private volatile OutputStream activeSessionSocketOut = null;

    public BleGattSessionManager(BtNativeBridge.Transport transport) {
        this.transport = transport;
    }

    public void onModDisabled() {
        cancelConnectRequested = true;
        synchronized (hciLock) {
            hciLock.notifyAll();
        }
        synchronized (attLock) {
            attLock.notifyAll();
        }
        cleanupSessionHardwareState();
        closeActiveSocketStreamQuietly();
    }

    /**
     * Runs a full-duplex persistent BLE control & notification stream over {@code @bvm02_ble}.
     * Preempts any stale prior client session cleanly.
     */
    public void runStreamSession(final ModContext mod, BufferedReader reader, final OutputStream os) {
        synchronized (sessionSwapLock) {
            cancelConnectRequested = true;
            synchronized (hciLock) {
                hciLock.notifyAll();
            }
            closeActiveSocketStreamQuietly();
            cleanupSessionHardwareState();
            activeSessionSocketOut = os;
        }

        final Object writeLock = new Object();
        final LineEmitter emitter = new LineEmitter() {
            @Override
            public void emitLine(String line) {
                synchronized (writeLock) {
                    if (activeSessionSocketOut != os) return;
                    try {
                        os.write((line + "\n").getBytes(UTF8));
                        os.flush();
                    } catch (Throwable ignored) {}
                }
            }
        };
        activeEmitter = emitter;
        transport.setFilterState(true, -1);

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
                        executeSessionCommand(mod, cmdLine, emitter);
                    } catch (Throwable cmdErr) {
                        if (mod != null) {
                            mod.log("BleGattSessionManager cmd err (" + cmdLine + "): " + cmdErr);
                        }
                        emitter.emitLine("ERR CMD_EXCEPTION " + sanitizeToken(cmdErr.getMessage()));
                    }
                }
            }
        }, "Bvm02BleSessionWorker");
        worker.setDaemon(true);
        worker.start();

        emitter.emitLine("OK STREAM_READY version=" + BtHookEntry.HOOK_VERSION);

        try {
            String raw;
            while ((raw = reader.readLine()) != null) {
                String trimmed = raw.trim();
                if (trimmed.isEmpty()) continue;
                if ("QUIT".equals(trimmed)) {
                    cancelConnectRequested = true;
                    synchronized (hciLock) {
                        hciLock.notifyAll();
                    }
                    break;
                }
                if ("DISCONNECT".equals(trimmed) || "SCAN_STOP".equals(trimmed)) {
                    if ("DISCONNECT".equals(trimmed)) {
                        cancelConnectRequested = true;
                        synchronized (hciLock) {
                            hciLock.notifyAll();
                        }
                        synchronized (attLock) {
                            attLock.notifyAll();
                        }
                    }
                }
                synchronized (queueLock) {
                    if (cmdQueue.size() < 64) {
                        cmdQueue.add(trimmed);
                        queueLock.notifyAll();
                    }
                }
            }
        } catch (Throwable ignored) {
        } finally {
            cancelConnectRequested = true;
            synchronized (hciLock) {
                hciLock.notifyAll();
            }
            synchronized (attLock) {
                attLock.notifyAll();
            }
            synchronized (queueLock) {
                readerDone[0] = true;
                cmdQueue.clear();
                queueLock.notifyAll();
            }
            try {
                worker.join(2500L);
            } catch (InterruptedException ignored) {}

            synchronized (sessionSwapLock) {
                if (activeSessionSocketOut == os) {
                    activeEmitter = null;
                    activeSessionSocketOut = null;
                    cleanupSessionHardwareState();
                    transport.setFilterState(false, -1);
                }
            }
        }
    }

    public void executeSessionCommand(ModContext mod, String line, LineEmitter emitter) {
        if (activeEmitter == null && emitter != null) {
            activeEmitter = emitter;
        }
        String[] parts = line.split("\\s+");
        if (parts.length == 0) return;
        String verb = parts[0];

        if ("PING".equals(verb)) {
            emitter.emitLine("PONG");
            return;
        }
        if ("SCAN_START".equals(verb)) {
            startBleScan(mod, emitter);
            return;
        }
        if ("SCAN_STOP".equals(verb)) {
            stopBleScan(emitter);
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
            connectAndDiscover(mod, mac, addrTypeHint, emitter);
            return;
        }
        if ("DISCONNECT".equals(verb)) {
            disconnectActiveLink(emitter, "USER_REQUESTED");
            return;
        }
        if ("ENABLE_NOTIFY".equals(verb) && parts.length >= 2) {
            String uuid = normalizeUuidKey(parts[1]);
            handleEnableNotify(uuid, emitter);
            return;
        }
        if ("READ_CHAR".equals(verb) && parts.length >= 2) {
            String uuid = normalizeUuidKey(parts[1]);
            handleReadChar(uuid, emitter);
            return;
        }
        if ("WRITE_CHAR".equals(verb) && parts.length >= 3) {
            String uuid = normalizeUuidKey(parts[1]);
            byte[] payload = hexToBytes(parts[2]);
            handleWriteChar(uuid, payload, emitter);
            return;
        }
        emitter.emitLine("ERR UNKNOWN_SESSION_CMD " + sanitizeToken(verb));
    }

    // ================= CONTROLLER INIT, SCAN & CONNECT =================

    private boolean ensureControllerLeReady(ModContext mod) {
        transport.setFilterState(true, activeConnHandle);
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
            if (leNumPkts > 0) {
                maxLeAclCredits = Math.min(leNumPkts, 4);
            } else {
                maxLeAclCredits = 2; // Shared BR/EDR ACL pool: cap conservatively to protect A2DP
            }
            if (mod != null) {
                mod.log("Controller LE ready: leAclLen=" + lePktLen + " leNumPkts=" + leNumPkts
                        + " creditCap=" + maxLeAclCredits);
            }
        }

        controllerInitialized = true;
        return true;
    }

    private void startBleScan(ModContext mod, LineEmitter emitter) {
        if (!ensureControllerLeReady(mod)) {
            emitter.emitLine("SCAN_STATE 0 ERR_CONTROLLER_INIT");
            return;
        }

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
            emitter.emitLine("SCAN_STATE 0 ERR_SCAN_PARAMS_" + st);
            return;
        }

        // Enable scan with Filter_Duplicates=0x00 so SCAN_RSP updates always arrive
        byte[] enRsp = sendHciCmdSync(HCI_LE_SET_SCAN_ENABLE, new byte[]{0x01, 0x00}, 1200L);
        if (enRsp == null || enRsp.length < 6 || (enRsp[5] & 0xFF) != 0) {
            int st = (enRsp != null && enRsp.length >= 6) ? (enRsp[5] & 0xFF) : -1;
            scanning = false;
            emitter.emitLine("SCAN_STATE 0 ERR_SCAN_ENABLE_" + st);
            return;
        }

        scanning = true;
        emitter.emitLine("SCAN_STATE 1");
    }

    private void stopBleScan(LineEmitter emitter) {
        if (scanning) {
            sendHciCmdSync(HCI_LE_SET_SCAN_ENABLE, new byte[]{0x00, 0x00}, 1000L);
            scanning = false;
        }
        if (emitter != null) {
            emitter.emitLine("SCAN_STATE 0");
        }
    }

    private void connectAndDiscover(ModContext mod, String mac, int addrTypeHint, LineEmitter emitter) {
        byte[] macLe = parseMacToLittleEndian(mac);
        if (macLe == null) {
            emitter.emitLine("CONN_STATE DISCONNECTED " + mac + " status=255 reason=INVALID_MAC");
            return;
        }
        if (!ensureControllerLeReady(mod)) {
            emitter.emitLine("CONN_STATE DISCONNECTED " + mac + " status=254 reason=ERR_CONTROLLER_INIT");
            return;
        }

        // Always stop scan and close any prior LE link before HCI_LE_Create_Connection
        stopBleScan(null);
        disconnectActiveLink(null, null);

        int[] candidateAddrTypes;
        if (addrTypeHint == 0 || addrTypeHint == 1) {
            candidateAddrTypes = new int[]{addrTypeHint};
        } else {
            Integer cached = getCachedAddrType(mac);
            if (cached != null) {
                int primary = cached.intValue();
                candidateAddrTypes = new int[]{primary, primary == 0 ? 1 : 0};
            } else {
                // Unknown address type (e.g., manual Add by MAC): try Public (0) then Random (1)
                candidateAddrTypes = new int[]{0, 1};
            }
        }

        cancelConnectRequested = false;
        emitter.emitLine("CONN_STATE CONNECTING " + mac);

        byte[] connEvt = null;
        int lastStatus = -1;
        for (int attempt = 0; attempt < candidateAddrTypes.length; attempt++) {
            if (cancelConnectRequested) {
                emitter.emitLine("CONN_STATE DISCONNECTED " + mac + " status=0 reason=CANCELED");
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
                // 0x0C = Command Disallowed (stale pending create_conn): cancel once and retry
                if (cmdStatus == 0x0C) {
                    sendHciCmdSync(HCI_LE_CREATE_CONNECTION_CANCEL, new byte[0], 1000L);
                }
                continue;
            }

            long deadline = System.currentTimeMillis() + waitMs;
            synchronized (hciLock) {
                while (pendingLeConnEvent == null && !cancelConnectRequested) {
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
                // Cancel pending initiator state in controller before next attempt or exit
                sendHciCmdSync(HCI_LE_CREATE_CONNECTION_CANCEL, new byte[0], 1000L);
                // Consume the 0x02 (Unknown Connection Identifier / Canceled) LE_Connection_Complete event
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
                lastStatus = 133; // Timeout
            }
        }

        if (cancelConnectRequested) {
            if (connEvt != null && (connEvt[3] & 0xFF) == 0) {
                int h = u16le(connEvt, 4) & 0x0FFF;
                sendDisconnectCmd(h);
            }
            transport.setFilterState(true, -1);
            emitter.emitLine("CONN_STATE DISCONNECTED " + mac + " status=0 reason=CANCELED");
            return;
        }

        if (connEvt == null || (connEvt[3] & 0xFF) != 0) {
            transport.setFilterState(true, -1);
            emitter.emitLine("CONN_STATE DISCONNECTED " + mac + " status=" + lastStatus + " reason=CONNECT_TIMEOUT");
            return;
        }

        int handle = u16le(connEvt, 4) & 0x0FFF;
        synchronized (hciLock) {
            activeConnHandle = handle;
            activeConnMac = mac;
            inflightLeAclPkts = 0;
            l2capReassembly = null;
            l2capExpectedLen = 0;
        }
        transport.setFilterState(true, handle);

        if (mod != null) {
            mod.log("BLE connected to " + mac + " handle=0x" + Integer.toHexString(handle));
        }
        emitter.emitLine(String.format(Locale.US, "CONN_STATE DISCOVERING %s handle=0x%04x",
                mac, Integer.valueOf(handle)));

        // Brief settle window before ATT service discovery (matches KitKat Broadcom peripheral timing)
        sleepQuietly(150L);
        if (activeConnHandle != handle) {
            return;
        }

        discoverBvm02GattTable(mac, emitter);
    }

    private void disconnectActiveLink(LineEmitter emitter, String reason) {
        int h;
        String prevMac;
        synchronized (hciLock) {
            h = activeConnHandle;
            prevMac = activeConnMac;
            activeConnHandle = -1;
            activeConnMac = "";
            inflightLeAclPkts = 0;
            l2capReassembly = null;
            l2capExpectedLen = 0;
            hciLock.notifyAll();
        }
        synchronized (attLock) {
            charByUuid.clear();
            charByValHandle.clear();
            attLock.notifyAll();
        }
        if (h >= 0 && h <= 0x0EFF) {
            // Keep C filter active briefly so Disconnection_Complete (0x05) is consumed cleanly
            sendDisconnectCmd(h);
            sleepQuietly(180L);
        }
        transport.setFilterState(true, -1);
        if (emitter != null && prevMac != null && !prevMac.isEmpty()) {
            emitter.emitLine("CONN_STATE DISCONNECTED " + prevMac + " status=0 reason="
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

    private void cleanupSessionHardwareState() {
        stopBleScan(null);
        disconnectActiveLink(null, null);
    }

    private void closeActiveSocketStreamQuietly() {
        OutputStream prev = activeSessionSocketOut;
        if (prev != null) {
            try { prev.close(); } catch (Throwable ignored) {}
        }
    }

    // ================= ATT / GATT CENTRAL DISCOVERY & OPERATIONS =================

    public boolean discoverBvm02GattTable(String mac, LineEmitter emitter) {
        synchronized (attLock) {
            charByUuid.clear();
            charByValHandle.clear();
        }

        int fff0Start = 0;
        int fff0End = 0;

        // 1. Discover Primary Services (UUID 0x2800) via ATT_READ_BY_GROUP_TYPE_REQ (0x10)
        int curStart = 0x0001;
        int guard = 0;
        while (curStart <= 0xFFFF && guard++ < 32) {
            byte[] req = new byte[]{
                    (byte) ATT_READ_BY_GROUP_TYPE_REQ,
                    (byte) (curStart & 0xFF), (byte) ((curStart >> 8) & 0xFF),
                    (byte) 0xFF, (byte) 0xFF,
                    0x00, 0x28
            };
            byte[] rsp = transactAtt(req, 3000L);
            if (rsp == null) {
                disconnectActiveLink(emitter, "ATT_SVC_DISCOVERY_TIMEOUT");
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
                emitter.emitLine(String.format(Locale.US, "GATT_SVC %s %04x %04x",
                        svcUuid, Integer.valueOf(sHandle), Integer.valueOf(eHandle)));
                if ("fff0".equals(svcUuid)) {
                    fff0Start = sHandle;
                    fff0End = eHandle;
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

        int searchStart = (fff0Start > 0 && fff0End >= fff0Start) ? fff0Start : 0x0001;
        int searchEnd = (fff0Start > 0 && fff0End >= fff0Start) ? fff0End : 0xFFFF;

        // 2. Discover Characteristics (UUID 0x2803) via ATT_READ_BY_TYPE_REQ (0x08)
        List<DiscoveredChar> discovered = new ArrayList<DiscoveredChar>();
        curStart = searchStart;
        guard = 0;
        while (curStart <= searchEnd && guard++ < 48) {
            byte[] req = new byte[]{
                    (byte) ATT_READ_BY_TYPE_REQ,
                    (byte) (curStart & 0xFF), (byte) ((curStart >> 8) & 0xFF),
                    (byte) (searchEnd & 0xFF), (byte) ((searchEnd >> 8) & 0xFF),
                    0x03, 0x28
            };
            byte[] rsp = transactAtt(req, 3000L);
            if (rsp == null) {
                disconnectActiveLink(emitter, "ATT_CHAR_DISCOVERY_TIMEOUT");
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
            synchronized (attLock) {
                charByUuid.put(c.shortUuid, c);
                charByValHandle.put(Integer.valueOf(c.valHandle), c);
            }
            emitter.emitLine(String.format(Locale.US, "GATT_CHAR %s %02x %04x %04x",
                    c.shortUuid, Integer.valueOf(c.props),
                    Integer.valueOf(c.valHandle), Integer.valueOf(c.endHandle)));
        }

        boolean hasBvm02Chars;
        StringBuilder specCsv = new StringBuilder();
        synchronized (attLock) {
            hasBvm02Chars = (fff0Start > 0)
                    || charByUuid.containsKey("fff2")
                    || charByUuid.containsKey("fff4")
                    || charByUuid.containsKey("fff1");
            for (DiscoveredChar c : charByUuid.values()) {
                if (specCsv.length() > 0) specCsv.append(',');
                specCsv.append(c.shortUuid).append(':').append(String.format(Locale.US, "%02x", Integer.valueOf(c.props)));
            }
        }

        if (!hasBvm02Chars) {
            disconnectActiveLink(emitter, "MISSING_SERVICE_FFF0");
            return false;
        }

        emitter.emitLine("GATT_READY " + mac + " " + (specCsv.length() > 0 ? specCsv.toString() : "none"));
        return true;
    }

    public void handleEnableNotify(String shortUuid, LineEmitter emitter) {
        DiscoveredChar ch;
        synchronized (attLock) {
            ch = charByUuid.get(shortUuid);
        }
        if (ch == null) {
            emitter.emitLine("OP_ERR ENABLE_NOTIFY " + shortUuid + " CHAR_NOT_FOUND");
            return;
        }

        if (ch.cccdHandle == 0 && ch.valHandle < ch.endHandle) {
            int startH = ch.valHandle + 1;
            int endH = Math.min(ch.endHandle, ch.valHandle + 6);
            byte[] findReq = new byte[]{
                    (byte) ATT_FIND_INFO_REQ,
                    (byte) (startH & 0xFF), (byte) ((startH >> 8) & 0xFF),
                    (byte) (endH & 0xFF), (byte) ((endH >> 8) & 0xFF)
            };
            byte[] findRsp = transactAtt(findReq, 2500L);
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

        if (ch.cccdHandle == 0) {
            // Peripheral exposes notify without separate 0x2902 descriptor handle
            emitter.emitLine("OP_OK ENABLE_NOTIFY " + shortUuid);
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
        byte[] rsp = transactAtt(writeCccd, 2500L);
        if (rsp != null && (rsp[0] & 0xFF) == ATT_WRITE_RSP) {
            emitter.emitLine("OP_OK ENABLE_NOTIFY " + shortUuid);
        } else {
            emitter.emitLine("OP_ERR ENABLE_NOTIFY " + shortUuid + " CCCD_WRITE_FAILED");
        }
    }

    public void handleReadChar(String shortUuid, LineEmitter emitter) {
        DiscoveredChar ch;
        synchronized (attLock) {
            ch = charByUuid.get(shortUuid);
        }
        if (ch == null) {
            emitter.emitLine("OP_ERR READ_CHAR " + shortUuid + " CHAR_NOT_FOUND");
            return;
        }
        byte[] req = new byte[]{
                (byte) ATT_READ_REQ,
                (byte) (ch.valHandle & 0xFF),
                (byte) ((ch.valHandle >> 8) & 0xFF)
        };
        byte[] rsp = transactAtt(req, 2500L);
        if (rsp == null) {
            emitter.emitLine("OP_ERR READ_CHAR " + shortUuid + " TIMEOUT");
            return;
        }
        int op = rsp[0] & 0xFF;
        if (op == ATT_READ_RSP) {
            byte[] val = new byte[rsp.length - 1];
            if (val.length > 0) {
                System.arraycopy(rsp, 1, val, 0, val.length);
            }
            emitter.emitLine("OP_OK READ_CHAR " + shortUuid + " " + (val.length > 0 ? bytesToHex(val) : "-"));
        } else if (op == ATT_ERROR_RSP && rsp.length >= 5) {
            emitter.emitLine("OP_ERR READ_CHAR " + shortUuid + " ATT_ERR_0x"
                    + Integer.toHexString(rsp[4] & 0xFF));
        } else {
            emitter.emitLine("OP_ERR READ_CHAR " + shortUuid + " UNEXPECTED_RSP");
        }
    }

    public void handleWriteChar(String shortUuid, byte[] payload, LineEmitter emitter) {
        if ("fff1".equals(shortUuid)) {
            emitter.emitLine("OP_ERR WRITE_CHAR fff1 FORBIDDEN_READ_ONLY_FFF1");
            return;
        }
        if (payload == null) {
            emitter.emitLine("OP_ERR WRITE_CHAR " + shortUuid + " INVALID_HEX");
            return;
        }
        DiscoveredChar ch;
        synchronized (attLock) {
            ch = charByUuid.get(shortUuid);
        }
        if (ch == null) {
            emitter.emitLine("OP_ERR WRITE_CHAR " + shortUuid + " CHAR_NOT_FOUND");
            return;
        }

        // Default ATT MTU is 23 bytes -> max 20-byte attribute value payload
        int len = Math.min(payload.length, 20);
        boolean useWriteReq = ((ch.props & 0x08) != 0) || ((ch.props & 0x04) == 0);
        byte[] pdu = new byte[3 + len];
        pdu[0] = (byte) (useWriteReq ? ATT_WRITE_REQ : ATT_WRITE_CMD);
        pdu[1] = (byte) (ch.valHandle & 0xFF);
        pdu[2] = (byte) ((ch.valHandle >> 8) & 0xFF);
        System.arraycopy(payload, 0, pdu, 3, len);

        if (!useWriteReq) {
            boolean ok = sendL2capPdu(L2CAP_CID_ATT, pdu, 2000L);
            emitter.emitLine(ok ? ("OP_OK WRITE_CHAR " + shortUuid)
                    : ("OP_ERR WRITE_CHAR " + shortUuid + " ACL_TX_FAILED"));
            return;
        }

        byte[] rsp = transactAtt(pdu, 2500L);
        if (rsp != null && (rsp[0] & 0xFF) == ATT_WRITE_RSP) {
            emitter.emitLine("OP_OK WRITE_CHAR " + shortUuid);
        } else if (rsp != null && (rsp[0] & 0xFF) == ATT_ERROR_RSP && rsp.length >= 5) {
            emitter.emitLine("OP_ERR WRITE_CHAR " + shortUuid + " ATT_ERR_0x"
                    + Integer.toHexString(rsp[4] & 0xFF));
        } else {
            emitter.emitLine("OP_ERR WRITE_CHAR " + shortUuid + " TIMEOUT");
        }
    }

    private byte[] transactAtt(byte[] attReq, long timeoutMs) {
        synchronized (attLock) {
            if (activeConnHandle < 0) return null;
            pendingAttResponse = null;
            attAwaitingResponse = true;
        }
        if (!sendL2capPdu(L2CAP_CID_ATT, attReq, timeoutMs)) {
            synchronized (attLock) {
                attAwaitingResponse = false;
            }
            return null;
        }
        long deadline = System.currentTimeMillis() + timeoutMs;
        synchronized (attLock) {
            try {
                while (pendingAttResponse == null && activeConnHandle >= 0 && !cancelConnectRequested) {
                    long rem = deadline - System.currentTimeMillis();
                    if (rem <= 0L) break;
                    attLock.wait(rem);
                }
                return pendingAttResponse;
            } catch (InterruptedException ie) {
                return null;
            } finally {
                attAwaitingResponse = false;
                pendingAttResponse = null;
            }
        }
    }

    // ================= HCI & L2CAP PACKET FRAMING / DISPATCH =================

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

    private boolean sendL2capPdu(int cid, byte[] l2capPayload, long creditWaitMs) {
        int handle;
        long deadline = System.currentTimeMillis() + creditWaitMs;
        synchronized (hciLock) {
            while (activeConnHandle >= 0 && inflightLeAclPkts >= maxLeAclCredits) {
                long rem = deadline - System.currentTimeMillis();
                if (rem <= 0L) break;
                try {
                    hciLock.wait(rem);
                } catch (InterruptedException ie) {
                    return false;
                }
            }
            handle = activeConnHandle;
            if (handle < 0 || handle > 0x0EFF) {
                return false;
            }
            inflightLeAclPkts++;
        }

        byte[] acl = wrapLeAclL2cap(handle, cid, l2capPayload);
        boolean ok = transport.sendLeAcl(acl);
        if (!ok) {
            synchronized (hciLock) {
                if (inflightLeAclPkts > 0) inflightLeAclPkts--;
                hciLock.notifyAll();
            }
        }
        return ok;
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
                if (activeConnHandle >= 0 && 3 + numH * 4 <= ev.length) {
                    for (int i = 0; i < numH; i++) {
                        int h = u16le(ev, 3 + i * 4) & 0x0FFF;
                        int completed = u16le(ev, 5 + i * 4);
                        if (h == activeConnHandle && completed > 0) {
                            inflightLeAclPkts = Math.max(0, inflightLeAclPkts - completed);
                            hciLock.notifyAll();
                        }
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
            String droppedMac = null;
            synchronized (hciLock) {
                if (st == 0 && h == activeConnHandle) {
                    droppedMac = activeConnMac;
                    activeConnHandle = -1;
                    activeConnMac = "";
                    inflightLeAclPkts = 0;
                    l2capReassembly = null;
                    hciLock.notifyAll();
                }
            }
            if (droppedMac != null) {
                transport.setFilterState(true, -1);
                synchronized (attLock) {
                    charByUuid.clear();
                    charByValHandle.clear();
                    attLock.notifyAll();
                }
                LineEmitter em = activeEmitter;
                if (em != null && !droppedMac.isEmpty()) {
                    em.emitLine("CONN_STATE DISCONNECTED " + droppedMac
                            + " status=" + reason + " reason=REMOTE_DISCONNECT_0x"
                            + Integer.toHexString(reason));
                }
            }
            return;
        }

        // LE Meta Event (0x3E)
        if (evCode == 0x3E && ev.length >= 3) {
            int sub = ev[2] & 0xFF;
            if (sub == 0x02) { // LE_Advertising_Report
                List<AdvReportItem> reports = parseLeAdvertisingReports(ev);
                LineEmitter em = activeEmitter;
                for (int i = 0; i < reports.size(); i++) {
                    AdvReportItem r = reports.get(i);
                    byte[] merged = updateAdvCacheAndMerge(r);
                    if (scanning && em != null) {
                        em.emitLine("ADV " + r.mac + " " + r.addrType + " " + r.rssi + " "
                                + (merged.length > 0 ? bytesToHex(merged) : "-"));
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

        int completedCid = -1;
        byte[] completedPdu = null;

        synchronized (hciLock) {
            if (handle != activeConnHandle) return;

            if (pbFlag == 0x02 || pbFlag == 0x00) {
                if (aclLen < 4) return;
                int l2capLen = u16le(acl, 4);
                int cid = u16le(acl, 6);
                int avail = aclLen - 4;
                if (avail >= l2capLen) {
                    completedCid = cid;
                    completedPdu = new byte[l2capLen];
                    System.arraycopy(acl, 8, completedPdu, 0, l2capLen);
                    l2capReassembly = null;
                    l2capExpectedLen = 0;
                } else if (l2capLen <= 512) {
                    l2capReassembly = new ByteArrayOutputStream(l2capLen);
                    l2capReassembly.write(acl, 8, avail);
                    l2capExpectedLen = l2capLen;
                    l2capCurrentCid = cid;
                }
            } else if (pbFlag == 0x01 && l2capReassembly != null) {
                l2capReassembly.write(acl, 4, aclLen);
                if (l2capReassembly.size() >= l2capExpectedLen) {
                    byte[] full = l2capReassembly.toByteArray();
                    completedCid = l2capCurrentCid;
                    completedPdu = new byte[l2capExpectedLen];
                    System.arraycopy(full, 0, completedPdu, 0, l2capExpectedLen);
                    l2capReassembly = null;
                    l2capExpectedLen = 0;
                }
            }
        }

        if (completedPdu != null) {
            handleCompleteL2capSdu(handle, completedCid, completedPdu);
        }
    }

    private void handleCompleteL2capSdu(final int handle, int cid, byte[] pdu) {
        if (pdu.length == 0) return;

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
                sendL2capPdu(L2CAP_CID_LE_SIGNALING, rsp, 500L);

                if (minInt >= 6 && maxInt >= minInt && maxInt <= 3200 && timeout >= 10 && timeout <= 3200) {
                    byte[] upd = new byte[]{
                            (byte) (handle & 0xFF), (byte) ((handle >> 8) & 0x0F),
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
        if (attOp == ATT_EXCHANGE_MTU_REQ) {
            // Respond with standard 23-byte LE default MTU
            sendL2capPdu(L2CAP_CID_ATT, new byte[]{(byte) ATT_EXCHANGE_MTU_RSP, 0x17, 0x00}, 500L);
            return;
        }

        if (attOp == ATT_HANDLE_VALUE_NTF || attOp == ATT_HANDLE_VALUE_IND) {
            if (attOp == ATT_HANDLE_VALUE_IND) {
                sendL2capPdu(L2CAP_CID_ATT, new byte[]{(byte) ATT_HANDLE_VALUE_CFM}, 500L);
            }
            if (pdu.length >= 3) {
                int valHandle = u16le(pdu, 1);
                DiscoveredChar ch;
                synchronized (attLock) {
                    ch = charByValHandle.get(Integer.valueOf(valHandle));
                }
                // Suppress unsolicited notifications outside Service 0xFFF0 (e.g. FW v1.14 emits
                // 10 Hz notifications on Battery Service 0x180F handle 0x0027 without CCCD write).
                if (ch == null) {
                    return;
                }
                byte[] val = new byte[pdu.length - 3];
                if (val.length > 0) {
                    System.arraycopy(pdu, 3, val, 0, val.length);
                }
                LineEmitter em = activeEmitter;
                if (em != null) {
                    em.emitLine("CHAR_NOTIFY " + ch.shortUuid + " " + (val.length > 0 ? bytesToHex(val) : "-"));
                }
            }
            return;
        }

        synchronized (attLock) {
            if (attAwaitingResponse) {
                pendingAttResponse = pdu;
                attLock.notifyAll();
            }
        }
    }

    // ================= PURE STATIC CODECS (HOST-UNIT-TESTABLE) =================

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
            // Check Bluetooth Base UUID: 0000xxxx-0000-1000-8000-00805f9b34fb (stored little-endian in ATT!)
            // LE bytes [0..11] = fb 34 9b 5f 80 00 00 80 00 10 00 00, [12..13] = xxxx, [14..15] = 00 00
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
