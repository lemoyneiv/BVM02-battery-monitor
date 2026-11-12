package bvm02.hook;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.ParcelFileDescriptor;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.util.Locale;

import hmgapi.hook.LoadedApp;
import hmgapi.hook.ModContext;

/**
 * Lazy-loaded JNI bridge to {@code libbvm02_ble.so} inside {@code com.android.bluetooth}.
 *
 * Uses two anonymous kernel pipes ({@link ParcelFileDescriptor#createPipe()}) and primitive
 * {@code int} JNI arguments so zero {@code JNIEnv} object allocations occur on Bluedroid's
 * real-time HCI RX thread.
 */
public final class BtNativeBridge {

    public static final int TX_CMD_SEND_HCI = 1;
    public static final int TX_CMD_SEND_ACL = 2;

    public static final int RX_TYPE_ACL = 0x02;
    public static final int RX_TYPE_EVT = 0x04;

    public interface PacketSink {
        void onHciEvent(byte[] evtPkt);
        void onLeAcl(byte[] aclPkt);
    }

    public interface Transport {
        boolean sendHciCommand(byte[] hciCmd);
        boolean sendLeAcl(byte[] aclPkt);
        void setFilterState(boolean listening, int activeLeHandle);
    }

    private static final Object INIT_LOCK = new Object();
    private static final Object TX_LOCK = new Object();

    private static boolean soLoaded = false;
    private static boolean initialized = false;
    private static String loadedSoPath = "unloaded";
    private static String lastInitError = "none";
    private static int lastInitRc = -999;

    @SuppressWarnings("unused")
    private static ParcelFileDescriptor txWritePfd;
    @SuppressWarnings("unused")
    private static ParcelFileDescriptor rxReadPfd;
    private static OutputStream txOut;
    private static volatile PacketSink activeSink;

    private static final Transport LIVE_TRANSPORT = new Transport() {
        @Override
        public boolean sendHciCommand(byte[] hciCmd) {
            return sendTxFrame(TX_CMD_SEND_HCI, hciCmd);
        }

        @Override
        public boolean sendLeAcl(byte[] aclPkt) {
            return sendTxFrame(TX_CMD_SEND_ACL, aclPkt);
        }

        @Override
        public void setFilterState(boolean listening, int activeLeHandle) {
            if (!initialized) return;
            try {
                nativeSetState(listening ? 1 : 0, activeLeHandle);
            } catch (Throwable ignored) {}
        }
    };

    private BtNativeBridge() {}

    public static Transport getLiveTransport() {
        return LIVE_TRANSPORT;
    }

    public static void setPacketSink(PacketSink sink) {
        activeSink = sink;
    }

    public static boolean ensureInitialized(ModContext mod, LoadedApp app) {
        synchronized (INIT_LOCK) {
            if (initialized) {
                return true;
            }
            try {
                if (!soLoaded) {
                    File soFile = locateNativeLibrary(app);
                    if (soFile == null || !soFile.isFile()) {
                        lastInitError = "libbvm02_ble.so not found in /data/app-lib/bvm02.app*";
                        if (mod != null) {
                            mod.log("BtNativeBridge: " + lastInitError);
                        }
                        return false;
                    }
                    System.load(soFile.getAbsolutePath());
                    soLoaded = true;
                    loadedSoPath = soFile.getAbsolutePath();
                }

                ParcelFileDescriptor[] txPipe = ParcelFileDescriptor.createPipe();
                ParcelFileDescriptor[] rxPipe = ParcelFileDescriptor.createPipe();
                int rc = nativeInit(txPipe[0].getFd(), rxPipe[1].getFd());
                lastInitRc = rc;

                // C side dup()s txPipe[0] and rxPipe[1]; close Java duplicates immediately
                try { txPipe[0].close(); } catch (Throwable ignored) {}
                try { rxPipe[1].close(); } catch (Throwable ignored) {}

                if (rc != 0) {
                    try { txPipe[1].close(); } catch (Throwable ignored) {}
                    try { rxPipe[0].close(); } catch (Throwable ignored) {}
                    lastInitError = "nativeInit returned " + rc;
                    if (mod != null) {
                        mod.log("BtNativeBridge: " + lastInitError);
                    }
                    return false;
                }

                txWritePfd = txPipe[1];
                rxReadPfd = rxPipe[0];
                txOut = new ParcelFileDescriptor.AutoCloseOutputStream(txPipe[1]);
                final InputStream rxIn = new ParcelFileDescriptor.AutoCloseInputStream(rxPipe[0]);

                Thread rxThread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        runRxLoop(mod, rxIn);
                    }
                }, "Bvm02HciRxReader");
                rxThread.setDaemon(true);
                rxThread.setPriority(Thread.NORM_PRIORITY);
                rxThread.start();

                initialized = true;
                lastInitError = "OK";
                if (mod != null) {
                    mod.log("BtNativeBridge initialized from " + loadedSoPath);
                }
                return true;
            } catch (Throwable t) {
                lastInitError = t.getClass().getSimpleName() + ": " + t.getMessage();
                if (mod != null) {
                    mod.log("BtNativeBridge init failed: " + lastInitError);
                }
                return false;
            }
        }
    }

    public static final int HANDLE_OP_KEEP = -1;
    public static final int HANDLE_OP_CLEAR_ALL = -2;
    public static final int HANDLE_OP_UNTRACK_FLAG = 0x10000;

    public static int encodeUntrackHandle(int handle) {
        return HANDLE_OP_UNTRACK_FLAG | (handle & 0x0FFF);
    }

    public static void shutdown() {
        if (!soLoaded) return;
        try {
            nativeShutdown();
        } catch (Throwable ignored) {}
    }

    public static String describeStatus(ModContext mod, LoadedApp app) {
        boolean ok = ensureInitialized(mod, app);
        int hookInstalled = -1;
        int workerAlive = -1;
        int rxEvt = -1;
        int rxAcl = -1;
        int txHci = -1;
        int txAcl = -1;
        int rxDrop = -1;
        int activeHandle = 0xFFFF;
        int activeHandleCount = 0;
        if (soLoaded) {
            try {
                hookInstalled = nativeGetStat(0);
                workerAlive = nativeGetStat(1);
                rxEvt = nativeGetStat(2);
                rxAcl = nativeGetStat(3);
                txHci = nativeGetStat(4);
                txAcl = nativeGetStat(5);
                rxDrop = nativeGetStat(6);
                activeHandle = nativeGetStat(7);
                activeHandleCount = nativeGetStat(8);
            } catch (Throwable ignored) {}
        }
        return String.format(Locale.US,
                "ready=%s soLoaded=%s path=%s initRc=%d err=%s hookInstalled=%d worker=%d activeHandle=0x%04x activeHandles=%d txHci=%d txAcl=%d rxEvt=%d rxAcl=%d rxDrop=%d",
                Boolean.valueOf(ok), Boolean.valueOf(soLoaded), loadedSoPath,
                Integer.valueOf(lastInitRc), lastInitError,
                Integer.valueOf(hookInstalled), Integer.valueOf(workerAlive),
                Integer.valueOf(activeHandle & 0xFFFF),
                Integer.valueOf(Math.max(0, activeHandleCount)),
                Integer.valueOf(txHci), Integer.valueOf(txAcl),
                Integer.valueOf(rxEvt), Integer.valueOf(rxAcl), Integer.valueOf(rxDrop));
    }

    private static boolean sendTxFrame(int cmdType, byte[] payload) {
        if (!initialized || payload == null || payload.length == 0 || payload.length > 1024) {
            return false;
        }
        byte[] frame = new byte[4 + payload.length];
        frame[0] = (byte) (cmdType & 0xFF);
        frame[1] = 0;
        frame[2] = (byte) (payload.length & 0xFF);
        frame[3] = (byte) ((payload.length >> 8) & 0xFF);
        System.arraycopy(payload, 0, frame, 4, payload.length);

        synchronized (TX_LOCK) {
            if (txOut == null) return false;
            try {
                txOut.write(frame);
                txOut.flush();
                return true;
            } catch (Throwable t) {
                return false;
            }
        }
    }

    private static void runRxLoop(ModContext mod, InputStream rxIn) {
        byte[] hdr = new byte[4];
        try {
            while (readExact(rxIn, hdr, 4)) {
                int pktType = hdr[0] & 0xFF;
                int len = (hdr[2] & 0xFF) | ((hdr[3] & 0xFF) << 8);
                if (len <= 0 || len > 1028) {
                    if (len > 0) {
                        byte[] discard = new byte[Math.min(len, 2048)];
                        readExact(rxIn, discard, discard.length);
                    }
                    continue;
                }
                byte[] pkt = new byte[len];
                if (!readExact(rxIn, pkt, len)) {
                    break;
                }
                PacketSink sink = activeSink;
                if (sink != null) {
                    try {
                        if (pktType == RX_TYPE_EVT) {
                            sink.onHciEvent(pkt);
                        } else if (pktType == RX_TYPE_ACL) {
                            sink.onLeAcl(pkt);
                        }
                    } catch (Throwable dispatchErr) {
                        if (mod != null) {
                            mod.log("BtNativeBridge dispatch err: " + dispatchErr);
                        }
                    }
                }
            }
        } catch (Throwable rxErr) {
            if (mod != null) {
                mod.log("BtNativeBridge RX loop ended: " + rxErr);
            }
        }
    }

    private static boolean readExact(InputStream in, byte[] dst, int len) throws Exception {
        int off = 0;
        while (off < len) {
            int n = in.read(dst, off, len - off);
            if (n < 0) return false;
            off += n;
        }
        return true;
    }

    private static File locateNativeLibrary(LoadedApp app) {
        String[] hostPackages = {"bvm02.app", "gen5w.ble.service"};
        String[] soNames = {"libbvm02_ble.so", "libgen5w_ble.so"};
        Context ctx = resolveContext(app);
        if (ctx != null) {
            try {
                PackageManager pm = ctx.getPackageManager();
                if (pm != null) {
                    for (int p = 0; p < hostPackages.length; p++) {
                        try {
                            ApplicationInfo ai = pm.getApplicationInfo(hostPackages[p], 0);
                            if (ai != null && ai.nativeLibraryDir != null) {
                                for (int s = 0; s < soNames.length; s++) {
                                    File cand = new File(ai.nativeLibraryDir, soNames[s]);
                                    if (cand.isFile()) {
                                        return cand;
                                    }
                                }
                            }
                        } catch (Throwable ignored) {}
                    }
                }
            } catch (Throwable ignored) {}
        }

        String[] fallbackDirs = {
                "/data/app-lib/bvm02.app-1",
                "/data/app-lib/bvm02.app-2",
                "/data/app-lib/bvm02.app-3",
                "/data/app-lib/bvm02.app",
                "/data/app-lib/gen5w.ble.service-1",
                "/data/app-lib/gen5w.ble.service-2"
        };
        for (int i = 0; i < fallbackDirs.length; i++) {
            for (int s = 0; s < soNames.length; s++) {
                File cand = new File(fallbackDirs[i], soNames[s]);
                if (cand.isFile()) {
                    return cand;
                }
            }
        }
        try {
            File appLibRoot = new File("/data/app-lib");
            File[] dirs = appLibRoot.listFiles();
            if (dirs != null) {
                for (int i = 0; i < dirs.length; i++) {
                    if (dirs[i] != null && dirs[i].isDirectory()) {
                        for (int s = 0; s < soNames.length; s++) {
                            File cand = new File(dirs[i], soNames[s]);
                            if (cand.isFile()) {
                                return cand;
                            }
                        }
                    }
                }
            }
        } catch (Throwable ignored) {}
        return null;
    }

    private static Context resolveContext(LoadedApp app) {
        if (app != null && app.context != null) {
            return app.context;
        }
        try {
            Class<?> atCls = Class.forName("android.app.ActivityThread");
            Method mCur = atCls.getMethod("currentApplication");
            Object obj = mCur.invoke(null);
            if (obj instanceof Context) {
                return (Context) obj;
            }
        } catch (Throwable ignored) {}
        return null;
    }

    private static native int nativeInit(int txReadFd, int rxWriteFd);
    private static native int nativeSetState(int bleListening, int activeLeHandle);
    private static native int nativeGetStat(int which);
    private static native void nativeShutdown();
}
