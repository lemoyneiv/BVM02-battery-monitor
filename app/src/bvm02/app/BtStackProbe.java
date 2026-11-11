package bvm02.app;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.os.IBinder;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Non-invasive, strictly read-only, in-RAM Gen5W Bluetooth & Broadcom BLE stack introspector.
 *
 * Gen5W head units (Android 4.4.2, API 19) ship Broadcom's proprietary Bluetooth framework
 * (/system/framework/com.broadcom.bt.jar) alongside or in place of stock AOSP Bluedroid GATT.
 * When BluetoothAdapter.startLeScan() returns false, this probe inspects:
 *   1. BluetoothAdapter internal mManagerService -> getBluetoothGatt() (IBluetoothGatt) & mService (IBluetooth)
 *   2. Runtime declared methods on BluetoothAdapter, BluetoothDevice, IBluetooth, and IBluetoothGatt
 *   3. System shared libraries, Binder services (ServiceManager), and installed Bluetooth packages/services
 *   4. Complete in-RAM DEX class & method inventory of /system/framework/com.broadcom.bt.jar (and .odex)
 *   5. Read-only /system/etc/bluetooth configs, /system/bin & /system/lib BT binaries, and non-PII BT props
 *
 * Zero root required, zero writes to internal /data eMMC flash, and zero PII/VIN/serial collection.
 */
public final class BtStackProbe {

    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static final int MAX_DEX_BYTES = 8 * 1024 * 1024;
    private static final AtomicBoolean PROBE_RUNNING = new AtomicBoolean(false);

    public static final class DexClassEntry {
        public final String className;
        public final String superName;
        public final int accessFlags;
        public final List<String> staticFields;
        public final List<String> declaredMethods;

        public DexClassEntry(String className, String superName, int accessFlags,
                             List<String> staticFields, List<String> declaredMethods) {
            this.className = className;
            this.superName = superName;
            this.accessFlags = accessFlags;
            this.staticFields = staticFields;
            this.declaredMethods = declaredMethods;
        }
    }

    private BtStackProbe() {}

    /**
     * Quick synchronous 1-line check of AOSP IBluetoothGatt & IBluetooth binder handles inside BluetoothAdapter.
     */
    public static String checkIBluetoothGattStatus(BluetoothAdapter adapter) {
        if (adapter == null) {
            return "adapter=null";
        }
        StringBuilder sb = new StringBuilder(160);
        try {
            Field fMgr = BluetoothAdapter.class.getDeclaredField("mManagerService");
            fMgr.setAccessible(true);
            Object mgr = fMgr.get(adapter);
            if (mgr == null) {
                sb.append("mManagerService=NULL");
            } else {
                sb.append("mManagerService=").append(describeBinderOwner(mgr));
                try {
                    Method mGetGatt = mgr.getClass().getMethod("getBluetoothGatt");
                    mGetGatt.setAccessible(true);
                    Object gattBinder = mGetGatt.invoke(mgr);
                    if (gattBinder == null) {
                        sb.append(" | getBluetoothGatt()=NULL");
                    } else {
                        sb.append(" | getBluetoothGatt()=").append(describeBinderOwner(gattBinder));
                    }
                } catch (NoSuchMethodException nsme) {
                    sb.append(" | getBluetoothGatt()=<method absent>");
                } catch (Throwable t) {
                    sb.append(" | getBluetoothGatt() threw ").append(t.getClass().getSimpleName())
                            .append(": ").append(t.getMessage());
                }
            }
        } catch (Throwable t) {
            sb.append("mManagerService reflect err: ").append(t.getMessage());
        }

        try {
            Field fSvc = BluetoothAdapter.class.getDeclaredField("mService");
            fSvc.setAccessible(true);
            Object svc = fSvc.get(adapter);
            sb.append(" | mService=").append(svc == null ? "NULL" : describeBinderOwner(svc));
        } catch (Throwable ignored) {}

        return sb.toString();
    }

    /**
     * Inspects internal fields of a returned BluetoothGatt object right after connectGatt().
     */
    public static String inspectBluetoothGattInstance(BluetoothGatt gatt) {
        if (gatt == null) return "gatt=null";
        StringBuilder sb = new StringBuilder(128);
        String[] fields = {"mService", "mClientIf", "mConnState", "mAutoConnect", "mTransport"};
        for (int i = 0; i < fields.length; i++) {
            try {
                Field f = BluetoothGatt.class.getDeclaredField(fields[i]);
                f.setAccessible(true);
                Object val = f.get(gatt);
                if (sb.length() > 0) sb.append(", ");
                if ("mService".equals(fields[i])) {
                    sb.append("mService=").append(val == null ? "NULL" : val.getClass().getSimpleName());
                } else {
                    sb.append(fields[i]).append('=').append(val);
                }
            } catch (Throwable ignored) {}
        }
        return sb.length() > 0 ? sb.toString() : gatt.getClass().getName();
    }

    /**
     * Reflectively queries Broadcom BleAdapter.getDeviceType(BluetoothDevice) if com.broadcom.bt is loaded.
     * Returns -1 when unavailable.
     */
    public static int tryGetBroadcomDeviceType(BluetoothDevice device) {
        if (device == null) return -1;
        String[] candidateClasses = {
            "com.broadcom.bt.le.api.BleAdapter",
            "com.broadcom.bt.service.gatt.BleAdapter"
        };
        for (int i = 0; i < candidateClasses.length; i++) {
            try {
                Class<?> cls = Class.forName(candidateClasses[i]);
                Method m = cls.getMethod("getDeviceType", BluetoothDevice.class);
                Object res = m.invoke(null, device);
                if (res instanceof Integer) {
                    return ((Integer) res).intValue();
                }
                if (res instanceof Byte) {
                    return ((Byte) res).intValue() & 0xFF;
                }
            } catch (Throwable ignored) {}
        }
        return -1;
    }

    /**
     * Runs the full read-only Gen5W Bluetooth & DEX stack probe on a background thread.
     */
    public static void runAsyncProbe(final Context context, final Runnable onCompleteCallback) {
        if (context == null) return;
        if (!PROBE_RUNNING.compareAndSet(false, true)) {
            DiagLogger.log("BT_PROBE", "BT stack probe already running in background...");
            return;
        }
        final Context appCtx = context.getApplicationContext();
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    runProbeInternal(appCtx);
                } catch (Throwable err) {
                    DiagLogger.log("BT_PROBE", "Unexpected probe error: " + err);
                } finally {
                    PROBE_RUNNING.set(false);
                    if (onCompleteCallback != null) {
                        onCompleteCallback.run();
                    }
                }
            }
        }, "Bvm02BtStackProbe");
        t.setPriority(Thread.NORM_PRIORITY - 1);
        t.start();
    }

    private static void runProbeInternal(Context ctx) {
        DiagLogger.log("BT_PROBE", "=== BEGIN GEN5W BLUETOOTH & BLE STACK PROBE (v0.1.1) ===");

        BluetoothAdapter adapter = null;
        try {
            adapter = BluetoothAdapter.getDefaultAdapter();
        } catch (Throwable t) {
            DiagLogger.log("BT_PROBE", "getDefaultAdapter threw: " + t);
        }

        // 1. Adapter internal binder handles & AIDL interface methods
        DiagLogger.log("BT_PROBE", "[1/6] Adapter Binder Handles: " + checkIBluetoothGattStatus(adapter));
        probeAdapterAndAidlInterfaces(adapter);

        // 2. System shared libraries & Binder ServiceManager inventory
        probeSharedLibrariesAndBinderServices(ctx);

        // 3. Installed Bluetooth / Broadcom / Projection packages & <service> declarations
        probeInstalledBtPackages(ctx);

        // 4. /system/framework Bluetooth JAR / ODEX in-RAM DEX extraction (e.g. com.broadcom.bt.jar)
        probeFrameworkBtJars();

        // 5. Runtime ClassLoader reflection check on candidate Broadcom / BLE classes
        probeCandidateClassesInClassLoader(ctx.getClassLoader());

        // 6. Read-only /system/etc/bluetooth configs, native libs/daemons, ps & non-PII BT properties
        probeSystemFilesAndDaemons();

        DiagLogger.log("BT_PROBE", "=== END GEN5W BLUETOOTH & BLE STACK PROBE ===");
    }

    private static void probeAdapterAndAidlInterfaces(BluetoothAdapter adapter) {
        // Log non-standard or BLE/GATT/Discovery-related methods on BluetoothAdapter & BluetoothDevice
        dumpFilteredClassMethods("BluetoothAdapter", BluetoothAdapter.class,
                new String[]{"le", "gatt", "scan", "discov", "brcm", "broadcom", "proxy", "profile", "uuid", "ble"});
        dumpFilteredClassMethods("BluetoothDevice", BluetoothDevice.class,
                new String[]{"le", "gatt", "type", "connect", "uuid", "brcm", "broadcom", "ble", "sdp"});

        if (adapter == null) return;

        // Dump all methods on IBluetoothManager, IBluetooth, and IBluetoothGatt AIDL interfaces
        try {
            Field fMgr = BluetoothAdapter.class.getDeclaredField("mManagerService");
            fMgr.setAccessible(true);
            Object mgr = fMgr.get(adapter);
            if (mgr != null) {
                dumpInterfaceMethods("IBluetoothManager", mgr.getClass());
                try {
                    Method mGetGatt = mgr.getClass().getMethod("getBluetoothGatt");
                    mGetGatt.setAccessible(true);
                    Object gattObj = mGetGatt.invoke(mgr);
                    if (gattObj != null) {
                        dumpInterfaceMethods("IBluetoothGatt(live)", gattObj.getClass());
                    }
                } catch (Throwable ignored) {}
            }
        } catch (Throwable ignored) {}

        try {
            Class<?> iBtGattCls = Class.forName("android.bluetooth.IBluetoothGatt");
            dumpAllDeclaredMethods("IBluetoothGatt(AIDL)", iBtGattCls);
        } catch (Throwable t) {
            DiagLogger.log("BT_PROBE", "Class android.bluetooth.IBluetoothGatt not found: " + t.getMessage());
        }

        try {
            Class<?> iBtCls = Class.forName("android.bluetooth.IBluetooth");
            dumpFilteredClassMethods("IBluetooth(AIDL)", iBtCls,
                    new String[]{"le", "gatt", "scan", "discov", "brcm", "broadcom", "type", "uuid", "ble", "remote"});
        } catch (Throwable ignored) {}
    }

    private static void probeSharedLibrariesAndBinderServices(Context ctx) {
        try {
            PackageManager pm = ctx.getPackageManager();
            String[] libs = pm.getSystemSharedLibraryNames();
            if (libs != null) {
                Arrays.sort(libs);
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < libs.length; i++) {
                    if (i > 0) sb.append(", ");
                    sb.append(libs[i]);
                }
                DiagLogger.log("BT_PROBE", "[2/6] System Shared Libraries (" + libs.length + "): " + sb);
            }
        } catch (Throwable t) {
            DiagLogger.log("BT_PROBE", "getSystemSharedLibraryNames err: " + t.getMessage());
        }

        try {
            Class<?> smCls = Class.forName("android.os.ServiceManager");
            Method mList = smCls.getMethod("listServices");
            Method mCheck = smCls.getMethod("checkService", String.class);
            String[] services = (String[]) mList.invoke(null);
            if (services != null) {
                Arrays.sort(services);
                List<String> matched = new ArrayList<String>();
                StringBuilder allNames = new StringBuilder();
                for (int i = 0; i < services.length; i++) {
                    String s = services[i];
                    if (s == null) continue;
                    if (allNames.length() > 0) allNames.append(", ");
                    allNames.append(s);
                    String low = s.toLowerCase(Locale.US);
                    if (containsAny(low, new String[]{
                            "bt", "blue", "gatt", "brcm", "broadcom", "bsa", "ble",
                            "wireless", "daudio", "mobis", "hkmc", "dipo", "car"
                    })) {
                        String desc = "?";
                        try {
                            Object binderObj = mCheck.invoke(null, s);
                            if (binderObj instanceof IBinder) {
                                IBinder b = (IBinder) binderObj;
                                desc = String.valueOf(b.getInterfaceDescriptor())
                                        + (b.isBinderAlive() ? " [ALIVE]" : " [DEAD]");
                            } else if (binderObj == null) {
                                desc = "null";
                            }
                        } catch (Throwable bt) {
                            desc = "err:" + bt.getClass().getSimpleName();
                        }
                        matched.add(s + " -> " + desc);
                    }
                }
                DiagLogger.log("BT_PROBE", "Binder Services (" + services.length + " total): " + allNames);
                for (int i = 0; i < matched.size(); i++) {
                    DiagLogger.log("BT_PROBE", "  Binder[" + i + "]: " + matched.get(i));
                }
            }
        } catch (Throwable t) {
            DiagLogger.log("BT_PROBE", "ServiceManager probe err: " + t.getMessage());
        }
    }

    private static void probeInstalledBtPackages(Context ctx) {
        try {
            PackageManager pm = ctx.getPackageManager();
            List<PackageInfo> pkgs = pm.getInstalledPackages(PackageManager.GET_SERVICES);
            if (pkgs == null) return;
            DiagLogger.log("BT_PROBE", "[3/6] Scanning " + pkgs.size() + " installed packages for BT/BLE components...");
            for (int i = 0; i < pkgs.size(); i++) {
                PackageInfo pi = pkgs.get(i);
                if (pi == null || pi.packageName == null) continue;
                String low = pi.packageName.toLowerCase(Locale.US);
                boolean relevant = containsAny(low, new String[]{
                        "bluetooth", "broadcom", "brcm", "bsa", "gatt", "bt", "dipo"
                });
                if (!relevant && pi.services != null) {
                    for (int s = 0; s < pi.services.length; s++) {
                        ServiceInfo si = pi.services[s];
                        if (si != null && si.name != null) {
                            String slow = si.name.toLowerCase(Locale.US);
                            if (containsAny(slow, new String[]{"bluetooth", "broadcom", "gatt", "ble", "btcm"})) {
                                relevant = true;
                                break;
                            }
                        }
                    }
                }
                if (!relevant) continue;

                boolean pkgEnabled = pi.applicationInfo != null && pi.applicationInfo.enabled;
                String srcDir = pi.applicationInfo != null ? String.valueOf(pi.applicationInfo.sourceDir) : "?";
                StringBuilder svcSb = new StringBuilder();
                if (pi.services != null) {
                    for (int s = 0; s < pi.services.length; s++) {
                        ServiceInfo si = pi.services[s];
                        if (si == null) continue;
                        if (svcSb.length() > 0) svcSb.append(", ");
                        svcSb.append(si.name).append(si.enabled ? "" : "(DISABLED)");
                    }
                }
                DiagLogger.log("BT_PROBE", "  Pkg: " + pi.packageName
                        + " (enabled=" + pkgEnabled + ", apk=" + srcDir + ")"
                        + (svcSb.length() > 0 ? (" services=[" + svcSb + "]") : ""));
            }
        } catch (Throwable t) {
            DiagLogger.log("BT_PROBE", "Installed BT package scan err: " + t.getMessage());
        }
    }

    private static void probeFrameworkBtJars() {
        File fwDir = new File("/system/framework");
        File[] files = fwDir.listFiles();
        if (files == null) {
            DiagLogger.log("BT_PROBE", "[4/6] /system/framework listFiles returned null");
            return;
        }
        Arrays.sort(files, new Comparator<File>() {
            @Override
            public int compare(File a, File b) {
                return a.getName().compareTo(b.getName());
            }
        });

        List<File> btFiles = new ArrayList<File>();
        for (int i = 0; i < files.length; i++) {
            File f = files[i];
            String low = f.getName().toLowerCase(Locale.US);
            if (containsAny(low, new String[]{"broadcom", "brcm", "bt", "blue", "bsa", "gatt"})) {
                btFiles.add(f);
            }
        }

        DiagLogger.log("BT_PROBE", "[4/6] /system/framework BT-related files (" + btFiles.size() + "):");
        for (int i = 0; i < btFiles.size(); i++) {
            File f = btFiles.get(i);
            DiagLogger.log("BT_PROBE", "  Framework file: " + f.getAbsolutePath()
                    + " (" + f.length() + " bytes, canRead=" + f.canRead() + ")");
        }

        for (int i = 0; i < btFiles.size(); i++) {
            File f = btFiles.get(i);
            if (!f.isFile() || !f.canRead() || f.length() <= 0 || f.length() > MAX_DEX_BYTES) continue;
            String nameLow = f.getName().toLowerCase(Locale.US);
            if (nameLow.endsWith(".jar") || nameLow.endsWith(".apk")) {
                inspectJarOrApkDex(f);
            } else if (nameLow.endsWith(".odex")) {
                // Only parse standalone .odex if we didn't already get classes.dex from its .jar
                String jarPartnerName = f.getName().substring(0, f.getName().length() - 5) + ".jar";
                File jarPartner = new File(f.getParentFile(), jarPartnerName);
                if (!jarHasClassesDex(jarPartner)) {
                    inspectRawDexOrOdexFile(f);
                }
            }
        }
    }

    private static boolean jarHasClassesDex(File jarFile) {
        if (jarFile == null || !jarFile.isFile() || !jarFile.canRead()) return false;
        ZipFile zf = null;
        try {
            zf = new ZipFile(jarFile);
            return zf.getEntry("classes.dex") != null;
        } catch (Throwable ignored) {
            return false;
        } finally {
            if (zf != null) {
                try { zf.close(); } catch (Throwable ignored) {}
            }
        }
    }

    private static void inspectJarOrApkDex(File jarFile) {
        ZipFile zf = null;
        try {
            zf = new ZipFile(jarFile);
            ZipEntry dexEntry = zf.getEntry("classes.dex");
            if (dexEntry == null) {
                StringBuilder entries = new StringBuilder();
                Enumeration<? extends ZipEntry> en = zf.entries();
                while (en.hasMoreElements()) {
                    ZipEntry ze = en.nextElement();
                    if (entries.length() > 0) entries.append(", ");
                    entries.append(ze.getName()).append('(').append(ze.getSize()).append(')');
                }
                DiagLogger.log("BT_DEX", jarFile.getName() + " has no classes.dex (entries: " + entries + ")");
                // Check arm/odex fallback if present
                File armOdex = new File(new File(jarFile.getParentFile(), "arm"),
                        jarFile.getName().replace(".jar", ".odex").replace(".apk", ".odex"));
                if (armOdex.isFile() && armOdex.canRead()) {
                    inspectRawDexOrOdexFile(armOdex);
                }
                return;
            }
            if (dexEntry.getSize() > MAX_DEX_BYTES) {
                DiagLogger.log("BT_DEX", jarFile.getName() + " classes.dex too large (" + dexEntry.getSize() + "B); skipping");
                return;
            }
            byte[] dexBytes = readStreamBounded(zf.getInputStream(dexEntry), MAX_DEX_BYTES);
            logDexInventory(jarFile.getName(), dexBytes);
        } catch (Throwable t) {
            DiagLogger.log("BT_DEX", "Error reading " + jarFile.getName() + ": " + t);
        } finally {
            if (zf != null) {
                try { zf.close(); } catch (Throwable ignored) {}
            }
        }
    }

    private static void inspectRawDexOrOdexFile(File file) {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
            byte[] raw = readStreamBounded(fis, MAX_DEX_BYTES);
            logDexInventory(file.getName(), raw);
        } catch (Throwable t) {
            DiagLogger.log("BT_DEX", "Error reading " + file.getName() + ": " + t);
        } finally {
            if (fis != null) {
                try { fis.close(); } catch (Throwable ignored) {}
            }
        }
    }

    private static void logDexInventory(String sourceName, byte[] rawBytes) {
        List<DexClassEntry> classes = extractDexInventory(rawBytes);
        DiagLogger.log("BT_DEX", "Parsed " + sourceName + " (" + rawBytes.length + "B) -> "
                + classes.size() + " class(es):");
        if (classes.isEmpty()) return;

        int totalMethods = 0;
        StringBuilder classSummary = new StringBuilder();
        for (int i = 0; i < classes.size(); i++) {
            DexClassEntry ce = classes.get(i);
            totalMethods += ce.declaredMethods.size();
            if (classSummary.length() > 0) classSummary.append(", ");
            classSummary.append(ce.className);
            if (classSummary.length() >= 480) {
                DiagLogger.log("BT_DEX", "  Classes: " + classSummary);
                classSummary.setLength(0);
            }
        }
        if (classSummary.length() > 0) {
            DiagLogger.log("BT_DEX", "  Classes: " + classSummary);
        }

        boolean dumpAllClasses = (totalMethods <= 900);
        for (int i = 0; i < classes.size(); i++) {
            DexClassEntry ce = classes.get(i);
            String low = ce.className.toLowerCase(Locale.US);
            boolean isBleOrCore = dumpAllClasses || containsAny(low, new String[]{
                    "le", "ble", "gatt", "scan", "client", "adapter", "btcm", "device", "service", "manager", "uuid"
            });
            if (!isBleOrCore) continue;

            DiagLogger.log("BT_DEX", "  [CLASS] " + formatClassModifiers(ce.accessFlags) + ce.className
                    + (ce.superName != null && !"java.lang.Object".equals(ce.superName)
                    ? (" extends " + ce.superName) : ""));
            for (int f = 0; f < ce.staticFields.size(); f++) {
                DiagLogger.log("BT_DEX", "    field: " + ce.staticFields.get(f));
            }
            for (int m = 0; m < ce.declaredMethods.size(); m++) {
                DiagLogger.log("BT_DEX", "    method: " + ce.declaredMethods.get(m));
            }
        }
    }

    private static void probeCandidateClassesInClassLoader(ClassLoader appLoader) {
        String[] candidates = {
            "com.broadcom.bt.le.api.BleAdapter",
            "com.broadcom.bt.le.api.BleClientProfile",
            "com.broadcom.bt.le.api.BleClientService",
            "com.broadcom.bt.le.api.BleGattID",
            "com.broadcom.bt.le.api.BleConstants",
            "com.broadcom.bt.service.gatt.BluetoothGatt",
            "com.broadcom.bt.hfdevice.hfbtcm.HfDeviceBTCMManager",
            "android.bluetooth.BluetoothGatt"
        };
        DiagLogger.log("BT_PROBE", "[5/6] ClassLoader <uses-library com.broadcom.bt> link check:");
        for (int i = 0; i < candidates.length; i++) {
            String cname = candidates[i];
            try {
                Class<?> cls = Class.forName(cname, false, appLoader);
                DiagLogger.log("BT_PROBE", "  Loaded " + cname + " (methods=" + cls.getDeclaredMethods().length + ")");
            } catch (Throwable t) {
                DiagLogger.log("BT_PROBE", "  Not in ClassLoader: " + cname + " (" + t.getClass().getSimpleName() + ")");
            }
        }
    }

    private static void probeSystemFilesAndDaemons() {
        DiagLogger.log("BT_PROBE", "[6/6] Read-only /system BT configs, libs, binaries & stack properties:");

        // /system/etc/bluetooth/*
        File etcBt = new File("/system/etc/bluetooth");
        File[] etcFiles = etcBt.listFiles();
        if (etcFiles != null) {
            Arrays.sort(etcFiles);
            for (int i = 0; i < etcFiles.length; i++) {
                File f = etcFiles[i];
                DiagLogger.log("BT_SYS", "  /system/etc/bluetooth/" + f.getName()
                        + " (" + f.length() + "B, canRead=" + f.canRead() + ")");
                if (f.isFile() && f.canRead() && f.length() > 0 && f.length() <= 4096
                        && (f.getName().endsWith(".conf") || f.getName().endsWith(".cfg"))) {
                    logSmallConfigFile(f);
                }
            }
        } else {
            DiagLogger.log("BT_SYS", "  /system/etc/bluetooth not listable");
        }

        // /system/etc/permissions/*bt* or *broadcom*
        File permDir = new File("/system/etc/permissions");
        File[] permFiles = permDir.listFiles();
        if (permFiles != null) {
            Arrays.sort(permFiles);
            for (int i = 0; i < permFiles.length; i++) {
                File f = permFiles[i];
                String low = f.getName().toLowerCase(Locale.US);
                if (containsAny(low, new String[]{"bt", "blue", "broadcom", "brcm", "gatt", "ble"})) {
                    DiagLogger.log("BT_SYS", "  Permission XML: " + f.getAbsolutePath() + " (" + f.length() + "B)");
                    if (f.isFile() && f.canRead() && f.length() <= 4096) {
                        logSmallConfigFile(f);
                    }
                }
            }
        }

        // /system/bin & /system/lib matching bt|blue|brcm|bsa|gatt
        listMatchingFiles("/system/bin", new String[]{"bt", "blue", "brcm", "broadcom", "bsa", "gatt"});
        listMatchingFiles("/system/lib", new String[]{"bt", "blue", "brcm", "broadcom", "bsa", "gatt"});
        listMatchingFiles("/system/lib/hw", new String[]{"bt", "blue", "brcm", "broadcom", "bsa", "gatt"});

        // Filtered getprop (strictly BT/BLE keys, redacting any MAC octets)
        runFilteredCommand(new String[]{"/system/bin/getprop"}, "BT_PROP",
                new String[]{"bt", "blue", "brcm", "broadcom", "bsa", "gatt", "ble"}, true);

        // Filtered ps (strictly BT/BLE processes)
        runFilteredCommand(new String[]{"/system/bin/ps"}, "BT_PROC",
                new String[]{"bt", "blue", "brcm", "broadcom", "bsa", "gatt", "dipo"}, false);
    }

    private static void logSmallConfigFile(File f) {
        BufferedReader br = null;
        try {
            br = new BufferedReader(new InputStreamReader(new FileInputStream(f), UTF8));
            String line;
            int lineCount = 0;
            while ((line = br.readLine()) != null && lineCount < 60) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith("//")) continue;
                DiagLogger.log("BT_CONF", "    " + f.getName() + ": " + redactMacOctets(trimmed));
                lineCount++;
            }
        } catch (Throwable ignored) {
        } finally {
            if (br != null) {
                try { br.close(); } catch (Throwable ignored) {}
            }
        }
    }

    private static void listMatchingFiles(String dirPath, String[] keywords) {
        File d = new File(dirPath);
        File[] list = d.listFiles();
        if (list == null) return;
        Arrays.sort(list);
        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (int i = 0; i < list.length; i++) {
            String name = list[i].getName();
            if (containsAny(name.toLowerCase(Locale.US), keywords)) {
                if (sb.length() > 0) sb.append(", ");
                sb.append(name).append('(').append(list[i].length()).append('B').append(')');
                count++;
            }
        }
        if (count > 0) {
            DiagLogger.log("BT_SYS", "  " + dirPath + " matches (" + count + "): " + sb);
        }
    }

    private static void runFilteredCommand(String[] cmd, String tag, String[] keywords, boolean isGetProp) {
        Process proc = null;
        BufferedReader br = null;
        try {
            proc = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            br = new BufferedReader(new InputStreamReader(proc.getInputStream(), UTF8));
            String line;
            int matched = 0;
            while ((line = br.readLine()) != null) {
                String low = line.toLowerCase(Locale.US);
                if (isGetProp && containsAny(low, new String[]{"serial", "vin", "token", "account", "passwd", "password"})) {
                    continue;
                }
                if (containsAny(low, keywords)) {
                    DiagLogger.log(tag, "  " + redactMacOctets(line.trim()));
                    matched++;
                    if (matched >= 80) break;
                }
            }
        } catch (Throwable t) {
            DiagLogger.log(tag, "  cmd " + cmd[0] + " err: " + t.getMessage());
        } finally {
            if (br != null) {
                try { br.close(); } catch (Throwable ignored) {}
            }
            if (proc != null) {
                try { proc.destroy(); } catch (Throwable ignored) {}
            }
        }
    }

    private static String redactMacOctets(String s) {
        if (s == null) return "";
        // Mask trailing 3 octets of any XX:XX:XX:XX:XX:XX MAC in system properties/configs
        return s.replaceAll("(?i)([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}):[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}",
                "$1:**:**:**");
    }

    // ================= PURE-JAVA IN-RAM DALVIK DEX / ODEX PARSER =================

    /**
     * Parses a Dalvik DEX ("dex\n035\0") or optimized ODEX ("dey\n036\0") byte buffer in RAM
     * and returns all defined classes with their declared static fields and method signatures.
     */
    public static List<DexClassEntry> extractDexInventory(byte[] rawBytes) {
        if (rawBytes == null || rawBytes.length < 112) {
            return Collections.emptyList();
        }

        byte[] dex = rawBytes;
        // Unwrap Dalvik DexOptHeader ("dey\n036\0") if reading a .odex file
        if (dex[0] == 'd' && dex[1] == 'e' && dex[2] == 'y' && dex[3] == '\n') {
            ByteBuffer odexHdr = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN);
            int dexOff = odexHdr.getInt(8);
            int dexLen = odexHdr.getInt(12);
            if (dexOff < 40 || dexLen < 112 || dexOff + dexLen > dex.length) {
                return Collections.emptyList();
            }
            byte[] slice = new byte[dexLen];
            System.arraycopy(dex, dexOff, slice, 0, dexLen);
            dex = slice;
        }

        if (dex[0] != 'd' || dex[1] != 'e' || dex[2] != 'x' || dex[3] != '\n') {
            return Collections.emptyList();
        }

        ByteBuffer buf = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN);
        int endianTag = buf.getInt(40);
        if (endianTag != 0x12345678) {
            return Collections.emptyList();
        }

        int stringIdsSize = buf.getInt(56);
        int stringIdsOff  = buf.getInt(60);
        int typeIdsSize   = buf.getInt(64);
        int typeIdsOff    = buf.getInt(68);
        int protoIdsSize  = buf.getInt(72);
        int protoIdsOff   = buf.getInt(76);
        int fieldIdsSize  = buf.getInt(80);
        int fieldIdsOff   = buf.getInt(84);
        int methodIdsSize = buf.getInt(88);
        int methodIdsOff  = buf.getInt(92);
        int classDefsSize = buf.getInt(96);
        int classDefsOff  = buf.getInt(100);

        if (classDefsSize <= 0 || classDefsOff <= 0 || classDefsOff + classDefsSize * 32 > dex.length) {
            return Collections.emptyList();
        }

        List<DexClassEntry> out = new ArrayList<DexClassEntry>(classDefsSize);
        for (int c = 0; c < classDefsSize; c++) {
            int cOff = classDefsOff + c * 32;
            int classIdx = buf.getInt(cOff);
            int accessFlags = buf.getInt(cOff + 4);
            int superIdx = buf.getInt(cOff + 8);
            int classDataOff = buf.getInt(cOff + 24);

            String className = readTypeName(dex, buf, stringIdsSize, stringIdsOff, typeIdsSize, typeIdsOff, classIdx);
            String superName = (superIdx >= 0 && superIdx < typeIdsSize)
                    ? readTypeName(dex, buf, stringIdsSize, stringIdsOff, typeIdsSize, typeIdsOff, superIdx)
                    : null;

            List<String> staticFields = new ArrayList<String>();
            List<String> methods = new ArrayList<String>();

            if (classDataOff > 0 && classDataOff < dex.length) {
                int[] pos = new int[]{classDataOff};
                int staticFieldsSize = readUleb128(dex, pos);
                int instanceFieldsSize = readUleb128(dex, pos);
                int directMethodsSize = readUleb128(dex, pos);
                int virtualMethodsSize = readUleb128(dex, pos);

                int fieldIdx = 0;
                for (int i = 0; i < staticFieldsSize && pos[0] < dex.length; i++) {
                    fieldIdx += readUleb128(dex, pos);
                    int fAccess = readUleb128(dex, pos);
                    staticFields.add(formatFieldSig(dex, buf, stringIdsSize, stringIdsOff,
                            typeIdsSize, typeIdsOff, fieldIdsSize, fieldIdsOff, fieldIdx, fAccess));
                }
                for (int i = 0; i < instanceFieldsSize && pos[0] < dex.length; i++) {
                    readUleb128(dex, pos);
                    readUleb128(dex, pos);
                }

                int methodIdx = 0;
                for (int i = 0; i < directMethodsSize && pos[0] < dex.length; i++) {
                    methodIdx += readUleb128(dex, pos);
                    int mAccess = readUleb128(dex, pos);
                    readUleb128(dex, pos); // code_off
                    String sig = formatMethodSig(dex, buf, stringIdsSize, stringIdsOff,
                            typeIdsSize, typeIdsOff, protoIdsSize, protoIdsOff,
                            methodIdsSize, methodIdsOff, methodIdx, mAccess);
                    if (sig != null) {
                        methods.add(sig);
                    }
                }

                methodIdx = 0;
                for (int i = 0; i < virtualMethodsSize && pos[0] < dex.length; i++) {
                    methodIdx += readUleb128(dex, pos);
                    int mAccess = readUleb128(dex, pos);
                    readUleb128(dex, pos); // code_off
                    String sig = formatMethodSig(dex, buf, stringIdsSize, stringIdsOff,
                            typeIdsSize, typeIdsOff, protoIdsSize, protoIdsOff,
                            methodIdsSize, methodIdsOff, methodIdx, mAccess);
                    if (sig != null) {
                        methods.add(sig);
                    }
                }
            }

            out.add(new DexClassEntry(className, superName, accessFlags, staticFields, methods));
        }

        Collections.sort(out, new Comparator<DexClassEntry>() {
            @Override
            public int compare(DexClassEntry a, DexClassEntry b) {
                return a.className.compareTo(b.className);
            }
        });
        return out;
    }

    private static int readUleb128(byte[] dex, int[] posRef) {
        int result = 0;
        int shift = 0;
        int p = posRef[0];
        while (p < dex.length && shift < 35) {
            int b = dex[p++] & 0xFF;
            result |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0) break;
            shift += 7;
        }
        posRef[0] = p;
        return result;
    }

    private static String readDexString(byte[] dex, ByteBuffer buf,
                                        int stringIdsSize, int stringIdsOff, int strIdx) {
        if (strIdx < 0 || strIdx >= stringIdsSize) return "?";
        int offPos = stringIdsOff + strIdx * 4;
        if (offPos < 0 || offPos + 4 > dex.length) return "?";
        int dataOff = buf.getInt(offPos);
        if (dataOff <= 0 || dataOff >= dex.length) return "";
        int[] pos = new int[]{dataOff};
        readUleb128(dex, pos); // skip utf16_size
        int start = pos[0];
        int end = start;
        while (end < dex.length && dex[end] != 0) {
            end++;
        }
        return new String(dex, start, end - start, UTF8);
    }

    private static String readTypeName(byte[] dex, ByteBuffer buf,
                                       int stringIdsSize, int stringIdsOff,
                                       int typeIdsSize, int typeIdsOff, int typeIdx) {
        if (typeIdx < 0 || typeIdx >= typeIdsSize) return "?";
        int offPos = typeIdsOff + typeIdx * 4;
        if (offPos < 0 || offPos + 4 > dex.length) return "?";
        int descStrIdx = buf.getInt(offPos);
        String rawDesc = readDexString(dex, buf, stringIdsSize, stringIdsOff, descStrIdx);
        return prettyTypeDescriptor(rawDesc);
    }

    private static String formatFieldSig(byte[] dex, ByteBuffer buf,
                                         int stringIdsSize, int stringIdsOff,
                                         int typeIdsSize, int typeIdsOff,
                                         int fieldIdsSize, int fieldIdsOff,
                                         int fieldIdx, int accessFlags) {
        if (fieldIdx < 0 || fieldIdx >= fieldIdsSize) return "?";
        int fOff = fieldIdsOff + fieldIdx * 8;
        if (fOff < 0 || fOff + 8 > dex.length) return "?";
        int typeIdx = buf.getShort(fOff + 2) & 0xFFFF;
        int nameIdx = buf.getInt(fOff + 4);
        String typeName = readTypeName(dex, buf, stringIdsSize, stringIdsOff, typeIdsSize, typeIdsOff, typeIdx);
        String name = readDexString(dex, buf, stringIdsSize, stringIdsOff, nameIdx);
        return formatMemberModifiers(accessFlags) + typeName + " " + name;
    }

    private static String formatMethodSig(byte[] dex, ByteBuffer buf,
                                          int stringIdsSize, int stringIdsOff,
                                          int typeIdsSize, int typeIdsOff,
                                          int protoIdsSize, int protoIdsOff,
                                          int methodIdsSize, int methodIdsOff,
                                          int methodIdx, int accessFlags) {
        if (methodIdx < 0 || methodIdx >= methodIdsSize) return null;
        int mOff = methodIdsOff + methodIdx * 8;
        if (mOff < 0 || mOff + 8 > dex.length) return null;
        int protoIdx = buf.getShort(mOff + 2) & 0xFFFF;
        int nameIdx = buf.getInt(mOff + 4);
        String name = readDexString(dex, buf, stringIdsSize, stringIdsOff, nameIdx);
        if ("<clinit>".equals(name)) return null;

        if (protoIdx < 0 || protoIdx >= protoIdsSize) {
            return formatMemberModifiers(accessFlags) + name + "(?)";
        }
        int pOff = protoIdsOff + protoIdx * 12;
        if (pOff < 0 || pOff + 12 > dex.length) return null;
        int returnTypeIdx = buf.getInt(pOff + 4);
        int paramsOff = buf.getInt(pOff + 8);

        String retType = readTypeName(dex, buf, stringIdsSize, stringIdsOff, typeIdsSize, typeIdsOff, returnTypeIdx);
        StringBuilder params = new StringBuilder();
        if (paramsOff > 0 && paramsOff + 4 <= dex.length) {
            int count = buf.getInt(paramsOff);
            for (int i = 0; i < count && (paramsOff + 4 + i * 2 + 2) <= dex.length; i++) {
                if (i > 0) params.append(", ");
                int pTypeIdx = buf.getShort(paramsOff + 4 + i * 2) & 0xFFFF;
                params.append(readTypeName(dex, buf, stringIdsSize, stringIdsOff, typeIdsSize, typeIdsOff, pTypeIdx));
            }
        }
        return formatMemberModifiers(accessFlags) + retType + " " + name + "(" + params + ")";
    }

    private static String prettyTypeDescriptor(String desc) {
        if (desc == null || desc.isEmpty()) return "?";
        int arrayDims = 0;
        int idx = 0;
        while (idx < desc.length() && desc.charAt(idx) == '[') {
            arrayDims++;
            idx++;
        }
        String base;
        if (idx >= desc.length()) {
            base = desc;
        } else {
            char c = desc.charAt(idx);
            switch (c) {
                case 'V': base = "void"; break;
                case 'Z': base = "boolean"; break;
                case 'B': base = "byte"; break;
                case 'S': base = "short"; break;
                case 'C': base = "char"; break;
                case 'I': base = "int"; break;
                case 'J': base = "long"; break;
                case 'F': base = "float"; break;
                case 'D': base = "double"; break;
                case 'L':
                    int semi = desc.endsWith(";") ? desc.length() - 1 : desc.length();
                    base = desc.substring(idx + 1, semi).replace('/', '.');
                    break;
                default:
                    base = desc.substring(idx);
                    break;
            }
        }
        if (arrayDims == 0) return base;
        StringBuilder sb = new StringBuilder(base.length() + arrayDims * 2);
        sb.append(base);
        for (int i = 0; i < arrayDims; i++) {
            sb.append("[]");
        }
        return sb.toString();
    }

    private static String formatClassModifiers(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & 0x0001) != 0) sb.append("public ");
        if ((flags & 0x0200) != 0) sb.append("interface ");
        else if ((flags & 0x4000) != 0) sb.append("enum ");
        else if ((flags & 0x0400) != 0) sb.append("abstract class ");
        else sb.append("class ");
        return sb.toString();
    }

    private static String formatMemberModifiers(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & 0x0001) != 0) sb.append("public ");
        else if ((flags & 0x0004) != 0) sb.append("protected ");
        else if ((flags & 0x0002) != 0) sb.append("private ");
        if ((flags & 0x0008) != 0) sb.append("static ");
        return sb.toString();
    }

    // ================= REFLECTION & IO HELPERS =================

    private static String describeBinderOwner(Object proxyOrStub) {
        if (proxyOrStub == null) return "NULL";
        StringBuilder sb = new StringBuilder();
        sb.append(proxyOrStub.getClass().getName());
        try {
            Method mAsBinder = proxyOrStub.getClass().getMethod("asBinder");
            Object bObj = mAsBinder.invoke(proxyOrStub);
            if (bObj instanceof IBinder) {
                IBinder b = (IBinder) bObj;
                sb.append(" (descriptor=").append(b.getInterfaceDescriptor())
                        .append(", alive=").append(b.isBinderAlive()).append(')');
            }
        } catch (Throwable ignored) {}
        return sb.toString();
    }

    private static void dumpInterfaceMethods(String label, Class<?> implCls) {
        Class<?>[] ifaces = implCls.getInterfaces();
        for (int i = 0; i < ifaces.length; i++) {
            if (!"android.os.IInterface".equals(ifaces[i].getName())) {
                dumpAllDeclaredMethods(label + "[" + ifaces[i].getName() + "]", ifaces[i]);
            }
        }
    }

    private static void dumpAllDeclaredMethods(String label, Class<?> cls) {
        Method[] methods = cls.getDeclaredMethods();
        List<String> sigs = new ArrayList<String>(methods.length);
        for (int i = 0; i < methods.length; i++) {
            sigs.add(formatReflectMethod(methods[i]));
        }
        Collections.sort(sigs);
        DiagLogger.log("BT_PROBE", "  " + label + " methods (" + sigs.size() + "):");
        for (int i = 0; i < sigs.size(); i++) {
            DiagLogger.log("BT_PROBE", "    " + sigs.get(i));
        }
    }

    private static void dumpFilteredClassMethods(String label, Class<?> cls, String[] keywords) {
        Method[] methods = cls.getDeclaredMethods();
        List<String> sigs = new ArrayList<String>();
        for (int i = 0; i < methods.length; i++) {
            String mname = methods[i].getName().toLowerCase(Locale.US);
            if (containsAny(mname, keywords)) {
                sigs.add(formatReflectMethod(methods[i]));
            }
        }
        Collections.sort(sigs);
        DiagLogger.log("BT_PROBE", "  " + label + " BLE/GATT/Discovery methods (" + sigs.size() + "):");
        for (int i = 0; i < sigs.size(); i++) {
            DiagLogger.log("BT_PROBE", "    " + sigs.get(i));
        }
    }

    private static String formatReflectMethod(Method m) {
        StringBuilder sb = new StringBuilder();
        int mod = m.getModifiers();
        if (Modifier.isPublic(mod)) sb.append("public ");
        else if (Modifier.isProtected(mod)) sb.append("protected ");
        else if (Modifier.isPrivate(mod)) sb.append("private ");
        if (Modifier.isStatic(mod)) sb.append("static ");
        sb.append(m.getReturnType().getSimpleName()).append(' ').append(m.getName()).append('(');
        Class<?>[] params = m.getParameterTypes();
        for (int i = 0; i < params.length; i++) {
            if (i > 0) sb.append(", ");
            sb.append(params[i].getSimpleName());
        }
        sb.append(')');
        return sb.toString();
    }

    private static byte[] readStreamBounded(InputStream is, int maxBytes) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(65536);
        byte[] buf = new byte[16384];
        int total = 0;
        int n;
        while ((n = is.read(buf)) >= 0) {
            if (total + n > maxBytes) {
                throw new IllegalStateException("Entry exceeds max RAM probe cap (" + maxBytes + "B)");
            }
            bos.write(buf, 0, n);
            total += n;
        }
        return bos.toByteArray();
    }

    private static boolean containsAny(String haystackLower, String[] needles) {
        for (int i = 0; i < needles.length; i++) {
            if (haystackLower.indexOf(needles[i]) >= 0) return true;
        }
        return false;
    }
}
