package bvm02.app;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.content.res.Resources;
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
 * Upgraded in v0.1.2 based on Ioniq 5 Gen5W (v0.1.1) telemetry:
 *  1. Adapter internal mManagerService (IBluetoothManager), getBluetoothGatt(), and mService (IBluetooth)
 *  2. System shared libraries & Bluetooth Binder services
 *  3. Installed BT packages including PackageManager.GET_DISABLED_COMPONENTS & GattService component state
 *  4. /system/app/Bluetooth.apk boolean config table (profile_supported_gatt, etc.) & DEX/ODEX inventory
 *  5. Targeted DEX/ODEX inspection of BluetoothManagerService (/system/framework/services.jar/.odex)
 *     and Broadcom GATT/RadioManager (/system/framework/com.broadcom.bt.jar) without dumping unrelated profiles
 *  6. Live read-only Broadcom BluetoothRadioManager constant & readiness inspection
 *  7. Read-only /system/etc/bluetooth configs, native BT libs, processes, and redacted BT properties
 *
 * Zero root required, zero writes to internal /data eMMC flash, and zero PII/VIN/serial collection.
 */
public final class BtStackProbe {

    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static final int MAX_DEX_BYTES = 16 * 1024 * 1024;
    private static final AtomicBoolean PROBE_RUNNING = new AtomicBoolean(false);

    public static final class DexClassEntry {
        public final String className;
        public final String superName;
        public final int accessFlags;
        public final List<String> staticFields;
        public final List<String> instanceFields;
        public final List<String> declaredMethods;

        public DexClassEntry(String className, String superName, int accessFlags,
                             List<String> staticFields, List<String> declaredMethods) {
            this(className, superName, accessFlags, staticFields,
                    Collections.<String>emptyList(), declaredMethods);
        }

        public DexClassEntry(String className, String superName, int accessFlags,
                             List<String> staticFields, List<String> instanceFields,
                             List<String> declaredMethods) {
            this.className = className;
            this.superName = superName;
            this.accessFlags = accessFlags;
            this.staticFields = staticFields;
            this.instanceFields = instanceFields;
            this.declaredMethods = declaredMethods;
        }
    }

    private BtStackProbe() {}

    /**
     * Reflectively extracts BluetoothAdapter.mManagerService (android.bluetooth.IBluetoothManager).
     */
    public static Object getIBluetoothManager(BluetoothAdapter adapter) {
        if (adapter == null) return null;
        try {
            Field fMgr = BluetoothAdapter.class.getDeclaredField("mManagerService");
            fMgr.setAccessible(true);
            return fMgr.get(adapter);
        } catch (Throwable ignored) {
            return null;
        }
    }

    /**
     * Reflectively extracts BluetoothAdapter.mService (android.bluetooth.IBluetooth).
     */
    public static Object getIBluetoothService(BluetoothAdapter adapter) {
        if (adapter == null) return null;
        try {
            Field fSvc = BluetoothAdapter.class.getDeclaredField("mService");
            fSvc.setAccessible(true);
            return fSvc.get(adapter);
        } catch (Throwable ignored) {
            return null;
        }
    }

    /**
     * Reflectively queries BluetoothAdapter.mManagerService.getBluetoothGatt().
     * Returns non-null IBluetoothGatt proxy when GattService is active, or null otherwise.
     */
    public static Object getLiveIBluetoothGatt(BluetoothAdapter adapter) {
        Object mgr = getIBluetoothManager(adapter);
        if (mgr == null) return null;
        try {
            Method mGetGatt = mgr.getClass().getMethod("getBluetoothGatt");
            mGetGatt.setAccessible(true);
            return mGetGatt.invoke(mgr);
        } catch (Throwable ignored) {
            return null;
        }
    }

    /**
     * Quick synchronous 1-line check of AOSP IBluetoothGatt & IBluetooth binder handles inside BluetoothAdapter.
     */
    public static String checkIBluetoothGattStatus(BluetoothAdapter adapter) {
        if (adapter == null) {
            return "adapter=null";
        }
        StringBuilder sb = new StringBuilder(180);
        try {
            Object mgr = getIBluetoothManager(adapter);
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
            Object svc = getIBluetoothService(adapter);
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
     * Reflectively queries Broadcom BleAdapter.getDeviceType(BluetoothDevice) if present.
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
     * Runs the targeted read-only Gen5W Bluetooth & DEX stack probe on a background thread.
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
        DiagLogger.log("BT_PROBE", "=== BEGIN GEN5W BLUETOOTH & BLE STACK PROBE (v0.1.2) ===");

        BluetoothAdapter adapter = null;
        try {
            adapter = BluetoothAdapter.getDefaultAdapter();
        } catch (Throwable t) {
            DiagLogger.log("BT_PROBE", "getDefaultAdapter threw: " + t);
        }

        // 1. Adapter internal binder handles & key AIDL methods
        DiagLogger.log("BT_PROBE", "[1/7] Adapter Binder Handles: " + checkIBluetoothGattStatus(adapter));
        probeAdapterAndAidlInterfaces(adapter);

        // 2. System shared libraries & Binder ServiceManager inventory
        probeSharedLibrariesAndBinderServices(ctx);

        // 3. Installed Bluetooth packages (including GET_DISABLED_COMPONENTS!) & GattService state
        probeInstalledBtPackages(ctx);

        // 4. /system/app/Bluetooth.apk boolean config table (profile_supported_*) & DEX/ODEX inventory
        probeBluetoothApkResourcesAndDex(ctx);

        // 5. Targeted /system/framework DEX/ODEX inspection: com.broadcom.bt.jar + services.jar (BluetoothManagerService)
        probeFrameworkBtAndServicesDex();

        // 6. Live read-only Broadcom RadioManager & ClassLoader link check
        probeBroadcomRadioManagerReadOnly(ctx.getClassLoader());

        // 7. Read-only /system/etc/bluetooth configs, native libs, redacted BT props & processes
        probeSystemFilesAndDaemons();

        DiagLogger.log("BT_PROBE", "=== END GEN5W BLUETOOTH & BLE STACK PROBE (v0.1.2) ===");
    }

    private static void probeAdapterAndAidlInterfaces(BluetoothAdapter adapter) {
        if (adapter == null) return;
        Object mgr = getIBluetoothManager(adapter);
        if (mgr != null) {
            dumpInterfaceMethods("IBluetoothManager", mgr.getClass());
            try {
                Method mRadio = mgr.getClass().getMethod("isRadioEnabled");
                Object rVal = mRadio.invoke(mgr);
                DiagLogger.log("BT_PROBE", "  IBluetoothManager.isRadioEnabled() -> " + rVal);
            } catch (Throwable ignored) {}
        }

        Object liveGatt = getLiveIBluetoothGatt(adapter);
        if (liveGatt != null) {
            DiagLogger.log("BT_PROBE", "  Live IBluetoothGatt binder present: " + describeBinderOwner(liveGatt));
        }
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
                DiagLogger.log("BT_PROBE", "[2/7] System Shared Libraries (" + libs.length + "): " + sb);
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
                for (int i = 0; i < services.length; i++) {
                    String s = services[i];
                    if (s == null) continue;
                    String low = s.toLowerCase(Locale.US);
                    if (containsAny(low, new String[]{
                            "bt", "blue", "gatt", "brcm", "broadcom", "bsa", "ble", "dipo"
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
                        DiagLogger.log("BT_PROBE", "  Binder: " + s + " -> " + desc);
                    }
                }
            }
        } catch (Throwable t) {
            DiagLogger.log("BT_PROBE", "ServiceManager probe err: " + t.getMessage());
        }
    }

    private static void probeInstalledBtPackages(Context ctx) {
        try {
            PackageManager pm = ctx.getPackageManager();
            int flags = PackageManager.GET_SERVICES | PackageManager.GET_DISABLED_COMPONENTS;
            List<PackageInfo> pkgs = pm.getInstalledPackages(flags);
            if (pkgs == null) return;
            DiagLogger.log("BT_PROBE", "[3/7] Installed BT packages (with GET_DISABLED_COMPONENTS):");
            for (int i = 0; i < pkgs.size(); i++) {
                PackageInfo pi = pkgs.get(i);
                if (pi == null || pi.packageName == null) continue;
                String low = pi.packageName.toLowerCase(Locale.US);
                if (!containsAny(low, new String[]{"bluetooth", "broadcom", "brcm", "bsa", "gatt", "btsettings"})) {
                    continue;
                }

                boolean pkgEnabled = pi.applicationInfo != null && pi.applicationInfo.enabled;
                String srcDir = pi.applicationInfo != null ? String.valueOf(pi.applicationInfo.sourceDir) : "?";
                StringBuilder svcSb = new StringBuilder();
                if (pi.services != null) {
                    for (int s = 0; s < pi.services.length; s++) {
                        ServiceInfo si = pi.services[s];
                        if (si == null) continue;
                        if (svcSb.length() > 0) svcSb.append(", ");
                        svcSb.append(si.name).append(si.enabled ? "" : "(MANIFEST_DISABLED)");
                    }
                }
                DiagLogger.log("BT_PROBE", "  Pkg: " + pi.packageName
                        + " (enabled=" + pkgEnabled + ", apk=" + srcDir + ")"
                        + (svcSb.length() > 0 ? (" services=[" + svcSb + "]") : " services=[]"));
            }

            // Explicitly query ComponentEnabledSetting for GattService candidates
            String[] gattCandidates = {
                "com.android.bluetooth.gatt.GattService",
                "com.broadcom.bt.service.gatt.GattService"
            };
            for (int i = 0; i < gattCandidates.length; i++) {
                try {
                    ComponentName cn = new ComponentName("com.android.bluetooth", gattCandidates[i]);
                    int state = pm.getComponentEnabledSetting(cn);
                    DiagLogger.log("BT_PROBE", "  ComponentEnabledSetting(" + cn.flattenToShortString()
                            + ") = " + state + " (0=DEFAULT, 1=ENABLED, 2=DISABLED)");
                } catch (Throwable t) {
                    DiagLogger.log("BT_PROBE", "  ComponentEnabledSetting(" + gattCandidates[i]
                            + ") threw: " + t.getClass().getSimpleName() + ": " + t.getMessage());
                }
            }
        } catch (Throwable t) {
            DiagLogger.log("BT_PROBE", "Installed BT package scan err: " + t.getMessage());
        }
    }

    private static void probeBluetoothApkResourcesAndDex(Context ctx) {
        DiagLogger.log("BT_PROBE", "[4/7] Inspecting com.android.bluetooth resources & DEX/ODEX:");
        String btApkPath = "/system/app/Bluetooth.apk";
        try {
            PackageInfo pi = ctx.getPackageManager().getPackageInfo("com.android.bluetooth", 0);
            if (pi != null && pi.applicationInfo != null && pi.applicationInfo.sourceDir != null) {
                btApkPath = pi.applicationInfo.sourceDir;
            }
        } catch (Throwable ignored) {}

        // 4A. Read all <bool> config entries from com.android.bluetooth (e.g. profile_supported_gatt)
        try {
            Context btCtx = ctx.createPackageContext("com.android.bluetooth", 0);
            Resources res = btCtx.getResources();
            StringBuilder boolSb = new StringBuilder();
            int foundCount = 0;

            for (int typeIdx = 1; typeIdx <= 16; typeIdx++) {
                int probeId = 0x7f000000 | (typeIdx << 16);
                String typeName;
                try {
                    typeName = res.getResourceTypeName(probeId);
                } catch (Throwable ignored) {
                    continue;
                }
                if (!"bool".equals(typeName)) continue;

                for (int entryIdx = 0; entryIdx < 96; entryIdx++) {
                    int id = probeId | entryIdx;
                    try {
                        String entryName = res.getResourceEntryName(id);
                        boolean val = res.getBoolean(id);
                        if (boolSb.length() > 0) boolSb.append(", ");
                        boolSb.append(entryName).append('=').append(val);
                        foundCount++;
                    } catch (Throwable endOfEntries) {
                        break;
                    }
                }
                break;
            }

            if (foundCount > 0) {
                DiagLogger.log("BT_PROBE", "  Bluetooth.apk <bool> configs (" + foundCount + "): " + boolSb);
            } else {
                // Fallback direct identifier lookup
                String[] keys = {
                    "profile_supported_gatt", "profile_supported_bt_le", "profile_supported_a2dp",
                    "profile_supported_hs_hfp", "profile_supported_hid", "profile_supported_map"
                };
                for (int i = 0; i < keys.length; i++) {
                    int id = res.getIdentifier(keys[i], "bool", "com.android.bluetooth");
                    if (id != 0) {
                        DiagLogger.log("BT_PROBE", "  Bluetooth.apk bool " + keys[i] + "=" + res.getBoolean(id));
                    } else {
                        DiagLogger.log("BT_PROBE", "  Bluetooth.apk bool " + keys[i] + "=<not defined>");
                    }
                }
            }
        } catch (Throwable t) {
            DiagLogger.log("BT_PROBE", "  Bluetooth.apk resource read err: " + t);
        }

        // 4B. Inspect /system/app/Bluetooth.apk (or Bluetooth.odex) in RAM
        File apkFile = new File(btApkPath);
        byte[] btDex = loadDexOrOdexBytes(apkFile);
        if (btDex != null) {
            logTargetedDexInventory(apkFile.getName(), btDex, null,
                    new String[]{"gatt", "adapterservice", "btservice.config", "btservice.profile", "radiomanager", "blescan"},
                    true);
            logMatchingDexStrings(apkFile.getName(), btDex,
                    new String[]{"gatt", "radiomanager", "profile_supported", "ibluetoothgatt", "blescan"});
        } else {
            DiagLogger.log("BT_DEX", "  Could not read DEX/ODEX for " + btApkPath);
        }
    }

    private static void probeFrameworkBtAndServicesDex() {
        DiagLogger.log("BT_PROBE", "[5/7] Targeted /system/framework DEX/ODEX inspection:");

        // 5A. com.broadcom.bt.jar -> ONLY dump gatt & radiomanager classes in detail (zero AVRCP/MAP/PBAP noise)
        File brcmJar = new File("/system/framework/com.broadcom.bt.jar");
        byte[] brcmDex = loadDexOrOdexBytes(brcmJar);
        if (brcmDex != null) {
            logTargetedDexInventory("com.broadcom.bt.jar", brcmDex,
                    new String[]{"com.broadcom.bt.gatt.", "com.broadcom.bt.service.radiomanager."},
                    new String[]{"com.broadcom.bt.gatt.", "com.broadcom.bt.service.radiomanager."},
                    false);
        }

        // 5B. /system/framework/services.jar (or services.odex) -> ONLY BluetoothManagerService & BT/GATT classes!
        File servicesJar = new File("/system/framework/services.jar");
        byte[] servicesDex = loadDexOrOdexBytes(servicesJar);
        if (servicesDex != null) {
            logTargetedDexInventory("services.jar", servicesDex,
                    new String[]{"bluetooth", "gatt", "radiomanager"},
                    new String[]{"bluetoothmanagerservice", "gatt", "radiomanager"},
                    true);
            logMatchingDexStrings("services.jar", servicesDex,
                    new String[]{"gattservice", "enablegatt", "enableradio", "ibluetoothgatt", "bluetooth.gatt", "radiomgr"});
        } else {
            DiagLogger.log("BT_DEX", "  Could not read /system/framework/services.jar (.odex) within RAM cap");
        }
    }

    private static void probeBroadcomRadioManagerReadOnly(ClassLoader appLoader) {
        DiagLogger.log("BT_PROBE", "[6/7] Live ClassLoader & Broadcom BluetoothRadioManager read-only check:");
        String[] candidates = {
            BroadcomGattEnabler.CLS_RADIO_MGR,
            BroadcomGattEnabler.CLS_GATT_CB,
            BroadcomGattEnabler.CLS_RADIO_CB,
            "com.broadcom.bt.gatt.BluetoothGattExtras",
            "android.bluetooth.BluetoothGatt"
        };
        for (int i = 0; i < candidates.length; i++) {
            String cname = candidates[i];
            try {
                Class<?> cls = Class.forName(cname, false, appLoader);
                DiagLogger.log("BT_PROBE", "  Loaded " + cname + " (methods=" + cls.getDeclaredMethods().length + ")");
            } catch (Throwable t) {
                DiagLogger.log("BT_PROBE", "  Not in ClassLoader: " + cname + " (" + t.getClass().getSimpleName() + ")");
            }
        }

        try {
            Class<?> rmCls = Class.forName(BroadcomGattEnabler.CLS_RADIO_MGR, true, appLoader);
            StringBuilder constSb = new StringBuilder();
            Field[] fields = rmCls.getDeclaredFields();
            for (int i = 0; i < fields.length; i++) {
                Field f = fields[i];
                if (Modifier.isStatic(f.getModifiers())) {
                    f.setAccessible(true);
                    Object v = f.get(null);
                    if (constSb.length() > 0) constSb.append(", ");
                    constSb.append(f.getName()).append('=').append(v);
                }
            }
            DiagLogger.log("BT_PROBE", "  BluetoothRadioManager static fields: {" + constSb + "}");
        } catch (Throwable t) {
            DiagLogger.log("BT_PROBE", "  BluetoothRadioManager static inspect err: " + t);
        }
    }

    private static void probeSystemFilesAndDaemons() {
        DiagLogger.log("BT_PROBE", "[7/7] Read-only /system/etc/bluetooth configs, native libs, props & processes:");

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
        }

        File permDir = new File("/system/etc/permissions");
        File[] permFiles = permDir.listFiles();
        if (permFiles != null) {
            Arrays.sort(permFiles);
            for (int i = 0; i < permFiles.length; i++) {
                File f = permFiles[i];
                String low = f.getName().toLowerCase(Locale.US);
                if (containsAny(low, new String[]{"bluetooth", "broadcom", "brcm"})) {
                    DiagLogger.log("BT_SYS", "  Permission XML: " + f.getAbsolutePath() + " (" + f.length() + "B)");
                    if (f.isFile() && f.canRead() && f.length() <= 4096) {
                        logSmallConfigFile(f);
                    }
                }
            }
        }

        listMatchingFiles("/system/bin", new String[]{"bt", "blue", "brcm", "broadcom", "bsa", "gatt"});
        listMatchingFiles("/system/lib", new String[]{"bluetooth", "libbt", "brcm", "broadcom", "gatt"});
        listMatchingFiles("/system/lib/hw", new String[]{"bluetooth", "bt", "brcm", "broadcom"});

        runFilteredCommand(new String[]{"/system/bin/getprop"}, "BT_PROP",
                new String[]{".bt", "bt.", "bluetooth", "brcm", "broadcom", "gatt", "ble."}, true);

        runFilteredCommand(new String[]{"/system/bin/ps"}, "BT_PROC",
                new String[]{"bluetooth", "btsettings", "btaudio", "brcm", "broadcom", "gatt", "dipo"}, false);
    }

    private static byte[] loadDexOrOdexBytes(File jarOrApk) {
        if (jarOrApk == null) return null;
        if (jarOrApk.isFile() && jarOrApk.canRead() && jarOrApk.length() > 0) {
            ZipFile zf = null;
            try {
                zf = new ZipFile(jarOrApk);
                ZipEntry dexEntry = zf.getEntry("classes.dex");
                if (dexEntry != null && dexEntry.getSize() > 0 && dexEntry.getSize() <= MAX_DEX_BYTES) {
                    return readStreamBounded(zf.getInputStream(dexEntry), MAX_DEX_BYTES);
                }
            } catch (Throwable ignored) {
            } finally {
                if (zf != null) {
                    try { zf.close(); } catch (Throwable ignored) {}
                }
            }
        }

        // Check sibling .odex and arm/.odex
        String baseName = jarOrApk.getName();
        int dot = baseName.lastIndexOf('.');
        String stem = (dot > 0) ? baseName.substring(0, dot) : baseName;
        File parent = jarOrApk.getParentFile();
        File[] odexCandidates = {
            new File(parent, stem + ".odex"),
            new File(new File(parent, "arm"), stem + ".odex")
        };
        for (int i = 0; i < odexCandidates.length; i++) {
            File odex = odexCandidates[i];
            if (odex.isFile() && odex.canRead() && odex.length() > 0 && odex.length() <= MAX_DEX_BYTES) {
                FileInputStream fis = null;
                try {
                    fis = new FileInputStream(odex);
                    DiagLogger.log("BT_DEX", "  Reading companion ODEX: " + odex.getAbsolutePath()
                            + " (" + odex.length() + "B)");
                    return readStreamBounded(fis, MAX_DEX_BYTES);
                } catch (Throwable t) {
                    DiagLogger.log("BT_DEX", "  Failed reading " + odex.getAbsolutePath() + ": " + t);
                } finally {
                    if (fis != null) {
                        try { fis.close(); } catch (Throwable ignored) {}
                    }
                }
            }
        }
        return null;
    }

    private static void logTargetedDexInventory(String sourceName, byte[] rawBytes,
                                                String[] parseFilterLower,
                                                String[] detailKeywordsLower,
                                                boolean listMatchedClassSummary) {
        List<DexClassEntry> classes = extractDexInventory(rawBytes, parseFilterLower);
        DiagLogger.log("BT_DEX", "Parsed " + sourceName + " (" + rawBytes.length + "B) -> "
                + classes.size() + (parseFilterLower != null ? " filtered" : "") + " class(es)");
        if (classes.isEmpty()) return;

        if (listMatchedClassSummary) {
            StringBuilder classSummary = new StringBuilder();
            for (int i = 0; i < classes.size(); i++) {
                if (classSummary.length() > 0) classSummary.append(", ");
                classSummary.append(classes.get(i).className);
                if (classSummary.length() >= 480) {
                    DiagLogger.log("BT_DEX", "  Classes: " + classSummary);
                    classSummary.setLength(0);
                }
            }
            if (classSummary.length() > 0) {
                DiagLogger.log("BT_DEX", "  Classes: " + classSummary);
            }
        }

        for (int i = 0; i < classes.size(); i++) {
            DexClassEntry ce = classes.get(i);
            String low = ce.className.toLowerCase(Locale.US);
            if (detailKeywordsLower != null && !containsAny(low, detailKeywordsLower)) {
                continue;
            }
            DiagLogger.log("BT_DEX", "  [CLASS] " + formatClassModifiers(ce.accessFlags) + ce.className
                    + (ce.superName != null && !"java.lang.Object".equals(ce.superName)
                    ? (" extends " + ce.superName) : ""));
            for (int f = 0; f < ce.staticFields.size(); f++) {
                DiagLogger.log("BT_DEX", "    sfield: " + ce.staticFields.get(f));
            }
            for (int f = 0; f < ce.instanceFields.size(); f++) {
                DiagLogger.log("BT_DEX", "    ifield: " + ce.instanceFields.get(f));
            }
            for (int m = 0; m < ce.declaredMethods.size(); m++) {
                DiagLogger.log("BT_DEX", "    method: " + ce.declaredMethods.get(m));
            }
        }
    }

    private static void logMatchingDexStrings(String sourceName, byte[] rawBytes, String[] needlesLower) {
        byte[] dex = unwrapOdexIfNeeded(rawBytes);
        if (dex == null) return;
        ByteBuffer buf = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN);
        if (buf.getInt(40) != 0x12345678) return;

        int stringIdsSize = buf.getInt(56);
        int stringIdsOff = buf.getInt(60);
        if (stringIdsSize <= 0 || stringIdsOff <= 0 || stringIdsOff + stringIdsSize * 4 > dex.length) {
            return;
        }

        StringBuilder sb = new StringBuilder();
        int matched = 0;
        for (int i = 0; i < stringIdsSize && matched < 45; i++) {
            String s = readDexString(dex, buf, stringIdsSize, stringIdsOff, i);
            if (s == null || s.length() < 4 || s.length() > 110) continue;
            // Skip raw descriptor signatures starting with '(' or '['
            char c0 = s.charAt(0);
            if (c0 == '(' || c0 == '[') continue;
            String low = s.toLowerCase(Locale.US);
            if (containsAny(low, needlesLower)) {
                if (sb.length() > 0) sb.append(" | ");
                sb.append('"').append(s.replace('\n', ' ')).append('"');
                matched++;
                if (sb.length() >= 440) {
                    DiagLogger.log("BT_DEX", "  " + sourceName + " strings: " + sb);
                    sb.setLength(0);
                }
            }
        }
        if (sb.length() > 0) {
            DiagLogger.log("BT_DEX", "  " + sourceName + " strings: " + sb);
        }
    }

    private static void logSmallConfigFile(File f) {
        BufferedReader br = null;
        try {
            br = new BufferedReader(new InputStreamReader(new FileInputStream(f), UTF8));
            String line;
            int lineCount = 0;
            while ((line = br.readLine()) != null && lineCount < 60) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith("//")
                        || trimmed.startsWith("<!--")) {
                    continue;
                }
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

    /**
     * Masks trailing 3 octets of both colon-delimited MACs (XX:XX:XX:**:**:**) and contiguous
     * 12-hex-digit adapter addresses (e.g. ro.btaddr C8D9D2******).
     */
    public static String redactMacOctets(String s) {
        if (s == null) return "";
        String masked = s.replaceAll(
                "(?i)([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}):[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}",
                "$1:**:**:**");
        String low = masked.toLowerCase(Locale.US);
        if (low.indexOf("addr") >= 0 || low.indexOf("mac") >= 0) {
            masked = masked.replaceAll(
                    "(?i)(?<![0-9a-f])([0-9a-f]{6})[0-9a-f]{6}(?![0-9a-f])",
                    "$1******");
        }
        return masked;
    }

    // ================= PURE-JAVA IN-RAM DALVIK DEX / ODEX PARSER =================

    public static List<DexClassEntry> extractDexInventory(byte[] rawBytes) {
        return extractDexInventory(rawBytes, null);
    }

    /**
     * Parses a Dalvik DEX ("dex\n035\0") or optimized ODEX ("dey\n036\0") byte buffer in RAM
     * and returns defined classes (optionally pre-filtered by lowercase substring match so large
     * system archives like services.odex allocate zero objects for unrelated classes).
     */
    public static List<DexClassEntry> extractDexInventory(byte[] rawBytes, String[] classFilterLower) {
        byte[] dex = unwrapOdexIfNeeded(rawBytes);
        if (dex == null) {
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

        List<DexClassEntry> out = new ArrayList<DexClassEntry>(
                classFilterLower == null ? classDefsSize : Math.min(classDefsSize, 64));
        for (int c = 0; c < classDefsSize; c++) {
            int cOff = classDefsOff + c * 32;
            int classIdx = buf.getInt(cOff);
            String className = readTypeName(dex, buf, stringIdsSize, stringIdsOff, typeIdsSize, typeIdsOff, classIdx);
            if (classFilterLower != null) {
                String low = className.toLowerCase(Locale.US);
                if (!containsAny(low, classFilterLower)) {
                    continue;
                }
            }

            int accessFlags = buf.getInt(cOff + 4);
            int superIdx = buf.getInt(cOff + 8);
            int classDataOff = buf.getInt(cOff + 24);

            String superName = (superIdx >= 0 && superIdx < typeIdsSize)
                    ? readTypeName(dex, buf, stringIdsSize, stringIdsOff, typeIdsSize, typeIdsOff, superIdx)
                    : null;

            List<String> staticFields = new ArrayList<String>();
            List<String> instanceFields = new ArrayList<String>();
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

                fieldIdx = 0;
                for (int i = 0; i < instanceFieldsSize && pos[0] < dex.length; i++) {
                    fieldIdx += readUleb128(dex, pos);
                    int fAccess = readUleb128(dex, pos);
                    instanceFields.add(formatFieldSig(dex, buf, stringIdsSize, stringIdsOff,
                            typeIdsSize, typeIdsOff, fieldIdsSize, fieldIdsOff, fieldIdx, fAccess));
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

            out.add(new DexClassEntry(className, superName, accessFlags, staticFields, instanceFields, methods));
        }

        Collections.sort(out, new Comparator<DexClassEntry>() {
            @Override
            public int compare(DexClassEntry a, DexClassEntry b) {
                return a.className.compareTo(b.className);
            }
        });
        return out;
    }

    private static byte[] unwrapOdexIfNeeded(byte[] rawBytes) {
        if (rawBytes == null || rawBytes.length < 112) {
            return null;
        }
        byte[] dex = rawBytes;
        if (dex[0] == 'd' && dex[1] == 'e' && dex[2] == 'y' && dex[3] == '\n') {
            ByteBuffer odexHdr = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN);
            int dexOff = odexHdr.getInt(8);
            int dexLen = odexHdr.getInt(12);
            if (dexOff < 40 || dexLen < 112 || dexOff + dexLen > dex.length) {
                return null;
            }
            byte[] slice = new byte[dexLen];
            System.arraycopy(dex, dexOff, slice, 0, dexLen);
            dex = slice;
        }
        if (dex[0] != 'd' || dex[1] != 'e' || dex[2] != 'x' || dex[3] != '\n') {
            return null;
        }
        return dex;
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
