package bvm02.app;

import android.bluetooth.BluetoothAdapter;
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
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Strictly passive, read-only, in-RAM Gen5W Bluetooth, HAL, DEX bytecode & ELF32 stack introspector (v0.1.5).
 *
 * SAFETY INVARIANTS (Gen5W Telechips TCC803x tcc.solution.bluetooth.mbox=1):
 *  - NEVER invokes @hide Binder IPC methods on system_server (never calls enableGatt, enableRadio,
 *    disableRadio, isRadioEnabled, or registerRadioMgrCallback).
 *  - NEVER enables or binds disabled components (com.android.bluetooth/.gatt.GattService).
 *  - NEVER loads or initializes com.broadcom.bt.* classes via Class.forName.
 *  - NEVER calls dlopen / System.loadLibrary on native .so files; inspects ELF32 .dynsym, .dynamic,
 *    PT_LOAD segments, and .rodata tables strictly via pure-Java FileInputStream byte parsing in RAM.
 *  - NEVER opens /dev character devices; lists /dev node names, /proc/<bt_pid>/maps, and /sys/bus/usb passively.
 *  - Zero writes to /system or internal /data eMMC flash, and zero PII/VIN/serial collection.
 */
public final class BtStackProbe {

    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static final int MAX_DEX_BYTES = 16 * 1024 * 1024;
    private static final int MAX_ELF_BYTES = 4 * 1024 * 1024;
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

    public static final class DexMethodTrace {
        public final String className;
        public final String methodSignature;
        public final int insnsUnits;
        public final List<String> ops;

        public DexMethodTrace(String className, String methodSignature, int insnsUnits, List<String> ops) {
            this.className = className;
            this.methodSignature = methodSignature;
            this.insnsUnits = insnsUnits;
            this.ops = ops;
        }
    }

    public static final class ElfSym {
        public final String name;
        public final long stValue;
        public final long stSize;
        public final int stInfo;

        public ElfSym(String name, long stValue, long stSize, int stInfo) {
            this.name = name;
            this.stValue = stValue;
            this.stSize = stSize;
            this.stInfo = stInfo;
        }

        public boolean isThumbFunc() {
            return (stInfo & 0x0F) == 2 && (stValue & 1L) != 0L;
        }

        public long cleanVaddr() {
            return ((stInfo & 0x0F) == 2) ? (stValue & ~1L) : stValue;
        }
    }

    public static final class ElfLoadSeg {
        public final long pOffset;
        public final long pVaddr;
        public final long pFilesz;

        public ElfLoadSeg(long pOffset, long pVaddr, long pFilesz) {
            this.pOffset = pOffset;
            this.pVaddr = pVaddr;
            this.pFilesz = pFilesz;
        }
    }

    public static final class Elf32Info {
        public final int machine;
        public final List<String> neededLibs;
        public final List<String> exportedSymbols;
        public final List<String> importedSymbols;
        public final List<String> rodataStrings;
        public final Map<String, ElfSym> exportedSymMap;
        public final List<ElfLoadSeg> loadSegments;

        public Elf32Info(int machine, List<String> neededLibs,
                         List<String> exportedSymbols, List<String> importedSymbols) {
            this(machine, neededLibs, exportedSymbols, importedSymbols,
                    Collections.<String>emptyList(),
                    Collections.<String, ElfSym>emptyMap(),
                    Collections.<ElfLoadSeg>emptyList());
        }

        public Elf32Info(int machine, List<String> neededLibs,
                         List<String> exportedSymbols, List<String> importedSymbols,
                         List<String> rodataStrings) {
            this(machine, neededLibs, exportedSymbols, importedSymbols, rodataStrings,
                    Collections.<String, ElfSym>emptyMap(),
                    Collections.<ElfLoadSeg>emptyList());
        }

        public Elf32Info(int machine, List<String> neededLibs,
                         List<String> exportedSymbols, List<String> importedSymbols,
                         List<String> rodataStrings,
                         Map<String, ElfSym> exportedSymMap,
                         List<ElfLoadSeg> loadSegments) {
            this.machine = machine;
            this.neededLibs = neededLibs;
            this.exportedSymbols = exportedSymbols;
            this.importedSymbols = importedSymbols;
            this.rodataStrings = rodataStrings;
            this.exportedSymMap = exportedSymMap;
            this.loadSegments = loadSegments;
        }

        public int vaddrToFileOffset(long vaddr, int fileLen) {
            if (vaddr < 0) return -1;
            for (int i = 0; i < loadSegments.size(); i++) {
                ElfLoadSeg seg = loadSegments.get(i);
                if (vaddr >= seg.pVaddr && vaddr < seg.pVaddr + seg.pFilesz) {
                    long off = seg.pOffset + (vaddr - seg.pVaddr);
                    if (off >= 0 && off < fileLen) {
                        return (int) off;
                    }
                }
            }
            if (loadSegments.isEmpty() && vaddr > 0 && vaddr < fileLen) {
                return (int) vaddr;
            }
            return -1;
        }

        public String readCStringAtVaddr(byte[] elf, long vaddr) {
            if (elf == null || vaddr <= 0) return null;
            int off = vaddrToFileOffset(vaddr, elf.length);
            if (off < 0 || off >= elf.length) return null;
            int end = off;
            int limit = Math.min(elf.length, off + 160);
            while (end < limit && elf[end] != 0) {
                int b = elf[end] & 0xFF;
                if (b < 0x20 || b > 0x7E) return null;
                end++;
            }
            return new String(elf, off, end - off, UTF8);
        }

        public long readUint32AtVaddr(byte[] elf, long vaddr) {
            if (elf == null || vaddr <= 0) return -1L;
            int off = vaddrToFileOffset(vaddr, elf.length);
            if (off < 0 || off + 4 > elf.length) return -1L;
            return ((long) (elf[off] & 0xFF))
                    | (((long) (elf[off + 1] & 0xFF)) << 8)
                    | (((long) (elf[off + 2] & 0xFF)) << 16)
                    | (((long) (elf[off + 3] & 0xFF)) << 24);
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
     * Standard read-only getter called by framework BluetoothAdapter.startLeScan / BluetoothDevice.connectGatt.
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
     * Runs the strictly passive Gen5W Bluetooth, HAL, DEX bytecode & ELF32 stack probe on a background thread.
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
        DiagLogger.log("BT_PROBE", "=== BEGIN PASSIVE GEN5W BLUETOOTH HAL, DEX & ELF32 STACK PROBE (v0.1.5) ===");

        BluetoothAdapter adapter = null;
        try {
            adapter = BluetoothAdapter.getDefaultAdapter();
        } catch (Throwable t) {
            DiagLogger.log("BT_PROBE", "getDefaultAdapter threw: " + t);
        }

        // 1. Passive Binder handle status check (zero hidden Binder IPC calls)
        DiagLogger.log("BT_PROBE", "[1/8] Adapter Binder Handles: " + checkIBluetoothGattStatus(adapter));
        Object liveGatt = getLiveIBluetoothGatt(adapter);
        if (liveGatt != null) {
            DiagLogger.log("BT_PROBE", "  Live IBluetoothGatt binder present: " + describeBinderOwner(liveGatt));
        }

        // 2. System shared libraries & Binder ServiceManager inventory
        probeSharedLibrariesAndBinderServices(ctx);

        // 3. Installed Bluetooth packages (including GET_DISABLED_COMPONENTS) & GattService state
        probeInstalledBtPackages(ctx);

        // 4. HMG-API read-only root snapshot (/proc/<bt_pid>/maps, /proc/<bt_pid>/fd, HAL dirs, init.*.rc)
        Set<String> mappedSoPaths = probeRootProcessMapsAndHal();

        // 5. /system/app/Bluetooth.apk boolean config table & targeted Dalvik bytecode X-ray (Config, ProfileService, b, f, AdapterService, GattService)
        probeBluetoothApkResourcesAndDex(ctx);

        // 6. /system/framework/services.jar (.odex) BluetoothManagerService Dalvik bytecode X-ray
        probeFrameworkBtAndServicesDex();

        // 7. Deep passive ELF32 multi-bucket .dynsym, hw_module_t, PT_LOAD prologues & full .rodata inspection
        probeNativeBtElfLibraries(mappedSoPaths);

        // 8. Unfiltered HAL directories, /dev nodes, USB sysfs, props & processes
        probeSystemFilesAndDaemons();

        DiagLogger.log("BT_PROBE", "=== END PASSIVE GEN5W BLUETOOTH HAL, DEX & ELF32 STACK PROBE (v0.1.5) ===");
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
                DiagLogger.log("BT_PROBE", "[2/8] System Shared Libraries (" + libs.length + "): " + sb);
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
            DiagLogger.log("BT_PROBE", "[3/8] Installed BT packages (with GET_DISABLED_COMPONENTS):");
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

    private static Set<String> probeRootProcessMapsAndHal() {
        DiagLogger.log("BT_PROBE", "[4/8] HMG-API read-only btprobe snapshot (/proc/<bt_pid>/maps, open fds, init.*.rc):");
        Set<String> mappedSoPaths = new LinkedHashSet<String>();
        try {
            String out = HmgapidClient.runManualServiceAndReadLog("btprobe", 4800);
            if (out == null || out.trim().isEmpty()) {
                DiagLogger.log("BT_ROOT", "  hmgapid btprobe service unavailable or empty (continuing with in-app HAL/ELF32/DEX X-ray)");
                return mappedSoPaths;
            }
            String[] lines = out.split("\n");
            for (int i = 0; i < lines.length; i++) {
                String line = lines[i].replace("\r", "").trim();
                if (line.isEmpty()) continue;
                String low = line.toLowerCase(Locale.US);
                if (containsAny(low, new String[]{"serial", "vin", "token", "account", "passwd", "password"})) {
                    continue;
                }
                DiagLogger.log("BT_ROOT", "  " + redactMacOctets(line));
                if (line.startsWith("BTMAP:") && line.endsWith(".so")) {
                    int slash = line.indexOf('/');
                    if (slash >= 0) {
                        mappedSoPaths.add(line.substring(slash).trim());
                    }
                }
            }
        } catch (Throwable t) {
            DiagLogger.log("BT_ROOT", "  btprobe snapshot err: " + t.getMessage());
        }
        return mappedSoPaths;
    }

    private static void probeBluetoothApkResourcesAndDex(Context ctx) {
        DiagLogger.log("BT_PROBE", "[5/8] Inspecting com.android.bluetooth resources & targeted Dalvik bytecode:");
        String btApkPath = "/system/app/Bluetooth.apk";
        try {
            PackageInfo pi = ctx.getPackageManager().getPackageInfo("com.android.bluetooth", 0);
            if (pi != null && pi.applicationInfo != null && pi.applicationInfo.sourceDir != null) {
                btApkPath = pi.applicationInfo.sourceDir;
            }
        } catch (Throwable ignored) {}

        Map<Integer, String> resIdMap = new HashMap<Integer, String>();
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
                        resIdMap.put(Integer.valueOf(id), entryName + "=" + val);
                        if (boolSb.length() > 0) boolSb.append(", ");
                        boolSb.append(String.format(Locale.US, "%s(0x%08x)=%s", entryName, Integer.valueOf(id), String.valueOf(val)));
                        foundCount++;
                    } catch (Throwable endOfEntries) {
                        break;
                    }
                }
                break;
            }

            if (foundCount > 0) {
                DiagLogger.log("BT_PROBE", "  Bluetooth.apk <bool> configs (" + foundCount + "): " + boolSb);
            }
        } catch (Throwable t) {
            DiagLogger.log("BT_PROBE", "  Bluetooth.apk resource read err: " + t);
        }

        File apkFile = new File(btApkPath);
        byte[] btDex = loadDexOrOdexBytes(apkFile);
        if (btDex != null) {
            List<DexMethodTrace> traces = new ArrayList<DexMethodTrace>();
            traces.addAll(extractDexMethodTraces(
                    btDex,
                    new String[]{
                            "com.android.bluetooth.btservice.profileservice",
                            "com.android.bluetooth.btservice.config",
                            "com.android.bluetooth.btservice.adapterservice",
                            "com.android.bluetooth.gatt.gattservice"
                    },
                    new String[]{
                            "<clinit>", "init", "getsupportedprofiles",
                            "oncreate", "onbind", "onstartcommand", "dostart", "dostop", "isavailable",
                            "processstart", "setprofileservicestate",
                            "isprofileallowed", "setprofilestate",
                            "start", "stop", "cleanup", "initbinder",
                            "enforceprivilegedpermission", "registerclient",
                            "startscan", "startscanwithuuids", "clientconnect"
                    },
                    resIdMap));
            // Also disassemble all methods of Broadcom's obfuscated profile config helpers (btservice.a, b, f)
            List<DexMethodTrace> allBtSvc = extractDexMethodTraces(
                    btDex,
                    new String[]{"com.android.bluetooth.btservice."},
                    null,
                    resIdMap);
            for (int i = 0; i < allBtSvc.size(); i++) {
                DexMethodTrace m = allBtSvc.get(i);
                if ("com.android.bluetooth.btservice.a".equals(m.className)
                        || "com.android.bluetooth.btservice.b".equals(m.className)
                        || "com.android.bluetooth.btservice.f".equals(m.className)) {
                    traces.add(m);
                }
            }
            logMethodTraces("Bluetooth.odex", traces);
        } else {
            DiagLogger.log("BT_DEX", "  Could not read DEX/ODEX for " + btApkPath);
        }
    }

    private static void probeFrameworkBtAndServicesDex() {
        DiagLogger.log("BT_PROBE", "[6/8] Passive /system/framework/services.jar (.odex) BluetoothManagerService bytecode X-ray:");

        File servicesJar = new File("/system/framework/services.jar");
        byte[] servicesDex = loadDexOrOdexBytes(servicesJar);
        if (servicesDex != null) {
            List<DexMethodTrace> traces = extractDexMethodTraces(
                    servicesDex,
                    new String[]{"com.android.server.bluetoothmanagerservice"},
                    new String[]{
                            "<clinit>", "<init>", "enablegatt", "getbluetoothgatt",
                            "bluetoothstatechangehandler", "handleenable", "dobind",
                            "sendgattservicestatuscallback", "handlemessage",
                            "onserviceconnected", "onservicedisconnected"
                    },
                    null);
            logMethodTraces("services.odex", traces);
        } else {
            DiagLogger.log("BT_DEX", "  Could not read /system/framework/services.jar (.odex) within RAM cap");
        }
    }

    private static void logMethodTraces(String label, List<DexMethodTrace> traces) {
        DiagLogger.log("BT_DEX", "  " + label + " targeted bytecode traces (" + traces.size() + " method(s)):");
        for (int i = 0; i < traces.size(); i++) {
            DexMethodTrace tr = traces.get(i);
            DiagLogger.log("BT_DEX", "  [CODE] " + tr.className + " :: " + tr.methodSignature
                    + " (" + tr.insnsUnits + " units, " + tr.ops.size() + " refs)");
            StringBuilder sb = new StringBuilder();
            for (int j = 0; j < tr.ops.size() && j < 140; j++) {
                if (sb.length() > 0) sb.append(" -> ");
                sb.append(tr.ops.get(j));
                if (sb.length() >= 440) {
                    DiagLogger.log("BT_DEX", "    ops: " + sb);
                    sb.setLength(0);
                }
            }
            if (sb.length() > 0) {
                DiagLogger.log("BT_DEX", "    ops: " + sb);
            }
        }
    }

    private static void probeNativeBtElfLibraries(Set<String> mappedSoPaths) {
        DiagLogger.log("BT_PROBE", "[7/8] Deep passive FileInputStream ELF32 multi-bucket .dynsym, hw_module_t, PT_LOAD & .rodata inspection (zero dlopen):");

        Set<String> targetPaths = new LinkedHashSet<String>();
        targetPaths.add("/system/lib/libbluetooth_jni.so");

        // Scan /system/lib/hw and /vendor/lib/hw for any Bluetooth or unknown HAL module (e.g. bplus.default.so)
        String[] hwDirs = {"/system/lib/hw", "/vendor/lib/hw"};
        for (int d = 0; d < hwDirs.length; d++) {
            File dir = new File(hwDirs[d]);
            File[] files = dir.listFiles();
            if (files == null) continue;
            Arrays.sort(files);
            for (int i = 0; i < files.length; i++) {
                File f = files[i];
                if (!f.isFile() || !f.getName().endsWith(".so")) continue;
                String low = f.getName().toLowerCase(Locale.US);
                if (!isUnrelatedHalModule(low)) {
                    targetPaths.add(f.getAbsolutePath());
                }
            }
        }

        // Scan /system/lib and /vendor/lib for Bluetooth / mbox / Broadcom / GATT libraries (skipping OS boilerplate)
        String[] libDirs = {"/system/lib", "/vendor/lib"};
        for (int d = 0; d < libDirs.length; d++) {
            File dir = new File(libDirs[d]);
            File[] files = dir.listFiles();
            if (files == null) continue;
            Arrays.sort(files);
            for (int i = 0; i < files.length; i++) {
                File f = files[i];
                if (!f.isFile() || !f.getName().endsWith(".so")) continue;
                String low = f.getName().toLowerCase(Locale.US);
                if (isStandardAndroidOsLibrary(low)) continue;
                if (containsAny(low, new String[]{"bluetooth", "bplus", "libbt", "brcm", "broadcom", "gatt", "mbox", "tcc_bt"})) {
                    targetPaths.add(f.getAbsolutePath());
                }
            }
        }

        // Include every non-boilerplate .so mapped inside com.android.bluetooth's address space
        if (mappedSoPaths != null) {
            for (String mp : mappedSoPaths) {
                String name = new File(mp).getName().toLowerCase(Locale.US);
                if (!isStandardAndroidOsLibrary(name)) {
                    targetPaths.add(mp);
                }
            }
        }

        for (String path : targetPaths) {
            File f = new File(path);
            if (!f.isFile() || !f.canRead()) {
                DiagLogger.log("BT_ELF", "  " + path + " -> absent or unreadable");
                continue;
            }
            if (f.length() <= 0 || f.length() > MAX_ELF_BYTES) {
                DiagLogger.log("BT_ELF", "  " + path + " (" + f.length() + "B) -> skipped (outside 4MB cap)");
                continue;
            }

            byte[] elfBytes = null;
            FileInputStream fis = null;
            try {
                fis = new FileInputStream(f);
                elfBytes = readStreamBounded(fis, MAX_ELF_BYTES);
            } catch (Throwable t) {
                DiagLogger.log("BT_ELF", "  Failed reading " + path + ": " + t.getMessage());
            } finally {
                if (fis != null) {
                    try { fis.close(); } catch (Throwable ignored) {}
                }
            }
            if (elfBytes == null) continue;

            Elf32Info info = extractElf32Info(elfBytes);
            if (info == null) {
                DiagLogger.log("BT_ELF", "  " + f.getName() + " (" + elfBytes.length + "B) -> not an ELF32 LSB shared object");
                continue;
            }

            DiagLogger.log("BT_ELF", "  [ELF32] " + f.getAbsolutePath() + " (" + elfBytes.length
                    + "B, machine=" + info.machine
                    + ", PT_LOAD=" + info.loadSegments.size()
                    + ", DT_NEEDED=" + info.neededLibs
                    + ", exported=" + info.exportedSymbols.size()
                    + ", imported=" + info.importedSymbols.size()
                    + ", rodataStrings=" + info.rodataStrings.size() + ")");

            boolean isPrimaryBtJniOrHal = path.contains("libbluetooth_jni.so")
                    || path.contains("/hw/")
                    || f.getName().toLowerCase(Locale.US).contains("bluetooth")
                    || f.getName().toLowerCase(Locale.US).contains("bplus")
                    || f.getName().toLowerCase(Locale.US).contains("mbox");

            logFilteredSymbolList("    import", info.importedSymbols, info.exportedSymMap, false,
                    (isPrimaryBtJniOrHal || info.importedSymbols.size() <= 180) ? null : new String[]{
                            "hw_", "bt", "tcc", "mbox", "gatt", "ble", "le_", "bta", "btm", "hci", "ipc", "ioctl", "open", "dlopen"
                    }, 220, false);

            if (info.exportedSymbols.size() <= 200) {
                logFilteredSymbolList("    export", info.exportedSymbols, info.exportedSymMap, true, null, 200, false);
            } else {
                // Multi-bucket non-competing symbol inventory so Classic BT (BTA_Av*) never starves GATT/BLE/L2CAP/HCI
                logFilteredSymbolList("    export[HAL/BTIF]", info.exportedSymbols, info.exportedSymMap, true,
                        new String[]{"hal_module", "btif_", "bluetooth_", "profile", "bplus", "sbluetooth"}, 200, true);
                logFilteredSymbolList("    export[GATT/ATT/SMP]", info.exportedSymbols, info.exportedSymMap, true,
                        new String[]{"gatt", "att_", "_att", "smp_"}, 260, true);
                logFilteredSymbolList("    export[BLE/BTM/GAP]", info.exportedSymbols, info.exportedSymMap, true,
                        new String[]{"ble", "bta_dm_", "btm_sec", "btm_acl", "btm_read", "btm_inq", "gap_"}, 260, true);
                logFilteredSymbolList("    export[L2CAP/GKI/BTU]", info.exportedSymbols, info.exportedSymMap, true,
                        new String[]{"l2ca_", "l2c_", "gki_", "btu_", "bta_sys"}, 260, true);
                logFilteredSymbolList("    export[HCI/VENDOR/TCC]", info.exportedSymbols, info.exportedSymMap, true,
                        new String[]{"hci", "vendor", "userial", "upio", "tcc", "mbox", "bt_hc", "brcm"}, 220, true);
            }

            logHalStructAndKeyPrologues(f.getName(), elfBytes, info);
            logElfRodataStrings(f.getName(), info.rodataStrings);
        }
    }

    private static void logHalStructAndKeyPrologues(String fileName, byte[] elf, Elf32Info info) {
        ElfSym halSym = info.exportedSymMap.get("HAL_MODULE_INFO_SYM");
        if (halSym != null) {
            long base = halSym.cleanVaddr();
            long tag = info.readUint32AtVaddr(elf, base);
            long idPtr = info.readUint32AtVaddr(elf, base + 8);
            long namePtr = info.readUint32AtVaddr(elf, base + 12);
            long authorPtr = info.readUint32AtVaddr(elf, base + 16);
            long methodsPtr = info.readUint32AtVaddr(elf, base + 20);
            long openFnPtr = (methodsPtr > 0) ? info.readUint32AtVaddr(elf, methodsPtr) : -1L;

            String idStr = info.readCStringAtVaddr(elf, idPtr);
            String nameStr = info.readCStringAtVaddr(elf, namePtr);
            String authorStr = info.readCStringAtVaddr(elf, authorPtr);
            DiagLogger.log("BT_ELF", String.format(Locale.US,
                    "    [HAL_STRUCT %s] vaddr=0x%x tag=0x%08x id='%s'(0x%x) name='%s' author='%s' methods=0x%x openFn=0x%x",
                    fileName, Long.valueOf(base), Long.valueOf(tag),
                    String.valueOf(idStr), Long.valueOf(idPtr),
                    String.valueOf(nameStr), String.valueOf(authorStr),
                    Long.valueOf(methodsPtr), Long.valueOf(openFnPtr)));

            if (openFnPtr > 0) {
                boolean thumb = (openFnPtr & 1L) != 0L;
                long cleanOpen = openFnPtr & ~1L;
                dumpElfBytesAtVaddr(fileName, "hw_methods->open", elf, info, cleanOpen, thumb, 160);
            }
        }

        String[] keySymbols = {
                "HAL_MODULE_INFO_SYM",
                "btif_gatt_get_interface",
                "BTA_DmBleObserve",
                "BTM_BleObserve",
                "BTA_DmSetBleScanParams",
                "BTM_BleSetScanParams",
                "BTA_DmBleStackEnable",
                "GATT_Register",
                "GATT_Connect",
                "GATT_Disconnect",
                "GATTC_ConfigureMTU",
                "GATTC_Discover",
                "GATTC_Read",
                "GATTC_Write",
                "L2CA_RegisterFixedChannel",
                "L2CA_ConnectFixedChnl",
                "L2CA_RemoveFixedChnl",
                "L2CA_SendFixedChnlData",
                "L2CA_SetFixedChannelTout",
                "GKI_getbuf",
                "GKI_freebuf",
                "bta_sys_sendmsg",
                "JNI_OnLoad",
                "_ZN7android21getBluetoothInterfaceEv",
                "_ZN7android35register_com_android_bluetooth_gattEP7_JNIEnv",
                "_ZN7android55register_com_android_bluetooth_btservice_AdapterServiceEP7_JNIEnv"
        };

        for (int i = 0; i < keySymbols.length; i++) {
            ElfSym sym = info.exportedSymMap.get(keySymbols[i]);
            if (sym == null) continue;
            int dumpLen = (int) Math.min(160L, sym.stSize > 0 ? sym.stSize : 128L);
            if (dumpLen < 32) dumpLen = (int) Math.max(sym.stSize, 32L);
            dumpElfBytesAtVaddr(fileName, sym.name + "(sz=" + sym.stSize + ")",
                    elf, info, sym.cleanVaddr(), sym.isThumbFunc(), dumpLen);
        }
    }

    private static void dumpElfBytesAtVaddr(String fileName, String label, byte[] elf, Elf32Info info,
                                            long cleanVaddr, boolean isThumb, int byteCount) {
        int fileOff = info.vaddrToFileOffset(cleanVaddr, elf.length);
        if (fileOff < 0 || fileOff >= elf.length) {
            DiagLogger.log("BT_ELF", String.format(Locale.US,
                    "    [HEX %s :: %s] vaddr=0x%x (unmapped)", fileName, label, Long.valueOf(cleanVaddr)));
            return;
        }
        int n = Math.min(byteCount, elf.length - fileOff);
        StringBuilder hex = new StringBuilder(n * 2);
        for (int i = 0; i < n; i++) {
            int b = elf[fileOff + i] & 0xFF;
            if (b < 0x10) hex.append('0');
            hex.append(Integer.toHexString(b));
        }
        DiagLogger.log("BT_ELF", String.format(Locale.US,
                "    [HEX %s :: %s] vaddr=0x%x off=0x%x mode=%s bytes(%d)=%s",
                fileName, label, Long.valueOf(cleanVaddr), Integer.valueOf(fileOff),
                isThumb ? "Thumb" : "ARM/Data", Integer.valueOf(n), hex.toString()));
    }

    private static void logElfRodataStrings(String fileName, List<String> rodataStrings) {
        if (rodataStrings == null || rodataStrings.isEmpty()) return;

        // 1. Unfiltered context window around "BluetoothServiceJni" or "get_profile_interface"
        for (int i = 0; i < rodataStrings.size(); i++) {
            String s = rodataStrings.get(i);
            if ("BluetoothServiceJni".equals(s) || s.startsWith("get_profile_interface")) {
                int start = Math.max(0, i - 10);
                int end = Math.min(rodataStrings.size(), i + 36);
                StringBuilder ctxSb = new StringBuilder();
                for (int k = start; k < end; k++) {
                    if (ctxSb.length() > 0) ctxSb.append(" | ");
                    ctxSb.append('"').append(redactMacOctets(rodataStrings.get(k))).append('"');
                    if (ctxSb.length() >= 440) {
                        DiagLogger.log("BT_ELF", "    rodata_ctx[" + fileName + " @" + s + "]: " + ctxSb);
                        ctxSb.setLength(0);
                    }
                }
                if (ctxSb.length() > 0) {
                    DiagLogger.log("BT_ELF", "    rodata_ctx[" + fileName + " @" + s + "]: " + ctxSb);
                }
            }
        }

        // 2. Full-binary targeted GATT / BLE / L2CAP / HCI / TCC / Broadcom .rodata scan (across ALL strings)
        String[] highPriorityKeywords = {
                "gatt", "att_", "ble", "l2cap", "fixed_chnl", "fixed ch", "tcc", "mbox",
                "/dev/", "libbt", "vendor", "bplus", "bcm", "433", "434", "435", "893",
                "uart", "tty", "bt_hc", "snoop", "get_profile_interface", "mock_stack",
                "hw_get", "bt_stack"
        };
        StringBuilder sb = new StringBuilder();
        int logged = 0;
        for (int i = 0; i < rodataStrings.size() && logged < 420; i++) {
            String s = rodataStrings.get(i);
            if (!containsAny(s.toLowerCase(Locale.US), highPriorityKeywords)) {
                continue;
            }
            if (sb.length() > 0) sb.append(" | ");
            sb.append('"').append(redactMacOctets(s)).append('"');
            logged++;
            if (sb.length() >= 440) {
                DiagLogger.log("BT_ELF", "    rodata_match[" + fileName + "]: " + sb);
                sb.setLength(0);
            }
        }
        if (sb.length() > 0) {
            DiagLogger.log("BT_ELF", "    rodata_match[" + fileName + "]: " + sb);
        } else {
            DiagLogger.log("BT_ELF", "    rodata_match[" + fileName + "]: <0 matched>");
        }
    }

    private static boolean isUnrelatedHalModule(String lowerName) {
        return lowerName.startsWith("audio.primary.")
                || lowerName.startsWith("audio.a2dp.")
                || lowerName.startsWith("audio.usb.")
                || lowerName.startsWith("audio.r_submix.")
                || lowerName.startsWith("audio_policy.")
                || lowerName.startsWith("camera.")
                || lowerName.startsWith("rearcamera.")
                || lowerName.startsWith("gralloc.")
                || lowerName.startsWith("hwcomposer.")
                || lowerName.startsWith("lights.")
                || lowerName.startsWith("gps.")
                || lowerName.startsWith("nfc.")
                || lowerName.startsWith("power.")
                || lowerName.startsWith("sensors.")
                || lowerName.startsWith("keystore.")
                || lowerName.startsWith("local_time.");
    }

    private static boolean isStandardAndroidOsLibrary(String lowerName) {
        String[] stdExact = {
                "libc.so", "libm.so", "libdl.so", "libstdc++.so", "liblog.so",
                "libcutils.so", "libutils.so", "libbinder.so", "libdvm.so",
                "libjavacore.so", "libnativehelper.so", "libandroid_runtime.so",
                "libandroid.so", "libandroidfw.so", "libhardware.so", "libhardware_legacy.so",
                "libicui18n.so", "libicuuc.so", "libskia.so", "libgui.so", "libui.so",
                "libegl.so", "libhwui.so", "libexpat.so", "libz.so", "libcrypto.so",
                "libssl.so", "libsqlite.so", "libnetutils.so", "libselinux.so",
                "libstlport.so", "libsonivox.so", "libmedia.so", "libmedia_jni.so",
                "libvorbisidec.so", "libinput.so", "libjpeg.so", "libpng.so",
                "libft2.so", "libbcc.so", "libbcinfo.so", "libllvm.so",
                "libwpa_client.so", "libnetd_client.so", "libmemtrack.so",
                "libpowermanager.so", "libsync.so", "libaudioutils.so",
                "libcommon_time_client.so", "libnbaudio.so", "libspeexresampler.so",
                "libeffects.so", "librs_jni.so", "libjavacrypto.so", "libportable.so",
                "libvariablespeed.so", "libleafiaaac.so", "libbt-codec_aac_dec.so",
                "libbt-client-api.so", "libbtsound.so", "libtinyalsa.so",
                "libopensles.so", "libETC1.so", "libetc1.so", "libpixelflinger.so",
                "libcorkscrew.so", "libgccdemangle.so", "libusbhost.so",
                "libhmgapi_hook.so"
        };
        for (int i = 0; i < stdExact.length; i++) {
            if (stdExact[i].equals(lowerName)) return true;
        }
        return lowerName.startsWith("libgles")
                || lowerName.startsWith("libharfbuzz")
                || lowerName.startsWith("libstagefright")
                || lowerName.startsWith("libdrm")
                || lowerName.startsWith("libcamera")
                || lowerName.startsWith("libwebrtc")
                || lowerName.startsWith("librs")
                || lowerName.startsWith("libwebview")
                || lowerName.startsWith("libomx.")
                || lowerName.startsWith("libtcc.")
                || lowerName.startsWith("libtcc_cdk")
                || lowerName.startsWith("libtcc_omx")
                || lowerName.startsWith("gralloc.")
                || lowerName.startsWith("memtrack.");
    }

    private static void logFilteredSymbolList(String prefix, List<String> symbols,
                                              Map<String, ElfSym> symMap, boolean includeAddrSize,
                                              String[] keywordsLower, int maxSymbols, boolean logIfZero) {
        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (int i = 0; i < symbols.size() && count < maxSymbols; i++) {
            String sym = symbols.get(i);
            if (isCompilerBoilerplateSymbol(sym)) continue;
            if (keywordsLower != null && !containsAny(sym.toLowerCase(Locale.US), keywordsLower)) {
                continue;
            }
            if (sb.length() > 0) sb.append(", ");
            sb.append(sym);
            if (includeAddrSize && symMap != null) {
                ElfSym es = symMap.get(sym);
                if (es != null) {
                    sb.append(String.format(Locale.US, "[0x%x,%d]",
                            Long.valueOf(es.stValue), Long.valueOf(es.stSize)));
                }
            }
            count++;
            if (sb.length() >= 460) {
                DiagLogger.log("BT_ELF", prefix + ": " + sb);
                sb.setLength(0);
            }
        }
        if (sb.length() > 0) {
            DiagLogger.log("BT_ELF", prefix + ": " + sb);
        } else if (logIfZero) {
            DiagLogger.log("BT_ELF", prefix + ": <0 matched>");
        }
    }

    private static boolean isCompilerBoilerplateSymbol(String sym) {
        return sym.startsWith("__aeabi_")
                || sym.startsWith("__gnu_")
                || sym.startsWith("__cxa_")
                || sym.startsWith("__stack_chk_")
                || "_edata".equals(sym)
                || "_end".equals(sym)
                || "__bss_start".equals(sym)
                || "_init".equals(sym)
                || "_fini".equals(sym);
    }

    private static void probeSystemFilesAndDaemons() {
        DiagLogger.log("BT_PROBE", "[8/8] Unfiltered HAL directories, /dev nodes, USB sysfs, props & processes:");

        // Unfiltered HAL directory listings so no weirdly named HAL .so can hide
        listAllFiles("/system/lib/hw");
        listAllFiles("/vendor/lib/hw");
        listAllFiles("/vendor/lib");

        listMatchingFiles("/system/bin", new String[]{"bt", "blue", "brcm", "broadcom", "bsa", "gatt", "mbox", "tcc"});
        listMatchingFiles("/system/xbin", new String[]{"bt", "blue", "brcm", "broadcom", "bsa", "gatt", "mbox", "tcc", "hciconfig", "hcitool"});

        listMatchingDevNodes(new String[]{"bt", "mbox", "tcc", "hci", "tty", "hidraw", "usb", "rfcomm", "uhid", "uinput"});
        probeSysfsUsbDevices();

        runFilteredCommand(new String[]{"/system/bin/getprop"}, "BT_PROP",
                new String[]{".bt", "bt.", "bluetooth", "brcm", "broadcom", "gatt", "ble.", "mbox", "tcc.solution", "ro.hardware", "ro.board"}, true);

        runFilteredCommand(new String[]{"/system/bin/ps"}, "BT_PROC",
                new String[]{"bluetooth", "btsettings", "btaudio", "brcm", "broadcom", "gatt", "dipo", "mbox", "tcc"}, false);
    }

    private static void listAllFiles(String dirPath) {
        File d = new File(dirPath);
        if (!d.exists()) {
            DiagLogger.log("BT_SYS", "  " + dirPath + " -> does not exist");
            return;
        }
        File[] list = d.listFiles();
        if (list == null) {
            DiagLogger.log("BT_SYS", "  " + dirPath + " -> listFiles() returned null (unreadable dir)");
            return;
        }
        Arrays.sort(list);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < list.length; i++) {
            File f = list[i];
            if (sb.length() > 0) sb.append(", ");
            sb.append(f.getName())
                    .append(f.isDirectory() ? "/" : ("(" + f.length() + "B)"));
            if (sb.length() >= 460) {
                DiagLogger.log("BT_SYS", "  " + dirPath + " all: " + sb);
                sb.setLength(0);
            }
        }
        if (sb.length() > 0) {
            DiagLogger.log("BT_SYS", "  " + dirPath + " all (" + list.length + " total): " + sb);
        } else {
            DiagLogger.log("BT_SYS", "  " + dirPath + " all (0 files)");
        }
    }

    private static void listMatchingDevNodes(String[] keywords) {
        File devDir = new File("/dev");
        File[] nodes = devDir.listFiles();
        if (nodes == null) {
            DiagLogger.log("BT_DEV", "  /dev.listFiles() returned null (restricted directory)");
            return;
        }
        Arrays.sort(nodes);
        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (int i = 0; i < nodes.length; i++) {
            File n = nodes[i];
            String name = n.getName();
            if (containsAny(name.toLowerCase(Locale.US), keywords)) {
                if (sb.length() > 0) sb.append(", ");
                sb.append(name)
                        .append('[')
                        .append(n.isDirectory() ? "d" : "-")
                        .append(n.canRead() ? "r" : "-")
                        .append(n.canWrite() ? "w" : "-")
                        .append(']');
                count++;
                if (sb.length() >= 460) {
                    DiagLogger.log("BT_DEV", "  /dev matches: " + sb);
                    sb.setLength(0);
                }
            }
        }
        if (sb.length() > 0) {
            DiagLogger.log("BT_DEV", "  /dev matches (" + count + " total): " + sb);
        }
    }

    private static void probeSysfsUsbDevices() {
        File usbSys = new File("/sys/bus/usb/devices");
        File[] entries = usbSys.listFiles();
        if (entries == null) return;
        Arrays.sort(entries);
        for (int i = 0; i < entries.length; i++) {
            File dev = entries[i];
            String name = dev.getName();
            if (name.indexOf(':') >= 0) continue;
            String vid = readTinyTextFile(new File(dev, "idVendor"));
            String pid = readTinyTextFile(new File(dev, "idProduct"));
            if (vid == null && pid == null) continue;
            String cls = readTinyTextFile(new File(dev, "bDeviceClass"));
            String prod = readTinyTextFile(new File(dev, "product"));
            String mfg = readTinyTextFile(new File(dev, "manufacturer"));
            DiagLogger.log("BT_USB", "  /sys/bus/usb/devices/" + name
                    + " -> VID:PID=" + (vid != null ? vid : "?") + ":" + (pid != null ? pid : "?")
                    + (cls != null ? (" class=" + cls) : "")
                    + (mfg != null ? (" mfg='" + mfg + "'") : "")
                    + (prod != null ? (" product='" + prod + "'") : ""));
        }
    }

    private static String readTinyTextFile(File f) {
        if (f == null || !f.isFile() || !f.canRead()) return null;
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(f);
            byte[] buf = new byte[128];
            int n = fis.read(buf);
            if (n <= 0) return null;
            String s = new String(buf, 0, n, UTF8).trim();
            return s.isEmpty() ? null : s;
        } catch (Throwable ignored) {
            return null;
        } finally {
            if (fis != null) {
                try { fis.close(); } catch (Throwable ignored) {}
            }
        }
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

        String path = jarOrApk.getAbsolutePath();
        int dot = path.lastIndexOf('.');
        if (dot > 0) {
            File odexFile = new File(path.substring(0, dot) + ".odex");
            if (odexFile.isFile() && odexFile.canRead()
                    && odexFile.length() > 0 && odexFile.length() <= MAX_DEX_BYTES) {
                DiagLogger.log("BT_DEX", "  Reading companion ODEX: " + odexFile.getAbsolutePath()
                        + " (" + odexFile.length() + "B)");
                FileInputStream fis = null;
                try {
                    fis = new FileInputStream(odexFile);
                    return readStreamBounded(fis, MAX_DEX_BYTES);
                } catch (Throwable t) {
                    DiagLogger.log("BT_DEX", "  Failed reading " + odexFile.getAbsolutePath() + ": " + t.getMessage());
                } finally {
                    if (fis != null) {
                        try { fis.close(); } catch (Throwable ignored) {}
                    }
                }
            }
        }
        return null;
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

    // ================= PURE-JAVA IN-RAM DALVIK DEX / ODEX PARSER & BYTECODE DISASSEMBLER =================

    public static List<DexClassEntry> extractDexInventory(byte[] rawBytes) {
        return extractDexInventory(rawBytes, null);
    }

    /**
     * Parses a Dalvik DEX ("dex\n035\0") or optimized ODEX ("dey\n036\0") byte buffer in RAM
     * and returns defined classes (optionally pre-filtered by lowercase substring match).
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
                            methodIdsSize, methodIdsOff, methodIdx, mAccess, false);
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
                            methodIdsSize, methodIdsOff, methodIdx, mAccess, false);
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

    /**
     * Disassembles Dalvik/ODEX code_item instructions in RAM for matching classes and method names,
     * extracting chronological string literals, class/resource constants, field accesses, and method calls.
     */
    public static List<DexMethodTrace> extractDexMethodTraces(byte[] rawBytes,
                                                              String[] classFilterLower,
                                                              String[] methodNamesLower,
                                                              Map<Integer, String> resIdMap) {
        byte[] dex = unwrapOdexIfNeeded(rawBytes);
        if (dex == null) return Collections.emptyList();

        ByteBuffer buf = ByteBuffer.wrap(dex).order(ByteOrder.LITTLE_ENDIAN);
        if (buf.getInt(40) != 0x12345678) return Collections.emptyList();

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

        List<DexMethodTrace> traces = new ArrayList<DexMethodTrace>();
        for (int c = 0; c < classDefsSize; c++) {
            int cOff = classDefsOff + c * 32;
            int classIdx = buf.getInt(cOff);
            String className = readTypeName(dex, buf, stringIdsSize, stringIdsOff, typeIdsSize, typeIdsOff, classIdx);
            String classLow = className.toLowerCase(Locale.US);
            if (classFilterLower != null && !containsAny(classLow, classFilterLower)) {
                continue;
            }

            int classDataOff = buf.getInt(cOff + 24);
            if (classDataOff <= 0 || classDataOff >= dex.length) continue;

            int[] pos = new int[]{classDataOff};
            int staticFieldsSize = readUleb128(dex, pos);
            int instanceFieldsSize = readUleb128(dex, pos);
            int directMethodsSize = readUleb128(dex, pos);
            int virtualMethodsSize = readUleb128(dex, pos);

            for (int i = 0; i < staticFieldsSize && pos[0] < dex.length; i++) {
                readUleb128(dex, pos);
                readUleb128(dex, pos);
            }
            for (int i = 0; i < instanceFieldsSize && pos[0] < dex.length; i++) {
                readUleb128(dex, pos);
                readUleb128(dex, pos);
            }

            for (int pass = 0; pass < 2; pass++) {
                int count = (pass == 0) ? directMethodsSize : virtualMethodsSize;
                int methodIdx = 0;
                for (int i = 0; i < count && pos[0] < dex.length; i++) {
                    methodIdx += readUleb128(dex, pos);
                    int mAccess = readUleb128(dex, pos);
                    int codeOff = readUleb128(dex, pos);
                    if (codeOff <= 0 || codeOff + 16 > dex.length) continue;

                    String mName = readMethodSimpleName(dex, buf, stringIdsSize, stringIdsOff,
                            methodIdsSize, methodIdsOff, methodIdx);
                    if (mName == null) continue;
                    if (methodNamesLower != null && !equalsAny(mName.toLowerCase(Locale.US), methodNamesLower)) {
                        continue;
                    }

                    String sig = formatMethodSig(dex, buf, stringIdsSize, stringIdsOff,
                            typeIdsSize, typeIdsOff, protoIdsSize, protoIdsOff,
                            methodIdsSize, methodIdsOff, methodIdx, mAccess, true);
                    if (sig == null) sig = mName;

                    int insnsUnits = buf.getInt(codeOff + 12);
                    int insnsOff = codeOff + 16;
                    if (insnsUnits <= 0 || insnsUnits > 32768 || insnsOff + insnsUnits * 2 > dex.length) {
                        continue;
                    }

                    List<String> ops = decodeCodeItemRefs(dex, buf, insnsOff, insnsUnits,
                            stringIdsSize, stringIdsOff, typeIdsSize, typeIdsOff,
                            fieldIdsSize, fieldIdsOff, methodIdsSize, methodIdsOff, resIdMap);
                    traces.add(new DexMethodTrace(className, sig, insnsUnits, ops));
                }
            }
        }
        return traces;
    }

    private static List<String> decodeCodeItemRefs(byte[] dex, ByteBuffer buf,
                                                   int insnsOff, int insnsUnits,
                                                   int stringIdsSize, int stringIdsOff,
                                                   int typeIdsSize, int typeIdsOff,
                                                   int fieldIdsSize, int fieldIdsOff,
                                                   int methodIdsSize, int methodIdsOff,
                                                   Map<Integer, String> resIdMap) {
        List<String> ops = new ArrayList<String>();
        int pc = 0;
        while (pc < insnsUnits) {
            int bOff = insnsOff + pc * 2;
            int word0 = buf.getShort(bOff) & 0xFFFF;
            int opcode = word0 & 0xFF;

            // Payload pseudo-instructions aligned at end of method
            if (word0 == 0x0100 && pc + 2 <= insnsUnits) { // packed-switch-payload
                int sz = buf.getShort(bOff + 2) & 0xFFFF;
                pc += 4 + sz * 2;
                continue;
            } else if (word0 == 0x0200 && pc + 2 <= insnsUnits) { // sparse-switch-payload
                int sz = buf.getShort(bOff + 2) & 0xFFFF;
                pc += 2 + sz * 4;
                continue;
            } else if (word0 == 0x0300 && pc + 4 <= insnsUnits) { // fill-array-data-payload
                int elemW = buf.getShort(bOff + 2) & 0xFFFF;
                int sz = buf.getInt(bOff + 4);
                if (elemW == 4 && sz > 0 && sz <= 32 && bOff + 8 + sz * 4 <= dex.length) {
                    StringBuilder arrSb = new StringBuilder("int[]{");
                    for (int k = 0; k < sz; k++) {
                        if (k > 0) arrSb.append(',');
                        int v = buf.getInt(bOff + 8 + k * 4);
                        arrSb.append(formatConstInt(v, resIdMap));
                    }
                    arrSb.append('}');
                    ops.add(arrSb.toString());
                }
                pc += 4 + (sz * elemW + 1) / 2;
                continue;
            }

            int width = dalvikOpcodeWidth(opcode);
            if (pc + width > insnsUnits) break;

            switch (opcode) {
                case 0x14: { // const vAA, #+BBBBBBBB
                    int lit = buf.getInt(bOff + 2);
                    if ((lit & 0xFF000000) == 0x7F000000 || (lit >= 100 && lit <= 10000)) {
                        ops.add("const " + formatConstInt(lit, resIdMap));
                    }
                    break;
                }
                case 0x1a: { // const-string
                    int sIdx = buf.getShort(bOff + 2) & 0xFFFF;
                    String s = readDexString(dex, buf, stringIdsSize, stringIdsOff, sIdx);
                    ops.add("\"" + s.replace('\n', ' ') + "\"");
                    break;
                }
                case 0x1b: { // const-string/jumbo
                    int sIdx = buf.getInt(bOff + 2);
                    String s = readDexString(dex, buf, stringIdsSize, stringIdsOff, sIdx);
                    ops.add("\"" + s.replace('\n', ' ') + "\"");
                    break;
                }
                case 0x1c: { // const-class
                    int tIdx = buf.getShort(bOff + 2) & 0xFFFF;
                    ops.add("class:" + shortClassName(readTypeName(dex, buf, stringIdsSize, stringIdsOff, typeIdsSize, typeIdsOff, tIdx)));
                    break;
                }
                case 0x22: { // new-instance
                    int tIdx = buf.getShort(bOff + 2) & 0xFFFF;
                    ops.add("new:" + shortClassName(readTypeName(dex, buf, stringIdsSize, stringIdsOff, typeIdsSize, typeIdsOff, tIdx)));
                    break;
                }
                case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57: case 0x58:
                case 0x60: case 0x61: case 0x62: case 0x63: case 0x64: case 0x65: case 0x66:
                case 0xe3: case 0xe5: case 0xe7: case 0xe8: case 0xea: case 0xfd: { // *get*
                    int fIdx = buf.getShort(bOff + 2) & 0xFFFF;
                    ops.add("get:" + formatShortFieldRef(dex, buf, stringIdsSize, stringIdsOff,
                            typeIdsSize, typeIdsOff, fieldIdsSize, fieldIdsOff, fIdx));
                    break;
                }
                case 0x59: case 0x5a: case 0x5b: case 0x5c: case 0x5d: case 0x5e: case 0x5f:
                case 0x67: case 0x68: case 0x69: case 0x6a: case 0x6b: case 0x6c: case 0x6d:
                case 0xe4: case 0xe6: case 0xe9: case 0xeb: case 0xfc: case 0xfe: { // *put*
                    int fIdx = buf.getShort(bOff + 2) & 0xFFFF;
                    ops.add("put:" + formatShortFieldRef(dex, buf, stringIdsSize, stringIdsOff,
                            typeIdsSize, typeIdsOff, fieldIdsSize, fieldIdsOff, fIdx));
                    break;
                }
                case 0x6e: case 0x6f: case 0x70: case 0x71: case 0x72:
                case 0x74: case 0x75: case 0x76: case 0x77: case 0x78:
                case 0xf0: { // invoke-*
                    int mIdx = buf.getShort(bOff + 2) & 0xFFFF;
                    ops.add("call:" + formatShortMethodRef(dex, buf, stringIdsSize, stringIdsOff,
                            typeIdsSize, typeIdsOff, fieldIdsOff, methodIdsSize, methodIdsOff, mIdx));
                    break;
                }
                case 0xf8: case 0xf9: case 0xfa: case 0xfb: { // invoke-virtual/super-quick (ODEX)
                    int vtIdx = buf.getShort(bOff + 2) & 0xFFFF;
                    ops.add("qcall:vt#" + vtIdx);
                    break;
                }
                default:
                    break;
            }
            pc += width;
        }
        return ops;
    }

    private static String formatConstInt(int v, Map<Integer, String> resIdMap) {
        if (resIdMap != null) {
            String r = resIdMap.get(Integer.valueOf(v));
            if (r != null) {
                return String.format(Locale.US, "0x%08x[%s]", Integer.valueOf(v), r);
            }
        }
        if ((v & 0xFF000000) == 0x7F000000) {
            return String.format(Locale.US, "0x%08x", Integer.valueOf(v));
        }
        return String.valueOf(v);
    }

    /**
     * Exact AOSP 4.4 KitKat libdex instruction width (in 16-bit code units) for all 256 opcodes 0x00..0xFF,
     * including ODEX quickened / volatile opcodes 0xE3..0xFF.
     */
    private static int dalvikOpcodeWidth(int op) {
        switch (op) {
            case 0x00: case 0x01: case 0x04: case 0x07:
            case 0x0a: case 0x0b: case 0x0c: case 0x0d:
            case 0x0e: case 0x0f: case 0x10: case 0x11: case 0x12:
            case 0x1d: case 0x1e: case 0x21: case 0x27: case 0x28:
            case 0xec: case 0xf1:
                return 1;
            case 0x18: // const-wide (51l)
                return 5;
            case 0x03: case 0x06: case 0x09:
            case 0x14: case 0x17: case 0x1b:
            case 0x24: case 0x25: case 0x26:
            case 0x2a: case 0x2b: case 0x2c:
            case 0x6e: case 0x6f: case 0x70: case 0x71: case 0x72:
            case 0x74: case 0x75: case 0x76: case 0x77: case 0x78:
            case 0xee: case 0xef: case 0xf0:
            case 0xf8: case 0xf9: case 0xfa: case 0xfb:
                return 3;
            default:
                if (op >= 0x7b && op <= 0x8f) return 1; // unop 12x
                if (op >= 0xb0 && op <= 0xcf) return 1; // binop/2addr 12x
                if ((op >= 0x3e && op <= 0x43) || op == 0x73 || op == 0x79 || op == 0x7a || op == 0xff) {
                    return 1; // unused 10x
                }
                return 2; // all remaining 20t/21c/21h/21s/21t/22b/22c/22cs/22s/22t/22x/23x ops
        }
    }

    private static String shortClassName(String fqcn) {
        if (fqcn == null) return "?";
        int dot = fqcn.lastIndexOf('.');
        return dot >= 0 ? fqcn.substring(dot + 1) : fqcn;
    }

    private static String formatShortFieldRef(byte[] dex, ByteBuffer buf,
                                              int stringIdsSize, int stringIdsOff,
                                              int typeIdsSize, int typeIdsOff,
                                              int fieldIdsSize, int fieldIdsOff, int fieldIdx) {
        if (fieldIdx < 0 || fieldIdx >= fieldIdsSize) return "field#" + fieldIdx;
        int fOff = fieldIdsOff + fieldIdx * 8;
        if (fOff < 0 || fOff + 8 > dex.length) return "field#" + fieldIdx;
        int ownerIdx = buf.getShort(fOff) & 0xFFFF;
        int nameIdx = buf.getInt(fOff + 4);
        String owner = shortClassName(readTypeName(dex, buf, stringIdsSize, stringIdsOff, typeIdsSize, typeIdsOff, ownerIdx));
        String name = readDexString(dex, buf, stringIdsSize, stringIdsOff, nameIdx);
        return owner + "." + name;
    }

    private static String formatShortMethodRef(byte[] dex, ByteBuffer buf,
                                               int stringIdsSize, int stringIdsOff,
                                               int typeIdsSize, int typeIdsOff,
                                               int unused,
                                               int methodIdsSize, int methodIdsOff, int methodIdx) {
        if (methodIdx < 0 || methodIdx >= methodIdsSize) return "method#" + methodIdx;
        int mOff = methodIdsOff + methodIdx * 8;
        if (mOff < 0 || mOff + 8 > dex.length) return "method#" + methodIdx;
        int ownerIdx = buf.getShort(mOff) & 0xFFFF;
        int nameIdx = buf.getInt(mOff + 4);
        String owner = shortClassName(readTypeName(dex, buf, stringIdsSize, stringIdsOff, typeIdsSize, typeIdsOff, ownerIdx));
        String name = readDexString(dex, buf, stringIdsSize, stringIdsOff, nameIdx);
        return owner + "." + name + "()";
    }

    private static String readMethodSimpleName(byte[] dex, ByteBuffer buf,
                                               int stringIdsSize, int stringIdsOff,
                                               int methodIdsSize, int methodIdsOff, int methodIdx) {
        if (methodIdx < 0 || methodIdx >= methodIdsSize) return null;
        int mOff = methodIdsOff + methodIdx * 8;
        if (mOff < 0 || mOff + 8 > dex.length) return null;
        int nameIdx = buf.getInt(mOff + 4);
        return readDexString(dex, buf, stringIdsSize, stringIdsOff, nameIdx);
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
                                          int methodIdx, int accessFlags,
                                          boolean includeClinit) {
        if (methodIdx < 0 || methodIdx >= methodIdsSize) return null;
        int mOff = methodIdsOff + methodIdx * 8;
        if (mOff < 0 || mOff + 8 > dex.length) return null;
        int protoIdx = buf.getShort(mOff + 2) & 0xFFFF;
        int nameIdx = buf.getInt(mOff + 4);
        String name = readDexString(dex, buf, stringIdsSize, stringIdsOff, nameIdx);
        if (!includeClinit && "<clinit>".equals(name)) return null;

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

    private static String formatMemberModifiers(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & 0x0001) != 0) sb.append("public ");
        else if ((flags & 0x0004) != 0) sb.append("protected ");
        else if ((flags & 0x0002) != 0) sb.append("private ");
        if ((flags & 0x0008) != 0) sb.append("static ");
        if ((flags & 0x0100) != 0) sb.append("native ");
        return sb.toString();
    }

    // ================= PURE-JAVA IN-RAM ELF32 .DYNSYM, .DYNAMIC & .RODATA PARSER =================

    /**
     * Convenience wrapper returning sorted defined dynamic symbol names from a 32-bit LSB ELF buffer.
     */
    public static List<String> extractElf32DynamicSymbols(byte[] elfBytes) {
        Elf32Info info = extractElf32Info(elfBytes);
        return info != null ? info.exportedSymbols : Collections.<String>emptyList();
    }

    /**
     * Parses a 32-bit little-endian ELF shared object (.so) buffer purely in RAM (zero dlopen)
     * and extracts DT_NEEDED library names, exported/imported dynamic C symbols, and printable
     * C string literals from non-executable allocated SHT_PROGBITS (.rodata) sections.
     */
    public static Elf32Info extractElf32Info(byte[] elf) {
        if (elf == null || elf.length < 52) {
            return null;
        }
        if (elf[0] != 0x7F || elf[1] != 'E' || elf[2] != 'L' || elf[3] != 'F') {
            return null;
        }
        if (elf[4] != 1 || elf[5] != 1) { // ELFCLASS32 (1) and ELFDATA2LSB (1)
            return null;
        }

        ByteBuffer buf = ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);
        int machine = buf.getShort(18) & 0xFFFF;
        long phOff = buf.getInt(28) & 0xFFFFFFFFL;
        long shOff = buf.getInt(32) & 0xFFFFFFFFL;
        int phEntSize = buf.getShort(42) & 0xFFFF;
        int phNum = buf.getShort(44) & 0xFFFF;
        int shEntSize = buf.getShort(46) & 0xFFFF;
        int shNum = buf.getShort(48) & 0xFFFF;
        int shStrNdx = buf.getShort(50) & 0xFFFF;

        List<ElfLoadSeg> loadSegs = new ArrayList<ElfLoadSeg>();
        if (phOff > 0 && phEntSize >= 32 && phNum > 0
                && phOff + (long) phEntSize * (long) phNum <= elf.length) {
            for (int i = 0; i < phNum; i++) {
                int pPos = (int) (phOff + (long) i * phEntSize);
                int pType = buf.getInt(pPos);
                if (pType == 1) { // PT_LOAD
                    long pOffset = buf.getInt(pPos + 4) & 0xFFFFFFFFL;
                    long pVaddr = buf.getInt(pPos + 8) & 0xFFFFFFFFL;
                    long pFilesz = buf.getInt(pPos + 16) & 0xFFFFFFFFL;
                    if (pFilesz > 0 && pOffset + pFilesz <= elf.length) {
                        loadSegs.add(new ElfLoadSeg(pOffset, pVaddr, pFilesz));
                    }
                }
            }
        }

        if (shOff <= 0 || shEntSize < 40 || shNum <= 0
                || shOff + (long) shEntSize * (long) shNum > elf.length) {
            return new Elf32Info(machine,
                    Collections.<String>emptyList(),
                    Collections.<String>emptyList(),
                    Collections.<String>emptyList(),
                    Collections.<String>emptyList(),
                    Collections.<String, ElfSym>emptyMap(),
                    loadSegs);
        }

        long shStrTabOff = 0;
        long shStrTabSize = 0;
        if (shStrNdx >= 0 && shStrNdx < shNum) {
            int shStrPos = (int) (shOff + (long) shStrNdx * shEntSize);
            if (buf.getInt(shStrPos + 4) == 3) {
                shStrTabOff = buf.getInt(shStrPos + 16) & 0xFFFFFFFFL;
                shStrTabSize = buf.getInt(shStrPos + 20) & 0xFFFFFFFFL;
            }
        }

        Set<String> neededSet = new LinkedHashSet<String>();
        Set<String> exportSet = new LinkedHashSet<String>();
        Set<String> importSet = new LinkedHashSet<String>();
        Set<String> rodataSet = new LinkedHashSet<String>();
        Map<String, ElfSym> exportedSymMap = new HashMap<String, ElfSym>();
        final int maxRodataStrings = 24000;

        for (int s = 0; s < shNum; s++) {
            int shPos = (int) (shOff + (long) s * shEntSize);
            long shNameOff = buf.getInt(shPos) & 0xFFFFFFFFL;
            int shType = buf.getInt(shPos + 4);
            long shFlags = buf.getInt(shPos + 8) & 0xFFFFFFFFL;
            long secOff = buf.getInt(shPos + 16) & 0xFFFFFFFFL;
            long secSize = buf.getInt(shPos + 20) & 0xFFFFFFFFL;
            int shLink = buf.getInt(shPos + 24);
            int entSize = buf.getInt(shPos + 36);

            if (secOff <= 0 || secSize <= 0 || secOff + secSize > elf.length) {
                continue;
            }

            // Extract printable C strings across ALL .rodata*, .data.rel.ro*, and .data sections
            if (shType == 1 && (shFlags & 0x2L) != 0 && (shFlags & 0x4L) == 0 && rodataSet.size() < maxRodataStrings) {
                String secName = (shStrTabOff > 0 && shStrTabSize > 0 && shStrTabOff + shStrTabSize <= elf.length)
                        ? readElfNullTermString(elf, shStrTabOff, shStrTabSize, shNameOff)
                        : null;
                if (secName == null || secName.startsWith(".rodata") || ".data".equals(secName)
                        || secName.startsWith(".data.rel.ro")) {
                    extractPrintableNullTermStrings(elf, (int) secOff, (int) secSize, rodataSet, maxRodataStrings);
                }
            }

            if (shType != 6 && shType != 11) { // 6 = SHT_DYNAMIC, 11 = SHT_DYNSYM
                continue;
            }
            if (shLink < 0 || shLink >= shNum) {
                continue;
            }

            int strShPos = (int) (shOff + (long) shLink * shEntSize);
            int strShType = buf.getInt(strShPos + 4);
            long strOff = buf.getInt(strShPos + 16) & 0xFFFFFFFFL;
            long strSize = buf.getInt(strShPos + 20) & 0xFFFFFFFFL;
            if (strShType != 3 || strOff <= 0 || strSize <= 0 || strOff + strSize > elf.length) {
                continue;
            }

            if (shType == 6) { // SHT_DYNAMIC -> extract DT_NEEDED (d_tag == 1)
                int step = (entSize >= 8) ? entSize : 8;
                for (long p = secOff; p + 8 <= secOff + secSize; p += step) {
                    int dTag = buf.getInt((int) p);
                    if (dTag == 0) break;
                    if (dTag == 1) {
                        long nameOff = buf.getInt((int) p + 4) & 0xFFFFFFFFL;
                        String libName = readElfNullTermString(elf, strOff, strSize, nameOff);
                        if (libName != null && !libName.isEmpty()) {
                            neededSet.add(libName);
                        }
                    }
                }
            } else { // SHT_DYNSYM -> extract exported & imported C symbol names + addresses/sizes
                int step = (entSize >= 16) ? entSize : 16;
                long idx = 0;
                for (long p = secOff; p + 16 <= secOff + secSize; p += step, idx++) {
                    if (idx == 0) continue;
                    long stName = buf.getInt((int) p) & 0xFFFFFFFFL;
                    long stValue = buf.getInt((int) p + 4) & 0xFFFFFFFFL;
                    long stSize = buf.getInt((int) p + 8) & 0xFFFFFFFFL;
                    int stInfo = elf[(int) p + 12] & 0xFF;
                    int stType = stInfo & 0x0F;
                    if (stType == 3 || stType == 4) continue;
                    int stShndx = buf.getShort((int) p + 14) & 0xFFFF;
                    String symName = readElfNullTermString(elf, strOff, strSize, stName);
                    if (symName == null || symName.isEmpty()) continue;
                    if (stShndx == 0) {
                        importSet.add(symName);
                    } else {
                        exportSet.add(symName);
                        exportedSymMap.put(symName, new ElfSym(symName, stValue, stSize, stInfo));
                    }
                }
            }
        }

        List<String> needed = new ArrayList<String>(neededSet);
        List<String> exported = new ArrayList<String>(exportSet);
        List<String> imported = new ArrayList<String>(importSet);
        List<String> rodata = new ArrayList<String>(rodataSet);
        Collections.sort(exported);
        Collections.sort(imported);
        return new Elf32Info(machine, needed, exported, imported, rodata, exportedSymMap, loadSegs);
    }

    private static void extractPrintableNullTermStrings(byte[] elf, int startOff, int len,
                                                        Set<String> out, int maxCount) {
        int endLimit = Math.min(elf.length, startOff + len);
        int runStart = -1;
        int alphaCount = 0;
        for (int i = startOff; i < endLimit && out.size() < maxCount; i++) {
            int b = elf[i] & 0xFF;
            if ((b >= 0x20 && b <= 0x7E) || b == '\t') {
                if (runStart < 0) {
                    runStart = i;
                    alphaCount = 0;
                }
                if ((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')) {
                    alphaCount++;
                }
            } else {
                if (b == 0 && runStart >= 0) {
                    int sLen = i - runStart;
                    if (sLen >= 3 && sLen <= 140 && alphaCount >= 2) {
                        String s = new String(elf, runStart, sLen, UTF8).trim();
                        if (s.length() >= 3 && !s.startsWith("(")) {
                            out.add(s);
                        }
                    }
                }
                runStart = -1;
                alphaCount = 0;
            }
        }
    }

    private static String readElfNullTermString(byte[] elf, long strTabOff, long strTabSize, long relOff) {
        if (relOff < 0 || relOff >= strTabSize) return null;
        int start = (int) (strTabOff + relOff);
        int limit = (int) Math.min((long) elf.length, strTabOff + strTabSize);
        int end = start;
        while (end < limit && elf[end] != 0) {
            end++;
        }
        if (end <= start) return "";
        return new String(elf, start, end - start, UTF8);
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

    private static boolean equalsAny(String valueLower, String[] candidatesLower) {
        for (int i = 0; i < candidatesLower.length; i++) {
            if (candidatesLower[i].equals(valueLower)) return true;
        }
        return false;
    }
}
