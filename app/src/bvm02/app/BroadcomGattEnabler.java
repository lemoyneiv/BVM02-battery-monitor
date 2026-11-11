package bvm02.app;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.content.Context;
import android.os.Handler;
import android.os.SystemClock;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;

/**
 * On-demand Broadcom BLE / GATT service activator for Gen5W head units (Android 4.4.2, API 19).
 *
 * Root cause identified from v0.1.1 on-car diagnostics (Hyundai Ioniq 5 Gen5W):
 *  - Gen5W ships Broadcom's enhanced Bluedroid stack (/system/framework/com.broadcom.bt.jar +
 *    android.bluetooth.IBluetoothManager with enableRadio(int) / enableGatt()).
 *  - By default at boot, Classic BT (HFP/A2DP) is active, while IBluetoothManager.getBluetoothGatt()
 *    returns NULL until an app acquires a BLE/GATT reference via
 *    com.broadcom.bt.service.radiomanager.BluetoothRadioManager.addLeRadioReference(...)
 *    (or IBluetoothManager.enableRadio(RADIO_TYPE_BLE) + enableGatt()).
 *  - While getBluetoothGatt() is NULL, BluetoothAdapter.startLeScan() immediately returns false (1ms)
 *    and BluetoothDevice.connectGatt() returns null.
 *
 * This helper uses pure Java reflection and dynamic Proxy instances (zero non-API-19 static bytecode
 * dependencies) to:
 *  1. Acquire BLE & GATT references via BluetoothRadioManager (which hosts the real Binder
 *     IBluetoothRadioMgrCallback$Stub for system_server IPC) and listen for
 *     onRadioStateChange(boolean) + onGattServiceStateChange(boolean, IBluetoothGatt).
 *  2. Trigger IBluetoothManager.enableRadio(RADIO_TYPE_BLE) and IBluetoothManager.enableGatt()
 *     if GattService has not come online within the initial settle window.
 *  3. Poll asynchronously on the main Handler until getBluetoothGatt() (or callback IBluetoothGatt)
 *     becomes live before starting startLeScan() or connectGatt().
 *  4. Release acquired LE/BLE radio references cleanly on app exit without disturbing Classic BT.
 */
public final class BroadcomGattEnabler {

    public static final String CLS_RADIO_MGR =
            "com.broadcom.bt.service.radiomanager.BluetoothRadioManager";
    public static final String CLS_GATT_CB =
            CLS_RADIO_MGR + "$BluetoothGattServiceStateChangeCallback";
    public static final String CLS_RADIO_CB =
            CLS_RADIO_MGR + "$BluetoothRadioStateChangeCallback";

    private static final long POLL_INTERVAL_MS = 100L;
    private static final long DIRECT_ENABLE_TRIGGER_MS = 300L;
    private static final long ENABLE_TIMEOUT_MS = 3200L;

    public interface ReadinessCallback {
        void onResult(boolean gattReady, String summary);
    }

    private final Context appContext;
    private final Handler mainHandler;

    private Class<?> radioMgrClass;
    private Object radioMgrInstance;
    private int radioTypeBle = -1;
    private Object gattStateProxy;
    private Object radioStateProxy;
    private boolean leRefAcquired = false;
    private boolean bleRadioRefAcquired = false;
    private boolean loggedConstantsOnce = false;

    private volatile boolean callbackRadioEnabled = false;
    private volatile boolean callbackGattEnabled = false;
    private volatile Object callbackGattBinder = null;

    private boolean activationInFlight = false;
    private long activationStartElapsed = 0L;
    private boolean directEnableAttempted = false;
    private final List<ReadinessCallback> waiters = new ArrayList<ReadinessCallback>();

    public BroadcomGattEnabler(Context context, Handler mainHandler) {
        this.appContext = context.getApplicationContext();
        this.mainHandler = mainHandler;
    }

    /**
     * Returns true if either BluetoothAdapter.mManagerService.getBluetoothGatt() or the
     * BluetoothRadioManager callback holds a live IBluetoothGatt binder.
     */
    public boolean isGattReadyNow(BluetoothAdapter adapter) {
        if (BtStackProbe.getLiveIBluetoothGatt(adapter) != null) {
            return true;
        }
        return callbackGattEnabled && callbackGattBinder != null;
    }

    public boolean hasCallbackGattBinder() {
        return callbackGattBinder != null;
    }

    /**
     * One-line status summary for the BT Diagnostics hardware card.
     */
    public String buildStatusLine(BluetoothAdapter adapter) {
        StringBuilder sb = new StringBuilder(160);
        Object mgr = BtStackProbe.getIBluetoothManager(adapter);
        Boolean mgrRadio = invokeBoolNoArg(mgr, "isRadioEnabled");
        sb.append("IBluetoothManager.isRadioEnabled=").append(mgrRadio != null ? mgrRadio : "?");

        ensureRadioMgrLoaded(adapter, false);
        if (radioMgrInstance != null) {
            Boolean rmRadio = invokeBoolNoArg(radioMgrInstance, "isRadioEnabled");
            Boolean rmGatt = invokeBoolNoArg(radioMgrInstance, "isGattServiceReady");
            sb.append(" | RadioMgr(radio=").append(rmRadio != null ? rmRadio : "?")
                    .append(", gattReady=").append(rmGatt != null ? rmGatt : "?")
                    .append(", RADIO_TYPE_BLE=").append(radioTypeBle)
                    .append(", leRef=").append(leRefAcquired)
                    .append(", bleRef=").append(bleRadioRefAcquired)
                    .append(')');
        } else {
            sb.append(" | RadioMgr=unavailable");
        }
        if (callbackGattBinder != null) {
            sb.append(" | cbGatt=LIVE");
        }
        return sb.toString();
    }

    /**
     * Ensures Broadcom BLE radio & GattService are active before startLeScan() or connectGatt().
     * Always invokes callback on mainHandler.
     */
    public void ensureGattReady(final BluetoothAdapter adapter, final ReadinessCallback callback) {
        if (adapter == null) {
            callback.onResult(false, "BluetoothAdapter is null");
            return;
        }
        if (BtStackProbe.getLiveIBluetoothGatt(adapter) != null) {
            callback.onResult(true, "IBluetoothGatt already live");
            return;
        }

        waiters.add(callback);
        if (activationInFlight) {
            DiagLogger.log("BRCM_BLE", "Joining in-flight Broadcom BLE/GATT activation...");
            return;
        }

        activationInFlight = true;
        activationStartElapsed = SystemClock.elapsedRealtime();
        directEnableAttempted = false;

        DiagLogger.log("BRCM_BLE", "=== Activating Broadcom BLE Radio & GattService ===");
        startRadioManagerAcquisition(adapter);

        // Check immediately in case enableGatt completed synchronously
        if (checkAndCompleteIfReady(adapter)) {
            return;
        }

        mainHandler.removeCallbacks(pollRunnable);
        pollAdapterRef = adapter;
        mainHandler.postDelayed(pollRunnable, POLL_INTERVAL_MS);
    }

    private BluetoothAdapter pollAdapterRef;

    private final Runnable pollRunnable = new Runnable() {
        @Override
        public void run() {
            if (!activationInFlight) return;
            BluetoothAdapter adapter = pollAdapterRef;
            if (checkAndCompleteIfReady(adapter)) {
                return;
            }

            long elapsed = SystemClock.elapsedRealtime() - activationStartElapsed;
            if (!directEnableAttempted && elapsed >= DIRECT_ENABLE_TRIGGER_MS) {
                directEnableAttempted = true;
                tryDirectIBluetoothManagerEnable(adapter, "settle+" + elapsed + "ms");
                if (checkAndCompleteIfReady(adapter)) {
                    return;
                }
            }

            if (elapsed >= ENABLE_TIMEOUT_MS) {
                String diag = buildFailureDiagnostic(adapter, elapsed);
                DiagLogger.log("BRCM_BLE", "Broadcom BLE/GATT activation timed out: " + diag);
                finishWaiters(false, diag);
                return;
            }

            mainHandler.postDelayed(this, POLL_INTERVAL_MS);
        }
    };

    private boolean checkAndCompleteIfReady(BluetoothAdapter adapter) {
        Object mgrGatt = BtStackProbe.getLiveIBluetoothGatt(adapter);
        Object cbGatt = callbackGattEnabled ? callbackGattBinder : null;
        if (mgrGatt != null || cbGatt != null) {
            long elapsed = SystemClock.elapsedRealtime() - activationStartElapsed;
            String msg = "GattService ONLINE in " + elapsed + "ms (mgrGatt="
                    + (mgrGatt != null ? "LIVE" : "NULL")
                    + ", cbGatt=" + (cbGatt != null ? "LIVE" : "NULL") + ")";
            DiagLogger.log("BRCM_BLE", msg);
            finishWaiters(true, msg);
            return true;
        }
        return false;
    }

    private void finishWaiters(boolean ready, String summary) {
        activationInFlight = false;
        mainHandler.removeCallbacks(pollRunnable);
        List<ReadinessCallback> copy = new ArrayList<ReadinessCallback>(waiters);
        waiters.clear();
        for (int i = 0; i < copy.size(); i++) {
            try {
                copy.get(i).onResult(ready, summary);
            } catch (Throwable t) {
                DiagLogger.log("BRCM_BLE", "ReadinessCallback error: " + t);
            }
        }
    }

    private void startRadioManagerAcquisition(final BluetoothAdapter adapter) {
        ensureRadioMgrLoaded(adapter, true);
        Object mgr = BtStackProbe.getIBluetoothManager(adapter);
        Boolean mgrRadioBefore = invokeBoolNoArg(mgr, "isRadioEnabled");
        DiagLogger.log("BRCM_BLE", "Pre-enable state: IBluetoothManager.isRadioEnabled=" + mgrRadioBefore
                + " | " + BtStackProbe.checkIBluetoothGattStatus(adapter));

        if (radioMgrClass != null && radioMgrInstance != null) {
            Boolean rmRadio = invokeBoolNoArg(radioMgrInstance, "isRadioEnabled");
            Boolean rmGatt = invokeBoolNoArg(radioMgrInstance, "isGattServiceReady");
            DiagLogger.log("BRCM_BLE", "BluetoothRadioManager state before acquire: isRadioEnabled="
                    + rmRadio + ", isGattServiceReady=" + rmGatt
                    + ", fields={" + dumpInstanceFields(radioMgrInstance) + "}");

            ClassLoader cl = radioMgrClass.getClassLoader();
            if (cl == null) {
                cl = appContext.getClassLoader();
            }

            // 1. Acquire RADIO_TYPE_BLE radio reference if constant is resolved
            if (radioTypeBle >= 0 && !bleRadioRefAcquired) {
                try {
                    Class<?> radioCbIface = Class.forName(CLS_RADIO_CB, true, cl);
                    if (radioStateProxy == null) {
                        radioStateProxy = createCallbackProxy(cl, radioCbIface, "Bvm02BleRadioCb", adapter);
                    }
                    Method mAddRadio = radioMgrClass.getMethod("addRadioReference", int.class, radioCbIface);
                    Object res = mAddRadio.invoke(radioMgrInstance, Integer.valueOf(radioTypeBle), radioStateProxy);
                    bleRadioRefAcquired = Boolean.TRUE.equals(res);
                    DiagLogger.log("BRCM_BLE", "RadioMgr.addRadioReference(RADIO_TYPE_BLE=" + radioTypeBle
                            + ") -> " + res);
                } catch (Throwable t) {
                    DiagLogger.log("BRCM_BLE", "RadioMgr.addRadioReference threw: " + unwrapThrowable(t));
                }
            }

            // 2. Acquire LE / GATT service reference
            if (!leRefAcquired) {
                try {
                    Class<?> gattCbIface = Class.forName(CLS_GATT_CB, true, cl);
                    if (gattStateProxy == null) {
                        gattStateProxy = createCallbackProxy(cl, gattCbIface, "Bvm02GattStateCb", adapter);
                    }
                    Method mAddLe = radioMgrClass.getMethod("addLeRadioReference", gattCbIface);
                    Object res = mAddLe.invoke(radioMgrInstance, gattStateProxy);
                    leRefAcquired = Boolean.TRUE.equals(res);
                    DiagLogger.log("BRCM_BLE", "RadioMgr.addLeRadioReference(proxy) -> " + res);
                } catch (Throwable t) {
                    DiagLogger.log("BRCM_BLE", "RadioMgr.addLeRadioReference threw: " + unwrapThrowable(t));
                }
            }

            DiagLogger.log("BRCM_BLE", "BluetoothRadioManager fields after acquire: {"
                    + dumpInstanceFields(radioMgrInstance) + "}");

            // If neither reference reported true, immediately test direct IBluetoothManager calls
            if (!leRefAcquired && !bleRadioRefAcquired) {
                directEnableAttempted = true;
                tryDirectIBluetoothManagerEnable(adapter, "immediate-fallback");
            }
        } else {
            DiagLogger.log("BRCM_BLE", "BluetoothRadioManager unavailable; trying direct IBluetoothManager enableGatt()");
            directEnableAttempted = true;
            tryDirectIBluetoothManagerEnable(adapter, "no-radiomgr");
        }
    }

    private void tryDirectIBluetoothManagerEnable(BluetoothAdapter adapter, String reason) {
        Object mgr = BtStackProbe.getIBluetoothManager(adapter);
        if (mgr == null) {
            DiagLogger.log("BRCM_BLE", "Direct enable skipped (" + reason + "): mManagerService is null");
            return;
        }
        int bleType = (radioTypeBle >= 0) ? radioTypeBle : 1;
        try {
            Method mEnableRadio = mgr.getClass().getMethod("enableRadio", int.class);
            mEnableRadio.setAccessible(true);
            Object rRes = mEnableRadio.invoke(mgr, Integer.valueOf(bleType));
            DiagLogger.log("BRCM_BLE", "Direct IBluetoothManager.enableRadio(" + bleType
                    + ") [" + reason + "] -> " + rRes);
        } catch (NoSuchMethodException ignored) {
        } catch (Throwable t) {
            DiagLogger.log("BRCM_BLE", "IBluetoothManager.enableRadio(" + bleType + ") threw: " + unwrapThrowable(t));
        }

        try {
            Method mEnableGatt = mgr.getClass().getMethod("enableGatt");
            mEnableGatt.setAccessible(true);
            Object gRes = mEnableGatt.invoke(mgr);
            DiagLogger.log("BRCM_BLE", "Direct IBluetoothManager.enableGatt() [" + reason + "] -> " + gRes);
        } catch (NoSuchMethodException nsme) {
            DiagLogger.log("BRCM_BLE", "IBluetoothManager.enableGatt() method not found");
        } catch (Throwable t) {
            DiagLogger.log("BRCM_BLE", "IBluetoothManager.enableGatt() threw: " + unwrapThrowable(t));
        }

        // Also check IBluetooth.enableRadio(bleType) if mService exposes it
        Object btSvc = BtStackProbe.getIBluetoothService(adapter);
        if (btSvc != null && BtStackProbe.getLiveIBluetoothGatt(adapter) == null) {
            try {
                Method mBtEnableRadio = btSvc.getClass().getMethod("enableRadio", int.class);
                mBtEnableRadio.setAccessible(true);
                Object btRes = mBtEnableRadio.invoke(btSvc, Integer.valueOf(bleType));
                DiagLogger.log("BRCM_BLE", "Direct IBluetooth.enableRadio(" + bleType
                        + ") [" + reason + "] -> " + btRes);
            } catch (Throwable ignored) {}
        }
    }

    /**
     * Creates a Java dynamic Proxy for Broadcom RadioManager callback interfaces that safely
     * handles Object methods (equals/hashCode/toString) when stored in ArrayList/HashMap.
     */
    public static Object createDetachedCallbackProxy(ClassLoader loader, Class<?> iface,
                                                     final String proxyLabel) {
        return createCallbackProxyInternal(loader, iface, proxyLabel, null, null);
    }

    private Object createCallbackProxy(ClassLoader loader, Class<?> iface,
                                       final String proxyLabel, final BluetoothAdapter adapter) {
        return createCallbackProxyInternal(loader, iface, proxyLabel, this, adapter);
    }

    static Object createCallbackProxyInternal(ClassLoader loader, Class<?> iface,
                                              final String proxyLabel,
                                              final BroadcomGattEnabler owner,
                                              final BluetoothAdapter adapter) {
        return Proxy.newProxyInstance(loader, new Class<?>[]{iface}, new InvocationHandler() {
            @Override
            public Object invoke(Object proxy, Method method, Object[] args) {
                String name = method.getName();
                int argCount = (args == null) ? 0 : args.length;

                if ("equals".equals(name) && argCount == 1) {
                    return Boolean.valueOf(proxy == args[0]);
                }
                if ("hashCode".equals(name) && argCount == 0) {
                    return Integer.valueOf(System.identityHashCode(proxy));
                }
                if ("toString".equals(name) && argCount == 0) {
                    return proxyLabel + "@" + Integer.toHexString(System.identityHashCode(proxy));
                }

                if (owner != null) {
                    if ("onGattServiceStateChange".equals(name) && argCount >= 2) {
                        final boolean enabled = Boolean.TRUE.equals(args[0]);
                        final Object gattBinder = args[1];
                        owner.onGattServiceStateChangedFromBinder(adapter, enabled, gattBinder);
                    } else if ("onRadioStateChange".equals(name) && argCount >= 1) {
                        final boolean enabled = Boolean.TRUE.equals(args[0]);
                        owner.onRadioStateChangedFromBinder(adapter, enabled);
                    }
                }

                Class<?> ret = method.getReturnType();
                if (ret == boolean.class) return Boolean.FALSE;
                if (ret == int.class) return Integer.valueOf(0);
                if (ret == long.class) return Long.valueOf(0L);
                if (ret == byte.class) return Byte.valueOf((byte) 0);
                if (ret == short.class) return Short.valueOf((short) 0);
                if (ret == float.class) return Float.valueOf(0.0f);
                if (ret == double.class) return Double.valueOf(0.0);
                if (ret == char.class) return Character.valueOf('\0');
                return null;
            }
        });
    }

    private void onGattServiceStateChangedFromBinder(final BluetoothAdapter adapter,
                                                     final boolean enabled,
                                                     final Object gattBinder) {
        callbackGattEnabled = enabled;
        callbackGattBinder = enabled ? gattBinder : null;
        DiagLogger.log("BRCM_BLE", "Callback onGattServiceStateChange(enabled=" + enabled
                + ", gatt=" + (gattBinder != null ? gattBinder.getClass().getName() : "NULL") + ")");
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                if (activationInFlight) {
                    checkAndCompleteIfReady(adapter);
                }
            }
        });
    }

    private void onRadioStateChangedFromBinder(final BluetoothAdapter adapter, final boolean enabled) {
        callbackRadioEnabled = enabled;
        DiagLogger.log("BRCM_BLE", "Callback onRadioStateChange(enabled=" + enabled + ")");
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                if (!activationInFlight) return;
                if (enabled && BtStackProbe.getLiveIBluetoothGatt(adapter) == null) {
                    // Radio just powered up; ensure GattService is requested right away
                    tryDirectIBluetoothManagerEnable(adapter, "after-onRadioStateChange(true)");
                    checkAndCompleteIfReady(adapter);
                }
            }
        });
    }

    /**
     * Fallback constructor path if BluetoothRadioManager delivered a live IBluetoothGatt via
     * onGattServiceStateChange(true, gatt) while BluetoothDevice.connectGatt() returned null.
     */
    public BluetoothGatt tryConstructAndConnectBluetoothGatt(Context ctx,
                                                             BluetoothDevice device,
                                                             boolean autoConnect,
                                                             BluetoothGattCallback callback) {
        Object gattBinder = callbackGattBinder;
        if (gattBinder == null || device == null || callback == null) {
            return null;
        }
        try {
            BluetoothGatt instance = null;
            Constructor<?>[] ctors = BluetoothGatt.class.getDeclaredConstructors();
            for (int i = 0; i < ctors.length; i++) {
                Constructor<?> c = ctors[i];
                Class<?>[] p = c.getParameterTypes();
                if (p.length == 4
                        && p[0] == Context.class
                        && p[1].isInstance(gattBinder)
                        && p[2] == BluetoothDevice.class
                        && p[3] == int.class) {
                    c.setAccessible(true);
                    // TRANSPORT_AUTO = 0 / TRANSPORT_LE = 2; 0 matches 3-arg connectGatt default on KitKat
                    instance = (BluetoothGatt) c.newInstance(ctx, gattBinder, device, Integer.valueOf(0));
                    break;
                } else if (p.length == 3
                        && p[0] == Context.class
                        && p[1].isInstance(gattBinder)
                        && p[2] == BluetoothDevice.class) {
                    c.setAccessible(true);
                    instance = (BluetoothGatt) c.newInstance(ctx, gattBinder, device);
                    break;
                }
            }
            if (instance == null) {
                return null;
            }
            Method mConnect = BluetoothGatt.class.getDeclaredMethod(
                    "connect", Boolean.class, BluetoothGattCallback.class);
            mConnect.setAccessible(true);
            Object ok = mConnect.invoke(instance, Boolean.valueOf(autoConnect), callback);
            DiagLogger.log("BRCM_BLE", "Constructed BluetoothGatt directly from callback IBluetoothGatt -> connect=" + ok);
            if (Boolean.TRUE.equals(ok)) {
                return instance;
            }
            try { instance.close(); } catch (Throwable ignored) {}
        } catch (Throwable t) {
            DiagLogger.log("BRCM_BLE", "Direct BluetoothGatt construction fallback failed: " + unwrapThrowable(t));
        }
        return null;
    }

    /**
     * Releases any Broadcom LE / BLE radio references acquired during this app session.
     * Never disables Classic Bluetooth (HFP / A2DP).
     */
    public void releaseAll(BluetoothAdapter adapter) {
        activationInFlight = false;
        mainHandler.removeCallbacks(pollRunnable);
        waiters.clear();

        if (radioMgrClass != null && radioMgrInstance != null) {
            ClassLoader cl = radioMgrClass.getClassLoader();
            if (cl == null) cl = appContext.getClassLoader();

            if (leRefAcquired && gattStateProxy != null) {
                try {
                    Class<?> gattCbIface = Class.forName(CLS_GATT_CB, true, cl);
                    Method mRelLe = radioMgrClass.getMethod("releaseLeRadioReference", gattCbIface);
                    Object res = mRelLe.invoke(radioMgrInstance, gattStateProxy);
                    DiagLogger.log("BRCM_BLE", "Released Broadcom LE radio reference -> " + res);
                } catch (Throwable t) {
                    DiagLogger.log("BRCM_BLE", "releaseLeRadioReference warning: " + unwrapThrowable(t));
                }
                leRefAcquired = false;
            }

            if (bleRadioRefAcquired && radioStateProxy != null && radioTypeBle >= 0) {
                try {
                    Class<?> radioCbIface = Class.forName(CLS_RADIO_CB, true, cl);
                    Method mRelRadio = radioMgrClass.getMethod("releaseRadioReference", int.class, radioCbIface);
                    Object res = mRelRadio.invoke(radioMgrInstance, Integer.valueOf(radioTypeBle), radioStateProxy);
                    DiagLogger.log("BRCM_BLE", "Released Broadcom RADIO_TYPE_BLE reference -> " + res);
                } catch (Throwable t) {
                    DiagLogger.log("BRCM_BLE", "releaseRadioReference warning: " + unwrapThrowable(t));
                }
                bleRadioRefAcquired = false;
            }
        }
        callbackGattBinder = null;
        callbackGattEnabled = false;
        callbackRadioEnabled = false;
    }

    private void ensureRadioMgrLoaded(BluetoothAdapter adapter, boolean logDetails) {
        if (radioMgrClass == null) {
            try {
                radioMgrClass = Class.forName(CLS_RADIO_MGR, true, appContext.getClassLoader());
            } catch (Throwable t1) {
                try {
                    radioMgrClass = Class.forName(CLS_RADIO_MGR);
                } catch (Throwable t2) {
                    if (logDetails) {
                        DiagLogger.log("BRCM_BLE", "Class " + CLS_RADIO_MGR + " not loadable: " + t2);
                    }
                    return;
                }
            }
        }

        if (!loggedConstantsOnce && radioMgrClass != null) {
            loggedConstantsOnce = true;
            StringBuilder csb = new StringBuilder();
            Field[] fields = radioMgrClass.getDeclaredFields();
            for (int i = 0; i < fields.length; i++) {
                Field f = fields[i];
                if (Modifier.isStatic(f.getModifiers())) {
                    try {
                        f.setAccessible(true);
                        Object v = f.get(null);
                        if (csb.length() > 0) csb.append(", ");
                        csb.append(f.getName()).append('=').append(v);
                        if ("RADIO_TYPE_BLE".equals(f.getName()) && v instanceof Integer) {
                            radioTypeBle = ((Integer) v).intValue();
                        }
                    } catch (Throwable ignored) {}
                }
            }
            if (logDetails) {
                DiagLogger.log("BRCM_BLE", "BluetoothRadioManager static fields: {" + csb + "}");
            }
        } else if (radioTypeBle < 0 && radioMgrClass != null) {
            try {
                Field fBle = radioMgrClass.getField("RADIO_TYPE_BLE");
                Object v = fBle.get(null);
                if (v instanceof Integer) {
                    radioTypeBle = ((Integer) v).intValue();
                }
            } catch (Throwable ignored) {}
        }

        if (radioMgrInstance == null && radioMgrClass != null) {
            try {
                Method mGet = radioMgrClass.getMethod("getRadioManager");
                radioMgrInstance = mGet.invoke(null);
            } catch (Throwable t) {
                if (logDetails) {
                    DiagLogger.log("BRCM_BLE", "BluetoothRadioManager.getRadioManager() threw: " + unwrapThrowable(t));
                }
            }
            if (radioMgrInstance == null && adapter != null) {
                Object mgr = BtStackProbe.getIBluetoothManager(adapter);
                if (mgr != null) {
                    try {
                        Constructor<?>[] ctors = radioMgrClass.getDeclaredConstructors();
                        for (int i = 0; i < ctors.length; i++) {
                            Class<?>[] p = ctors[i].getParameterTypes();
                            if (p.length == 1 && p[0].isInstance(mgr)) {
                                ctors[i].setAccessible(true);
                                radioMgrInstance = ctors[i].newInstance(mgr);
                                DiagLogger.log("BRCM_BLE", "Constructed BluetoothRadioManager(IBluetoothManager) directly.");
                                break;
                            }
                        }
                    } catch (Throwable t) {
                        if (logDetails) {
                            DiagLogger.log("BRCM_BLE", "Fallback BluetoothRadioManager ctor failed: " + unwrapThrowable(t));
                        }
                    }
                }
            }
        }
    }

    private String buildFailureDiagnostic(BluetoothAdapter adapter, long elapsedMs) {
        StringBuilder sb = new StringBuilder(220);
        sb.append("after ").append(elapsedMs).append("ms: ");
        sb.append(BtStackProbe.checkIBluetoothGattStatus(adapter));
        sb.append(" | cbRadio=").append(callbackRadioEnabled)
                .append(" cbGatt=").append(callbackGattEnabled);
        if (radioMgrInstance != null) {
            sb.append(" | rmFields={").append(dumpInstanceFields(radioMgrInstance)).append('}');
        }
        return sb.toString();
    }

    private static Boolean invokeBoolNoArg(Object target, String methodName) {
        if (target == null) return null;
        try {
            Method m = target.getClass().getMethod(methodName);
            m.setAccessible(true);
            Object v = m.invoke(target);
            if (v instanceof Boolean) {
                return (Boolean) v;
            }
        } catch (Throwable ignored) {}
        return null;
    }

    private static String dumpInstanceFields(Object target) {
        if (target == null) return "null";
        StringBuilder sb = new StringBuilder(128);
        try {
            Field[] fields = target.getClass().getDeclaredFields();
            for (int i = 0; i < fields.length; i++) {
                Field f = fields[i];
                if (Modifier.isStatic(f.getModifiers())) continue;
                f.setAccessible(true);
                Object v = f.get(target);
                if (sb.length() > 0) sb.append(", ");
                sb.append(f.getName()).append('=');
                if (v == null) {
                    sb.append("null");
                } else if (v instanceof Boolean || v instanceof Number || v instanceof String) {
                    sb.append(v);
                } else if (v instanceof java.util.Collection) {
                    sb.append("size:").append(((java.util.Collection<?>) v).size());
                } else if (v instanceof java.util.Map) {
                    sb.append("size:").append(((java.util.Map<?, ?>) v).size());
                } else {
                    sb.append(v.getClass().getSimpleName());
                }
            }
        } catch (Throwable t) {
            sb.append("err:").append(t.getMessage());
        }
        return sb.toString();
    }

    private static String unwrapThrowable(Throwable t) {
        if (t instanceof java.lang.reflect.InvocationTargetException && t.getCause() != null) {
            t = t.getCause();
        }
        return t.getClass().getSimpleName() + ": " + t.getMessage();
    }
}
