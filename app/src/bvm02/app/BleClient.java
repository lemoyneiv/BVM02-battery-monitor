package bvm02.app;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Gen5W Android 4.4.2 (API 19) Bluetooth LE Scanner & Serialized GATT Client for LNEX BVM02.
 *
 * Key API 19 / Broadcom KitKat architectural safeguards:
 *  1. Uses API 18/19 BluetoothAdapter.startLeScan / stopLeScan (never API 21 BluetoothLeScanner).
 *  2. Always stops active LE scan BEFORE calling 3-arg BluetoothDevice.connectGatt(ctx, false, cb)
 *     on the main thread to avoid Broadcom KitKat GATT status 133 collisions.
 *  3. Operates strictly in non-MTU mode (20-byte ATT payload; never calls API 21 requestMtu),
 *     reassembling multi-chunk notifications on 0xFFF4 via Bvm02Protocol.FrameAssembler.
 *  4. Strictly serializes all GATT operations (CCCD descriptor write, characteristic reads,
 *     characteristic writes) one-at-a-time with a per-operation watchdog timeout.
 *  5. Immediately invokes gatt.close() on disconnect/shutdown so Android 4.4's limited system-wide
 *     GATT clientIf slots are never leaked, and passive Classic BT (HFP/A2DP) is never disturbed.
 */
public final class BleClient {

    public static final long SCAN_DURATION_MS = 12000L;
    public static final long VOLTAGE_POLL_INTERVAL_MS = 1500L;
    private static final long GATT_OP_TIMEOUT_MS = 3500L;
    private static final long CONNECT_TIMEOUT_MS = 12000L;

    public enum ConnState {
        DISCONNECTED,
        CONNECTING,
        DISCOVERING,
        HANDSHAKING,
        STREAMING
    }

    public static final class ScannedDevice {
        public final String mac;
        public final String name;
        public final int rssi;
        public final boolean bvm02Match;
        public final boolean hasServiceFff0;
        public final String advHexPreview;
        public final long lastSeenElapsedMs;

        public ScannedDevice(String mac, String name, int rssi, boolean bvm02Match,
                             boolean hasServiceFff0, String advHexPreview, long lastSeenElapsedMs) {
            this.mac = mac;
            this.name = name;
            this.rssi = rssi;
            this.bvm02Match = bvm02Match;
            this.hasServiceFff0 = hasServiceFff0;
            this.advHexPreview = advHexPreview;
            this.lastSeenElapsedMs = lastSeenElapsedMs;
        }
    }

    public interface Listener {
        void onScanStateChanged(boolean scanning, String summary);
        void onScanResultsUpdated(List<ScannedDevice> devices);
        void onConnectionStateChanged(ConnState state, SensorConfig sensor, String statusText);
        void onRealtimeVoltage(SensorConfig sensor, Bvm02Protocol.RealtimeReading reading,
                               boolean resolvedIs24V, int socPercent, Bvm02Protocol.HealthStatus health);
        void onSensorMetadataUpdated(SensorConfig sensor, float fwVersion, int hwVersion, String remoteName);
        void onPasswordResult(SensorConfig sensor, boolean accepted);
    }

    private enum OpKind {
        ENABLE_NOTIFY,
        READ_CHAR,
        WRITE_CHAR
    }

    private static final class GattOp {
        final OpKind kind;
        final UUID charUuid;
        final byte[] writePayload;
        final String label;

        GattOp(OpKind kind, UUID charUuid, byte[] writePayload, String label) {
            this.kind = kind;
            this.charUuid = charUuid;
            this.writePayload = writePayload;
            this.label = label;
        }
    }

    private final Context appContext;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final Listener listener;

    private BluetoothManager btManager;
    private BluetoothAdapter btAdapter;

    // BLE Scanner state
    private boolean isScanning = false;
    private final Map<String, ScannedDevice> scannedMap = new LinkedHashMap<String, ScannedDevice>();

    // Active GATT connection state (guarded on mainHandler)
    private final AtomicInteger connGeneration = new AtomicInteger(0);
    private ConnState connState = ConnState.DISCONNECTED;
    private SensorConfig activeSensor = null;
    private BluetoothGatt activeGatt = null;
    private BluetoothGattService activeServiceFff0 = null;
    private final Bvm02Protocol.FrameAssembler rxAssembler = new Bvm02Protocol.FrameAssembler();
    private boolean retriedStatus133 = false;

    // Discovered metadata & counters
    private float activeFwVersion = 0.0f;
    private int activeHwVersion = 0;
    private String activeRemoteName = "";
    private int rxReadCount = 0;
    private int rxNotifyCount = 0;
    private int txWriteCount = 0;
    private int gattErrorCount = 0;

    // Serialized GATT operation queue
    private final List<GattOp> opQueue = new ArrayList<GattOp>();
    private GattOp inflightOp = null;
    private int discoverRetryCount = 0;

    public BleClient(Context context, Listener listener) {
        this.appContext = context.getApplicationContext();
        this.listener = listener;
        refreshAdapterReferences();
    }

    private void refreshAdapterReferences() {
        try {
            Object svc = appContext.getSystemService(Context.BLUETOOTH_SERVICE);
            if (svc instanceof BluetoothManager) {
                btManager = (BluetoothManager) svc;
                btAdapter = btManager.getAdapter();
            }
            if (btAdapter == null) {
                btAdapter = BluetoothAdapter.getDefaultAdapter();
            }
        } catch (Throwable t) {
            DiagLogger.log("BT_ERR", "Error obtaining BluetoothAdapter: " + t.getMessage());
        }
    }

    public boolean isAdapterAvailable() {
        refreshAdapterReferences();
        return btAdapter != null;
    }

    public boolean isAdapterEnabled() {
        refreshAdapterReferences();
        try {
            return btAdapter != null && btAdapter.isEnabled();
        } catch (Throwable t) {
            return false;
        }
    }

    public boolean requestEnableAdapter() {
        refreshAdapterReferences();
        if (btAdapter == null) return false;
        try {
            boolean ok = btAdapter.enable();
            DiagLogger.log("BT_ADAPTER", "Requested BluetoothAdapter.enable() -> " + ok);
            return ok;
        } catch (Throwable t) {
            DiagLogger.log("BT_ERR", "BluetoothAdapter.enable() failed: " + t.getMessage());
            return false;
        }
    }

    public ConnState getConnectionState() {
        return connState;
    }

    public SensorConfig getActiveSensor() {
        return activeSensor;
    }

    public boolean isScanning() {
        return isScanning;
    }

    /**
     * Generates a non-invasive diagnostic report of the Gen5W Bluetooth hardware & coexistence state.
     */
    public String buildHardwareSummary() {
        refreshAdapterReferences();
        StringBuilder sb = new StringBuilder(320);
        boolean hasFeatureXml = false;
        try {
            hasFeatureXml = appContext.getPackageManager()
                    .hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE);
        } catch (Throwable ignored) {}

        if (btAdapter == null) {
            sb.append("Adapter: NULL (Bluetooth hardware unavailable on this build)\n");
            sb.append("feature_bluetooth_le XML: ").append(hasFeatureXml);
            return sb.toString();
        }

        String name = "?";
        String addr = "?";
        int state = -1;
        int hfp = BluetoothProfile.STATE_DISCONNECTED;
        int a2dp = BluetoothProfile.STATE_DISCONNECTED;
        int bondedCount = 0;
        try {
            name = String.valueOf(btAdapter.getName());
            addr = String.valueOf(btAdapter.getAddress());
            state = btAdapter.getState();
            hfp = btAdapter.getProfileConnectionState(BluetoothProfile.HEADSET);
            a2dp = btAdapter.getProfileConnectionState(BluetoothProfile.A2DP);
            Set<BluetoothDevice> bonded = btAdapter.getBondedDevices();
            if (bonded != null) bondedCount = bonded.size();
        } catch (Throwable t) {
            sb.append("Adapter query warning: ").append(t.getMessage()).append('\n');
        }

        sb.append("Adapter: ").append(name).append(" [").append(addr).append("]  State=").append(adapterStateStr(state))
                .append("  BLE_XML=").append(hasFeatureXml).append('\n');
        sb.append("Classic BT Coexistence: HFP=").append(profileStateStr(hfp))
                .append("  A2DP=").append(profileStateStr(a2dp))
                .append("  Bonded=").append(bondedCount).append('\n');
        sb.append("GATT Session: ").append(connState.name())
                .append(activeSensor != null ? (" (" + activeSensor.mac + ")") : "")
                .append("  |  Reads=").append(rxReadCount)
                .append("  Notifies=").append(rxNotifyCount)
                .append("  Writes=").append(txWriteCount)
                .append("  Errs=").append(gattErrorCount);
        return sb.toString();
    }

    // ================= BLE SCANNING (API 19 startLeScan) =================

    private final Runnable stopScanTimeoutRunnable = new Runnable() {
        @Override
        public void run() {
            if (isScanning) {
                DiagLogger.log("BLE_SCAN", "Scan window completed (" + (SCAN_DURATION_MS / 1000L)
                        + "s). Total BLE peripherals seen: " + scannedMap.size());
                stopScan();
            }
        }
    };

    private final BluetoothAdapter.LeScanCallback leScanCallback = new BluetoothAdapter.LeScanCallback() {
        @Override
        public void onLeScan(final BluetoothDevice device, final int rssi, final byte[] scanRecord) {
            if (device == null) return;
            final String mac;
            String devName = null;
            try {
                mac = device.getAddress();
                devName = device.getName();
            } catch (Throwable t) {
                return;
            }
            if (mac == null || mac.isEmpty()) return;

            final byte[] recCopy;
            if (scanRecord != null && scanRecord.length > 0) {
                int cap = Math.min(scanRecord.length, 62);
                recCopy = new byte[cap];
                System.arraycopy(scanRecord, 0, recCopy, 0, cap);
            } else {
                recCopy = new byte[0];
            }

            final String advName = Bvm02Protocol.parseAdvertisedName(recCopy);
            final String resolvedName = (devName != null && !devName.trim().isEmpty())
                    ? devName.trim()
                    : (advName != null ? advName : "");
            final boolean hasFff0 = Bvm02Protocol.hasAdvertisedServiceFff0(recCopy);
            final boolean isMatch = Bvm02Protocol.isLikelyBvm02Device(resolvedName, recCopy);
            final String hexPreview = buildAdvPreview(recCopy);

            mainHandler.post(new Runnable() {
                @Override
                public void run() {
                    if (!isScanning) return;
                    boolean isNew = !scannedMap.containsKey(mac);
                    ScannedDevice entry = new ScannedDevice(
                            mac.toUpperCase(Locale.US),
                            resolvedName,
                            rssi,
                            isMatch,
                            hasFff0,
                            hexPreview,
                            SystemClock.elapsedRealtime()
                    );
                    scannedMap.put(entry.mac, entry);
                    if (isNew) {
                        DiagLogger.log("BLE_SCAN", "Discovered BLE peripheral: name='"
                                + (resolvedName.isEmpty() ? "<unnamed>" : resolvedName)
                                + "' mac=" + entry.mac
                                + " rssi=" + rssi + "dBm"
                                + " bvm02Match=" + isMatch
                                + " fff0=" + hasFff0
                                + " adv=[" + hexPreview + "]");
                    }
                    listener.onScanResultsUpdated(getSortedScanResults());
                }
            });
        }
    };

    public void startScan() {
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                refreshAdapterReferences();
                if (btAdapter == null) {
                    DiagLogger.log("BLE_SCAN", "Cannot scan: BluetoothAdapter is null.");
                    listener.onScanStateChanged(false, "Bluetooth hardware adapter unavailable.");
                    return;
                }
                if (!isAdapterEnabled()) {
                    DiagLogger.log("BLE_SCAN", "Bluetooth adapter is disabled; attempting enable...");
                    listener.onScanStateChanged(false, "Bluetooth is OFF — enable Bluetooth on head unit.");
                    return;
                }
                if (isScanning) {
                    stopScanInternal(false);
                }

                scannedMap.clear();
                listener.onScanResultsUpdated(Collections.<ScannedDevice>emptyList());

                boolean started = false;
                try {
                    started = btAdapter.startLeScan(leScanCallback);
                } catch (Throwable t) {
                    DiagLogger.log("BLE_SCAN", "startLeScan threw exception: " + t.getMessage());
                }

                if (started) {
                    isScanning = true;
                    DiagLogger.log("BLE_SCAN", "Started API 19 BluetoothAdapter.startLeScan()");
                    listener.onScanStateChanged(true, "Scanning BLE peripherals (12s)...");
                    mainHandler.removeCallbacks(stopScanTimeoutRunnable);
                    mainHandler.postDelayed(stopScanTimeoutRunnable, SCAN_DURATION_MS);
                } else {
                    isScanning = false;
                    DiagLogger.log("BLE_SCAN", "BluetoothAdapter.startLeScan() returned false!");
                    listener.onScanStateChanged(false,
                            "startLeScan() returned false — check BT Diagnostics log or try Add by MAC.");
                }
            }
        });
    }

    public void stopScan() {
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                stopScanInternal(true);
            }
        });
    }

    private void stopScanInternal(boolean notifyUi) {
        mainHandler.removeCallbacks(stopScanTimeoutRunnable);
        if (isScanning && btAdapter != null) {
            try {
                btAdapter.stopLeScan(leScanCallback);
                DiagLogger.log("BLE_SCAN", "Stopped BLE scan.");
            } catch (Throwable t) {
                DiagLogger.log("BLE_SCAN", "stopLeScan warning: " + t.getMessage());
            }
        }
        boolean wasScanning = isScanning;
        isScanning = false;
        if (notifyUi || wasScanning) {
            int bvmCount = 0;
            for (ScannedDevice d : scannedMap.values()) {
                if (d.bvm02Match) bvmCount++;
            }
            listener.onScanStateChanged(false, "Scan finished: " + bvmCount + " BVM02 match(es), "
                    + scannedMap.size() + " total BLE device(s).");
        }
    }

    public List<ScannedDevice> getSortedScanResults() {
        List<ScannedDevice> list = new ArrayList<ScannedDevice>(scannedMap.values());
        Collections.sort(list, new Comparator<ScannedDevice>() {
            @Override
            public int compare(ScannedDevice a, ScannedDevice b) {
                if (a.bvm02Match != b.bvm02Match) {
                    return a.bvm02Match ? -1 : 1;
                }
                return Integer.compare(b.rssi, a.rssi);
            }
        });
        return list;
    }

    // ================= GATT CONNECTION & HANDSHAKE =================

    public void connect(final SensorConfig sensor) {
        if (sensor == null || !sensor.isConfigured()) return;
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                retriedStatus133 = false;
                connectInternal(sensor);
            }
        });
    }

    private void connectInternal(final SensorConfig sensor) {
        refreshAdapterReferences();
        if (btAdapter == null || !isAdapterEnabled()) {
            updateConnState(ConnState.DISCONNECTED, sensor, "Bluetooth is disabled");
            return;
        }

        // Critical on KitKat Broadcom BT: stop LE scan before initiating GATT connection
        stopScanInternal(true);

        // Cleanly tear down any previous GATT session & release clientIf slot
        closeGattInternal();

        BluetoothDevice remote;
        try {
            remote = btAdapter.getRemoteDevice(sensor.mac);
        } catch (Throwable t) {
            DiagLogger.log("GATT_ERR", "Invalid Bluetooth MAC '" + sensor.mac + "': " + t.getMessage());
            updateConnState(ConnState.DISCONNECTED, sensor, "Invalid MAC: " + sensor.mac);
            return;
        }

        activeSensor = sensor;
        activeFwVersion = 0.0f;
        activeHwVersion = 0;
        activeRemoteName = sensor.advertisedName;
        discoverRetryCount = 0;
        rxAssembler.reset();

        final int gen = connGeneration.incrementAndGet();
        updateConnState(ConnState.CONNECTING, sensor, "Connecting to " + sensor.getDisplayName() + "...");

        DiagLogger.log("GATT", "Calling API 19 connectGatt(autoConnect=false) to "
                + sensor.mac + " [gen=" + gen + "]");

        try {
            // Strictly 3-arg connectGatt for Android 4.4.2 API 19 compatibility
            activeGatt = remote.connectGatt(appContext, false, createGattCallback(gen, sensor));
        } catch (Throwable t) {
            gattErrorCount++;
            DiagLogger.log("GATT_ERR", "connectGatt threw exception: " + t.getMessage());
            updateConnState(ConnState.DISCONNECTED, sensor, "connectGatt error: " + t.getMessage());
            return;
        }

        if (activeGatt == null) {
            gattErrorCount++;
            DiagLogger.log("GATT_ERR", "connectGatt returned null BluetoothGatt!");
            updateConnState(ConnState.DISCONNECTED, sensor, "connectGatt returned null");
            return;
        }

        mainHandler.postDelayed(new Runnable() {
            @Override
            public void run() {
                if (connGeneration.get() == gen
                        && (connState == ConnState.CONNECTING || connState == ConnState.DISCOVERING)) {
                    gattErrorCount++;
                    DiagLogger.log("GATT_TIMEOUT", "Connection timed out after "
                            + (CONNECT_TIMEOUT_MS / 1000L) + "s for " + sensor.mac);
                    closeGattInternal();
                    updateConnState(ConnState.DISCONNECTED, sensor, "Connection timed out — ensure sensor is in range & phone app is closed");
                }
            }
        }, CONNECT_TIMEOUT_MS);
    }

    public void disconnect() {
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                SensorConfig prev = activeSensor;
                DiagLogger.log("GATT", "Manual disconnect requested"
                        + (prev != null ? (" for " + prev.mac) : ""));
                closeGattInternal();
                updateConnState(ConnState.DISCONNECTED, prev, "Disconnected");
            }
        });
    }

    public void shutdown() {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            stopScanInternal(false);
            closeGattInternal();
        } else {
            mainHandler.post(new Runnable() {
                @Override
                public void run() {
                    stopScanInternal(false);
                    closeGattInternal();
                }
            });
        }
    }

    private void closeGattInternal() {
        connGeneration.incrementAndGet();
        mainHandler.removeCallbacks(pollVoltageRunnable);
        mainHandler.removeCallbacks(opWatchdogRunnable);
        opQueue.clear();
        inflightOp = null;
        activeServiceFff0 = null;
        rxAssembler.reset();

        if (activeGatt != null) {
            BluetoothGatt g = activeGatt;
            activeGatt = null;
            try {
                g.disconnect();
            } catch (Throwable ignored) {}
            try {
                g.close();
                DiagLogger.log("GATT", "BluetoothGatt closed cleanly (clientIf slot released).");
            } catch (Throwable t) {
                DiagLogger.log("GATT_WARN", "BluetoothGatt.close() warning: " + t.getMessage());
            }
        }
    }

    private BluetoothGattCallback createGattCallback(final int gen, final SensorConfig sensor) {
        return new BluetoothGattCallback() {
            @Override
            public void onConnectionStateChange(final BluetoothGatt gatt, final int status, final int newState) {
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        if (gen != connGeneration.get()) {
                            try { gatt.close(); } catch (Throwable ignored) {}
                            return;
                        }
                        DiagLogger.log("GATT_STATE", "onConnectionStateChange: status=" + status
                                + " newState=" + newState + " (" + gattConnStateStr(newState) + ") mac=" + sensor.mac);

                        if (newState == BluetoothProfile.STATE_CONNECTED && status == BluetoothGatt.GATT_SUCCESS) {
                            updateConnState(ConnState.DISCOVERING, sensor, "Connected — discovering GATT services...");
                            discoverRetryCount = 0;
                            triggerServiceDiscovery(gatt, gen);
                        } else {
                            boolean canRetry133 = (status == 133 && !retriedStatus133);
                            closeGattInternal();
                            if (canRetry133) {
                                retriedStatus133 = true;
                                DiagLogger.log("GATT_RETRY", "Broadcom GATT status 133 on initial connect; retrying once in 650ms...");
                                updateConnState(ConnState.CONNECTING, sensor, "Retrying GATT handshake (status 133)...");
                                mainHandler.postDelayed(new Runnable() {
                                    @Override
                                    public void run() {
                                        connectInternal(sensor);
                                    }
                                }, 650L);
                            } else {
                                if (status != BluetoothGatt.GATT_SUCCESS) {
                                    gattErrorCount++;
                                }
                                String reason = (status == BluetoothGatt.GATT_SUCCESS)
                                        ? "Disconnected"
                                        : ("Disconnected (GATT status " + status + ")");
                                updateConnState(ConnState.DISCONNECTED, sensor, reason);
                            }
                        }
                    }
                });
            }

            @Override
            public void onServicesDiscovered(final BluetoothGatt gatt, final int status) {
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        if (gen != connGeneration.get()) return;
                        DiagLogger.log("GATT_SVC", "onServicesDiscovered: status=" + status);
                        if (status != BluetoothGatt.GATT_SUCCESS) {
                            gattErrorCount++;
                            closeGattInternal();
                            updateConnState(ConnState.DISCONNECTED, sensor, "Service discovery failed (status " + status + ")");
                            return;
                        }
                        handleServicesDiscovered(gatt, gen, sensor);
                    }
                });
            }

            @Override
            public void onDescriptorWrite(final BluetoothGatt gatt, final BluetoothGattDescriptor descriptor, final int status) {
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        if (gen != connGeneration.get()) return;
                        DiagLogger.log("GATT_DESC", "onDescriptorWrite: uuid="
                                + (descriptor != null ? descriptor.getUuid() : "null") + " status=" + status);
                        completeInflightOp();
                    }
                });
            }

            @Override
            public void onCharacteristicRead(final BluetoothGatt gatt,
                                             final BluetoothGattCharacteristic characteristic,
                                             final int status) {
                final UUID uuid = characteristic != null ? characteristic.getUuid() : null;
                final byte[] data = copyBytes(characteristic != null ? characteristic.getValue() : null);
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        if (gen != connGeneration.get()) return;
                        if (status == BluetoothGatt.GATT_SUCCESS && uuid != null) {
                            rxReadCount++;
                            handleCharacteristicReadData(sensor, uuid, data);
                        } else {
                            gattErrorCount++;
                            DiagLogger.log("GATT_READ", "Read failed on " + uuid + " status=" + status);
                        }
                        completeInflightOp();
                    }
                });
            }

            @Override
            public void onCharacteristicWrite(final BluetoothGatt gatt,
                                              final BluetoothGattCharacteristic characteristic,
                                              final int status) {
                final UUID uuid = characteristic != null ? characteristic.getUuid() : null;
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        if (gen != connGeneration.get()) return;
                        if (status == BluetoothGatt.GATT_SUCCESS) {
                            txWriteCount++;
                        } else {
                            gattErrorCount++;
                            DiagLogger.log("GATT_WRITE", "Write failed on " + uuid + " status=" + status);
                        }
                        completeInflightOp();
                    }
                });
            }

            @Override
            public void onCharacteristicChanged(final BluetoothGatt gatt,
                                                final BluetoothGattCharacteristic characteristic) {
                final UUID uuid = characteristic != null ? characteristic.getUuid() : null;
                final byte[] data = copyBytes(characteristic != null ? characteristic.getValue() : null);
                mainHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        if (gen != connGeneration.get()) return;
                        rxNotifyCount++;
                        handleCharacteristicNotification(sensor, uuid, data);
                    }
                });
            }
        };
    }

    private void triggerServiceDiscovery(final BluetoothGatt gatt, final int gen) {
        mainHandler.postDelayed(new Runnable() {
            @Override
            public void run() {
                if (gen != connGeneration.get() || activeGatt != gatt) return;
                boolean ok = false;
                try {
                    ok = gatt.discoverServices();
                } catch (Throwable t) {
                    DiagLogger.log("GATT_ERR", "discoverServices threw: " + t.getMessage());
                }
                DiagLogger.log("GATT_SVC", "Called gatt.discoverServices() -> " + ok);
                if (!ok) {
                    gattErrorCount++;
                    closeGattInternal();
                    updateConnState(ConnState.DISCONNECTED, activeSensor, "discoverServices() failed");
                }
            }
        }, 180L); // Short settle delay helps Broadcom KitKat GATT service discovery stability
    }

    private void handleServicesDiscovered(BluetoothGatt gatt, int gen, SensorConfig sensor) {
        List<BluetoothGattService> services = gatt.getServices();
        int count = services != null ? services.size() : 0;
        DiagLogger.log("GATT_SVC", "Discovered " + count + " GATT service(s) on " + sensor.mac);

        if (count == 0 && discoverRetryCount < 2) {
            discoverRetryCount++;
            DiagLogger.log("GATT_SVC", "Empty service list; retrying discoverServices (#" + discoverRetryCount + ")...");
            triggerServiceDiscovery(gatt, gen);
            return;
        }

        if (services != null) {
            for (BluetoothGattService s : services) {
                StringBuilder csb = new StringBuilder();
                List<BluetoothGattCharacteristic> chars = s.getCharacteristics();
                if (chars != null) {
                    for (BluetoothGattCharacteristic c : chars) {
                        if (csb.length() > 0) csb.append(", ");
                        csb.append(shortUuid(c.getUuid())).append("(props=0x")
                                .append(Integer.toHexString(c.getProperties())).append(')');
                    }
                }
                DiagLogger.log("GATT_TABLE", "Service " + shortUuid(s.getUuid()) + " -> [" + csb + "]");
            }
        }

        activeServiceFff0 = gatt.getService(Bvm02Protocol.UUID_SERVICE);
        if (activeServiceFff0 == null) {
            gattErrorCount++;
            DiagLogger.log("GATT_ERR", "Primary BVM02 service 0xFFF0 not found on peripheral!");
            closeGattInternal();
            updateConnState(ConnState.DISCONNECTED, sensor, "Peripheral does not expose BVM02 service 0xFFF0");
            return;
        }

        updateConnState(ConnState.HANDSHAKING, sensor, "Initializing BVM02 GATT channels...");

        // 1. Enable notifications on 0xFFF4
        if (activeServiceFff0.getCharacteristic(Bvm02Protocol.UUID_CMD_NOTIFY) != null) {
            enqueueOp(new GattOp(OpKind.ENABLE_NOTIFY, Bvm02Protocol.UUID_CMD_NOTIFY, null, "Enable 0xFFF4 Notify"));
        }

        // 2. Read firmware & hardware version on 0xFFF1 (strictly READ-ONLY)
        if (activeServiceFff0.getCharacteristic(Bvm02Protocol.UUID_VERSION_INFO) != null) {
            enqueueOp(new GattOp(OpKind.READ_CHAR, Bvm02Protocol.UUID_VERSION_INFO, null, "Read 0xFFF1 Version"));
        }

        // 3. Read remote UTF-8 name on 0xFFF6 if present
        if (activeServiceFff0.getCharacteristic(Bvm02Protocol.UUID_DEVICE_NAME) != null) {
            enqueueOp(new GattOp(OpKind.READ_CHAR, Bvm02Protocol.UUID_DEVICE_NAME, null, "Read 0xFFF6 Name"));
        }

        // 4. Sync local wall-clock time (Cmd 0x01, non-MTU mode) and verify PIN (Cmd 0x36)
        if (activeServiceFff0.getCharacteristic(Bvm02Protocol.UUID_CMD_WRITE) != null) {
            enqueueCommandFrames(Bvm02Protocol.buildSyncTimeCmd(System.currentTimeMillis(), false), "Cmd 0x01 SyncTime");
            if (Bvm02Protocol.isValidPin(sensor.pin)) {
                enqueueCommandFrames(Bvm02Protocol.buildVerifyPasswordCmd(sensor.pin), "Cmd 0x36 VerifyPIN");
            }
        }

        // 5. Immediate initial voltage read on 0xFFF2, then start 1.5s live polling loop
        enqueueVoltageRead();
        mainHandler.removeCallbacks(pollVoltageRunnable);
        mainHandler.postDelayed(pollVoltageRunnable, VOLTAGE_POLL_INTERVAL_MS);
    }

    public void sendSetPassword(final String newPin4) {
        if (!Bvm02Protocol.isValidPin(newPin4)) return;
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                if (activeGatt == null || activeServiceFff0 == null) return;
                enqueueCommandFrames(Bvm02Protocol.buildSetPasswordCmd(newPin4), "Cmd 0x35 SetPIN");
            }
        });
    }

    private void enqueueCommandFrames(byte[] fullFrame, String label) {
        List<byte[]> chunks = Bvm02Protocol.splitIntoBleChunks(fullFrame, Bvm02Protocol.BLE_ATT_DEFAULT_PAYLOAD);
        for (int i = 0; i < chunks.size(); i++) {
            enqueueOp(new GattOp(OpKind.WRITE_CHAR, Bvm02Protocol.UUID_CMD_WRITE, chunks.get(i),
                    label + (chunks.size() > 1 ? (" [" + (i + 1) + "/" + chunks.size() + "]") : "")));
        }
    }

    private void enqueueVoltageRead() {
        if (activeServiceFff0 == null) return;
        if (activeServiceFff0.getCharacteristic(Bvm02Protocol.UUID_READ_VOLTAGE) == null) return;

        // Avoid stacking duplicate 0xFFF2 reads if one is already queued
        for (GattOp op : opQueue) {
            if (op.kind == OpKind.READ_CHAR && Bvm02Protocol.UUID_READ_VOLTAGE.equals(op.charUuid)) {
                return;
            }
        }
        enqueueOp(new GattOp(OpKind.READ_CHAR, Bvm02Protocol.UUID_READ_VOLTAGE, null, "Poll 0xFFF2 Voltage"));
    }

    private final Runnable pollVoltageRunnable = new Runnable() {
        @Override
        public void run() {
            if (activeGatt == null || activeServiceFff0 == null) return;
            enqueueVoltageRead();
            mainHandler.postDelayed(this, VOLTAGE_POLL_INTERVAL_MS);
        }
    };

    // ================= SERIALIZED GATT QUEUE ENGINE =================

    private final Runnable opWatchdogRunnable = new Runnable() {
        @Override
        public void run() {
            if (inflightOp != null) {
                gattErrorCount++;
                DiagLogger.log("GATT_WATCHDOG", "Timed out waiting for GATT callback on: " + inflightOp.label);
                inflightOp = null;
                pumpNextOp();
            }
        }
    };

    private void enqueueOp(GattOp op) {
        opQueue.add(op);
        if (inflightOp == null) {
            pumpNextOp();
        }
    }

    private void completeInflightOp() {
        mainHandler.removeCallbacks(opWatchdogRunnable);
        inflightOp = null;
        pumpNextOp();
    }

    private void pumpNextOp() {
        if (inflightOp != null || opQueue.isEmpty()) return;
        if (activeGatt == null || activeServiceFff0 == null) {
            opQueue.clear();
            return;
        }

        GattOp op = opQueue.remove(0);
        BluetoothGattCharacteristic ch = activeServiceFff0.getCharacteristic(op.charUuid);
        if (ch == null) {
            pumpNextOp();
            return;
        }

        inflightOp = op;
        boolean started = false;
        boolean expectsCallback = true;

        try {
            if (op.kind == OpKind.ENABLE_NOTIFY) {
                boolean notifySet = activeGatt.setCharacteristicNotification(ch, true);
                BluetoothGattDescriptor cccd = ch.getDescriptor(Bvm02Protocol.UUID_CCCD);
                if (cccd == null) {
                    List<BluetoothGattDescriptor> descs = ch.getDescriptors();
                    if (descs != null && descs.size() == 1) {
                        cccd = descs.get(0);
                    }
                }
                if (notifySet && cccd != null) {
                    int props = ch.getProperties();
                    byte[] val = ((props & BluetoothGattCharacteristic.PROPERTY_INDICATE) != 0
                            && (props & BluetoothGattCharacteristic.PROPERTY_NOTIFY) == 0)
                            ? BluetoothGattDescriptor.ENABLE_INDICATION_VALUE
                            : BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE;
                    cccd.setValue(val);
                    started = activeGatt.writeDescriptor(cccd);
                    DiagLogger.log("GATT_OP", op.label + " -> writeDescriptor=" + started);
                } else {
                    DiagLogger.log("GATT_OP", op.label + " -> setCharacteristicNotification=" + notifySet + " (no CCCD write needed)");
                    started = notifySet;
                    expectsCallback = false;
                }
            } else if (op.kind == OpKind.READ_CHAR) {
                started = activeGatt.readCharacteristic(ch);
            } else if (op.kind == OpKind.WRITE_CHAR) {
                int props = ch.getProperties();
                if ((props & BluetoothGattCharacteristic.PROPERTY_WRITE) != 0) {
                    ch.setWriteType(BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT);
                } else if ((props & BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE) != 0) {
                    ch.setWriteType(BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE);
                }
                ch.setValue(op.writePayload);
                started = activeGatt.writeCharacteristic(ch);
                DiagLogger.log("GATT_TX", op.label + " (" + op.writePayload.length + "B): "
                        + Bvm02Protocol.bytesToHex(op.writePayload) + " -> " + started);
            }
        } catch (Throwable t) {
            gattErrorCount++;
            DiagLogger.log("GATT_ERR", op.label + " threw: " + t.getMessage());
            started = false;
        }

        if (!started || !expectsCallback) {
            if (!started) gattErrorCount++;
            inflightOp = null;
            pumpNextOp();
        } else {
            mainHandler.removeCallbacks(opWatchdogRunnable);
            mainHandler.postDelayed(opWatchdogRunnable, GATT_OP_TIMEOUT_MS);
        }
    }

    // ================= DATA DISPATCH =================

    private void handleCharacteristicReadData(SensorConfig sensor, UUID uuid, byte[] data) {
        if (Bvm02Protocol.UUID_READ_VOLTAGE.equals(uuid)) {
            Bvm02Protocol.RealtimeReading reading = Bvm02Protocol.parseRealtimeVoltage(data);
            if (reading == null) {
                DiagLogger.log("GATT_READ", "0xFFF2 returned malformed payload: " + Bvm02Protocol.bytesToHex(data));
                return;
            }
            if (connState != ConnState.STREAMING) {
                updateConnState(ConnState.STREAMING, sensor, "Live: " + sensor.getDisplayName());
            }
            if (rxReadCount <= 3 || (rxReadCount % 20 == 0)) {
                DiagLogger.log("BVM02_VOLT", "0xFFF2 [" + reading.rawHex + "] -> "
                        + Bvm02Protocol.formatVolts(reading.centivolts)
                        + (reading.hasTemp ? (" temp=" + reading.tempCelsius + "C") : "")
                        + " hw24V=" + reading.hardwareIs24V);
            }
            boolean is24V = sensor.resolveIs24V(reading.hardwareIs24V);
            int soc = Bvm02Protocol.computeStateOfChargePercent(reading.centivolts, is24V);
            Bvm02Protocol.HealthStatus health = Bvm02Protocol.classifyVoltageStatus(reading.centivolts, is24V);

            DiagLogger.recordTelemetrySample(
                    sensor.mac,
                    sensor.getDisplayName(),
                    reading.centivolts,
                    soc,
                    reading.tempCelsius,
                    reading.hasTemp,
                    is24V
            );
            listener.onRealtimeVoltage(sensor, reading, is24V, soc, health);
        } else if (Bvm02Protocol.UUID_VERSION_INFO.equals(uuid)) {
            Bvm02Protocol.VersionInfo ver = Bvm02Protocol.parseVersionInfo(data);
            if (ver != null) {
                activeFwVersion = ver.firmwareVersion;
                activeHwVersion = ver.hardwareVersion;
                DiagLogger.log("BVM02_VER", "0xFFF1 [" + ver.rawHex + "] -> FW v"
                        + String.format(Locale.US, "%.2f", ver.firmwareVersion)
                        + ", HW rev " + ver.hardwareVersion);
                listener.onSensorMetadataUpdated(sensor, activeFwVersion, activeHwVersion, activeRemoteName);
            }
        } else if (Bvm02Protocol.UUID_DEVICE_NAME.equals(uuid)) {
            String remoteName = Bvm02Protocol.parseDeviceName(data);
            DiagLogger.log("BVM02_NAME", "0xFFF6 -> '" + remoteName + "'");
            if (!remoteName.isEmpty()) {
                activeRemoteName = remoteName;
                listener.onSensorMetadataUpdated(sensor, activeFwVersion, activeHwVersion, activeRemoteName);
            }
        }
    }

    private void handleCharacteristicNotification(SensorConfig sensor, UUID uuid, byte[] data) {
        DiagLogger.log("GATT_NOTIFY", shortUuid(uuid) + " (" + data.length + "B): " + Bvm02Protocol.bytesToHex(data));
        if (!Bvm02Protocol.UUID_CMD_NOTIFY.equals(uuid)) return;

        List<Bvm02Protocol.DecodedFrame> frames = rxAssembler.feed(data);
        for (Bvm02Protocol.DecodedFrame f : frames) {
            DiagLogger.log("BVM02_RX", String.format(Locale.US,
                    "Frame cmd=0x%02X payloadLen=%d crcOk=%s raw=[%s]",
                    f.cmd, f.payload.length, f.checksumValid, f.rawHex));
            if (f.cmd == Bvm02Protocol.CMD_VERIFY_PASSWORD && f.payload.length >= 1) {
                boolean accepted = (f.payload[0] == 1);
                DiagLogger.log("BVM02_AUTH", "PIN verification result: " + (accepted ? "ACCEPTED" : "REJECTED"));
                listener.onPasswordResult(sensor, accepted);
            } else if (f.cmd == Bvm02Protocol.CMD_SET_PASSWORD && f.payload.length >= 1) {
                DiagLogger.log("BVM02_AUTH", "PIN update response byte=" + (f.payload[0] & 0xFF));
            } else if (f.cmd == Bvm02Protocol.CMD_ASYNC_EVENT && f.payload.length >= 1) {
                int ev = f.payload[0] & 0xFF;
                DiagLogger.log("BVM02_EVENT", "Async peripheral notification event=" + ev
                        + (ev == 1 ? " (new cranking event recorded)" : (ev == 2 ? " (new history ready)" : "")));
            }
        }
    }

    private void updateConnState(ConnState st, SensorConfig sensor, String message) {
        this.connState = st;
        listener.onConnectionStateChanged(st, sensor, message);
    }

    // ================= FORMATTING HELPERS =================

    private static byte[] copyBytes(byte[] src) {
        if (src == null || src.length == 0) return new byte[0];
        byte[] out = new byte[src.length];
        System.arraycopy(src, 0, out, 0, src.length);
        return out;
    }

    private static String buildAdvPreview(byte[] rec) {
        if (rec == null || rec.length == 0) return "";
        int end = rec.length;
        while (end > 0 && rec[end - 1] == 0) {
            end--;
        }
        int cap = Math.min(end, 18);
        if (cap <= 0) return "";
        byte[] slice = new byte[cap];
        System.arraycopy(rec, 0, slice, 0, cap);
        return Bvm02Protocol.bytesToHex(slice) + (end > cap ? " ..." : "");
    }

    private static String shortUuid(UUID u) {
        if (u == null) return "null";
        String s = u.toString().toLowerCase(Locale.US);
        if (s.startsWith("0000") && s.endsWith("-0000-1000-8000-00805f9b34fb") && s.length() == 36) {
            return "0x" + s.substring(4, 8).toUpperCase(Locale.US);
        }
        return s;
    }

    private static String adapterStateStr(int s) {
        switch (s) {
            case BluetoothAdapter.STATE_OFF: return "OFF";
            case BluetoothAdapter.STATE_TURNING_ON: return "TURNING_ON";
            case BluetoothAdapter.STATE_ON: return "ON";
            case BluetoothAdapter.STATE_TURNING_OFF: return "TURNING_OFF";
            default: return "UNKNOWN(" + s + ")";
        }
    }

    private static String profileStateStr(int s) {
        switch (s) {
            case BluetoothProfile.STATE_DISCONNECTED: return "DISCONNECTED";
            case BluetoothProfile.STATE_CONNECTING: return "CONNECTING";
            case BluetoothProfile.STATE_CONNECTED: return "CONNECTED";
            case BluetoothProfile.STATE_DISCONNECTING: return "DISCONNECTING";
            default: return String.valueOf(s);
        }
    }

    private static String gattConnStateStr(int s) {
        switch (s) {
            case BluetoothProfile.STATE_DISCONNECTED: return "STATE_DISCONNECTED";
            case BluetoothProfile.STATE_CONNECTING: return "STATE_CONNECTING";
            case BluetoothProfile.STATE_CONNECTED: return "STATE_CONNECTED";
            case BluetoothProfile.STATE_DISCONNECTING: return "STATE_DISCONNECTING";
            default: return "STATE_" + s;
        }
    }
}
