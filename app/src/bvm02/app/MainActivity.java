package bvm02.app;

import android.app.Activity;
import android.app.AlertDialog;
import android.bluetooth.BluetoothAdapter;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputFilter;
import android.text.InputType;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.BaseAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * Main 24:9 Widescreen Activity for BVM02 Battery Monitor on Gen5W (Android 4.4.2, API 19).
 *
 * Lifecycle policy:
 *  - Connects to the selected LNEX BVM02 sensor only while the app is open.
 *  - Cleanly disconnects and closes BluetoothGatt on Exit / onDestroy so Android 4.4's
 *    GATT clientIf slots and Classic Bluetooth (HFP/A2DP) are never disturbed.
 *  - Zero automated writes to internal /data eMMC flash; logs & CSV telemetry remain in RAM
 *    until explicitly exported to USB (<usb>/BVM02Logs/).
 */
public class MainActivity extends Activity implements BleClient.Listener, DiagLogger.LogListener {

    private static final int TAB_MONITOR = 0;
    private static final int TAB_SCANNER = 1;
    private static final int TAB_DIAG    = 2;

    private final Handler uiHandler = new Handler(Looper.getMainLooper());
    private SensorStore sensorStore;
    private BleClient bleClient;

    // Sidebar views
    private View layoutLogoHeader;
    private TextView tvTitle;
    private TextView tvBleStatus;
    private Button btnQuickConnect;
    private Button btnTabMonitor;
    private Button btnTabScanner;
    private Button btnTabDiag;
    private Button btnExportLog;
    private Button btnExitApp;
    private View layoutDiagBar;
    private TextView tvDiagInfo;

    // Tab containers
    private View layoutModeMonitor;
    private View layoutModeScanner;
    private View layoutModeDiag;
    private int currentTab = TAB_MONITOR;

    // Live Monitor views
    private final Button[] slotButtons = new Button[SensorStore.MAX_SLOTS];
    private Button btnEditSensor;
    private Button btnToggleConn;
    private TextView tvSensorTitle;
    private TextView tvSensorMeta;
    private TextView tvVoltageValue;
    private TextView tvHealthBadge;
    private TextView tvSocValue;
    private ProgressBar pbSoc;
    private TextView tvTempValue;
    private TextView tvSystemMode;
    private TextView tvStatMinmax;
    private TextView tvStatUpdated;
    private TextView tvChartSubtitle;
    private Button btnClearGraph;
    private VoltageSparklineView viewSparkline;

    // BLE Scanner views
    private Button btnScanToggle;
    private Button btnScanFilter;
    private Button btnManualMac;
    private TextView tvScanSummary;
    private ListView lvScanDevices;
    private TextView tvScanEmpty;
    private ScanDeviceAdapter scanAdapter;
    private boolean filterBvm02Only = true;
    private List<BleClient.ScannedDevice> allScannedDevices = new ArrayList<BleClient.ScannedDevice>();

    // BT Diagnostics views
    private TextView tvBtHwSummary;
    private Button btnRefreshBtInfo;
    private Button btnDiagExport;
    private Button btnDiagClear;
    private ScrollView svDiagLog;
    private TextView tvDiagConsole;

    // Live session telemetry state (in-RAM)
    private int sessionMinCv = Integer.MAX_VALUE;
    private int sessionMaxCv = Integer.MIN_VALUE;
    private int sessionReadCount = 0;
    private boolean lastHardware24V = false;
    private float activeFwVersion = 0.0f;
    private int activeHwVersion = 0;
    private String activeRemoteName = "";
    private int pinAuthStatus = 0; // 0 = pending/unknown, 1 = accepted, -1 = rejected
    private boolean logRefreshScheduled = false;
    private boolean usbExportInProgress = false;
    private boolean btReceiverRegistered = false;

    private final BroadcastReceiver btStateReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (intent == null) return;
            if (BluetoothAdapter.ACTION_STATE_CHANGED.equals(intent.getAction())) {
                int state = intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR);
                DiagLogger.log("BT_STATE", "BluetoothAdapter state broadcast: " + state);
                refreshCompactBtStatus();
                if (currentTab == TAB_DIAG) {
                    refreshDiagnosticsPanel();
                }
                if (state == BluetoothAdapter.STATE_ON) {
                    SensorConfig active = sensorStore.getSlot(sensorStore.getActiveSlot());
                    if (active.isConfigured() && bleClient.getConnectionState() == BleClient.ConnState.DISCONNECTED) {
                        bleClient.connect(active);
                    }
                }
            }
        }
    };

    private final Runnable refreshDiagConsoleRunnable = new Runnable() {
        @Override
        public void run() {
            logRefreshScheduled = false;
            if (isFinishing()) return;
            if (currentTab == TAB_DIAG && tvDiagConsole != null) {
                tvDiagConsole.setText(DiagLogger.snapshotText(400));
                if (svDiagLog != null) {
                    svDiagLog.post(new Runnable() {
                        @Override
                        public void run() {
                            svDiagLog.fullScroll(View.FOCUS_DOWN);
                        }
                    });
                }
            }
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        setContentView(R.layout.activity_main);

        sensorStore = new SensorStore(this);
        bleClient = new BleClient(this, this);

        bindViews();
        wireListeners();

        DiagLogger.setListener(this);
        registerBtStateReceiver();

        refreshSlotButtons();
        refreshSelectedSensorHeader();
        refreshCompactBtStatus();
        refreshDiagnosticsPanel();
        switchTab(TAB_MONITOR);

        // Auto-connect to active saved sensor slot on launch if configured
        SensorConfig initialSensor = sensorStore.getSlot(sensorStore.getActiveSlot());
        if (initialSensor.isConfigured()) {
            if (bleClient.isAdapterAvailable() && bleClient.isAdapterEnabled()) {
                bleClient.connect(initialSensor);
            } else if (bleClient.isAdapterAvailable()) {
                tvBleStatus.setText("BLE: Bluetooth is OFF");
                tvBleStatus.setTextColor(colorRes(R.color.accent_red));
                promptEnableBluetooth(initialSensor);
            } else {
                tvBleStatus.setText("BLE: No Adapter");
                tvBleStatus.setTextColor(colorRes(R.color.accent_red));
            }
        } else {
            DiagLogger.log("UI", "No saved BVM02 sensor in Slot " + (sensorStore.getActiveSlot() + 1)
                    + ". Ready to scan or add by MAC.");
        }
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        refreshCompactBtStatus();
    }

    @Override
    protected void onDestroy() {
        DiagLogger.setListener(null);
        unregisterBtStateReceiver();
        uiHandler.removeCallbacksAndMessages(null);
        if (bleClient != null) {
            bleClient.shutdown();
        }
        super.onDestroy();
    }

    private void bindViews() {
        // Sidebar
        layoutLogoHeader = findViewById(R.id.layout_logo_header);
        tvTitle = (TextView) findViewById(R.id.tv_title);
        tvBleStatus = (TextView) findViewById(R.id.tv_ble_status);
        btnQuickConnect = (Button) findViewById(R.id.btn_quick_connect);
        btnTabMonitor = (Button) findViewById(R.id.btn_tab_monitor);
        btnTabScanner = (Button) findViewById(R.id.btn_tab_scanner);
        btnTabDiag = (Button) findViewById(R.id.btn_tab_diag);
        btnExportLog = (Button) findViewById(R.id.btn_export_log);
        btnExitApp = (Button) findViewById(R.id.btn_exit_app);
        layoutDiagBar = findViewById(R.id.layout_diag_bar);
        tvDiagInfo = (TextView) findViewById(R.id.tv_diag_info);

        // Modes
        layoutModeMonitor = findViewById(R.id.layout_mode_monitor);
        layoutModeScanner = findViewById(R.id.layout_mode_scanner);
        layoutModeDiag = findViewById(R.id.layout_mode_diag);

        // Live Monitor
        slotButtons[0] = (Button) findViewById(R.id.btn_slot_0);
        slotButtons[1] = (Button) findViewById(R.id.btn_slot_1);
        slotButtons[2] = (Button) findViewById(R.id.btn_slot_2);
        slotButtons[3] = (Button) findViewById(R.id.btn_slot_3);
        btnEditSensor = (Button) findViewById(R.id.btn_edit_sensor);
        btnToggleConn = (Button) findViewById(R.id.btn_toggle_conn);
        tvSensorTitle = (TextView) findViewById(R.id.tv_sensor_title);
        tvSensorMeta = (TextView) findViewById(R.id.tv_sensor_meta);
        tvVoltageValue = (TextView) findViewById(R.id.tv_voltage_value);
        tvHealthBadge = (TextView) findViewById(R.id.tv_health_badge);
        tvSocValue = (TextView) findViewById(R.id.tv_soc_value);
        pbSoc = (ProgressBar) findViewById(R.id.pb_soc);
        tvTempValue = (TextView) findViewById(R.id.tv_temp_value);
        tvSystemMode = (TextView) findViewById(R.id.tv_system_mode);
        tvStatMinmax = (TextView) findViewById(R.id.tv_stat_minmax);
        tvStatUpdated = (TextView) findViewById(R.id.tv_stat_updated);
        tvChartSubtitle = (TextView) findViewById(R.id.tv_chart_subtitle);
        btnClearGraph = (Button) findViewById(R.id.btn_clear_graph);
        viewSparkline = (VoltageSparklineView) findViewById(R.id.view_sparkline);

        // Scanner
        btnScanToggle = (Button) findViewById(R.id.btn_scan_toggle);
        btnScanFilter = (Button) findViewById(R.id.btn_scan_filter);
        btnManualMac = (Button) findViewById(R.id.btn_manual_mac);
        tvScanSummary = (TextView) findViewById(R.id.tv_scan_summary);
        lvScanDevices = (ListView) findViewById(R.id.lv_scan_devices);
        tvScanEmpty = (TextView) findViewById(R.id.tv_scan_empty);

        scanAdapter = new ScanDeviceAdapter();
        lvScanDevices.setAdapter(scanAdapter);

        // Diagnostics
        tvBtHwSummary = (TextView) findViewById(R.id.tv_bt_hw_summary);
        btnRefreshBtInfo = (Button) findViewById(R.id.btn_refresh_bt_info);
        btnDiagExport = (Button) findViewById(R.id.btn_diag_export);
        btnDiagClear = (Button) findViewById(R.id.btn_diag_clear);
        svDiagLog = (ScrollView) findViewById(R.id.sv_diag_log);
        tvDiagConsole = (TextView) findViewById(R.id.tv_diag_console);
    }

    private void wireListeners() {
        layoutLogoHeader.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ScreenshotHelper.captureToUsb(MainActivity.this, tvTitle);
            }
        });

        btnTabMonitor.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                switchTab(TAB_MONITOR);
            }
        });

        btnTabScanner.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                switchTab(TAB_SCANNER);
            }
        });

        btnTabDiag.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                switchTab(TAB_DIAG);
            }
        });

        layoutDiagBar.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                switchTab(TAB_DIAG);
            }
        });

        btnQuickConnect.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                SensorConfig active = sensorStore.getSlot(sensorStore.getActiveSlot());
                if (active.isConfigured()) {
                    switchTab(TAB_MONITOR);
                    connectWithBtCheck(active);
                } else {
                    switchTab(TAB_SCANNER);
                    startScanWithBtCheck();
                }
            }
        });

        btnExportLog.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                triggerUsbExport();
            }
        });

        btnExitApp.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                DiagLogger.log("APP", "User tapped Exit — disconnecting GATT cleanly.");
                bleClient.shutdown();
                finish();
            }
        });

        for (int i = 0; i < SensorStore.MAX_SLOTS; i++) {
            final int slotIdx = i;
            slotButtons[i].setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View v) {
                    onSlotButtonClicked(slotIdx);
                }
            });
            slotButtons[i].setOnLongClickListener(new View.OnLongClickListener() {
                @Override
                public boolean onLongClick(View v) {
                    sensorStore.setActiveSlot(slotIdx);
                    refreshSlotButtons();
                    refreshSelectedSensorHeader();
                    showSensorConfigDialog(slotIdx);
                    return true;
                }
            });
        }

        btnEditSensor.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                showSensorConfigDialog(sensorStore.getActiveSlot());
            }
        });

        btnToggleConn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                BleClient.ConnState st = bleClient.getConnectionState();
                if (st != BleClient.ConnState.DISCONNECTED) {
                    bleClient.disconnect();
                } else {
                    SensorConfig active = sensorStore.getSlot(sensorStore.getActiveSlot());
                    if (active.isConfigured()) {
                        connectWithBtCheck(active);
                    } else {
                        switchTab(TAB_SCANNER);
                        startScanWithBtCheck();
                    }
                }
            }
        });

        btnClearGraph.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                resetSessionTelemetryStats();
                Toast.makeText(MainActivity.this, "Cleared live session trace", Toast.LENGTH_SHORT).show();
            }
        });

        btnScanToggle.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (bleClient.isScanning()) {
                    bleClient.stopScan();
                } else {
                    startScanWithBtCheck();
                }
            }
        });

        btnScanFilter.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                filterBvm02Only = !filterBvm02Only;
                btnScanFilter.setText(filterBvm02Only ? "Filter: BVM02 Only" : "Filter: Show All BLE");
                btnScanFilter.setTextColor(colorRes(filterBvm02Only ? R.color.accent_cyan : R.color.accent_gold));
                rebuildFilteredScanList();
            }
        });

        btnManualMac.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                showManualMacDialog();
            }
        });

        lvScanDevices.setOnItemClickListener(new AdapterView.OnItemClickListener() {
            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                BleClient.ScannedDevice item = scanAdapter.getItem(position);
                if (item != null) {
                    bleClient.stopScan();
                    showAssignScannedDeviceDialog(item);
                }
            }
        });

        btnRefreshBtInfo.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                DiagLogger.log("BT_PROBE", "Manual BT stack probe:\n" + bleClient.buildHardwareSummary());
                refreshCompactBtStatus();
                refreshDiagnosticsPanel();
            }
        });

        btnDiagExport.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                triggerUsbExport();
            }
        });

        btnDiagClear.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                DiagLogger.clear();
                refreshDiagnosticsPanel();
            }
        });
    }

    // ================= NAVIGATION & UI UPDATES =================

    private void switchTab(int tab) {
        currentTab = tab;
        layoutModeMonitor.setVisibility(tab == TAB_MONITOR ? View.VISIBLE : View.GONE);
        layoutModeScanner.setVisibility(tab == TAB_SCANNER ? View.VISIBLE : View.GONE);
        layoutModeDiag.setVisibility(tab == TAB_DIAG ? View.VISIBLE : View.GONE);

        styleTabButton(btnTabMonitor, tab == TAB_MONITOR);
        styleTabButton(btnTabScanner, tab == TAB_SCANNER);
        styleTabButton(btnTabDiag, tab == TAB_DIAG);

        if (tab == TAB_DIAG) {
            refreshDiagnosticsPanel();
        }
    }

    private void styleTabButton(Button btn, boolean selected) {
        btn.setBackgroundColor(colorRes(selected ? R.color.accent_blue : R.color.bg_button));
        btn.setTypeface(null, selected ? Typeface.BOLD : Typeface.NORMAL);
    }

    private void onSlotButtonClicked(int slotIdx) {
        int prevSlot = sensorStore.getActiveSlot();
        SensorConfig cfg = sensorStore.getSlot(slotIdx);
        sensorStore.setActiveSlot(slotIdx);
        refreshSlotButtons();

        if (!cfg.isConfigured()) {
            bleClient.disconnect();
            resetSessionTelemetryStats();
            refreshSelectedSensorHeader();
            switchTab(TAB_SCANNER);
            startScanWithBtCheck();
            return;
        }

        if (slotIdx != prevSlot) {
            resetSessionTelemetryStats();
            refreshSelectedSensorHeader();
            connectWithBtCheck(cfg);
        } else if (bleClient.getConnectionState() == BleClient.ConnState.DISCONNECTED) {
            refreshSelectedSensorHeader();
            connectWithBtCheck(cfg);
        }
    }

    private void refreshSlotButtons() {
        int activeIdx = sensorStore.getActiveSlot();
        for (int i = 0; i < SensorStore.MAX_SLOTS; i++) {
            SensorConfig c = sensorStore.getSlot(i);
            String title = (i + 1) + ": " + c.getDisplayName();
            slotButtons[i].setText(title);
            boolean isSel = (i == activeIdx);
            if (isSel) {
                slotButtons[i].setBackgroundColor(colorRes(R.color.accent_blue));
                slotButtons[i].setTypeface(null, Typeface.BOLD);
                slotButtons[i].setTextColor(colorRes(R.color.text_primary));
            } else if (c.isConfigured()) {
                slotButtons[i].setBackgroundColor(0xFF233042);
                slotButtons[i].setTypeface(null, Typeface.NORMAL);
                slotButtons[i].setTextColor(colorRes(R.color.text_primary));
            } else {
                slotButtons[i].setBackgroundColor(colorRes(R.color.bg_button));
                slotButtons[i].setTypeface(null, Typeface.NORMAL);
                slotButtons[i].setTextColor(colorRes(R.color.text_secondary));
            }
        }
        updateToggleConnButton();
    }

    private void refreshSelectedSensorHeader() {
        SensorConfig cfg = sensorStore.getSlot(sensorStore.getActiveSlot());
        if (!cfg.isConfigured()) {
            tvSensorTitle.setText("Slot " + (cfg.slotIndex + 1) + ": No Sensor Configured");
            tvSensorMeta.setText("Open BLE Scanner or tap Add by MAC to pair an LNEX BVM02 monitor");
            tvSystemMode.setText("12V (Auto)");
            updateToggleConnButton();
            return;
        }

        tvSensorTitle.setText(cfg.getDisplayName());
        StringBuilder meta = new StringBuilder();
        meta.append("MAC: ").append(cfg.mac);
        if (activeFwVersion > 0.0f) {
            meta.append("  |  FW v").append(String.format(Locale.US, "%.2f", activeFwVersion));
            if (activeHwVersion > 0) {
                meta.append(" (HW ").append(activeHwVersion).append(')');
            }
        } else if (!cfg.advertisedName.isEmpty() && !cfg.advertisedName.equals(cfg.getDisplayName())) {
            meta.append("  |  BLE: ").append(cfg.advertisedName);
        }
        if (pinAuthStatus == 1) {
            meta.append("  |  PIN OK");
        } else if (pinAuthStatus == -1) {
            meta.append("  |  PIN REJECTED");
        }
        tvSensorMeta.setText(meta.toString());
        tvSystemMode.setText(cfg.getVoltageModeDescription(lastHardware24V));
        viewSparkline.setSystem24V(cfg.resolveIs24V(lastHardware24V));
        updateToggleConnButton();
    }

    private void updateToggleConnButton() {
        SensorConfig cfg = sensorStore.getSlot(sensorStore.getActiveSlot());
        BleClient.ConnState st = bleClient.getConnectionState();
        if (st != BleClient.ConnState.DISCONNECTED) {
            btnToggleConn.setText("Disconnect");
            btnToggleConn.setBackgroundColor(colorRes(R.color.accent_red));
        } else if (cfg.isConfigured()) {
            btnToggleConn.setText("Connect");
            btnToggleConn.setBackgroundColor(colorRes(R.color.accent_green));
        } else {
            btnToggleConn.setText("Scan BLE");
            btnToggleConn.setBackgroundColor(colorRes(R.color.accent_blue));
        }
    }

    private void resetSessionTelemetryStats() {
        sessionMinCv = Integer.MAX_VALUE;
        sessionMaxCv = Integer.MIN_VALUE;
        sessionReadCount = 0;
        lastHardware24V = false;
        activeFwVersion = 0.0f;
        activeHwVersion = 0;
        activeRemoteName = "";
        pinAuthStatus = 0;

        tvVoltageValue.setText("--.-- V");
        tvVoltageValue.setTextColor(colorRes(R.color.accent_green));
        tvHealthBadge.setText("STANDBY");
        tvHealthBadge.setTextColor(colorRes(R.color.text_secondary));
        tvHealthBadge.setBackgroundColor(0xFF252B36);
        tvSocValue.setText("-- %");
        pbSoc.setProgress(0);
        tvTempValue.setText("-- °C");
        tvStatMinmax.setText("-- / --");
        tvStatUpdated.setText("Waiting...");
        viewSparkline.clearSamples();
        tvChartSubtitle.setText("Polling UUID 0xFFF2 @ 1.5s  |  0 samples");
    }

    private void refreshCompactBtStatus() {
        boolean avail = bleClient.isAdapterAvailable();
        boolean enabled = bleClient.isAdapterEnabled();
        BleClient.ConnState st = bleClient.getConnectionState();
        if (!avail) {
            tvDiagInfo.setText("BT HW: Unavailable\nTap for Diagnostics");
        } else if (!enabled) {
            tvDiagInfo.setText("BT HW: OFF\nEnable Bluetooth to connect");
        } else {
            tvDiagInfo.setText("BT HW: ON (API 19 LE)\nGATT: " + st.name());
        }
    }

    private void refreshDiagnosticsPanel() {
        if (tvBtHwSummary != null) {
            tvBtHwSummary.setText(bleClient.buildHardwareSummary());
        }
        if (tvDiagConsole != null) {
            tvDiagConsole.setText(DiagLogger.snapshotText(400));
            if (svDiagLog != null) {
                svDiagLog.post(new Runnable() {
                    @Override
                    public void run() {
                        svDiagLog.fullScroll(View.FOCUS_DOWN);
                    }
                });
            }
        }
    }

    // ================= BLUETOOTH CHECK & USB EXPORT =================

    private void connectWithBtCheck(SensorConfig sensor) {
        if (!bleClient.isAdapterAvailable()) {
            Toast.makeText(this, "Bluetooth hardware unavailable on this unit", Toast.LENGTH_LONG).show();
            return;
        }
        if (!bleClient.isAdapterEnabled()) {
            promptEnableBluetooth(sensor);
            return;
        }
        bleClient.connect(sensor);
    }

    private void startScanWithBtCheck() {
        if (!bleClient.isAdapterAvailable()) {
            Toast.makeText(this, "Bluetooth hardware unavailable on this unit", Toast.LENGTH_LONG).show();
            return;
        }
        if (!bleClient.isAdapterEnabled()) {
            promptEnableBluetooth(null);
            return;
        }
        bleClient.startScan();
    }

    private void promptEnableBluetooth(final SensorConfig connectAfterEnable) {
        new AlertDialog.Builder(this, AlertDialog.THEME_HOLO_DARK)
                .setTitle("Enable Head Unit Bluetooth?")
                .setMessage("Bluetooth is currently turned off. Enable Bluetooth on the head unit to communicate with the LNEX BVM02 battery monitor?")
                .setPositiveButton("Enable Bluetooth", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        boolean ok = bleClient.requestEnableAdapter();
                        if (!ok) {
                            Toast.makeText(MainActivity.this,
                                    "Could not enable Bluetooth automatically — please enable Bluetooth in system settings.",
                                    Toast.LENGTH_LONG).show();
                        } else {
                            Toast.makeText(MainActivity.this,
                                    "Enabling Bluetooth...",
                                    Toast.LENGTH_SHORT).show();
                        }
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void triggerUsbExport() {
        if (usbExportInProgress) return;
        usbExportInProgress = true;
        final String hwHeader = bleClient.buildHardwareSummary();
        Toast.makeText(this, "Exporting logs & CSV to USB...", Toast.LENGTH_SHORT).show();

        new Thread(new Runnable() {
            @Override
            public void run() {
                final DiagLogger.ExportResult res = DiagLogger.exportToUsb(hwHeader);
                uiHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        usbExportInProgress = false;
                        if (isFinishing()) return;
                        if (res.error != null) {
                            Toast.makeText(MainActivity.this, res.error, Toast.LENGTH_LONG).show();
                        } else {
                            String msg = "Saved to USB BVM02Logs: "
                                    + (res.logFile != null ? res.logFile.getName() : "")
                                    + (res.csvFile != null ? (" + " + res.csvFile.getName()) : "");
                            Toast.makeText(MainActivity.this, msg, Toast.LENGTH_LONG).show();
                        }
                        if (currentTab == TAB_DIAG) {
                            refreshDiagnosticsPanel();
                        }
                    }
                });
            }
        }, "Bvm02UsbExport").start();
    }

    // ================= BleClient.Listener CALLBACKS =================

    @Override
    public void onScanStateChanged(boolean scanning, String summary) {
        if (isFinishing()) return;
        btnScanToggle.setText(scanning ? "Stop Scan" : "Start BLE Scan");
        btnScanToggle.setBackgroundColor(colorRes(scanning ? R.color.accent_red : R.color.accent_blue));
        tvScanSummary.setText(summary);
        refreshCompactBtStatus();
    }

    @Override
    public void onScanResultsUpdated(List<BleClient.ScannedDevice> devices) {
        if (isFinishing()) return;
        allScannedDevices = (devices != null) ? devices : new ArrayList<BleClient.ScannedDevice>();
        rebuildFilteredScanList();
    }

    private void rebuildFilteredScanList() {
        List<BleClient.ScannedDevice> visible = new ArrayList<BleClient.ScannedDevice>();
        int bvmMatches = 0;
        for (BleClient.ScannedDevice d : allScannedDevices) {
            if (d.bvm02Match) bvmMatches++;
            if (!filterBvm02Only || d.bvm02Match) {
                visible.add(d);
            }
        }
        scanAdapter.setItems(visible);

        int hiddenCount = allScannedDevices.size() - visible.size();
        if (visible.isEmpty()) {
            tvScanEmpty.setVisibility(View.VISIBLE);
            if (hiddenCount > 0) {
                tvScanEmpty.setText("0 BVM02 devices matched so far, but " + hiddenCount
                        + " other BLE peripheral(s) were detected (confirming Gen5W BLE RX works!). Tap 'Filter: BVM02 Only' above to inspect all peripherals.");
            } else {
                tvScanEmpty.setText("Note: BVM02 is a single-connection BLE peripheral. Disconnect any phone app from the BVM02 so it advertises on BLE.");
            }
        } else {
            tvScanEmpty.setVisibility(View.GONE);
        }

        if (bleClient.isScanning()) {
            tvScanSummary.setText("Scanning... " + bvmMatches + " BVM02 match(es), "
                    + allScannedDevices.size() + " total BLE peripheral(s) seen.");
        }
    }

    @Override
    public void onConnectionStateChanged(BleClient.ConnState state, SensorConfig sensor, String statusText) {
        if (isFinishing()) return;
        tvBleStatus.setText("BLE: " + statusText);
        switch (state) {
            case STREAMING:
                tvBleStatus.setTextColor(colorRes(R.color.accent_green));
                break;
            case CONNECTING:
            case DISCOVERING:
            case HANDSHAKING:
                tvBleStatus.setTextColor(colorRes(R.color.accent_cyan));
                break;
            case DISCONNECTED:
            default:
                tvBleStatus.setTextColor(colorRes(R.color.accent_gold));
                break;
        }
        updateToggleConnButton();
        refreshCompactBtStatus();
        if (currentTab == TAB_DIAG) {
            tvBtHwSummary.setText(bleClient.buildHardwareSummary());
        }
    }

    @Override
    public void onRealtimeVoltage(SensorConfig sensor, Bvm02Protocol.RealtimeReading reading,
                                  boolean resolvedIs24V, int socPercent, Bvm02Protocol.HealthStatus health) {
        if (isFinishing()) return;

        lastHardware24V = reading.hardwareIs24V;
        sessionReadCount++;
        if (reading.centivolts < sessionMinCv) sessionMinCv = reading.centivolts;
        if (reading.centivolts > sessionMaxCv) sessionMaxCv = reading.centivolts;

        tvVoltageValue.setText(Bvm02Protocol.formatVolts(reading.centivolts));
        applyHealthStyling(health);

        tvSocValue.setText(socPercent + " %");
        pbSoc.setProgress(socPercent);

        if (reading.hasTemp) {
            int tempF = Math.round(reading.tempCelsius * 1.8f + 32.0f);
            tvTempValue.setText(reading.tempCelsius + " °C (" + tempF + " °F)");
        } else {
            tvTempValue.setText("N/A");
        }

        tvSystemMode.setText(sensor.getVoltageModeDescription(reading.hardwareIs24V));
        tvStatMinmax.setText(String.format(Locale.US, "%.2fV / %.2fV",
                sessionMinCv / 100.0f, sessionMaxCv / 100.0f));

        String nowStr = new SimpleDateFormat("HH:mm:ss", Locale.US).format(new Date());
        tvStatUpdated.setText(nowStr + " (#" + sessionReadCount + ")");

        viewSparkline.addSample(reading.centivolts, resolvedIs24V);
        tvChartSubtitle.setText("Polling UUID 0xFFF2 @ 1.5s  |  "
                + viewSparkline.getSampleCount() + " trace pts ("
                + DiagLogger.getSampleCount() + " CSV rows)");

        if (currentTab == TAB_DIAG && (sessionReadCount % 5 == 0)) {
            tvBtHwSummary.setText(bleClient.buildHardwareSummary());
        }
    }

    private void applyHealthStyling(Bvm02Protocol.HealthStatus health) {
        tvHealthBadge.setText(health.label);
        switch (health) {
            case HEALTHY:
                tvVoltageValue.setTextColor(colorRes(R.color.accent_green));
                tvHealthBadge.setTextColor(colorRes(R.color.accent_green));
                tvHealthBadge.setBackgroundColor(0xFF193829);
                break;
            case CHARGING:
                tvVoltageValue.setTextColor(colorRes(R.color.accent_cyan));
                tvHealthBadge.setTextColor(colorRes(R.color.accent_cyan));
                tvHealthBadge.setBackgroundColor(0xFF163247);
                break;
            case MODERATE:
                tvVoltageValue.setTextColor(colorRes(R.color.accent_gold));
                tvHealthBadge.setTextColor(colorRes(R.color.accent_gold));
                tvHealthBadge.setBackgroundColor(0xFF3A2E16);
                break;
            case LOW:
            case CRITICAL:
            case OVER_VOLTAGE:
            default:
                tvVoltageValue.setTextColor(colorRes(R.color.accent_red));
                tvHealthBadge.setTextColor(colorRes(R.color.accent_red));
                tvHealthBadge.setBackgroundColor(0xFF3D1A1A);
                break;
        }
    }

    @Override
    public void onSensorMetadataUpdated(SensorConfig sensor, float fwVersion, int hwVersion, String remoteName) {
        if (isFinishing()) return;
        this.activeFwVersion = fwVersion;
        this.activeHwVersion = hwVersion;
        this.activeRemoteName = (remoteName != null) ? remoteName : "";

        // Persist discovered advertised name once if the saved slot didn't have one yet
        if (sensor != null && sensor.advertisedName.isEmpty() && !this.activeRemoteName.isEmpty()) {
            SensorConfig updated = new SensorConfig(
                    sensor.slotIndex,
                    sensor.mac,
                    sensor.label,
                    this.activeRemoteName,
                    sensor.pin,
                    sensor.voltageMode
            );
            sensorStore.saveSlot(updated);
            refreshSlotButtons();
        }
        refreshSelectedSensorHeader();
    }

    @Override
    public void onPasswordResult(SensorConfig sensor, boolean accepted) {
        if (isFinishing()) return;
        pinAuthStatus = accepted ? 1 : -1;
        refreshSelectedSensorHeader();
        if (!accepted) {
            Toast.makeText(this,
                    "Sensor rejected PIN '" + (sensor != null ? sensor.pin : "")
                            + "'. Tap Sensor Config to update PIN (or power-cycle BVM02 to reset to 0000).",
                    Toast.LENGTH_LONG).show();
        }
    }

    // ================= DiagLogger.LogListener =================

    @Override
    public void onLogUpdated() {
        uiHandler.post(new Runnable() {
            @Override
            public void run() {
                if (currentTab == TAB_DIAG && !logRefreshScheduled) {
                    logRefreshScheduled = true;
                    uiHandler.postDelayed(refreshDiagConsoleRunnable, 250L);
                }
            }
        });
    }

    // ================= DIALOGS (API 19 HOLO DARK) =================

    private void showAssignScannedDeviceDialog(final BleClient.ScannedDevice dev) {
        int existingSlot = sensorStore.findSlotByMac(dev.mac);
        int defaultSlot = existingSlot >= 0 ? existingSlot : sensorStore.getActiveSlot();
        if (existingSlot < 0 && sensorStore.getSlot(defaultSlot).isConfigured()) {
            int empty = sensorStore.findFirstEmptySlot();
            if (empty >= 0) defaultSlot = empty;
        }

        SensorConfig existingCfg = existingSlot >= 0 ? sensorStore.getSlot(existingSlot) : null;
        String initialLabel = existingCfg != null ? existingCfg.label : "";
        String initialPin = existingCfg != null ? existingCfg.pin : "0000";
        int initialMode = existingCfg != null ? existingCfg.voltageMode : SensorConfig.MODE_AUTO;

        LinearLayout root = buildDialogContainer();

        TextView info = new TextView(this);
        info.setText("Peripheral: " + (dev.name.isEmpty() ? "<Unnamed BLE>" : dev.name)
                + "\nMAC: " + dev.mac + "   |   RSSI: " + dev.rssi + " dBm");
        info.setTextColor(colorRes(R.color.accent_cyan));
        info.setTextSize(13f);
        root.addView(info);

        addDialogFieldLabel(root, "Save to Sensor Slot (1–4):");
        final Spinner spSlot = new Spinner(this);
        spSlot.setAdapter(buildSlotSpinnerAdapter());
        spSlot.setSelection(defaultSlot);
        root.addView(spSlot);

        addDialogFieldLabel(root, "Custom Display Label (optional, e.g. Starter 12V):");
        final EditText etLabel = new EditText(this);
        etLabel.setSingleLine(true);
        etLabel.setHint(dev.name.isEmpty() ? "Main Battery" : dev.name);
        etLabel.setText(initialLabel);
        root.addView(etLabel);

        addDialogFieldLabel(root, "4-Digit Sensor PIN (default 0000):");
        final EditText etPin = buildPinEditText(initialPin);
        root.addView(etPin);

        addDialogFieldLabel(root, "Battery System Voltage:");
        final Spinner spMode = new Spinner(this);
        spMode.setAdapter(buildVoltageModeSpinnerAdapter());
        spMode.setSelection(initialMode);
        root.addView(spMode);

        new AlertDialog.Builder(this, AlertDialog.THEME_HOLO_DARK)
                .setTitle("Pair & Connect BVM02 Sensor")
                .setView(root)
                .setPositiveButton("Save & Connect", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        int targetSlot = spSlot.getSelectedItemPosition();
                        String label = etLabel.getText().toString().trim();
                        String pin = etPin.getText().toString().trim();
                        if (!Bvm02Protocol.isValidPin(pin)) {
                            pin = "0000";
                        }
                        int vmode = spMode.getSelectedItemPosition();
                        SensorConfig saved = new SensorConfig(
                                targetSlot,
                                dev.mac,
                                label,
                                dev.name,
                                pin,
                                vmode
                        );
                        sensorStore.saveSlot(saved);
                        DiagLogger.log("CONFIG", "Saved sensor " + saved.mac + " to Slot " + (targetSlot + 1));

                        resetSessionTelemetryStats();
                        refreshSlotButtons();
                        refreshSelectedSensorHeader();
                        switchTab(TAB_MONITOR);
                        connectWithBtCheck(saved);
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void showManualMacDialog() {
        int defaultSlot = sensorStore.getActiveSlot();
        if (sensorStore.getSlot(defaultSlot).isConfigured()) {
            int empty = sensorStore.findFirstEmptySlot();
            if (empty >= 0) defaultSlot = empty;
        }

        LinearLayout root = buildDialogContainer();

        addDialogFieldLabel(root, "Bluetooth MAC Address (AA:BB:CC:DD:EE:FF):");
        final EditText etMac = new EditText(this);
        etMac.setSingleLine(true);
        etMac.setHint("AA:BB:CC:DD:EE:FF");
        etMac.setFilters(new InputFilter[]{new InputFilter.LengthFilter(17)});
        root.addView(etMac);

        addDialogFieldLabel(root, "Save to Sensor Slot (1–4):");
        final Spinner spSlot = new Spinner(this);
        spSlot.setAdapter(buildSlotSpinnerAdapter());
        spSlot.setSelection(defaultSlot);
        root.addView(spSlot);

        addDialogFieldLabel(root, "Custom Display Label:");
        final EditText etLabel = new EditText(this);
        etLabel.setSingleLine(true);
        etLabel.setHint("Starter Battery");
        root.addView(etLabel);

        addDialogFieldLabel(root, "4-Digit Sensor PIN (default 0000):");
        final EditText etPin = buildPinEditText("0000");
        root.addView(etPin);

        new AlertDialog.Builder(this, AlertDialog.THEME_HOLO_DARK)
                .setTitle("Add BVM02 Sensor by MAC")
                .setView(root)
                .setPositiveButton("Save & Connect", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        String mac = etMac.getText().toString().trim().toUpperCase(Locale.US);
                        if (!SensorConfig.isValidMacAddress(mac)) {
                            Toast.makeText(MainActivity.this,
                                    "Invalid MAC format — expected AA:BB:CC:DD:EE:FF",
                                    Toast.LENGTH_LONG).show();
                            return;
                        }
                        int slot = spSlot.getSelectedItemPosition();
                        String label = etLabel.getText().toString().trim();
                        String pin = etPin.getText().toString().trim();
                        if (!Bvm02Protocol.isValidPin(pin)) {
                            pin = "0000";
                        }
                        SensorConfig cfg = new SensorConfig(slot, mac, label, "BVM02", pin, SensorConfig.MODE_AUTO);
                        sensorStore.saveSlot(cfg);
                        DiagLogger.log("CONFIG", "Manually added MAC " + mac + " in Slot " + (slot + 1));

                        resetSessionTelemetryStats();
                        refreshSlotButtons();
                        refreshSelectedSensorHeader();
                        switchTab(TAB_MONITOR);
                        connectWithBtCheck(cfg);
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void showSensorConfigDialog(final int slotIndex) {
        final SensorConfig current = sensorStore.getSlot(slotIndex);
        if (!current.isConfigured()) {
            Toast.makeText(this,
                    "Slot " + (slotIndex + 1) + " is empty — select a device in BLE Scanner or Add by MAC.",
                    Toast.LENGTH_SHORT).show();
            switchTab(TAB_SCANNER);
            return;
        }

        LinearLayout root = buildDialogContainer();

        TextView tvMac = new TextView(this);
        tvMac.setText("Slot " + (slotIndex + 1) + "  |  MAC: " + current.mac
                + (!current.advertisedName.isEmpty() ? ("  (" + current.advertisedName + ")") : ""));
        tvMac.setTextColor(colorRes(R.color.accent_cyan));
        tvMac.setTextSize(13f);
        root.addView(tvMac);

        addDialogFieldLabel(root, "Custom Display Label:");
        final EditText etLabel = new EditText(this);
        etLabel.setSingleLine(true);
        etLabel.setHint(current.advertisedName.isEmpty() ? "Starter Battery" : current.advertisedName);
        etLabel.setText(current.label);
        root.addView(etLabel);

        addDialogFieldLabel(root, "4-Digit Sensor PIN (default 0000):");
        final EditText etPin = buildPinEditText(current.pin);
        root.addView(etPin);

        final boolean connectedToThisSlot =
                (bleClient.getConnectionState() == BleClient.ConnState.STREAMING)
                        && bleClient.getActiveSensor() != null
                        && current.mac.equalsIgnoreCase(bleClient.getActiveSensor().mac);

        final CheckBox cbPushPin = new CheckBox(this);
        cbPushPin.setText("Also program this new PIN onto connected BVM02 sensor (Cmd 0x35)");
        cbPushPin.setEnabled(connectedToThisSlot);
        cbPushPin.setTextSize(12f);
        root.addView(cbPushPin);

        addDialogFieldLabel(root, "Battery System Voltage:");
        final Spinner spMode = new Spinner(this);
        spMode.setAdapter(buildVoltageModeSpinnerAdapter());
        spMode.setSelection(current.voltageMode);
        root.addView(spMode);

        new AlertDialog.Builder(this, AlertDialog.THEME_HOLO_DARK)
                .setTitle("Configure Sensor Slot " + (slotIndex + 1))
                .setView(root)
                .setPositiveButton("Save", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        String newLabel = etLabel.getText().toString().trim();
                        String newPin = etPin.getText().toString().trim();
                        if (!Bvm02Protocol.isValidPin(newPin)) {
                            Toast.makeText(MainActivity.this,
                                    "PIN must be 4 digits (0000–9999)",
                                    Toast.LENGTH_LONG).show();
                            return;
                        }
                        int newMode = spMode.getSelectedItemPosition();
                        SensorConfig updated = new SensorConfig(
                                slotIndex,
                                current.mac,
                                newLabel,
                                current.advertisedName,
                                newPin,
                                newMode
                        );
                        sensorStore.saveSlot(updated);
                        refreshSlotButtons();
                        refreshSelectedSensorHeader();

                        if (connectedToThisSlot && cbPushPin.isChecked()) {
                            bleClient.sendSetPassword(newPin);
                            Toast.makeText(MainActivity.this,
                                    "Sent Cmd 0x35 PIN update to BVM02",
                                    Toast.LENGTH_SHORT).show();
                        } else if (!current.pin.equals(newPin)) {
                            connectWithBtCheck(updated);
                        }
                    }
                })
                .setNeutralButton("Remove Sensor", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        if (bleClient.getActiveSensor() != null
                                && current.mac.equalsIgnoreCase(bleClient.getActiveSensor().mac)) {
                            bleClient.disconnect();
                        }
                        sensorStore.clearSlot(slotIndex);
                        DiagLogger.log("CONFIG", "Removed sensor from Slot " + (slotIndex + 1));
                        resetSessionTelemetryStats();
                        refreshSlotButtons();
                        refreshSelectedSensorHeader();
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private LinearLayout buildDialogContainer() {
        float d = getResources().getDisplayMetrics().density;
        int padH = Math.round(18f * d);
        int padV = Math.round(10f * d);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(padH, padV, padH, padV);
        return layout;
    }

    private void addDialogFieldLabel(LinearLayout parent, String text) {
        float d = getResources().getDisplayMetrics().density;
        TextView tv = new TextView(this);
        tv.setText(text);
        tv.setTextColor(colorRes(R.color.text_secondary));
        tv.setTextSize(12f);
        tv.setPadding(0, Math.round(8f * d), 0, Math.round(2f * d));
        parent.addView(tv);
    }

    private EditText buildPinEditText(String initialPin) {
        EditText et = new EditText(this);
        et.setSingleLine(true);
        et.setInputType(InputType.TYPE_CLASS_NUMBER);
        et.setFilters(new InputFilter[]{new InputFilter.LengthFilter(4)});
        et.setText(Bvm02Protocol.isValidPin(initialPin) ? initialPin : "0000");
        return et;
    }

    private ArrayAdapter<String> buildSlotSpinnerAdapter() {
        List<String> items = new ArrayList<String>(SensorStore.MAX_SLOTS);
        for (int i = 0; i < SensorStore.MAX_SLOTS; i++) {
            SensorConfig c = sensorStore.getSlot(i);
            items.add("Slot " + (i + 1) + (c.isConfigured()
                    ? (" — " + c.getDisplayName() + " [" + c.mac + "]")
                    : " — (Empty)"));
        }
        ArrayAdapter<String> ad = new ArrayAdapter<String>(this, android.R.layout.simple_spinner_item, items);
        ad.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        return ad;
    }

    private ArrayAdapter<String> buildVoltageModeSpinnerAdapter() {
        String[] modes = {
            "Auto-detect from BVM02 (Recommended)",
            "Force 12V Lead-Acid Curve",
            "Force 24V Series Curve"
        };
        ArrayAdapter<String> ad = new ArrayAdapter<String>(this, android.R.layout.simple_spinner_item, modes);
        ad.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        return ad;
    }

    // ================= BLE SCANNER LIST ADAPTER =================

    private final class ScanDeviceAdapter extends BaseAdapter {
        private List<BleClient.ScannedDevice> items = new ArrayList<BleClient.ScannedDevice>();
        private final LayoutInflater inflater = LayoutInflater.from(MainActivity.this);

        void setItems(List<BleClient.ScannedDevice> next) {
            this.items = (next != null) ? next : new ArrayList<BleClient.ScannedDevice>();
            notifyDataSetChanged();
        }

        @Override
        public int getCount() {
            return items.size();
        }

        @Override
        public BleClient.ScannedDevice getItem(int position) {
            if (position < 0 || position >= items.size()) return null;
            return items.get(position);
        }

        @Override
        public long getItemId(int position) {
            return position;
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            View row = convertView;
            if (row == null) {
                row = inflater.inflate(R.layout.item_scan_device, parent, false);
            }
            BleClient.ScannedDevice d = getItem(position);
            if (d == null) return row;

            TextView tvName = (TextView) row.findViewById(R.id.tv_item_name);
            TextView tvBadge = (TextView) row.findViewById(R.id.tv_item_badge);
            TextView tvMacAdv = (TextView) row.findViewById(R.id.tv_item_mac_adv);
            TextView tvRssi = (TextView) row.findViewById(R.id.tv_item_rssi);
            TextView tvAction = (TextView) row.findViewById(R.id.tv_item_action_hint);

            tvName.setText(d.name.isEmpty() ? "<Unnamed BLE Peripheral>" : d.name);

            int savedSlot = sensorStore.findSlotByMac(d.mac);
            if (savedSlot >= 0) {
                tvBadge.setVisibility(View.VISIBLE);
                tvBadge.setText("SAVED SLOT " + (savedSlot + 1));
                tvBadge.setTextColor(colorRes(R.color.accent_cyan));
                tvBadge.setBackgroundColor(0xFF163247);
                tvAction.setText("Connect");
            } else if (d.bvm02Match) {
                tvBadge.setVisibility(View.VISIBLE);
                tvBadge.setText("BVM02 MATCH");
                tvBadge.setTextColor(colorRes(R.color.accent_green));
                tvBadge.setBackgroundColor(0xFF1C3B2B);
                tvAction.setText("Pair & Connect");
            } else {
                tvBadge.setVisibility(View.VISIBLE);
                tvBadge.setText("OTHER BLE");
                tvBadge.setTextColor(colorRes(R.color.text_secondary));
                tvBadge.setBackgroundColor(0xFF252B36);
                tvAction.setText("Select");
            }

            StringBuilder sub = new StringBuilder();
            sub.append("MAC: ").append(d.mac);
            if (d.hasServiceFff0) {
                sub.append("  |  UUID 0xFFF0");
            }
            if (!d.advHexPreview.isEmpty()) {
                sub.append("  |  Adv: ").append(d.advHexPreview);
            }
            tvMacAdv.setText(sub.toString());

            tvRssi.setText(d.rssi + " dBm");
            return row;
        }
    }

    // ================= BROADCAST & RESOURCE HELPERS =================

    private void registerBtStateReceiver() {
        if (btReceiverRegistered) return;
        try {
            registerReceiver(btStateReceiver, new IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED));
            btReceiverRegistered = true;
        } catch (Throwable ignored) {}
    }

    private void unregisterBtStateReceiver() {
        if (!btReceiverRegistered) return;
        try {
            unregisterReceiver(btStateReceiver);
        } catch (Throwable ignored) {}
        btReceiverRegistered = false;
    }

    @SuppressWarnings("deprecation")
    private int colorRes(int resId) {
        return getResources().getColor(resId);
    }
}
