# BVM02 Battery Monitor for Gen5W

An open-source Android application built natively for **Hyundai / Kia / Genesis Gen5W** widescreen infotainment head units (`Android 4.4.2 KitKat`, API 19) to monitor **LNEX BVM02** 12V/24V Bluetooth Low Energy (BLE) battery sensors directly on the car's 1920x720 display using the head unit's built-in Bluetooth hardware.

> **Safety & Non-Affiliation:** Operate this app **only while the vehicle is safely parked**. Independent open-source project; unaffiliated with Hyundai, Kia, Genesis, or LNEX. See [DISCLAIMER.md](DISCLAIMER.md).

---

## Why This Project Exists

The LNEX BVM02 battery monitor's original companion Android app (`BatterySense` / `com.storm.battery`) is no longer available on the Google Play Store — and even when sideloaded as an APK, it **cannot run on Gen5W head units** due to three post-KitKat API dependencies (`minSdkVersion 21+`, API 23 4-argument `connectGatt`, and hanging indefinitely when `requestMtu` is absent on Android 4.4).

**BVM02 Battery Monitor for Gen5W** implements the BVM02 GATT protocol (`Service 0xFFF0`) from scratch in lightweight, zero-bloat Java targeting **API 19 Dalvik (`dex 035`)** with a driver-oriented **24:9 widescreen interface**.

---

## Current Scope — `v0.1.6` Hardware Proof-of-Concept

* **24:9 Automotive Widescreen UI:** Left driver-side navigation sidebar, high-contrast dark theme, and large touch targets tailored for `1920x720` Gen5W screens.
* **Safe API 19 BLE Scanner, `system_server` Guard, Live `@bvm02_ble` Capability Inspector & Passive Broadcom `bplus` ELF32 X-Ray:**
  * Uses strictly standard public Android 4.4 API 19 BLE/GATT APIs (`startLeScan`, `connectGatt`), never invoking hidden `@hide` `IBluetoothManager` (`enableGatt`, `enableRadio`) or leftover `com.broadcom.bt.*` Binder calls that can fault `system_server` on Telechips `tcc.solution.bluetooth.mbox=1` firmware where `GattService` is manifest-disabled.
  * Automatically checks `getBluetoothGatt()` before scanning or connecting so unavailable firmware GATT services are reported cleanly with zero `system_server` impact.
  * Includes a strictly read-only HMG-API hook (`hooks.jar` / `bvm02.hook.BtHookEntry`) scoped solely to `com.android.bluetooth` (`@bvm02_ble` abstract UNIX socket) plus an on-demand **`BtStackProbe`** (`BT Diagnostics` -> `Probe BT Stack`) that inspects live Broadcom LMP/HCI LE feature bits (`LE Supported (Controller)`, HCI `0x2001..0x200E` command mask, `bt_hc_cbacks`, `btu_cb`) and dumps `bplus.default.so` HCI/BTU/BTM/GKI machine code via pure read-only I/O.
  * Supports **`Add by MAC`** (`AA:BB:CC:DD:EE:FF`) to directly connect to a known BVM02 address when `IBluetoothGatt` is available.
* **Live Battery Telemetry (`UUID 0xFFF2` @ 1.5s):**
  * Real-time terminal voltage (`0.01 V` precision), piecewise-linear **State-of-Charge (`0–100%`)**, sensor temperature (`°C / °F`), `12V / 24V` auto-detection or manual override, session `Min / Max`, and an allocation-free rolling voltage sparkline trace.
* **Up to 4 Saved Sensor Slots:** Switch between e.g. Starter 12V, Auxiliary Battery, Trailer, or Secondary vehicle batteries with per-slot custom labels and 4-digit PIN authentication (`0x36` verify / `0x35` update).
* **Clean Foreground-Only BLE Lifecycle:**
  * Connects **only while the app is open** and executes `gatt.disconnect()` + `gatt.close()` immediately on exit so Android 4.4's limited `clientIf` slots and Classic Bluetooth (`HFP` phone calls / `A2DP` audio) are never disturbed.
* **Zero Internal eMMC Flash Wear + USB Diagnostics & Screenshots:**
  * All GATT trace logs and CSV telemetry samples live strictly in a bounded **in-RAM ring buffer** (`DiagLogger`).
  * Export `.txt` BLE diagnostic logs and `.csv` voltage time-series to `<usb>/BVM02Logs/` on any FAT32/exFAT USB stick.
  * Tap the top-left **BVM02** header with a USB stick inserted to save a `1920x720` PNG screenshot to `<usb>/BVM02Logs/` (automatically correcting Telechips `BGRA` channel ordering).

### Roadmap (Phase 2 — Post On-Car BLE Verification)

All underlying command opcodes and payload layouts are already documented in [PROTOCOL.md](PROTOCOL.md):
* **Cranking / Starting System Test (`Cmd 0x03` & Async `0x20`):** High-speed starter voltage dip waveform capture & health grading.
* **Alternator Charging Test (`Cmd 0x04` / `0x05`):** Guided idle & 2,500 RPM regulation test (`13.30V–15.30V`).
* **On-Sensor History Sync & Trip Log (`Cmd 0x02` / `0x30`):** Multi-day historical voltage download when reconnecting after parking.

---

## Installation on Gen5W

Build artifacts are generated in `dist/` in four formats:

| Package Archive | Target Environment |
| :--- | :--- |
| `bvm02-gen5w-v0.1.6-hmgapi-usb.zip` | **HMG-API Auto-Installer:** Extract directly onto the root of a FAT32 USB flash drive (`HMGAPI/updates/bvm02-gen5w-v0.1.6.zip`) and insert into the vehicle's data USB port. |
| `bvm02-gen5w-v0.1.6.hmgapi.zip` | **HMG-API Mod Archive:** Direct `.hmgapi.zip` package signed with ECDSA P-256 (`META-HMGAPI/signature`). |
| `bvm02-gen5w-v0.1.6-nemesis-usb.zip` | **NEMESIS USB Sideload:** Extract onto a FAT32 USB drive (`nemesis/apps/...`) for NEMESIS Manager installation. |
| `bvm02-gen5w-v0.1.6-nemesis-package.zip` | **NEMESIS Store Repository Package.** |

### Manual ADB Install (Bench / Engineering Mode)

```bash
adb install -r build/Bvm02Monitor.apk
adb shell am start -n bvm02.app/.MainActivity
```

---

## Pairing & On-Car Testing Guide

1. **Disconnect Phone App First:** The LNEX BVM02 is a **single-connection** BLE peripheral. Force-close or disconnect any smartphone app connected to the BVM02 so the sensor resumes BLE advertising.
2. **Open `BLE Scanner` Tab:**
   * Tap **`Start BLE Scan`**. Discovered BVM02 sensors appear with a green **`BVM02 MATCH`** badge and live RSSI (`dBm`).
   * *Hardware PoC Tip:* Toggle **`Filter: BVM02 Only`** -> **`Filter: Show All BLE`** to see every BLE advertisement received by the head unit's Bluetooth chip.
3. **Save to Slot 1–4 & Connect:**
   * Tap your BVM02 sensor, choose a slot (`1–4`), enter an optional label (e.g., `Starter 12V`) and 4-digit PIN (factory default is **`0000`**; power-cycling the BVM02 resets its PIN to `0000`), and tap **`Save & Connect`**.
4. **Exporting On-Car BLE Logs to USB:**
   * Insert a FAT32/exFAT USB stick into the car's USB port and tap **`Export Log to USB`** in the left sidebar (or inside **`BT Diagnostics`**).
   * Retrieve `<usb>/BVM02Logs/bvm02_diag_YYYYMMDD_HHMMSS.txt` and `bvm02_voltage_YYYYMMDD_HHMMSS.csv`.

---

## Building & Running Automated Tests

Requires Linux/macOS with **Python 3.8+** and **Java 11+ (`javac`, `java`, `keytool`)**. The build script automatically bootstraps Android SDK Platform `android-19` and Build-Tools `30.0.3` into `../tools/android-sdk` if `ANDROID_HOME` is not set:

```bash
# Build APK + HMG-API & NEMESIS distribution packages
./build.sh

# Run full unit, DEX API-19 bytecode, v1 signature, zipalign, and mksh verification suite
python3 tests/run_tests.py
```

---

## Documentation

* [PROTOCOL.md](PROTOCOL.md) — Complete reverse-engineered LNEX BVM02 BLE GATT & binary frame specification.
* [AGENT_GUIDE.md](AGENT_GUIDE.md) — Gen5W API 19 Dalvik, BLE `startLeScan` / `connectGatt`, eMMC flash-wear, and `mksh` engineering invariants.
* [DISCLAIMER.md](DISCLAIMER.md) — Driver safety and legal non-affiliation notice.

## License

Licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)** — see [LICENSE](LICENSE).
