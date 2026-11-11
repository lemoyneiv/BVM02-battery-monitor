# Agent & Maintainer Engineering Guide (`bvm02-gen5w`)

This guide documents the hardware, operating system, Bluetooth LE, flash-wear, and packaging invariants required when maintaining **BVM02 Battery Monitor for Gen5W** (`bvm02.app`).

---

## 1. Target Hardware & OS Constraints (Hyundai/Kia/Genesis Gen5W)

1. **Android 4.4.2 KitKat (API Level 19) on Dalvik (`dex 035`):**
   * Gen5W head units (Telechips TCC803x SoC) run Android 4.4.2 on the legacy **Dalvik VM** — not ART.
   * `AndroidManifest.xml` must maintain `minSdkVersion="19"` and `targetSdkVersion="19"`.
   * Bytecode is compiled with `javac --release 8` against `platforms/android-19/android.jar` and lowered with R8 `--min-api 19` to produce `dex\n035\x00` single-DEX bytecode.
   * **Never reference classes or methods added in API 20+** (`tests/run_tests.py` disassembles `classes.dex` with `dexdump` and verifies every `android.*` / `java.*` class and method signature against API 19 `android.jar`).

2. **APK Signature Scheme v1 (JAR Signing) ONLY:**
   * Android 4.4 `PackageParser` only understands `META-INF/*.RSA` JAR signatures and can reject or misparse APK Signature Scheme v2/v3 signing blocks.
   * Always sign with:
     ```bash
     apksigner sign --v1-signing-enabled true --v2-signing-enabled false --v3-signing-enabled false
     ```

3. **24:9 Ultra-Widescreen Automotive Display (`1920x720`):**
   * Declare `<meta-data android:name="android.max_aspect" android:value="4.0" />` in `AndroidManifest.xml` so the system window manager never letterboxes the app to 16:9.
   * Keep primary navigation and status actions anchored in the **left driver-side sidebar** (`220dp` width) with large, glare-free dark-palette touch targets (`>= 38dp` height).

---

## 2. Gen5W Bluetooth LE (API 19 & Broadcom Stack) Invariants

1. **API 19 BLE Scanning + Dual-Mode Inquiry Fallback:**
   * Try `BluetoothAdapter.startLeScan(LeScanCallback)` first, and if Gen5W Broadcom firmware returns `false` (when `/system/framework/com.broadcom.bt.jar` replaces Bluedroid `IBluetoothGatt`), automatically fall back to `BluetoothAdapter.startDiscovery()` (`ACTION_FOUND` / `ACTION_NAME_CHANGED`) and sort `DEVICE_TYPE_LE` / `DEVICE_TYPE_DUAL` peripherals ahead of Classic BT devices.
   * Declare `<uses-library android:name="com.broadcom.bt" android:required="false" />` in `AndroidManifest.xml` so Dalvik links Gen5W's Broadcom Bluetooth shared library when present without blocking installation elsewhere.
   * Never reference `android.bluetooth.le.*` (`BluetoothLeScanner`, `ScanFilter`, `ScanSettings`), which were introduced in API 21.
   * Parse advertised device names (`0x08` / `0x09`) and `0xFFF0` service UUIDs directly from `byte[] scanRecord` (`Bvm02Protocol.parseAdvertisedName`), because `BluetoothDevice.getName()` is frequently `null` on KitKat BLE scan callbacks.

2. **Stop Scan & Cancel Discovery Before `connectGatt` & Use 3-Arg Overload:**
   * Always stop any active LE scan (`stopLeScan`) and cancel inquiry (`cancelDiscovery`) **before** initiating `BluetoothDevice.connectGatt(context, false, callback)` on the main thread. Concurrent scanning/inquiry + GATT connection setup is a primary trigger of Broadcom KitKat GATT `status=133` failures.
   * Never call the 4-argument `connectGatt(..., TRANSPORT_LE)` overload (API 23).

3. **Non-MTU Operation (20-Byte ATT Payload) & Serialized GATT Queue:**
   * `BluetoothGatt.requestMtu()` does not exist on API 19. All TX frames > 20 bytes must be split into 20-byte chunks (`Bvm02Protocol.splitIntoBleChunks`), and multi-chunk notifications on `0xFFF4` must be reassembled via `Bvm02Protocol.FrameAssembler`.
   * Android's `BluetoothGatt` drops concurrent requests silently (`readCharacteristic`, `writeCharacteristic`, `writeDescriptor` return `false` if another operation is in flight). All GATT operations must go through `BleClient`'s single-in-flight queue with watchdog recovery.

4. **Strict `gatt.close()` & Passive Classic BT Coexistence:**
   * Android 4.4 enforces a small system-wide pool of GATT `clientIf` registrations (~6–8). Every disconnect, timeout, or app exit **must** call `gatt.disconnect()` followed immediately by `gatt.close()`.
   * Never toggle the head unit's Bluetooth adapter off or interfere with bonded Classic Bluetooth profiles (`HFP` hands-free calling / `A2DP` audio). Only connect while the app is open in the foreground/active session.

---

## 3. Zero Internal eMMC Flash Wear Policy

* Automotive eMMC flash inside the head unit is soldered and non-replaceable.
* **Never write diagnostic logs, voltage CSV traces, or temporary files to `/data`, `getFilesDir()`, `getCacheDir()`, or SQLite.**
* `DiagLogger` maintains bounded ring buffers strictly in RAM (`4,500` log lines, `3,600` telemetry samples) and exports atomically (`.*.part` -> `renameTo`) **only** to an external USB drive (`<usb>/BVM02Logs/`) upon explicit user request.
* `SensorStore` writes `SharedPreferences` **strictly** when the user explicitly adds, edits, removes, or switches a saved sensor slot — never during live BLE polling.

---

## 4. Shell Scripts & HMG-API / NEMESIS Packaging

* All shell scripts under `mod/` (`open.sh`, `svc/screenshot.sh`, `svc/reboot.sh`) execute under Android 4.4 `mksh` + minimal Android `toolbox` (not GNU coreutils or busybox):
  * Shebang must be `#!/system/bin/sh` with LF line endings.
  * Never use `awk`, `sed`, `grep -q`, `head`, `tail`, `tr`, `cut`, `wc`, `find`, `sort`, `stat`, `timeout`, `seq`, `printf`, `dirname`, `basename`, `readlink`, `[[ ... ]]`, or arrays.
* `mod/mod.json` declares `"usb": ["BVM02Logs"]` so HMG-API pre-creates `<usb>/BVM02Logs` on USB insertion for unprivileged `media_rw` writes.

---

## 5. Terminology & Safety Guardrails

* **Neutral Projection Terminology:** Never mention `"Android Auto"` in UI strings, dialogs, layouts, or toasts (`tests/run_tests.py` enforces this automatically). Use neutral phrasing such as `"wireless projection"` if discussing radio coexistence.
* **Firmware Write Block:** Never write to GATT characteristic `0xFFF1` or transmit command `0xFF`.
* **Build & Verify Before Every Commit:**
  ```bash
  ./build.sh
  python3 tests/run_tests.py
  ```
