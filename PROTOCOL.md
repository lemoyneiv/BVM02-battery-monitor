# LNEX BVM02 Bluetooth LE Protocol Reference

This document specifies the Bluetooth Low Energy (BLE) GATT profile, binary framing, and telemetry algorithms used by the **LNEX BVM02** 12V/24V Wireless Battery Monitor, reverse-engineered from the discontinued vendor Android client (`com.storm.battery` / `BatterySense.apk`) and verified against the BVM02 user manual (`B09NTPWY9C.pdf`).

> **Firmware Upgrade Safety Rule:** Characteristic `0xFFF1` (when written) and Command `0xFF` trigger an unauthenticated OTA firmware bootloader mode on the sensor. **Never write to `0xFFF1` or send command `0xFF`** from `bvm02-gen5w` (`0xFFF1` is strictly read-only for querying the firmware/hardware version).

---

## 1. BLE Advertising & Discovery

* **Connection Topology:** Single-central BLE 4.x peripheral. While a phone app is actively connected to the BVM02, the sensor **stops advertising** and is invisible to other scanners. Disconnect or close any phone app so the sensor resumes advertising.
* **Known Advertised Local Names (AD Types `0x08` / `0x09`):**
  * `BVM02*`
  * `BL-*`
  * `CarCell*`
  * `BatterySense*` *(Note: explicitly exclude Victron's unrelated `SmartBatterySense`)*
  * `BatMonitor*`
* **Primary Advertised Service UUID:** `0xFFF0` (`0000fff0-0000-1000-8000-00805f9b34fb`), carried in AD Types `0x02`/`0x03` (16-bit Service UUIDs), `0x16` (Service Data), or `0x06`/`0x07` (128-bit UUIDs).
* **Android 4.4.2 (API 19) Quirk:** `BluetoothDevice.getName()` frequently returns `null` during initial `BluetoothAdapter.LeScanCallback.onLeScan()` callbacks. Always parse AD Types `0x09` (Complete Local Name) and `0x08` (Shortened Local Name) directly from the raw `byte[] scanRecord`.

---

## 2. Why the Vendor APK Fails on Gen5W (Android 4.4.2, API 19)

Reverse engineering `BatterySense.apk` revealed **three hard API > 19 blockers** that prevent the vendor app from running or completing a GATT handshake on Gen5W head units:

1. **API 23 `connectGatt` Signature:** `BLEDevice.connect()` invokes the 4-argument overload `BluetoothDevice.connectGatt(Context, boolean, BluetoothGattCallback, int transport)` (`BluetoothDevice.TRANSPORT_LE = 2`), added in Android 6.0 (API 23). On API 19 Dalvik, this throws `java.lang.NoSuchMethodError`.
   * **Gen5W Fix:** Always call the 3-argument API 18/19 overload `device.connectGatt(context, false, callback)` after stopping `stopLeScan()`.
2. **Silent Hang on Non-Existent `requestMtu`:** In the vendor app's `onServicesDiscovered()`, the app calls `setMTU(200)` and **only enables `0xFFF4` notifications inside `onMtuChanged()`**. On `Build.VERSION.SDK_INT < 21`, `setMTU()` returns `false` immediately without invoking `requestMtu()`, so `onMtuChanged()` never fires and the vendor app hangs indefinitely after service discovery.
   * **Gen5W Fix:** Operate strictly in **non-MTU mode** (default 23-byte ATT MTU = **20-byte payload**). Immediately enable `0xFFF4` notifications (`0x2902` CCCD), read `0xFFF1`/`0xFFF6`, send `0x01`/`0x36`, and poll `0xFFF2` directly from `onServicesDiscovered()`.
3. **API 21 `BluetoothLeAdvertiser` Lookup:** `BLEManager` calls `BluetoothAdapter.getBluetoothLeAdvertiser()` (API 21). Omitted completely in `bvm02-gen5w`.

---

## 3. GATT Service & Characteristics (`0xFFF0`)

| Short UUID | Full 128-Bit UUID | Properties | Direction & Purpose |
| :--- | :--- | :--- | :--- |
| **`0xFFF0`** | `0000fff0-0000-1000-8000-00805f9b34fb` | Primary Service | LNEX BVM02 Battery Monitor Service |
| **`0xFFF1`** | `0000fff1-0000-1000-8000-00805f9b34fb` | Read *(Write = OTA)* | **Read-Only** Firmware & Hardware Version (`bytes[11..13]`) |
| **`0xFFF2`** | `0000fff2-0000-1000-8000-00805f9b34fb` | Read | **Live Telemetry:** Real-time Voltage (`u16` BE), Temp (`i8` °C), 24V Flag |
| **`0xFFF3`** | `0000fff3-0000-1000-8000-00805f9b34fb` | Write / Write No Resp | **Command TX:** Binary framed requests (chunked <= 20 bytes on API 19) |
| **`0xFFF4`** | `0000fff4-0000-1000-8000-00805f9b34fb` | Notify (CCCD `0x2902`) | **Command RX:** Binary framed responses & async peripheral events |
| **`0xFFF6`** | `0000fff6-0000-1000-8000-00805f9b34fb` | Read | **Device Name:** UTF-8 string (null/`0xFF` padded) |

### Characteristic `0xFFF2` — Real-Time Voltage & Temperature (Read)

Polled every `1.5s` while `Live Monitor` is connected:

| Byte Offset | Type | Description |
| :--- | :--- | :--- |
| `0..1` | `uint16` Big-Endian | Battery voltage in **centivolts** (`0.01 V` units). Example: `0x04 0xF0` = `1264` -> `12.64 V`. |
| `2` | `int8` Signed | Sensor temperature in **°C** (`-40` to `+85`). Value `0x80` (`-128`) is the **no-temperature sentinel** (`hasTemp = false`). |
| `3` *(optional)* | `uint8` | Hardware system flag: `0x00` = 12V system, non-zero = 24V system. |

### Characteristic `0xFFF1` — Firmware & Hardware Version (Read-Only)

When read (`length >= 14` bytes):
* `firmwareVersion = ((data[11] & 0xFF) * 100 + (data[12] & 0xFF)) / 100.0f` (e.g., `0x02, 0x05` -> `v2.05`)
* `hardwareVersion = data[13] & 0xFF`

---

## 4. Binary Command Framing (`0xFFF3` TX / `0xFFF4` RX)

All commands written to `0xFFF3` and responses notified on `0xFFF4` share a 7-byte envelope around a variable-length `payload`:

```text
Offset:   [0]      [1]        [2]     [3]     [4 .. N-4]     [N-3]      [N-2]  [N-1]
Value:   0x0F   (P_LEN + 3)   CMD    DIR      PAYLOAD...    CHECKSUM    0xFF   0xFF
```

* **Direction Byte (`frame[3]`):** `0x00` on Host -> Peripheral (`0xFFF3` TX); `0x01` on Peripheral -> Host (`0xFFF4` RX).
* **Total Frame Length (`N`):** `(frame[1] & 0xFF) + 4` = `payload.length + 7`.
* **Checksum (`frame[N-3]`):**
  * **Host TX & Standard Peripheral RX (e.g. `0x20` async events):**
    ```java
    int sum = 1;
    for (int i = 2; i <= N - 4; i++) {
        sum = (sum + (frame[i] & 0xFF)) & 0xFF;
    }
    byte checksum = (byte) sum;
    ```
  * **Verified FW `v1.14` (`HW rev 2`) Peripheral Short-ACK Quirks (`frame[3] == 0x01`):**
    * `0x01` SyncTime ACK (`0F 04 01 01 00 02 FF FF`) computes `sum(bytes[2..N-4]) & 0xFF` (`0x02`) without adding an extra `+1` on top of `frame[3] = 0x01`.
    * `0x36` VerifyPIN ACK (`0F 04 36 01 01 37 FF FF`) populates `payload[0]` inside a static 8-byte ACK template whose checksum byte remains `(cmd + 1) & 0xFF` (`0x37`).
    * `Bvm02Protocol.isValidFrameChecksum()` accepts all three verified variants while still rejecting corrupted frames.
* **Unsolicited `0x180F` Notifications on FW `v1.14`:** Upon LE connection, FW `v1.14` emits unsolicited 10 Hz 1-byte notifications (`0x00`) on Battery Service (`0x180F`) value handle `0x0027` without a CCCD write. `@bvm02_ble` filters out notifications outside Service `0xFFF0` at the bridge to prevent unnecessary IPC wakeups.
* **20-Byte ATT Reassembly (API 19):** Responses exceeding 20 bytes (such as `0x02`, `0x03`, and `0x30`) arrive split across consecutive `onCharacteristicChanged()` callbacks on `0xFFF4`. Read `(chunk[1] & 0xFF) + 4` on the leading `0x0F` header and accumulate chunks until `N` bytes are received (`Bvm02Protocol.FrameAssembler`).

---

## 5. Command Reference (v0.1.0 PoC & Phase 2 Roadmap)

### Implemented in v0.1.0 (Live Monitor PoC)

* **`0x01` — Sync Clock (`CMD_SYNC_TIME`)**
  * **TX Payload (9 bytes, non-MTU local wall clock):** `[sec, min, hour24, dayOfMonth, month(1..12), year / 256, year % 256, 0x00, 0x00]`. *(Note: When MTU > 23 is negotiated on modern Android, the vendor app sends GMT fields with `payload[7..8]` reserved; in API 19 non-MTU mode it sends local wall-clock fields).*
* **`0x36` — Verify 4-Digit PIN (`CMD_VERIFY_PASSWORD`)**
  * **Default PIN:** `"0000"` (disconnecting the BVM02 from vehicle battery power resets its PIN to `"0000"`).
  * **TX Payload (4 bytes):** Each ASCII digit `'0'..'9'` encoded as numeric byte `0x00..0x09` (e.g., `"1234"` -> `[0x01, 0x02, 0x03, 0x04]`).
  * **RX Payload (`0x36`):** `payload[0] == 0x01` indicates PIN accepted; `0x00` indicates PIN rejected.
* **`0x35` — Set 4-Digit PIN (`CMD_SET_PASSWORD`)**
  * **TX Payload (4 bytes):** Numeric digits `0x00..0x09`.
* **`0x20` — Asynchronous Peripheral Event (`CMD_ASYNC_EVENT`)**
  * Unsolicited notification sent by the sensor on `0xFFF4`:
    * `payload[0] == 0x01`: New engine cranking waveform recorded (`0x03` ready).
    * `payload[0] == 0x02`: New historical sample page ready (`0x02` / `0x30`).

### Documented for Phase 2 Implementation (Cranking, Charging & History)

* **`0x03` — Read Cranking / Starting Waveform (`CMD_GET_CRANKING`)**
  * **TX Payload (2 bytes):** `[0x00, 0x00]`.
  * **RX Payload (non-MTU API 19 mode):**
    * `30` big-endian `uint16` centivolt samples (60 bytes) followed by a 7-byte timestamp (`[sec, min, hour, day, month, yearHi, yearLo]`). *(In negotiated MTU mode, 60 samples / 120 bytes are returned).*
    * **Cranking Health Thresholds (12V / 24V):**
      * Minimum cranking voltage `< 7.50 V` (`< 15.00 V` for 24V): **Low / Replace Check**
      * `7.50 V .. 9.59 V` (`15.00 V .. 19.19 V` for 24V): **Moderate**
      * `>= 9.60 V` (`>= 19.20 V` for 24V): **Normal Cranking**
* **`0x04` — Start Alternator Charging Test (`CMD_START_CHARGE`)**
  * **TX Payload (1 byte):** `[0x00]`.
  * **RX Payload (2 bytes):** Big-endian `uint16` centivolts. When `> 13.00 V` (`> 26.00 V` for 24V), prompts user to rev engine to 2,500 RPM and hold for 5 seconds before querying `0x05`.
* **`0x05` — Read Alternator Charging Test Result (`CMD_GET_CHARGE_DATA`)**
  * **TX Payload (1 byte):** `[0x00]`.
  * **RX Payload (4 bytes):**
    * `bytes[0..1]`: `idleSpeed` `uint16` BE centivolts
    * `bytes[2..3]`: `highSpeed` `uint16` BE centivolts
    * **Normal Alternator Regulation Window:** `13.30 V .. 15.30 V` (`26.60 V .. 30.60 V` for 24V). Below `13.30 V` = undercharging; above `15.30 V` = overcharging.
* **`0x02` — Read History v1 (`CMD_GET_HISTORY_V1`, FW < 2.0)**
  * **TX Payload (3 bytes):** `[daysAgo, hourIndex(0..23), 0x00]`.
  * **RX Payload (non-MTU):** 30 voltage samples (`2`-minute intervals per hour) starting at payload offset 2.
* **`0x30` — Read History v2 & Trip Log (`CMD_GET_HISTORY_V2`, FW >= 2.0 or `BatMonitor`)**
  * **TX Payload (3 bytes):** `[recordIndex / 256, recordIndex % 256, 0x00]`.
  * **RX Payload:** 4-byte GMT timestamp/index header followed by compact voltage samples (`0xFFFF` sentinel marks end of stored records; MSB `0x80` bit encodes engine-running / driving state for automatic trip start/stop segmentation).
* **`0x07` / `0x08` — Set / Get Battery Replacement Date**
* **`0x31` — Clear Stored Sensor History**
* **`0x33` — Soft-Restart Sensor**

---

## 6. Piecewise-Linear State-of-Charge (SoC) Curve

Matched to `DeviceUtil.getElectricity()` in `BatterySense.apk`:

| SoC (%) | 12V System Voltage | 24V System Voltage (`2x`) |
| :---: | :---: | :---: |
| **100%** | `>= 12.70 V` | `>= 25.40 V` |
| **90%** | `12.50 V` | `25.00 V` |
| **80%** | `12.40 V` | `24.80 V` |
| **70%** | `12.30 V` | `24.60 V` |
| **60%** | `12.20 V` | `24.40 V` |
| **50%** | `12.10 V` | `24.20 V` |
| **40%** | `11.90 V` | `23.80 V` |
| **20%** | `11.60 V` | `23.20 V` |
| **10%** | `11.30 V` | `22.60 V` |
| **0%** | `<= 10.50 V` | `<= 21.00 V` |

Intermediate voltages are linearly interpolated within their enclosing segment. Note that when the alternator is actively charging (`>= 13.20 V` / `>= 26.40 V`), surface voltage reads `100%` SoC and the health badge displays **`CHARGING`**.
