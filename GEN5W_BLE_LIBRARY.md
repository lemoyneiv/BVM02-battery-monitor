# Gen5W General-Purpose BLE Central & Scanner Library (`@gen5w_ble` / `gen5w.ble`)

Stock Hyundai / Kia / Genesis **Gen5W** infotainment firmware (`Android 4.4.2 KitKat`, API 19) ships with `GattService` disabled in `Bluetooth.apk` and `bplus.default.so` compiled with `BLE_INCLUDED=FALSE` — even though the on-board Broadcom Bluetooth 4.x controller supports full simultaneous **Classic BR/EDR (`HFP` + `A2DP`) and Bluetooth Low Energy (`LE`)**.

Starting in **`v0.3.0`**, the `com.android.bluetooth` HMG-API hook module (`hooks.jar` + `libbvm02_ble.so`) acts as a **multi-app, multi-device, general-purpose BLE GATT Central & Scanner daemon**, accompanied by a zero-dependency client JAR (`dist/gen5w-ble-client-v0.3.0.jar`).

---

## Key Capabilities

* **Zero App-Specific Assumptions on `@gen5w_ble`:**
  * Discovers **all** Primary Services (`0x2800`) and Characteristics (`0x2803`) across `0x0001..0xFFFF` (both 16-bit Bluetooth SIG UUIDs and custom 128-bit UUIDs such as Nordic UART `6e400001-...`, ELM327/OBD-II BLE dongles, TPMS sensors, relays, and environmental beacons).
  * Legacy `@bvm02_ble` remains 100% backwards-compatible (`Service 0xFFF0` default + `0xFFF1` read-only write guard).
* **Multi-App & Multi-Device Concurrency (Up to 4 Simultaneous BLE Connections):**
  * Multiple independent Gen5W apps or background services can open concurrent stream sessions to `@gen5w_ble` without preempting one another.
  * A single app can also hold up to 4 concurrent BLE connections (`MULTICONN 1`) using `@<MAC>` target prefixes.
  * Native `libbvm02_ble.so` tracks up to 8 concurrent LE connection handles in `my_data_ind`, intercepting LE ACL packets and zeroing LE credits in `Number_Of_Completed_Packets` (`0x13`) while forwarding 100% of Classic Bluetooth (`HFP` / `A2DP`) traffic untouched.
* **ATT MTU Negotiation (`23..517` Bytes), Outbound L2CAP Fragmentation & Long Reads:**
  * Defaults safely to `ATT_MTU = 23` unless requested (preserving compatibility with non-MTU sensors like LNEX BVM02).
  * `REQUEST_MTU <mtu>` negotiates larger ATT MTUs (`0x02` / `0x03`) up to `517` bytes.
  * Automatically fragments outbound L2CAP SDUs (`PB=0x00` start + `PB=0x01` continuation) across the controller's `HCI_LE_Read_Buffer_Size` packet limit (`27` bytes on Bluetooth 4.0 controllers) with credit-paced flow control.
  * `READ_BLOB <uuid> <offset>` (`0x0C` / `0x0D`) and `READ_LONG_CHAR <uuid>` read attributes longer than `MTU - 1` up to `512` bytes.

---

## Using the Standalone Java SDK (`gen5w-ble-client-v0.3.0.jar`)

Add `dist/gen5w-ble-client-v0.3.0.jar` to your API-19 Gen5W app's classpath (`gen5w.ble.Gen5wBleClient` + `gen5w.ble.Gen5wBleAdvRecord`):

```java
import gen5w.ble.Gen5wBleAdvRecord;
import gen5w.ble.Gen5wBleClient;
import java.util.Map;

Gen5wBleClient ble = new Gen5wBleClient(new Gen5wBleClient.SimpleListener() {
    @Override
    public void onSessionReady(String serverVersion) {
        ble.startScan();
    }

    @Override
    public void onAdvertisement(String mac, int addrType, int rssi, Gen5wBleAdvRecord adv) {
        if ("OBDII-BLE".equals(adv.localName) || adv.hasServiceUuid("fff0")) {
            ble.stopScan();
            ble.connectDevice(mac, addrType, "*");
        }
    }

    @Override
    public void onConnected(String mac, Map<String, Integer> charPropsByUuid) {
        ble.requestMtu(mac, 185);
        ble.enableNotifications(mac, "6e400003-b5a3-f393-e0a9-e50e24dcca9e");
    }

    @Override
    public void onCharacteristicChanged(String mac, String uuid, byte[] value) {
        // Handle incoming notification bytes
    }
});
ble.connectBridge();
```

---

## Raw Abstract UNIX Socket Protocol (`@gen5w_ble`)

Any language (Java `LocalSocket`, C, Python, or a helper CLI invoked from `mksh`) can connect to abstract UNIX domain socket `\0gen5w_ble` (permitted callers: `root` UID `0`, `system` UID `1000`, `bluetooth` UID `1002`, or any Android app UID `>= 10000`).

### One-Shot Queries
Send a single newline-terminated command and read lines until `END`:
* `PING` -> `OK PONG version=0.3.0 pid=... uid=... enabled=true`
* `BRIDGE_STATUS` -> native JNI hook & packet counters (`activeHandles=...`)
* `SESSIONS` -> active client session count, connected handles, negotiated MTUs, and LE ACL credits

### Full-Duplex `STREAM_SESSION` Commands
Send `STREAM_SESSION GENERIC\n` (waits for `OK STREAM_READY version=0.3.0`), then issue newline-terminated commands:

| Command | Description |
| :--- | :--- |
| `MULTICONN 1` | Prefix all connection-scoped events with `@<MAC> ` and allow multiple simultaneous connections in one session. |
| `SCAN_START` / `SCAN_STOP` | Shared active BLE scan (`ADV <mac> <addrType> <rssi> <adHex>`). |
| `CONNECT <mac> [addrType] [svcUuid\|*]` | Connect (`addrType`: `0`=Public, `1`=Random, `-1`=auto) and discover GATT services/characteristics (`*` = all services). |
| `[@<MAC>] REQUEST_MTU <23..517>` | Negotiate ATT MTU (`OP_OK REQUEST_MTU <effectiveMtu>`). |
| `[@<MAC>] SET_MAX_MTU <23..517>` | Configure server MTU advertised if peripheral initiates `ATT_EXCHANGE_MTU_REQ`. |
| `[@<MAC>] ENABLE_NOTIFY <uuid>` | Discover `0x2902` CCCD and enable notifications/indications (`CHAR_NOTIFY <uuid> <hex>`). |
| `[@<MAC>] DISABLE_NOTIFY <uuid>` | Write `0x0000` to `0x2902` CCCD and stop forwarding `CHAR_NOTIFY`. |
| `[@<MAC>] READ_CHAR <uuid>` | Standard `ATT_READ_REQ` (`0x0A`) read (`OP_OK READ_CHAR <uuid> <hex>`). |
| `[@<MAC>] READ_BLOB <uuid> <off>` | Offset read via `ATT_READ_BLOB_REQ` (`0x0C`). |
| `[@<MAC>] READ_LONG_CHAR <uuid>` | Multi-packet `0x0A` + `0x0C` read up to `512` bytes. |
| `[@<MAC>] WRITE_CHAR <uuid> <hex>` | Write up to `attMtu - 3` bytes (auto-fragmented across LE ACL buffers). |
| `[@<MAC>] WRITE_CHAR_NR <uuid> <hex>` | Write Without Response (`0x52`) up to `attMtu - 3` bytes. |
| `[@<MAC>] PROTECT_CHAR <uuid>` | Mark characteristic read-only for the lifetime of the connection. |
| `[@<MAC>] DISCONNECT` / `QUIT` | Cleanly terminate a specific BLE link (`HCI_Disconnect`) or close the session. |

### Limitations (By Design)
* **Unauthenticated / Just-Works GATT Only:** SMP LE Security Manager pairing (`LTK` bonding / encrypted characteristics such as BLE HID keyboards) is intentionally out of scope.
* **Central + Observer Roles Only:** GATT Server / Peripheral advertising roles are not exposed.
