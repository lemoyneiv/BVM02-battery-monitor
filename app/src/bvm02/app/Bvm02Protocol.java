package bvm02.app;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.UUID;

/**
 * Pure Java codec and battery state-of-charge calculator for the LNEX BVM02 Bluetooth LE
 * Battery Monitor (Service 0xFFF0), engineered for Android 4.4.2 (API 19, non-MTU 20-byte ATT).
 *
 * NOTE: Characteristic 0xFFF1 is strictly READ-ONLY in this client (firmware version query).
 * Firmware upgrade writes to 0xFFF1 / command 0xFF are intentionally omitted to prevent
 * accidental sensor bricking.
 */
public final class Bvm02Protocol {

    private static final Charset UTF8 = Charset.forName("UTF-8");

    public static final String UUID_SERVICE_STR       = "0000fff0-0000-1000-8000-00805f9b34fb";
    public static final String UUID_VERSION_INFO_STR  = "0000fff1-0000-1000-8000-00805f9b34fb";
    public static final String UUID_READ_VOLTAGE_STR  = "0000fff2-0000-1000-8000-00805f9b34fb";
    public static final String UUID_CMD_WRITE_STR     = "0000fff3-0000-1000-8000-00805f9b34fb";
    public static final String UUID_CMD_NOTIFY_STR    = "0000fff4-0000-1000-8000-00805f9b34fb";
    public static final String UUID_DEVICE_NAME_STR   = "0000fff6-0000-1000-8000-00805f9b34fb";
    public static final String UUID_CCCD_STR          = "00002902-0000-1000-8000-00805f9b34fb";

    public static final UUID UUID_SERVICE       = UUID.fromString(UUID_SERVICE_STR);
    public static final UUID UUID_VERSION_INFO  = UUID.fromString(UUID_VERSION_INFO_STR);
    public static final UUID UUID_READ_VOLTAGE  = UUID.fromString(UUID_READ_VOLTAGE_STR);
    public static final UUID UUID_CMD_WRITE     = UUID.fromString(UUID_CMD_WRITE_STR);
    public static final UUID UUID_CMD_NOTIFY    = UUID.fromString(UUID_CMD_NOTIFY_STR);
    public static final UUID UUID_DEVICE_NAME   = UUID.fromString(UUID_DEVICE_NAME_STR);
    public static final UUID UUID_CCCD          = UUID.fromString(UUID_CCCD_STR);

    public static final int BLE_ATT_DEFAULT_PAYLOAD = 20;

    // Frame markers
    public static final byte FRAME_HEADER = 0x0F;
    public static final byte FRAME_TAIL   = (byte) 0xFF;

    // BVM02 Command IDs (written to 0xFFF3, notified on 0xFFF4)
    public static final int CMD_SYNC_TIME        = 0x01;
    public static final int CMD_GET_HISTORY_V1   = 0x02;
    public static final int CMD_GET_CRANKING     = 0x03;
    public static final int CMD_START_CHARGE     = 0x04;
    public static final int CMD_GET_CHARGE_DATA  = 0x05;
    public static final int CMD_SET_REPLACE_DATE = 0x07;
    public static final int CMD_GET_REPLACE_DATE = 0x08;
    public static final int CMD_ASYNC_EVENT      = 0x20;
    public static final int CMD_GET_HISTORY_V2   = 0x30;
    public static final int CMD_CLEAR_HISTORY    = 0x31;
    public static final int CMD_RESTART          = 0x33;
    public static final int CMD_SET_PASSWORD     = 0x35;
    public static final int CMD_VERIFY_PASSWORD  = 0x36;

    // Known advertised BLE name prefixes/substrings for LNEX BVM02 family sensors
    private static final String[] KNOWN_NAME_TOKENS = {
        "bvm02",
        "bl-",
        "carcell",
        "batterysense",
        "batmonitor"
    };

    private Bvm02Protocol() {}

    // ================= DATA MODELS =================

    public static final class RealtimeReading {
        public final int centivolts;
        public final float volts;
        public final int tempCelsius;
        public final boolean hasTemp;
        public final boolean hardwareIs24V;
        public final String rawHex;

        public RealtimeReading(int centivolts, int tempCelsius, boolean hasTemp,
                               boolean hardwareIs24V, String rawHex) {
            this.centivolts = centivolts;
            this.volts = centivolts / 100.0f;
            this.tempCelsius = tempCelsius;
            this.hasTemp = hasTemp;
            this.hardwareIs24V = hardwareIs24V;
            this.rawHex = rawHex;
        }
    }

    public static final class VersionInfo {
        public final float firmwareVersion;
        public final int hardwareVersion;
        public final String rawHex;

        public VersionInfo(float firmwareVersion, int hardwareVersion, String rawHex) {
            this.firmwareVersion = firmwareVersion;
            this.hardwareVersion = hardwareVersion;
            this.rawHex = rawHex;
        }
    }

    public static final class DecodedFrame {
        public final int cmd;
        public final byte[] payload;
        public final boolean checksumValid;
        public final String rawHex;

        public DecodedFrame(int cmd, byte[] payload, boolean checksumValid, String rawHex) {
            this.cmd = cmd;
            this.payload = payload;
            this.checksumValid = checksumValid;
            this.rawHex = rawHex;
        }
    }

    public enum HealthStatus {
        OVER_VOLTAGE("OVER-VOLT"),
        CHARGING("CHARGING"),
        HEALTHY("HEALTHY"),
        MODERATE("MODERATE"),
        LOW("LOW BATTERY"),
        CRITICAL("CRITICAL");

        public final String label;

        HealthStatus(String label) {
            this.label = label;
        }
    }

    // ================= BINARY FRAME CODEC =================

    /**
     * Builds a framed BVM02 command packet:
     *   [0]       = 0x0F
     *   [1]       = payload.length + 3
     *   [2]       = cmd
     *   [3]       = 0x00
     *   [4..N-4]  = payload
     *   [N-3]     = (1 + sum(bytes[2..N-4])) & 0xFF
     *   [N-2..N-1]= 0xFF, 0xFF
     */
    public static byte[] buildFrame(int cmd, byte[] payload) {
        byte[] body = (payload != null) ? payload : new byte[0];
        int totalLen = body.length + 7;
        byte[] frame = new byte[totalLen];
        frame[0] = FRAME_HEADER;
        frame[1] = (byte) ((body.length + 3) & 0xFF);
        frame[2] = (byte) (cmd & 0xFF);
        frame[3] = 0x00;
        if (body.length > 0) {
            System.arraycopy(body, 0, frame, 4, body.length);
        }
        frame[totalLen - 3] = computeChecksum(frame, totalLen);
        frame[totalLen - 2] = FRAME_TAIL;
        frame[totalLen - 1] = FRAME_TAIL;
        return frame;
    }

    public static byte computeChecksum(byte[] frame, int totalLen) {
        int sum = 1;
        for (int i = 2; i <= totalLen - 4; i++) {
            sum = (sum + (frame[i] & 0xFF)) & 0xFF;
        }
        return (byte) (sum & 0xFF);
    }

    public static DecodedFrame decodeCompleteFrame(byte[] frame) {
        if (frame == null || frame.length < 7) return null;
        if (frame[0] != FRAME_HEADER) return null;
        int expectedTotal = (frame[1] & 0xFF) + 4;
        if (frame.length < expectedTotal) return null;

        int cmd = frame[2] & 0xFF;
        int payloadLen = expectedTotal - 7;
        byte[] payload = new byte[Math.max(0, payloadLen)];
        if (payloadLen > 0) {
            System.arraycopy(frame, 4, payload, 0, payloadLen);
        }
        byte expectedCrc = computeChecksum(frame, expectedTotal);
        boolean crcOk = (frame[expectedTotal - 3] == expectedCrc)
                && (frame[expectedTotal - 2] == FRAME_TAIL)
                && (frame[expectedTotal - 1] == FRAME_TAIL);
        return new DecodedFrame(cmd, payload, crcOk, bytesToHex(frame));
    }

    /**
     * Stateful reassembler for multi-chunk 20-byte BLE notifications on UUID 0xFFF4.
     * Essential on Android 4.4.2 (API 19), where GATT MTU negotiation (requestMtu) does not exist
     * and responses >20 bytes arrive across consecutive onCharacteristicChanged callbacks.
     */
    public static final class FrameAssembler {
        private byte[] buffer = new byte[0];
        private int expectedLength = 0;

        public synchronized void reset() {
            buffer = new byte[0];
            expectedLength = 0;
        }

        public synchronized List<DecodedFrame> feed(byte[] chunk) {
            List<DecodedFrame> out = new ArrayList<DecodedFrame>();
            if (chunk == null || chunk.length == 0) return out;

            if (expectedLength == 0) {
                // Scan for 0x0F frame start
                int startIdx = -1;
                for (int i = 0; i < chunk.length; i++) {
                    if (chunk[i] == FRAME_HEADER) {
                        startIdx = i;
                        break;
                    }
                }
                if (startIdx < 0 || startIdx + 1 >= chunk.length) {
                    return out;
                }
                int lenField = chunk[startIdx + 1] & 0xFF;
                int total = lenField + 4;
                if (total < 7 || total > 512) {
                    return out;
                }
                expectedLength = total;
                int copyLen = chunk.length - startIdx;
                buffer = new byte[copyLen];
                System.arraycopy(chunk, startIdx, buffer, 0, copyLen);
            } else {
                byte[] combined = new byte[buffer.length + chunk.length];
                System.arraycopy(buffer, 0, combined, 0, buffer.length);
                System.arraycopy(chunk, 0, combined, buffer.length, chunk.length);
                buffer = combined;
            }

            while (expectedLength > 0 && buffer.length >= expectedLength) {
                byte[] packet = new byte[expectedLength];
                System.arraycopy(buffer, 0, packet, 0, expectedLength);
                DecodedFrame decoded = decodeCompleteFrame(packet);
                if (decoded != null) {
                    out.add(decoded);
                }

                int remaining = buffer.length - expectedLength;
                if (remaining <= 0) {
                    reset();
                    break;
                }
                byte[] leftover = new byte[remaining];
                System.arraycopy(buffer, expectedLength, leftover, 0, remaining);
                reset();
                out.addAll(feed(leftover));
                break;
            }
            return out;
        }
    }

    /**
     * Splits outbound GATT writes into 20-byte chunks for API 19 default ATT MTU (23 bytes -> 20 payload).
     */
    public static List<byte[]> splitIntoBleChunks(byte[] data, int maxChunkSize) {
        List<byte[]> chunks = new ArrayList<byte[]>();
        if (data == null || data.length == 0) return chunks;
        int limit = (maxChunkSize > 0) ? maxChunkSize : BLE_ATT_DEFAULT_PAYLOAD;
        for (int offset = 0; offset < data.length; offset += limit) {
            int len = Math.min(limit, data.length - offset);
            byte[] part = new byte[len];
            System.arraycopy(data, offset, part, 0, len);
            chunks.add(part);
        }
        return chunks;
    }

    // ================= COMMAND BUILDERS =================

    /**
     * Command 0x01: Synchronize current clock to the BVM02 sensor.
     * In non-MTU mode (isMtu=false on API 19), local wall-clock Calendar fields are sent.
     */
    public static byte[] buildSyncTimeCmd(long epochMillis, boolean useGmt) {
        Calendar cal = useGmt
                ? Calendar.getInstance(TimeZone.getTimeZone("GMT"))
                : Calendar.getInstance();
        cal.setTimeInMillis(epochMillis);
        int year = cal.get(Calendar.YEAR);
        byte[] payload = new byte[9];
        payload[0] = (byte) cal.get(Calendar.SECOND);
        payload[1] = (byte) cal.get(Calendar.MINUTE);
        payload[2] = (byte) cal.get(Calendar.HOUR_OF_DAY);
        payload[3] = (byte) cal.get(Calendar.DAY_OF_MONTH);
        payload[4] = (byte) (cal.get(Calendar.MONTH) + 1);
        payload[5] = (byte) ((year / 256) & 0xFF);
        payload[6] = (byte) ((year % 256) & 0xFF);
        payload[7] = 0x00;
        payload[8] = 0x00;
        return buildFrame(CMD_SYNC_TIME, payload);
    }

    /**
     * Command 0x36: Verify 4-digit numeric PIN (default "0000").
     * Each digit '0'..'9' is encoded as byte value 0..9.
     */
    public static byte[] buildVerifyPasswordCmd(String pin4) {
        return buildFrame(CMD_VERIFY_PASSWORD, encodePinDigits(pin4));
    }

    /**
     * Command 0x35: Update 4-digit numeric PIN on the BVM02 sensor.
     */
    public static byte[] buildSetPasswordCmd(String pin4) {
        return buildFrame(CMD_SET_PASSWORD, encodePinDigits(pin4));
    }

    public static boolean isValidPin(String pin) {
        if (pin == null || pin.length() != 4) return false;
        for (int i = 0; i < 4; i++) {
            char c = pin.charAt(i);
            if (c < '0' || c > '9') return false;
        }
        return true;
    }

    private static byte[] encodePinDigits(String pin4) {
        if (!isValidPin(pin4)) {
            throw new IllegalArgumentException("PIN must be exactly 4 digits (0000-9999)");
        }
        byte[] digits = new byte[4];
        for (int i = 0; i < 4; i++) {
            digits[i] = (byte) (pin4.charAt(i) - '0');
        }
        return digits;
    }

    // ================= CHARACTERISTIC PARSERS =================

    /**
     * Parses characteristic 0xFFF2 (Real-Time Voltage, Temperature & 12V/24V flag):
     *   bytes[0..1] = uint16 big-endian centivolts (e.g. 1264 -> 12.64V)
     *   byte[2]     = signed int8 temperature in Celsius (0x80 = no temp / invalid sentinel)
     *   byte[3]     = hardware 24V indicator (0 = 12V, non-zero = 24V)
     */
    public static RealtimeReading parseRealtimeVoltage(byte[] data) {
        if (data == null || data.length < 2) return null;
        int centivolts = ((data[0] & 0xFF) << 8) | (data[1] & 0xFF);
        boolean hasTemp = false;
        int tempC = 0;
        boolean hw24V = false;
        if (data.length > 2) {
            int rawTemp = data[2] & 0xFF;
            if (rawTemp != 0x80) {
                hasTemp = true;
                tempC = (int) data[2]; // signed int8 (-127..+127 C)
            }
        }
        if (data.length > 3) {
            hw24V = (data[3] != 0);
        }
        return new RealtimeReading(centivolts, tempC, hasTemp, hw24V, bytesToHex(data));
    }

    /**
     * Parses characteristic 0xFFF1 (Firmware & Hardware version read):
     *   bytes[11..12] = firmware major.minor (((b11 & 0xFF) * 100 + (b12 & 0xFF)) / 100f)
     *   byte[13]      = hardware version integer
     */
    public static VersionInfo parseVersionInfo(byte[] data) {
        if (data == null || data.length == 0) return null;
        String hex = bytesToHex(data);
        if (data.length >= 14) {
            int major = data[11] & 0xFF;
            int minor = data[12] & 0xFF;
            float fw = (major * 100 + minor) / 100.0f;
            int hw = data[13] & 0xFF;
            return new VersionInfo(fw, hw, hex);
        }
        return new VersionInfo(0.0f, 0, hex);
    }

    /**
     * Parses characteristic 0xFFF6 (UTF-8 device name).
     */
    public static String parseDeviceName(byte[] data) {
        if (data == null || data.length == 0) return "";
        int end = data.length;
        while (end > 0 && (data[end - 1] == 0 || data[end - 1] == (byte) 0xFF)) {
            end--;
        }
        if (end <= 0) return "";
        return new String(data, 0, end, UTF8).trim();
    }

    // ================= BLE SCAN RECORD PARSERS (API 19) =================

    /**
     * Extracts Complete Local Name (0x09) or Shortened Local Name (0x08) from raw 31/62-byte
     * BLE advertisement scanRecord. Crucial on Android 4.4.2 where BluetoothDevice.getName()
     * is frequently null on initial LeScanCallback invocations.
     */
    public static String parseAdvertisedName(byte[] scanRecord) {
        if (scanRecord == null || scanRecord.length == 0) return null;
        String shortName = null;
        int i = 0;
        while (i < scanRecord.length) {
            int len = scanRecord[i] & 0xFF;
            if (len == 0) break;
            if (i + len >= scanRecord.length) break;
            int type = scanRecord[i + 1] & 0xFF;
            int valueLen = len - 1;
            if (valueLen > 0 && (type == 0x09 || type == 0x08)) {
                int actualLen = valueLen;
                while (actualLen > 0 && scanRecord[i + 2 + actualLen - 1] == 0) {
                    actualLen--;
                }
                if (actualLen > 0) {
                    String s = new String(scanRecord, i + 2, actualLen, UTF8).trim();
                    if (!s.isEmpty()) {
                        if (type == 0x09) return s;
                        shortName = s;
                    }
                }
            }
            i += len + 1;
        }
        return shortName;
    }

    /**
     * Checks whether the raw BLE advertisement includes Service UUID 0xFFF0
     * (in 16-bit UUID lists 0x02/0x03, 16-bit Service Data 0x16, or 128-bit UUID lists 0x06/0x07).
     */
    public static boolean hasAdvertisedServiceFff0(byte[] scanRecord) {
        if (scanRecord == null || scanRecord.length == 0) return false;
        int i = 0;
        while (i < scanRecord.length) {
            int len = scanRecord[i] & 0xFF;
            if (len == 0 || i + len >= scanRecord.length) break;
            int type = scanRecord[i + 1] & 0xFF;
            int valStart = i + 2;
            int valLen = len - 1;

            if (type == 0x02 || type == 0x03) {
                for (int off = 0; off + 1 < valLen; off += 2) {
                    int uuid16 = (scanRecord[valStart + off] & 0xFF)
                            | ((scanRecord[valStart + off + 1] & 0xFF) << 8);
                    if (uuid16 == 0xFFF0) return true;
                }
            } else if (type == 0x16 && valLen >= 2) {
                int uuid16 = (scanRecord[valStart] & 0xFF)
                        | ((scanRecord[valStart + 1] & 0xFF) << 8);
                if (uuid16 == 0xFFF0) return true;
            } else if (type == 0x06 || type == 0x07) {
                // 128-bit little-endian Bluetooth Base UUID: fb 34 9b 5f 80 00 00 80 00 10 00 00 f0 ff 00 00
                for (int off = 0; off + 15 < valLen; off += 16) {
                    int b12 = scanRecord[valStart + off + 12] & 0xFF;
                    int b13 = scanRecord[valStart + off + 13] & 0xFF;
                    if (b12 == 0xF0 && b13 == 0xFF) return true;
                }
            }
            i += len + 1;
        }
        return false;
    }

    /**
     * Returns true if the BLE device name or advertisement payload matches the LNEX BVM02 family.
     * Excludes Victron's unrelated "SmartBatterySense" peripheral (matching original app filter).
     */
    public static boolean isLikelyBvm02Device(String deviceName, byte[] scanRecord) {
        String effectiveName = deviceName;
        if (effectiveName == null || effectiveName.trim().isEmpty()) {
            effectiveName = parseAdvertisedName(scanRecord);
        }
        if (effectiveName != null) {
            String lower = effectiveName.trim().toLowerCase(Locale.US);
            if (lower.contains("smartbatterysense")) {
                return false;
            }
            for (String token : KNOWN_NAME_TOKENS) {
                if (lower.startsWith(token) || lower.contains(token)) {
                    return true;
                }
            }
        }
        return hasAdvertisedServiceFff0(scanRecord);
    }

    // ================= BATTERY STATE-OF-CHARGE & HEALTH MATH =================

    /**
     * Exact piecewise-linear State-of-Charge (0..100%) curve from BVM02's DeviceUtil.getElectricity().
     *
     * 12V breakpoints (centivolts):
     *   <= 1050 (10.50V) ->   0%
     *   1050 .. 1130     ->   0% ..  10%
     *   1130 .. 1160     ->  10% ..  20%
     *   1160 .. 1190     ->  20% ..  40%
     *   1190 .. 1210     ->  40% ..  50%
     *   1210 .. 1220     ->  50% ..  60%
     *   1220 .. 1230     ->  60% ..  70%
     *   1230 .. 1240     ->  70% ..  80%
     *   1240 .. 1250     ->  80% ..  90%
     *   1250 .. 1270     ->  90% .. 100%
     *   >  1270 (12.70V) -> 100%
     *
     * 24V mode uses exact 2x voltage breakpoints (2100..2540 centivolts).
     */
    public static int computeStateOfChargePercent(int centivolts, boolean is24V) {
        int scale = is24V ? 2 : 1;
        int[] v = {
            1050 * scale,
            1130 * scale,
            1160 * scale,
            1190 * scale,
            1210 * scale,
            1220 * scale,
            1230 * scale,
            1240 * scale,
            1250 * scale,
            1270 * scale
        };
        int[] soc = {0, 10, 20, 40, 50, 60, 70, 80, 90, 100};

        if (centivolts <= v[0]) return 0;
        if (centivolts >= v[v.length - 1]) return 100;

        for (int i = 0; i < v.length - 1; i++) {
            if (centivolts >= v[i] && centivolts <= v[i + 1]) {
                float frac = (float) (centivolts - v[i]) / (float) (v[i + 1] - v[i]);
                int pct = Math.round(soc[i] + frac * (soc[i + 1] - soc[i]));
                return Math.max(0, Math.min(100, pct));
            }
        }
        return 100;
    }

    public static HealthStatus classifyVoltageStatus(int centivolts, boolean is24V) {
        int scale = is24V ? 2 : 1;
        if (centivolts > 1530 * scale) {
            return HealthStatus.OVER_VOLTAGE;
        }
        if (centivolts >= 1320 * scale) {
            return HealthStatus.CHARGING;
        }
        int soc = computeStateOfChargePercent(centivolts, is24V);
        if (soc >= 60) {
            return HealthStatus.HEALTHY;
        }
        if (soc >= 40) {
            return HealthStatus.MODERATE;
        }
        if (centivolts >= 1130 * scale) {
            return HealthStatus.LOW;
        }
        return HealthStatus.CRITICAL;
    }

    public static String formatVolts(int centivolts) {
        return String.format(Locale.US, "%.2f V", centivolts / 100.0f);
    }

    public static String bytesToHex(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return "";
        StringBuilder sb = new StringBuilder(bytes.length * 3);
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) sb.append(' ');
            int v = bytes[i] & 0xFF;
            char hi = Character.forDigit((v >>> 4) & 0x0F, 16);
            char lo = Character.forDigit(v & 0x0F, 16);
            sb.append(Character.toUpperCase(hi)).append(Character.toUpperCase(lo));
        }
        return sb.toString();
    }
}
