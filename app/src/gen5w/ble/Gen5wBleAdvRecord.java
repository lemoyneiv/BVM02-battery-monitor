package gen5w.ble;

import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * General-purpose Bluetooth Low Energy Advertising Data (AD) & Scan Response decoder
 * for Gen5W head units (Android 4.4.2 KitKat, API 19).
 *
 * Zero external or application-specific dependencies.
 */
public final class Gen5wBleAdvRecord {

    private static final Charset UTF8 = Charset.forName("UTF-8");

    public final byte[] rawBytes;
    public final int flags;
    public final String localName;
    public final Integer txPowerLevel;
    public final List<String> serviceUuids;
    public final Map<Integer, byte[]> manufacturerData;
    public final Map<String, byte[]> serviceData;

    private Gen5wBleAdvRecord(
            byte[] rawBytes,
            int flags,
            String localName,
            Integer txPowerLevel,
            List<String> serviceUuids,
            Map<Integer, byte[]> manufacturerData,
            Map<String, byte[]> serviceData) {
        this.rawBytes = (rawBytes != null) ? rawBytes.clone() : new byte[0];
        this.flags = flags;
        this.localName = localName;
        this.txPowerLevel = txPowerLevel;
        this.serviceUuids = Collections.unmodifiableList(serviceUuids);
        this.manufacturerData = Collections.unmodifiableMap(manufacturerData);
        this.serviceData = Collections.unmodifiableMap(serviceData);
    }

    public boolean hasServiceUuid(String uuid) {
        String key = normalizeUuid(uuid);
        return serviceUuids.contains(key);
    }

    public byte[] getManufacturerSpecificData(int companyId) {
        byte[] b = manufacturerData.get(Integer.valueOf(companyId & 0xFFFF));
        return (b != null) ? b.clone() : null;
    }

    public byte[] getServiceData(String uuid) {
        byte[] b = serviceData.get(normalizeUuid(uuid));
        return (b != null) ? b.clone() : null;
    }

    public static Gen5wBleAdvRecord parse(byte[] ad) {
        int flags = -1;
        String completeName = null;
        String shortName = null;
        Integer txPower = null;
        List<String> uuids = new ArrayList<String>();
        Map<Integer, byte[]> mfg = new LinkedHashMap<Integer, byte[]>();
        Map<String, byte[]> svcData = new LinkedHashMap<String, byte[]>();

        if (ad != null) {
            int pos = 0;
            while (pos < ad.length) {
                int len = ad[pos++] & 0xFF;
                if (len == 0 || pos + len > ad.length) break;
                int type = ad[pos] & 0xFF;
                int valOff = pos + 1;
                int valLen = len - 1;

                switch (type) {
                    case 0x01: // Flags
                        if (valLen >= 1) flags = ad[valOff] & 0xFF;
                        break;
                    case 0x02: // Incomplete 16-bit UUIDs
                    case 0x03: // Complete 16-bit UUIDs
                        for (int i = 0; i + 2 <= valLen; i += 2) {
                            addUnique(uuids, decodeUuid16Le(ad, valOff + i));
                        }
                        break;
                    case 0x06: // Incomplete 128-bit UUIDs
                    case 0x07: // Complete 128-bit UUIDs
                        for (int i = 0; i + 16 <= valLen; i += 16) {
                            addUnique(uuids, decodeUuid128Le(ad, valOff + i));
                        }
                        break;
                    case 0x08: // Shortened Local Name
                        if (valLen > 0) shortName = new String(ad, valOff, valLen, UTF8).trim();
                        break;
                    case 0x09: // Complete Local Name
                        if (valLen > 0) completeName = new String(ad, valOff, valLen, UTF8).trim();
                        break;
                    case 0x0A: // TX Power Level
                        if (valLen >= 1) txPower = Integer.valueOf((int) ad[valOff]);
                        break;
                    case 0x16: // Service Data - 16-bit UUID
                        if (valLen >= 2) {
                            String su = decodeUuid16Le(ad, valOff);
                            byte[] sd = new byte[valLen - 2];
                            if (sd.length > 0) System.arraycopy(ad, valOff + 2, sd, 0, sd.length);
                            svcData.put(su, sd);
                        }
                        break;
                    case 0x21: // Service Data - 128-bit UUID
                        if (valLen >= 16) {
                            String su = decodeUuid128Le(ad, valOff);
                            byte[] sd = new byte[valLen - 16];
                            if (sd.length > 0) System.arraycopy(ad, valOff + 16, sd, 0, sd.length);
                            svcData.put(su, sd);
                        }
                        break;
                    case 0xFF: // Manufacturer Specific Data
                        if (valLen >= 2) {
                            int companyId = (ad[valOff] & 0xFF) | ((ad[valOff + 1] & 0xFF) << 8);
                            byte[] md = new byte[valLen - 2];
                            if (md.length > 0) System.arraycopy(ad, valOff + 2, md, 0, md.length);
                            mfg.put(Integer.valueOf(companyId), md);
                        }
                        break;
                    default:
                        break;
                }
                pos += len;
            }
        }

        String resolvedName = (completeName != null && !completeName.isEmpty()) ? completeName : shortName;
        return new Gen5wBleAdvRecord(ad, flags, resolvedName, txPower, uuids, mfg, svcData);
    }

    public static String normalizeUuid(String raw) {
        if (raw == null) return "";
        String s = raw.trim().toLowerCase(Locale.US);
        if (s.startsWith("0x")) s = s.substring(2);
        if (s.length() == 36 && s.startsWith("0000") && s.endsWith("-0000-1000-8000-00805f9b34fb")) {
            return s.substring(4, 8);
        }
        return s;
    }

    private static void addUnique(List<String> list, String item) {
        if (!list.contains(item)) list.add(item);
    }

    private static String decodeUuid16Le(byte[] b, int off) {
        int u16 = (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8);
        return String.format(Locale.US, "%04x", Integer.valueOf(u16));
    }

    private static String decodeUuid128Le(byte[] b, int off) {
        byte[] baseLe = new byte[]{
                (byte) 0xFB, 0x34, (byte) 0x9B, 0x5F, (byte) 0x80, 0x00,
                0x00, (byte) 0x80, 0x00, 0x10, 0x00, 0x00
        };
        boolean isBtBase = (b[off + 14] == 0x00 && b[off + 15] == 0x00);
        for (int i = 0; isBtBase && i < 12; i++) {
            if (b[off + i] != baseLe[i]) isBtBase = false;
        }
        if (isBtBase) {
            return decodeUuid16Le(b, off + 12);
        }
        StringBuilder sb = new StringBuilder(36);
        for (int i = 15; i >= 0; i--) {
            sb.append(String.format(Locale.US, "%02x", Integer.valueOf(b[off + i] & 0xFF)));
            if (i == 12 || i == 10 || i == 8 || i == 6) sb.append('-');
        }
        return sb.toString();
    }
}
