package bvm02.app;

import java.util.Locale;

/**
 * Configuration model for one saved BVM02 sensor slot (up to 4 slots supported).
 */
public final class SensorConfig {
    public static final int MODE_AUTO = 0;
    public static final int MODE_12V  = 1;
    public static final int MODE_24V  = 2;

    public final int slotIndex;
    public final String mac;
    public final String label;
    public final String advertisedName;
    public final String pin;
    public final int voltageMode;

    public SensorConfig(int slotIndex, String mac, String label,
                        String advertisedName, String pin, int voltageMode) {
        this.slotIndex = slotIndex;
        this.mac = (mac != null) ? mac.trim().toUpperCase(Locale.US) : "";
        this.label = (label != null) ? label.trim() : "";
        this.advertisedName = (advertisedName != null) ? advertisedName.trim() : "";
        this.pin = (pin != null) ? pin.trim() : "0000";
        this.voltageMode = (voltageMode == MODE_12V || voltageMode == MODE_24V) ? voltageMode : MODE_AUTO;
    }

    public boolean isConfigured() {
        return !mac.isEmpty();
    }

    public String getDisplayName() {
        if (!label.isEmpty()) return label;
        if (!advertisedName.isEmpty()) return advertisedName;
        if (!mac.isEmpty()) return mac;
        return "+ Add Sensor";
    }

    public boolean resolveIs24V(boolean hardwareReported24V) {
        if (voltageMode == MODE_24V) return true;
        if (voltageMode == MODE_12V) return false;
        return hardwareReported24V;
    }

    public String getVoltageModeDescription(boolean hardwareReported24V) {
        boolean is24 = resolveIs24V(hardwareReported24V);
        String base = is24 ? "24V" : "12V";
        if (voltageMode == MODE_AUTO) {
            return base + " (Auto)";
        }
        return base + " (Manual)";
    }

    public static boolean isValidMacAddress(String mac) {
        if (mac == null) return false;
        String s = mac.trim();
        if (s.length() != 17) return false;
        for (int i = 0; i < 17; i++) {
            char c = s.charAt(i);
            if (i % 3 == 2) {
                if (c != ':') return false;
            } else {
                boolean hex = (c >= '0' && c <= '9')
                        || (c >= 'a' && c <= 'f')
                        || (c >= 'A' && c <= 'F');
                if (!hex) return false;
            }
        }
        return true;
    }
}
