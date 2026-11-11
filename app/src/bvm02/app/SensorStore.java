package bvm02.app;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * Persists up to 4 saved BVM02 sensor configurations in SharedPreferences.
 *
 * FLASH WEAR INVARIANT: Writes occur strictly when the user explicitly saves, edits,
 * deletes, or switches a sensor slot. Zero background or telemetry writes ever occur.
 */
public final class SensorStore {
    public static final int MAX_SLOTS = 4;
    private static final String PREFS_NAME = "bvm02_sensors_prefs";
    private static final String KEY_ACTIVE_SLOT = "active_slot";

    private final SharedPreferences prefs;

    public SensorStore(Context context) {
        this.prefs = context.getApplicationContext().getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    public int getActiveSlot() {
        int s = prefs.getInt(KEY_ACTIVE_SLOT, 0);
        if (s < 0 || s >= MAX_SLOTS) return 0;
        return s;
    }

    public void setActiveSlot(int slotIndex) {
        if (slotIndex < 0 || slotIndex >= MAX_SLOTS) return;
        if (prefs.getInt(KEY_ACTIVE_SLOT, -1) == slotIndex) return;
        prefs.edit().putInt(KEY_ACTIVE_SLOT, slotIndex).apply();
    }

    public SensorConfig getSlot(int slotIndex) {
        if (slotIndex < 0 || slotIndex >= MAX_SLOTS) {
            return new SensorConfig(0, "", "", "", "0000", SensorConfig.MODE_AUTO);
        }
        String pfx = "slot_" + slotIndex + "_";
        String mac = prefs.getString(pfx + "mac", "");
        String label = prefs.getString(pfx + "label", "");
        String adv = prefs.getString(pfx + "adv_name", "");
        String pin = prefs.getString(pfx + "pin", "0000");
        int mode = prefs.getInt(pfx + "vmode", SensorConfig.MODE_AUTO);
        return new SensorConfig(slotIndex, mac, label, adv, pin, mode);
    }

    public SensorConfig[] getAllSlots() {
        SensorConfig[] all = new SensorConfig[MAX_SLOTS];
        for (int i = 0; i < MAX_SLOTS; i++) {
            all[i] = getSlot(i);
        }
        return all;
    }

    public void saveSlot(SensorConfig config) {
        if (config == null || config.slotIndex < 0 || config.slotIndex >= MAX_SLOTS) return;
        String pfx = "slot_" + config.slotIndex + "_";
        prefs.edit()
                .putString(pfx + "mac", config.mac)
                .putString(pfx + "label", config.label)
                .putString(pfx + "adv_name", config.advertisedName)
                .putString(pfx + "pin", config.pin)
                .putInt(pfx + "vmode", config.voltageMode)
                .putInt(KEY_ACTIVE_SLOT, config.slotIndex)
                .apply();
    }

    public void clearSlot(int slotIndex) {
        if (slotIndex < 0 || slotIndex >= MAX_SLOTS) return;
        String pfx = "slot_" + slotIndex + "_";
        prefs.edit()
                .remove(pfx + "mac")
                .remove(pfx + "label")
                .remove(pfx + "adv_name")
                .remove(pfx + "pin")
                .remove(pfx + "vmode")
                .apply();
    }

    public int findSlotByMac(String mac) {
        if (mac == null || mac.trim().isEmpty()) return -1;
        String target = mac.trim();
        for (int i = 0; i < MAX_SLOTS; i++) {
            SensorConfig c = getSlot(i);
            if (c.isConfigured() && c.mac.equalsIgnoreCase(target)) {
                return i;
            }
        }
        return -1;
    }

    public int findFirstEmptySlot() {
        for (int i = 0; i < MAX_SLOTS; i++) {
            if (!getSlot(i).isConfigured()) return i;
        }
        return -1;
    }
}
