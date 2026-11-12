package bvm02.hook;

import hmgapi.hook.LoadedApp;
import hmgapi.hook.ModContext;
import hmgapi.hook.ModEntry;

/**
 * HMG-API live hook entry point for BVM02 Battery Monitor ({@code bvm02-gen5w}).
 *
 * Strictly isolated to {@code com.android.bluetooth}: does nothing in the zygote,
 * {@code system_server}, or any other application process.
 */
public final class BtHookEntry extends ModEntry {

    public static final String HOOK_VERSION = "0.3.0";
    private static final String BT_PACKAGE = "com.android.bluetooth";

    @Override
    public void zygoteInit(ModContext mod) {
        // Intentional no-op: zero work in zygote or system_server.
    }

    @Override
    public void appLoaded(ModContext mod, LoadedApp app) {
        if (app == null || !BT_PACKAGE.equals(app.packageName)) {
            return;
        }
        if (mod != null) {
            mod.log("BtHookEntry v" + HOOK_VERSION + " active in " + app.processName
                    + " (pid=" + android.os.Process.myPid()
                    + ", uid=" + android.os.Process.myUid() + ")");
        }
        BtBleBridgeServer.startIfNeeded(mod, app);
    }

    @Override
    public void onEnabled(ModContext mod, boolean enabled) {
        BtBleBridgeServer.setModEnabled(enabled);
    }
}
