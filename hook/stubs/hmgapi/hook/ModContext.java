package hmgapi.hook;

import java.io.File;

/**
 * Compile-only signature stub of HMG-API's runtime {@code hmgapi.hook.ModContext}.
 * Never packaged into {@code hooks.jar}; resolved from {@code /system/framework/hmgapi-hook.jar} at runtime.
 */
public final class ModContext {
    public final String id;
    public final String version;
    public final File dir;

    ModContext(String id, String version, File dir) {
        this.id = id;
        this.version = version;
        this.dir = dir;
    }

    public boolean enabled() {
        return true;
    }

    public void log(String message) {}
}
