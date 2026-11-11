package hmgapi.hook;

import android.content.Context;

/**
 * Compile-only signature stub of HMG-API's runtime {@code hmgapi.hook.LoadedApp}.
 * Never packaged into {@code hooks.jar}; resolved from {@code /system/framework/hmgapi-hook.jar} at runtime.
 */
public final class LoadedApp {
    public final String packageName;
    public final String processName;
    public final ClassLoader classLoader;
    public final Context context;

    LoadedApp(String packageName, String processName, ClassLoader classLoader, Context context) {
        this.packageName = packageName;
        this.processName = processName;
        this.classLoader = classLoader;
        this.context = context;
    }
}
