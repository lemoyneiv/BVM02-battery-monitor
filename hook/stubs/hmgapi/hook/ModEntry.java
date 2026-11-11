package hmgapi.hook;

/**
 * Compile-only signature stub of HMG-API's runtime {@code hmgapi.hook.ModEntry}.
 * Never packaged into {@code hooks.jar}; resolved from {@code /system/framework/hmgapi-hook.jar} at runtime.
 */
public abstract class ModEntry {
    public void zygoteInit(ModContext mod) throws Throwable {}
    public void appLoaded(ModContext mod, LoadedApp app) throws Throwable {}
    public void onSettingsChanged(ModContext mod) throws Throwable {}
    public void onEnabled(ModContext mod, boolean enabled) throws Throwable {}
}
