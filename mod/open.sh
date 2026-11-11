#!/system/bin/sh
# Open the BVM02 Battery Monitor app from NEMESIS Manager,
# installing its APK first if needed.
MOD=${ROOT:-}/data/hmgapi/mods/bvm02-gen5w
say() { echo "BVM02: $1"; }
[ "$(getprop sys.boot_completed)" = 1 ] || { say "Android isn't up yet: try again in a minute"; exit 1; }
case "$(pm path bvm02.app 2>/dev/null)" in
    package:*) ;;
    *)
        A=$MOD/app/Bvm02Monitor.apk
        [ -f "$A" ] || { say "the app isn't on this unit: install BVM02 again"; exit 1; }
        setprop sys.boot_completed 0
        r=$(pm install -r "$A" 2>&1)
        setprop sys.boot_completed 1
        case "$r" in
            *Success*) say "installed the app" ;;
            *) say "the app didn't install: $r"; exit 1 ;;
        esac ;;
esac
am start -n bvm02.app/.MainActivity >/dev/null 2>&1 || { say "couldn't open the app"; exit 1; }
