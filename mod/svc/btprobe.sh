#!/system/bin/sh
# Strictly read-only, passive Gen5W Bluetooth HAL & process map inspector (v0.3.0).
# Zero writes to /system, /data, or USB; zero /data content or PII/VIN/serial reads.

run_ts="$(date +%s 2>/dev/null)"
echo "=== BEGIN BTPROBE ROOT READ-ONLY SNAPSHOT (ts=$run_ts) ==="

btpid=""
for p in /proc/[0-9]*; do
    [ -r "$p/cmdline" ] || continue
    pid="${p#/proc/}"
    if grep "com\.android\.bluetooth" "$p/cmdline" >/dev/null 2>&1; then
        btpid="$pid"
        echo "BTPID: $pid (com.android.bluetooth)"
    elif grep "com\.hkmc\.bluetooth" "$p/cmdline" >/dev/null 2>&1; then
        echo "OTHER_BTPID: $pid (com.hkmc.bluetooth)"
    elif grep "com\.android\.btsettings" "$p/cmdline" >/dev/null 2>&1; then
        echo "OTHER_BTPID: $pid (com.android.btsettings)"
    fi
done

if [ -n "$btpid" ] && [ -r "/proc/$btpid/maps" ]; then
    seen="|"
    while read -r range perms off dev inode path rest; do
        case "$path" in
            /system/*|/vendor/*|/dev/*|*bvm02-gen5w*)
                case "$seen" in
                    *"|$path|"*) ;;
                    *)
                        seen="${seen}${path}|"
                        echo "BTMAP: $perms $path"
                        ;;
                esac
                ;;
        esac
    done < "/proc/$btpid/maps"

    ls -l "/proc/$btpid/fd" 2>/dev/null | while read -r perms owner grp dt tm fdname arrow target rest; do
        case "$arrow" in
            "->")
                case "$target" in
                    /data/*) ;;
                    /dev/*|socket:*|anon_inode:*|/system/*|/vendor/*)
                        echo "BTFD: fd=$fdname -> $target"
                        ;;
                esac
                ;;
        esac
    done
else
    echo "BTPID_WARN: com.android.bluetooth process maps unavailable (btpid=$btpid)"
fi

logcat -d -s HMG-API:V BVM02Hook:V 2>/dev/null | while IFS= read -r hline; do
    case "$hline" in
        *bvm02-gen5w*|*BVM02Hook*|*@bvm02_ble*)
            echo "HMGLOG: $hline"
            ;;
    esac
done

for d in /system/lib/hw /vendor/lib /vendor/lib/hw; do
    if [ -d "$d" ]; then
        echo "DIR_LS $d:"
        ls -l "$d" 2>/dev/null
    else
        echo "DIR_ABSENT: $d"
    fi
done

echo "DEV_NODES:"
for n in /dev/tcc* /dev/ttyTCC* /dev/uhid /dev/uinput /dev/rfcomm* /dev/hci* /dev/hidraw*; do
    [ -e "$n" ] && ls -l "$n" 2>/dev/null
done
if [ -d /dev/bus/usb ]; then
    echo "DEV_BUS_USB:"
    ls -l /dev/bus/usb /dev/bus/usb/* 2>/dev/null
fi

if [ -r /proc/devices ]; then
    echo "PROC_DEVICES:"
    while IFS= read -r dline; do
        [ -n "$dline" ] && echo "  $dline"
    done < /proc/devices
fi

echo "KERNEL_MODULES:"
lsmod 2>/dev/null
for m in /sys/module/*; do
    mname="${m##*/}"
    case "$mname" in
        *bt*|*BT*|*blue*|*brcm*|*mbox*|*usb*|*hid*|*rfcomm*|*tty*)
            echo "  sys_module: $mname"
            ;;
    esac
done

for rcf in /init.rc /init.*.rc; do
    [ -r "$rcf" ] || continue
    while IFS= read -r rline; do
        case "$rline" in
            ""|\#*) continue ;;
            *serial*|*SERIAL*|*vin*|*VIN*) continue ;;
            *bt*|*BT*|*blue*|*Blue*|*mbox*|*MBOX*|*brcm*|*BRCM*|*uhid*|*rfcomm*|*gatt*|*GATT*)
                echo "INITRC $rcf: $rline"
                ;;
        esac
    done < "$rcf"
done

echo "=== END BTPROBE ROOT READ-ONLY SNAPSHOT ==="
exit 0
