#!/system/bin/sh
dest=""
for m in /storage/usb0 /storage/usb1 /storage/usb2 /mnt/media_rw/usb0 /mnt/media_rw/usb1 /mnt/usb0 /mnt/usb1 /storage/ext_sd; do
    if [ -d "$m/BVM02Logs" ] && [ -w "$m/BVM02Logs" ]; then
        dest="$m/BVM02Logs"
        break
    fi
done

if [ -z "$dest" ]; then
    exit 1
fi

ts=$(date +%Y%m%d_%H%M%S)
tmp="$dest/.bvm02_shot_${ts}.part"
out="$dest/bvm02_screenshot_${ts}.png"
if [ -e "$out" ]; then
    n=1
    while [ -e "$dest/bvm02_screenshot_${ts}_${n}.png" ]; do
        n=$((n + 1))
    done
    out="$dest/bvm02_screenshot_${ts}_${n}.png"
fi

rm -f "$tmp"
/system/bin/screencap -p "$tmp" >/dev/null 2>&1
if [ -s "$tmp" ]; then
    mv "$tmp" "$out"
    sync
    exit 0
fi

rm -f "$tmp"
exit 1
