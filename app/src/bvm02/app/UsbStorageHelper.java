package bvm02.app;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Resolves external USB flash drive mount directories on Gen5W head units.
 * Strictly avoids internal eMMC (/data, /sdcard) storage paths.
 */
public final class UsbStorageHelper {

    public static final String USB_FOLDER_NAME = "BVM02Logs";

    public static final String[] KNOWN_USB_MOUNT_POINTS = {
        "/storage/usb0",
        "/storage/usb1",
        "/storage/usb2",
        "/mnt/media_rw/usb0",
        "/mnt/media_rw/usb1",
        "/mnt/usb0",
        "/mnt/usb1",
        "/storage/ext_sd"
    };

    private UsbStorageHelper() {}

    public static List<File> findMountedUsbRoots() {
        Set<String> paths = new LinkedHashSet<String>();
        for (String p : KNOWN_USB_MOUNT_POINTS) {
            File f = new File(p);
            if (f.isDirectory() && f.canWrite()) {
                paths.add(f.getAbsolutePath());
            }
        }

        // Also inspect /proc/mounts for vfat/exfat USB mounts on custom firmwares
        File procMounts = new File("/proc/mounts");
        if (procMounts.isFile() && procMounts.canRead()) {
            BufferedReader br = null;
            try {
                br = new BufferedReader(new FileReader(procMounts));
                String line;
                while ((line = br.readLine()) != null) {
                    String[] parts = line.split("\\s+");
                    if (parts.length >= 3) {
                        String mnt = parts[1];
                        String fs = parts[2];
                        if ((mnt.contains("usb") || mnt.contains("udisk") || mnt.contains("ext_sd"))
                                && ("vfat".equalsIgnoreCase(fs) || "exfat".equalsIgnoreCase(fs) || "fuse".equalsIgnoreCase(fs))) {
                            File dir = new File(mnt);
                            if (dir.isDirectory() && dir.canWrite()) {
                                paths.add(dir.getAbsolutePath());
                            }
                        }
                    }
                }
            } catch (Throwable ignored) {
            } finally {
                if (br != null) {
                    try { br.close(); } catch (Throwable ignored) {}
                }
            }
        }

        List<File> out = new ArrayList<File>(paths.size());
        for (String p : paths) {
            out.add(new File(p));
        }
        return out;
    }

    public static File getUsbLogDirectory(boolean createIfMissing) {
        List<File> roots = findMountedUsbRoots();
        for (File root : roots) {
            File target = new File(root, USB_FOLDER_NAME);
            if (!target.exists() && createIfMissing) {
                target.mkdirs();
            }
            if (target.isDirectory() && target.canWrite()) {
                return target;
            }
            if (!createIfMissing && root.isDirectory() && root.canWrite()) {
                return root;
            }
        }
        return null;
    }
}
