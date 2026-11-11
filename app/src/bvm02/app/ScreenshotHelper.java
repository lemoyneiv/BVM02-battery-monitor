package bvm02.app;

import android.app.Activity;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.view.View;
import android.widget.Toast;

import java.io.File;
import java.io.FileOutputStream;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Captures screenshots strictly to an attached USB flash drive (<usb>/BVM02Logs/).
 * Zero writes to internal /data eMMC flash are ever performed.
 */
public final class ScreenshotHelper {
    private static final AtomicBoolean CAPTURING = new AtomicBoolean(false);
    private static final long HMGAPID_POLL_INTERVAL_MS = 120L;
    private static final long HMGAPID_TIMEOUT_MS = 3500L;

    private ScreenshotHelper() {}

    /**
     * Pure pixel detector for Telechips TCC803x /system/bin/screencap BGRA <-> RGBA channel swap.
     */
    public static boolean shouldSwapRedBlue(int[] argbPixels, int imgWidth, int imgHeight,
                                            int roiLeft, int roiTop, int roiRight, int roiBottom) {
        if (argbPixels == null || imgWidth <= 0 || imgHeight <= 0) return false;
        if (argbPixels.length < imgWidth * imgHeight) return false;

        int left = Math.max(0, Math.min(imgWidth, roiLeft));
        int right = Math.max(0, Math.min(imgWidth, roiRight));
        int top = Math.max(0, Math.min(imgHeight, roiTop));
        int bottom = Math.max(0, Math.min(imgHeight, roiBottom));
        if (right <= left || bottom <= top) return false;

        int swappedVotes = 0;
        int normalVotes = 0;
        for (int y = top; y < bottom; y++) {
            int rowBase = y * imgWidth;
            for (int x = left; x < right; x++) {
                int p = argbPixels[rowBase + x];
                int a = (p >>> 24) & 0xFF;
                if (a < 180) continue;
                int r = (p >>> 16) & 0xFF;
                int g = (p >>> 8) & 0xFF;
                int b = p & 0xFF;
                if (r - b >= 35 && r > g) {
                    swappedVotes++;
                } else if (b - r >= 35 && b > g) {
                    normalVotes++;
                }
            }
        }
        return swappedVotes >= 12 && swappedVotes > (normalVotes * 3);
    }

    public static void swapRedBlueInPlace(int[] argbPixels) {
        if (argbPixels == null) return;
        for (int i = 0; i < argbPixels.length; i++) {
            int p = argbPixels[i];
            argbPixels[i] = (p & 0xFF00FF00)
                    | ((p & 0x00FF0000) >>> 16)
                    | ((p & 0x000000FF) << 16);
        }
    }

    public static void captureToUsb(final Activity activity, final View blueTitleAnchor) {
        if (activity == null || activity.isFinishing()) return;
        if (!CAPTURING.compareAndSet(false, true)) return;

        final Handler uiHandler = new Handler(Looper.getMainLooper());
        final int roiLeft, roiTop, roiRight, roiBottom;
        if (blueTitleAnchor != null && blueTitleAnchor.getWidth() > 0 && blueTitleAnchor.getHeight() > 0) {
            int[] loc = new int[2];
            blueTitleAnchor.getLocationOnScreen(loc);
            roiLeft = loc[0];
            roiTop = loc[1];
            roiRight = loc[0] + blueTitleAnchor.getWidth();
            roiBottom = loc[1] + blueTitleAnchor.getHeight();
        } else {
            roiLeft = roiTop = roiRight = roiBottom = 0;
        }

        new Thread(new Runnable() {
            @Override
            public void run() {
                File savedFile = null;
                String errMsg = null;
                try {
                    File usbFolder = UsbStorageHelper.getUsbLogDirectory(true);
                    if (usbFolder == null || !usbFolder.exists() || !usbFolder.canWrite()) {
                        errMsg = "No USB drive attached — insert USB stick to save screenshot";
                        DiagLogger.log("SCREENSHOT", errMsg);
                        return;
                    }

                    Set<String> existingNames = new HashSet<String>();
                    File[] beforeList = usbFolder.listFiles();
                    if (beforeList != null) {
                        for (File f : beforeList) {
                            if (f != null && f.isFile() && isScreenshotPng(f.getName())) {
                                existingNames.add(f.getName());
                            }
                        }
                    }

                    long triggerWallMs = System.currentTimeMillis();
                    if (HmgapidClient.requestScreenshot()) {
                        savedFile = waitForHmgapidScreenshot(usbFolder, existingNames, triggerWallMs);
                        if (savedFile != null) {
                            normalizeColorsIfNeeded(savedFile, roiLeft, roiTop, roiRight, roiBottom);
                            DiagLogger.log("SCREENSHOT", "Saved root screenshot to USB: " + savedFile.getAbsolutePath());
                        }
                    }

                    if (savedFile == null) {
                        savedFile = captureDecorViewToUsb(activity, uiHandler, usbFolder);
                        if (savedFile != null) {
                            DiagLogger.log("SCREENSHOT", "Saved view screenshot to USB: " + savedFile.getAbsolutePath());
                        } else {
                            errMsg = "Failed to write screenshot to USB drive";
                            DiagLogger.log("SCREENSHOT", errMsg);
                        }
                    }
                } catch (Throwable t) {
                    errMsg = "Screenshot error: " + t.getMessage();
                    DiagLogger.log("SCREENSHOT", errMsg);
                } finally {
                    CAPTURING.set(false);
                    final File finalSaved = savedFile;
                    final String finalErr = errMsg;
                    uiHandler.post(new Runnable() {
                        @Override
                        public void run() {
                            if (!activity.isFinishing()) {
                                if (finalSaved != null) {
                                    Toast.makeText(activity,
                                            "Screenshot saved to USB: " + finalSaved.getName(),
                                            Toast.LENGTH_SHORT).show();
                                } else if (finalErr != null) {
                                    Toast.makeText(activity, finalErr, Toast.LENGTH_SHORT).show();
                                }
                            }
                        }
                    });
                }
            }
        }, "Bvm02Screenshot").start();
    }

    private static boolean isScreenshotPng(String name) {
        return name != null && name.startsWith("bvm02_screenshot_") && name.endsWith(".png");
    }

    private static File waitForHmgapidScreenshot(File usbFolder, Set<String> existingNames, long triggerWallMs) {
        long deadline = SystemClock.elapsedRealtime() + HMGAPID_TIMEOUT_MS;
        while (SystemClock.elapsedRealtime() < deadline) {
            File[] files = usbFolder.listFiles();
            if (files != null) {
                File newest = null;
                for (File f : files) {
                    if (f == null || !f.isFile() || !isScreenshotPng(f.getName())) continue;
                    if (!existingNames.contains(f.getName()) && f.length() > 0 && f.lastModified() >= triggerWallMs - 2000L) {
                        if (newest == null || f.lastModified() > newest.lastModified()) {
                            newest = f;
                        }
                    }
                }
                if (newest != null) return newest;
            }
            SystemClock.sleep(HMGAPID_POLL_INTERVAL_MS);
        }
        return null;
    }

    private static void normalizeColorsIfNeeded(File pngFile, int roiLeft, int roiTop, int roiRight, int roiBottom) {
        if (roiRight <= roiLeft || roiBottom <= roiTop) return;
        Bitmap bmp = null;
        try {
            BitmapFactory.Options opts = new BitmapFactory.Options();
            opts.inPreferredConfig = Bitmap.Config.ARGB_8888;
            opts.inMutable = true;
            bmp = BitmapFactory.decodeFile(pngFile.getAbsolutePath(), opts);
            if (bmp == null) return;
            int w = bmp.getWidth();
            int h = bmp.getHeight();
            int[] pixels = new int[w * h];
            bmp.getPixels(pixels, 0, w, 0, 0, w, h);
            if (!shouldSwapRedBlue(pixels, w, h, roiLeft, roiTop, roiRight, roiBottom)) {
                return;
            }
            swapRedBlueInPlace(pixels);
            bmp.setPixels(pixels, 0, w, 0, 0, w, h);

            File part = new File(pngFile.getParentFile(), "." + pngFile.getName() + ".fix.part");
            FileOutputStream fos = new FileOutputStream(part);
            try {
                bmp.compress(Bitmap.CompressFormat.PNG, 100, fos);
                fos.flush();
                try { fos.getFD().sync(); } catch (Throwable ignored) {}
            } finally {
                try { fos.close(); } catch (Throwable ignored) {}
            }
            if (part.length() > 0) {
                pngFile.delete();
                part.renameTo(pngFile);
            } else {
                part.delete();
            }
        } catch (Throwable ignored) {
        } finally {
            if (bmp != null) bmp.recycle();
        }
    }

    private static File captureDecorViewToUsb(final Activity activity, Handler uiHandler, File usbFolder) {
        final AtomicReference<Bitmap> ref = new AtomicReference<Bitmap>();
        final CountDownLatch latch = new CountDownLatch(1);
        uiHandler.post(new Runnable() {
            @Override
            public void run() {
                try {
                    View root = activity.getWindow().getDecorView();
                    int w = root.getWidth();
                    int h = root.getHeight();
                    if (w > 0 && h > 0) {
                        Bitmap b = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888);
                        Canvas c = new Canvas(b);
                        root.draw(c);
                        ref.set(b);
                    }
                } catch (Throwable ignored) {
                } finally {
                    latch.countDown();
                }
            }
        });

        try {
            latch.await(2500, TimeUnit.MILLISECONDS);
        } catch (InterruptedException ignored) {}

        Bitmap bmp = ref.get();
        if (bmp == null) return null;
        try {
            String ts = new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(new Date());
            File out = new File(usbFolder, "bvm02_screenshot_" + ts + ".png");
            int n = 1;
            while (out.exists()) {
                out = new File(usbFolder, "bvm02_screenshot_" + ts + "_" + n + ".png");
                n++;
            }
            File part = new File(usbFolder, "." + out.getName() + ".part");
            FileOutputStream fos = new FileOutputStream(part);
            try {
                bmp.compress(Bitmap.CompressFormat.PNG, 100, fos);
                fos.flush();
                try { fos.getFD().sync(); } catch (Throwable ignored) {}
            } finally {
                try { fos.close(); } catch (Throwable ignored) {}
            }
            if (part.length() > 0 && part.renameTo(out)) {
                return out;
            }
            part.delete();
            return null;
        } catch (Throwable ignored) {
            return null;
        } finally {
            bmp.recycle();
        }
    }
}
