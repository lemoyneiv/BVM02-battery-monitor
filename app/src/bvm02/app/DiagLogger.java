package bvm02.app;

import android.os.Build;
import android.util.Log;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.Charset;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;

/**
 * Bounded, thread-safe, purely in-RAM diagnostic & CSV telemetry ring buffer.
 *
 * CRITICAL GEN5W INVARIANT: Never writes logs or voltage samples to internal /data eMMC flash.
 * Disk I/O occurs strictly to an external USB flash drive (<usb>/BVM02Logs/) upon explicit
 * user action ("Export Log to USB").
 */
public final class DiagLogger {

    private static final String LOGCAT_TAG = "BVM02Gen5W";
    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static final int MAX_LOG_LINES = 4500;
    private static final int MAX_CSV_SAMPLES = 3600;

    public interface LogListener {
        void onLogUpdated();
    }

    public static final class TelemetrySample {
        public final long wallTimeMs;
        public final String mac;
        public final String sensorName;
        public final int centivolts;
        public final int socPercent;
        public final int tempC;
        public final boolean hasTemp;
        public final boolean is24V;

        public TelemetrySample(long wallTimeMs, String mac, String sensorName, int centivolts,
                               int socPercent, int tempC, boolean hasTemp, boolean is24V) {
            this.wallTimeMs = wallTimeMs;
            this.mac = mac;
            this.sensorName = sensorName;
            this.centivolts = centivolts;
            this.socPercent = socPercent;
            this.tempC = tempC;
            this.hasTemp = hasTemp;
            this.is24V = is24V;
        }
    }

    public static final class ExportResult {
        public final File logFile;
        public final File csvFile;
        public final String error;

        public ExportResult(File logFile, File csvFile, String error) {
            this.logFile = logFile;
            this.csvFile = csvFile;
            this.error = error;
        }
    }

    private static final Object LOCK = new Object();
    private static final LinkedList<String> LOG_RING = new LinkedList<String>();
    private static final LinkedList<TelemetrySample> CSV_RING = new LinkedList<TelemetrySample>();
    private static volatile LogListener listener;

    static {
        log("INIT", "BVM02 Battery Monitor v" + Bvm02Protocol.APP_VERSION
                + " initialized (SDK=" + Build.VERSION.SDK_INT
                + ", Release=" + Build.VERSION.RELEASE
                + ", Model=" + Build.MODEL
                + ", Product=" + Build.PRODUCT
                + ", ABI=" + Build.CPU_ABI + ")");
    }

    private DiagLogger() {}

    public static void setListener(LogListener l) {
        listener = l;
    }

    public static void log(String category, String message) {
        String ts = new SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(new Date());
        String cat = (category != null) ? category : "INFO";
        String line = ts + " [" + cat + "] " + message;
        try {
            Log.i(LOGCAT_TAG, "[" + cat + "] " + message);
        } catch (Throwable ignored) {
            // Safe when running in host JVM unit tests
        }
        synchronized (LOCK) {
            LOG_RING.addLast(line);
            while (LOG_RING.size() > MAX_LOG_LINES) {
                LOG_RING.removeFirst();
            }
        }
        LogListener l = listener;
        if (l != null) {
            l.onLogUpdated();
        }
    }

    public static void recordTelemetrySample(String mac, String sensorName, int centivolts,
                                             int socPercent, int tempC, boolean hasTemp, boolean is24V) {
        TelemetrySample s = new TelemetrySample(
                System.currentTimeMillis(),
                mac != null ? mac : "",
                sensorName != null ? sensorName : "",
                centivolts,
                socPercent,
                tempC,
                hasTemp,
                is24V
        );
        synchronized (LOCK) {
            CSV_RING.addLast(s);
            while (CSV_RING.size() > MAX_CSV_SAMPLES) {
                CSV_RING.removeFirst();
            }
        }
    }

    public static String snapshotText(int maxRecentLines) {
        synchronized (LOCK) {
            int total = LOG_RING.size();
            int start = (maxRecentLines > 0 && total > maxRecentLines) ? (total - maxRecentLines) : 0;
            StringBuilder sb = new StringBuilder((total - start) * 72);
            int idx = 0;
            for (String line : LOG_RING) {
                if (idx >= start) {
                    sb.append(line).append('\n');
                }
                idx++;
            }
            return sb.toString();
        }
    }

    public static int getSampleCount() {
        synchronized (LOCK) {
            return CSV_RING.size();
        }
    }

    public static void clear() {
        synchronized (LOCK) {
            LOG_RING.clear();
            CSV_RING.clear();
        }
        log("DIAG", "Cleared in-RAM diagnostic & telemetry buffers.");
    }

    /**
     * Atomically writes the RAM diagnostic log and (if non-empty) CSV telemetry session
     * strictly to an attached USB drive (<usb>/BVM02Logs/).
     */
    public static ExportResult exportToUsb(String extraHardwareHeader) {
        File usbDir = UsbStorageHelper.getUsbLogDirectory(true);
        if (usbDir == null || !usbDir.isDirectory() || !usbDir.canWrite()) {
            return new ExportResult(null, null, "No writable USB flash drive found. Insert a FAT32/exFAT USB stick.");
        }

        String stamp = new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(new Date());
        List<String> linesCopy;
        List<TelemetrySample> samplesCopy;
        synchronized (LOCK) {
            linesCopy = new ArrayList<String>(LOG_RING);
            samplesCopy = new ArrayList<TelemetrySample>(CSV_RING);
        }

        try {
            // 1. Diagnostic log (.txt)
            File logFinal = uniqueFile(usbDir, "bvm02_diag_" + stamp, ".txt");
            File logPart = new File(usbDir, "." + logFinal.getName() + ".part");
            StringBuilder logSb = new StringBuilder(linesCopy.size() * 80 + 512);
            logSb.append("=== BVM02 Battery Monitor for Gen5W — Diagnostic Export ===\n");
            logSb.append("Exported: ").append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z", Locale.US).format(new Date())).append('\n');
            if (extraHardwareHeader != null && !extraHardwareHeader.isEmpty()) {
                logSb.append(extraHardwareHeader).append("\n");
            }
            logSb.append("-----------------------------------------------------------\n");
            for (String l : linesCopy) {
                logSb.append(l).append('\n');
            }
            writeAtomically(logPart, logFinal, logSb.toString().getBytes(UTF8));

            // 2. Session voltage CSV (.csv) if samples were collected
            File csvFinal = null;
            if (!samplesCopy.isEmpty()) {
                csvFinal = uniqueFile(usbDir, "bvm02_voltage_" + stamp, ".csv");
                File csvPart = new File(usbDir, "." + csvFinal.getName() + ".part");
                SimpleDateFormat isoFmt = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US);
                StringBuilder csvSb = new StringBuilder(samplesCopy.size() * 64 + 128);
                csvSb.append("timestamp_iso,epoch_ms,mac,sensor_name,voltage_v,centivolts,soc_percent,temp_c,system_mode\n");
                for (TelemetrySample s : samplesCopy) {
                    csvSb.append(isoFmt.format(new Date(s.wallTimeMs))).append(',')
                            .append(s.wallTimeMs).append(',')
                            .append(escapeCsv(s.mac)).append(',')
                            .append(escapeCsv(s.sensorName)).append(',')
                            .append(String.format(Locale.US, "%.2f", s.centivolts / 100.0f)).append(',')
                            .append(s.centivolts).append(',')
                            .append(s.socPercent).append(',')
                            .append(s.hasTemp ? Integer.toString(s.tempC) : "").append(',')
                            .append(s.is24V ? "24V" : "12V").append('\n');
                }
                writeAtomically(csvPart, csvFinal, csvSb.toString().getBytes(UTF8));
            }

            log("USB", "Exported diagnostics to USB: " + logFinal.getAbsolutePath()
                    + (csvFinal != null ? (" + " + csvFinal.getName()) : ""));
            return new ExportResult(logFileOrNull(logFinal), logFileOrNull(csvFinal), null);
        } catch (Throwable t) {
            String err = "USB export failed: " + t.getMessage();
            log("USB_ERR", err);
            return new ExportResult(null, null, err);
        }
    }

    private static File logFileOrNull(File f) {
        return (f != null && f.isFile()) ? f : null;
    }

    private static String escapeCsv(String v) {
        if (v == null) return "";
        if (v.indexOf(',') >= 0 || v.indexOf('"') >= 0 || v.indexOf('\n') >= 0) {
            return "\"" + v.replace("\"", "\"\"") + "\"";
        }
        return v;
    }

    private static File uniqueFile(File dir, String base, String ext) {
        File f = new File(dir, base + ext);
        int n = 1;
        while (f.exists()) {
            f = new File(dir, base + "_" + n + ext);
            n++;
        }
        return f;
    }

    private static void writeAtomically(File partFile, File finalFile, byte[] bytes) throws Exception {
        if (partFile.exists()) {
            partFile.delete();
        }
        FileOutputStream fos = null;
        try {
            fos = new FileOutputStream(partFile);
            fos.write(bytes);
            fos.flush();
            try {
                fos.getFD().sync();
            } catch (Throwable ignored) {}
        } finally {
            if (fos != null) {
                try { fos.close(); } catch (Throwable ignored) {}
            }
        }
        if (finalFile.exists()) {
            finalFile.delete();
        }
        if (!partFile.renameTo(finalFile)) {
            throw new IllegalStateException("Could not rename " + partFile.getName() + " to " + finalFile.getName());
        }
    }
}
