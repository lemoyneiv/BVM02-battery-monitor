package bvm02.app;

import android.net.LocalSocket;
import android.net.LocalSocketAddress;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Client for hmgapid daemon running on Gen5W over local abstract socket @hmgapid.
 * Protocol: "LFD1", u32 argc, then argc x (u32 len, bytes); all little-endian.
 * Response frames: 'O' u32 len bytes (stdout/stderr), 'X' u32 len(4) u32 code (exit code).
 */
public final class HmgapidClient {
    private HmgapidClient() {}

    public static final class Result {
        public final int code;
        public final String text;

        public Result(int code, String text) {
            this.code = code;
            this.text = text != null ? text : "";
        }
    }

    public static int call(String... args) {
        return callResult(true, args).code;
    }

    public static Result callResult(boolean logDaemonOutput, String... args) {
        if (args == null || args.length == 0) return new Result(-1, "");
        LocalSocket socket = null;
        try {
            socket = new LocalSocket();
            socket.connect(new LocalSocketAddress("hmgapid", LocalSocketAddress.Namespace.ABSTRACT));
            socket.setSoTimeout(5000);

            ByteArrayOutputStream req = new ByteArrayOutputStream();
            req.write(new byte[]{'L', 'F', 'D', '1'});
            u32(req, args.length);
            for (String arg : args) {
                byte[] bytes = arg.getBytes("UTF-8");
                u32(req, bytes.length);
                req.write(bytes);
            }

            OutputStream out = socket.getOutputStream();
            out.write(req.toByteArray());
            out.flush();

            InputStream in = socket.getInputStream();
            ByteArrayOutputStream textOut = new ByteArrayOutputStream();
            byte[] header = new byte[5];
            while (readFully(in, header, 5)) {
                int type = header[0] & 0xFF;
                long len = ((long) (header[1] & 0xFF))
                        | (((long) (header[2] & 0xFF)) << 8)
                        | (((long) (header[3] & 0xFF)) << 16)
                        | (((long) (header[4] & 0xFF)) << 24);

                if (type == 'O') {
                    if (len > 0 && len <= 131072) {
                        byte[] outBuf = new byte[(int) len];
                        if (readFully(in, outBuf, (int) len)) {
                            if (textOut.size() < 131072) {
                                int room = 131072 - textOut.size();
                                textOut.write(outBuf, 0, Math.min(room, outBuf.length));
                            }
                            if (logDaemonOutput) {
                                String msg = new String(outBuf, "UTF-8").trim();
                                if (!msg.isEmpty()) {
                                    DiagLogger.log("HMGAPID", "daemon output: " + msg);
                                }
                            }
                        }
                    } else {
                        skipFully(in, len);
                    }
                } else if (type == 'X') {
                    if (len == 4) {
                        byte[] codeBuf = new byte[4];
                        if (readFully(in, codeBuf, 4)) {
                            long code = ((long) (codeBuf[0] & 0xFF))
                                    | (((long) (codeBuf[1] & 0xFF)) << 8)
                                    | (((long) (codeBuf[2] & 0xFF)) << 16)
                                    | (((long) (codeBuf[3] & 0xFF)) << 24);
                            return new Result((int) code, textOut.toString("UTF-8"));
                        }
                    }
                    return new Result(-1, textOut.toString("UTF-8"));
                } else {
                    return new Result(-1, textOut.toString("UTF-8"));
                }
            }
            return new Result(-1, textOut.toString("UTF-8"));
        } catch (Throwable ignored) {
            return new Result(-1, "");
        } finally {
            if (socket != null) {
                try { socket.close(); } catch (Throwable ignored) {}
            }
        }
    }

    public static boolean requestScreenshot() {
        int rc = call("service-start", "screenshot");
        if (rc == 0) return true;
        return call("service-restart", "screenshot") == 0;
    }

    /**
     * Triggers a manual one-shot mod service via hmgapid, waits across hmgapid's 1-second
     * supervisor tick until a newly completed run marker appears in service-log (up to maxWaitMs),
     * and returns only the latest run's output.
     */
    public static String runManualServiceAndReadLog(String serviceName, int maxWaitMs) {
        Result ping = callResult(false, "ping");
        if (ping.code != 0) {
            return null;
        }

        final String beginMarker = "=== BEGIN BTPROBE ROOT READ-ONLY SNAPSHOT";
        final String endMarker = "=== END BTPROBE ROOT READ-ONLY SNAPSHOT ===";

        Result preLog = callResult(false, "service-log", serviceName);
        int priorEnds = (preLog.code == 0) ? countOccurrences(preLog.text, endMarker) : 0;
        int priorLen = (preLog.code == 0 && preLog.text != null) ? preLog.text.length() : 0;

        Result start = callResult(false, "service-start", serviceName);
        if (start.code != 0) {
            start = callResult(false, "service-restart", serviceName);
            if (start.code != 0) {
                return "SERVICE_START_ERR: code=" + start.code + " msg=" + start.text.trim();
            }
        }

        long deadline = System.currentTimeMillis() + Math.max(1500, maxWaitMs);
        Result lastLog = null;
        while (System.currentTimeMillis() < deadline) {
            try { Thread.sleep(250); } catch (InterruptedException ie) { break; }
            lastLog = callResult(false, "service-log", serviceName);
            if (lastLog.code == 0 && lastLog.text != null) {
                int nowEnds = countOccurrences(lastLog.text, endMarker);
                if (nowEnds > priorEnds || (priorEnds > 0 && lastLog.text.length() != priorLen && lastLog.text.endsWith(endMarker + "\n"))) {
                    return extractLatestRunSlice(lastLog.text, beginMarker);
                }
            }
        }

        if (lastLog == null) {
            lastLog = callResult(false, "service-log", serviceName);
        }
        if (lastLog.code == 0 && lastLog.text != null && !lastLog.text.trim().isEmpty()) {
            return extractLatestRunSlice(lastLog.text, beginMarker);
        }
        Result svcs = callResult(false, "services");
        String svcState = (svcs.code == 0 && svcs.text != null) ? svcs.text.trim().replace('\n', ';') : ("err=" + svcs.code);
        return "SERVICE_LOG_ERR: code=" + lastLog.code + " msg=" + lastLog.text.trim() + " [services=" + svcState + "]";
    }

    public static int countOccurrences(String haystack, String needle) {
        if (haystack == null || needle == null || needle.isEmpty()) return 0;
        int count = 0;
        int idx = 0;
        while ((idx = haystack.indexOf(needle, idx)) >= 0) {
            count++;
            idx += needle.length();
        }
        return count;
    }

    public static String extractLatestRunSlice(String fullLog, String beginMarker) {
        if (fullLog == null || beginMarker == null || beginMarker.isEmpty()) return fullLog;
        int lastBegin = fullLog.lastIndexOf(beginMarker);
        return (lastBegin >= 0) ? fullLog.substring(lastBegin) : fullLog;
    }

    private static void u32(ByteArrayOutputStream o, int v) {
        o.write(v & 0xFF);
        o.write((v >> 8) & 0xFF);
        o.write((v >> 16) & 0xFF);
        o.write((v >> 24) & 0xFF);
    }

    private static boolean readFully(InputStream in, byte[] b, int len) {
        int offset = 0;
        try {
            while (offset < len) {
                int read = in.read(b, offset, len - offset);
                if (read < 0) return false;
                offset += read;
            }
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static void skipFully(InputStream in, long len) {
        try {
            byte[] discard = new byte[2048];
            long remaining = len;
            while (remaining > 0) {
                long skipped = in.skip(remaining);
                if (skipped > 0) {
                    remaining -= skipped;
                } else {
                    int toRead = (int) Math.min((long) discard.length, remaining);
                    int read = in.read(discard, 0, toRead);
                    if (read < 0) break;
                    remaining -= read;
                }
            }
        } catch (Throwable ignored) {}
    }
}
