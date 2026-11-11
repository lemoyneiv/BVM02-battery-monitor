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

    public static int call(String... args) {
        if (args == null || args.length == 0) return -1;
        LocalSocket socket = null;
        try {
            socket = new LocalSocket();
            socket.connect(new LocalSocketAddress("hmgapid", LocalSocketAddress.Namespace.ABSTRACT));
            socket.setSoTimeout(4000);

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
            byte[] header = new byte[5];
            while (readFully(in, header, 5)) {
                int type = header[0] & 0xFF;
                long len = ((long) (header[1] & 0xFF))
                        | (((long) (header[2] & 0xFF)) << 8)
                        | (((long) (header[3] & 0xFF)) << 16)
                        | (((long) (header[4] & 0xFF)) << 24);

                if (type == 'O') {
                    if (len > 0 && len <= 65536) {
                        byte[] outBuf = new byte[(int) len];
                        if (readFully(in, outBuf, (int) len)) {
                            String msg = new String(outBuf, "UTF-8");
                            DiagLogger.log("HMGAPID", "daemon output: " + msg.trim());
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
                            return (int) code;
                        }
                    }
                    return -1;
                } else {
                    return -1;
                }
            }
            return -1;
        } catch (Throwable ignored) {
            return -1;
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
