package bvm02.hook;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.RandomAccessFile;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import hmgapi.hook.ModContext;

/**
 * Fault-safe, strictly read-only in-process memory inspector for {@code com.android.bluetooth}.
 *
 * Reads the live Broadcom controller LMP features, supported HCI LE commands, HCI/LMP version,
 * and {@code bt_hc_cbacks} / {@code bt_hc_interface_t} function tables cached in {@code bplus.default.so}'s
 * RAM segments without calling any native functions or writing a single byte to RAM or flash.
 */
public final class BtMemInspector {

    private static final Charset UTF8 = Charset.forName("UTF-8");
    private static final int MAX_ELF_BYTES = 4 * 1024 * 1024;

    static final class Vma {
        final long start;
        final long end;
        final String perms;
        final long fileOffset;
        final String path;

        Vma(long start, long end, String perms, long fileOffset, String path) {
            this.start = start;
            this.end = end;
            this.perms = perms;
            this.fileOffset = fileOffset;
            this.path = path;
        }

        boolean isSafeReadable() {
            if (perms == null || perms.length() < 1 || perms.charAt(0) != 'r') {
                return false;
            }
            if (path != null && path.startsWith("/dev/")) {
                return false;
            }
            return end > start && start >= 0x10000L;
        }
    }

    static final class SymEntry {
        final String name;
        final long stValue;
        final long stSize;
        final int stInfo;

        SymEntry(String name, long stValue, long stSize, int stInfo) {
            this.name = name;
            this.stValue = stValue;
            this.stSize = stSize;
            this.stInfo = stInfo;
        }

        long cleanOffset() {
            return ((stInfo & 0xF) == 2) ? (stValue & ~1L) : stValue;
        }
    }

    private BtMemInspector() {}

    public static List<String> inspectLiveCapabilities(ModContext mod) {
        List<String> out = new ArrayList<String>();
        out.add("hook_version=" + BtHookEntry.HOOK_VERSION + " process=com.android.bluetooth pid="
                + android.os.Process.myPid() + " uid=" + android.os.Process.myUid()
                + " mod_enabled=" + (mod == null || mod.enabled()));

        List<Vma> allVmas = parseProcSelfMaps();
        out.add("vma_total=" + allVmas.size());

        String bplusPath = null;
        long loadBias = -1L;
        for (int i = 0; i < allVmas.size(); i++) {
            Vma v = allVmas.get(i);
            if (v.path != null && v.path.endsWith("/bplus.default.so")) {
                out.add(String.format(Locale.US, "bplus_vma=0x%x-0x%x perms=%s off=0x%x path=%s",
                        Long.valueOf(v.start), Long.valueOf(v.end), v.perms,
                        Long.valueOf(v.fileOffset), v.path));
                if (loadBias < 0 && v.perms.indexOf('x') >= 0 && v.fileOffset == 0L) {
                    loadBias = v.start;
                    bplusPath = v.path;
                }
            }
        }

        if (loadBias <= 0L || bplusPath == null) {
            out.add("status=BPLUS_NOT_MAPPED");
            return out;
        }

        SafeProcMem procMem = new SafeProcMem(allVmas);
        try {
            out.add("mem_backend=" + procMem.describeBackend());
            byte[] elfMagic = procMem.read(loadBias, 4);
            boolean magicOk = elfMagic != null && elfMagic.length == 4
                    && elfMagic[0] == 0x7F && elfMagic[1] == 'E' && elfMagic[2] == 'L' && elfMagic[3] == 'F';
            out.add(String.format(Locale.US, "bplus_load_bias=0x%x elf_magic_ok=%s",
                    Long.valueOf(loadBias), Boolean.valueOf(magicOk)));
            if (!magicOk) {
                return out;
            }

            Map<String, SymEntry> syms = loadTargetSymbols(new File(bplusPath));
            out.add("bplus_dynsym_loaded=" + syms.size());

            // 1. Direct exported control-block & callback pointers in .data/.bss
            inspectCallbackTable(out, procMem, loadBias, syms.get("bt_hc_cbacks"), "bt_hc_cbacks", 8);
            inspectCallbackTable(out, procMem, loadBias, syms.get("bt_vendor_cbacks"), "bt_vendor_cbacks", 6);
            inspectInterfaceGetter(out, procMem, loadBias, syms.get("bt_hc_get_interface"), "bt_hc_interface_t", 9);

            SymEntry btmCbSym = syms.get("btm_cb");
            if (btmCbSym != null) {
                out.add(String.format(Locale.US, "sym_btm_cb=0x%x size=%d",
                        Long.valueOf(btmCbSym.cleanOffset()), Long.valueOf(btmCbSym.stSize)));
            }
            SymEntry btuCbSym = syms.get("btu_cb");
            if (btuCbSym != null) {
                byte[] btuBytes = procMem.read(loadBias + btuCbSym.cleanOffset(),
                        (int) Math.min(64L, Math.max(btuCbSym.stSize, 32L)));
                out.add(String.format(Locale.US, "live_btu_cb@0x%x(%dB)=%s",
                        Long.valueOf(btuCbSym.cleanOffset()),
                        Long.valueOf(btuCbSym.stSize),
                        toHex(btuBytes)));
            }

            // 2. Simulate BTM_ReadLocalFeatures() -> uint8_t[8] LMP features
            SymEntry featSym = syms.get("BTM_ReadLocalFeatures");
            if (featSym != null) {
                long fnAddr = loadBias + featSym.cleanOffset();
                byte[] fnCode = procMem.read(fnAddr, (int) Math.max(featSym.stSize, 24L));
                out.add("fn_BTM_ReadLocalFeatures=" + toHex(fnCode));
                Thumb2GetterSim.SimResult res = Thumb2GetterSim.simulate(
                        fnAddr, (int) Math.max(featSym.stSize, 24L), 0L, procMem);
                out.add(String.format(Locale.US,
                        "sim_BTM_ReadLocalFeatures: ok=%s r0=0x%x (rel=0x%x) gotTarget=0x%x (rel=0x%x) reason=%s",
                        Boolean.valueOf(res.ok), Long.valueOf(res.r0), Long.valueOf(res.r0 - loadBias),
                        Long.valueOf(res.gotTarget), Long.valueOf(res.gotTarget > loadBias ? res.gotTarget - loadBias : 0L),
                        res.stopReason));
                if (res.ok && res.r0 > loadBias) {
                    byte[] feat = procMem.read(res.r0, 8);
                    out.add("live_local_features=" + toHex(feat) + " " + decodeLmpFeatures(feat));
                }
            }

            // 3. Simulate BTM_ReadLocalSupportedCommands() -> uint8_t[64] supported HCI command mask
            SymEntry cmdsSym = syms.get("BTM_ReadLocalSupportedCommands");
            if (cmdsSym != null) {
                long fnAddr = loadBias + cmdsSym.cleanOffset();
                byte[] fnCode = procMem.read(fnAddr, (int) Math.max(cmdsSym.stSize, 24L));
                out.add("fn_BTM_ReadLocalSupportedCommands=" + toHex(fnCode));
                Thumb2GetterSim.SimResult res = Thumb2GetterSim.simulate(
                        fnAddr, (int) Math.max(cmdsSym.stSize, 24L), 0L, procMem);
                out.add(String.format(Locale.US,
                        "sim_BTM_ReadLocalSupportedCommands: ok=%s r0=0x%x (rel=0x%x) reason=%s",
                        Boolean.valueOf(res.ok), Long.valueOf(res.r0), Long.valueOf(res.r0 - loadBias),
                        res.stopReason));
                if (res.ok && res.r0 > loadBias) {
                    byte[] cmds = procMem.read(res.r0, 64);
                    out.add("live_supported_cmds_0_31=" + toHexSlice(cmds, 0, 32));
                    out.add("live_supported_cmds_32_63=" + toHexSlice(cmds, 32, 32));
                    out.add("decoded_le_cmds=" + decodeSupportedLeCommands(cmds));
                }
            }

            // 4. Simulate BTM_ReadBrcmFeatures() -> uint8_t[8] Broadcom vendor feature bits
            SymEntry brcmSym = syms.get("BTM_ReadBrcmFeatures");
            if (brcmSym != null) {
                long fnAddr = loadBias + brcmSym.cleanOffset();
                byte[] fnCode = procMem.read(fnAddr, (int) Math.max(brcmSym.stSize, 24L));
                out.add("fn_BTM_ReadBrcmFeatures=" + toHex(fnCode));
                Thumb2GetterSim.SimResult res = Thumb2GetterSim.simulate(
                        fnAddr, (int) Math.max(brcmSym.stSize, 24L), 0L, procMem);
                if (res.ok && res.r0 > loadBias) {
                    byte[] bf = procMem.read(res.r0, 8);
                    out.add(String.format(Locale.US, "live_brcm_features@rel=0x%x=%s",
                            Long.valueOf(res.r0 - loadBias), toHex(bf)));
                }
            }

            // 5. Simulate btm_get_hci_version() & BTM_ReadLocalVersion(&scratch)
            SymEntry hciVerSym = syms.get("btm_get_hci_version");
            if (hciVerSym != null) {
                long fnAddr = loadBias + hciVerSym.cleanOffset();
                byte[] fnCode = procMem.read(fnAddr, (int) Math.max(hciVerSym.stSize, 24L));
                out.add("fn_btm_get_hci_version=" + toHex(fnCode));
                Thumb2GetterSim.SimResult res = Thumb2GetterSim.simulate(
                        fnAddr, (int) Math.max(hciVerSym.stSize, 24L), 0L, procMem);
                out.add("sim_btm_get_hci_version: ok=" + res.ok + " hci_ver=" + res.r0 + " reason=" + res.stopReason);
            }

            SymEntry locVerSym = syms.get("BTM_ReadLocalVersion");
            if (locVerSym != null) {
                long fnAddr = loadBias + locVerSym.cleanOffset();
                byte[] fnCode = procMem.read(fnAddr, (int) Math.max(locVerSym.stSize, 52L));
                out.add("fn_BTM_ReadLocalVersion=" + toHex(fnCode));
                Thumb2GetterSim.SimResult res = Thumb2GetterSim.simulate(
                        fnAddr, (int) Math.max(locVerSym.stSize, 52L), Thumb2GetterSim.SCRATCH_BASE, procMem);
                out.add("sim_BTM_ReadLocalVersion: ok=" + res.ok + " status=" + res.r0
                        + " scratch12=" + toHexSlice(res.scratch, 0, 12)
                        + " " + decodeVersionScratch(res.scratch)
                        + " reason=" + res.stopReason);
            }
        } finally {
            procMem.close();
        }
        return out;
    }

    private static void inspectCallbackTable(List<String> out, SafeProcMem mem, long loadBias,
                                             SymEntry ptrSym, String label, int numWords) {
        if (ptrSym == null) {
            out.add(label + "=SYM_ABSENT");
            return;
        }
        long slotAddr = loadBias + ptrSym.cleanOffset();
        byte[] ptrBytes = mem.read(slotAddr, 4);
        if (ptrBytes == null || ptrBytes.length < 4) {
            out.add(String.format(Locale.US, "%s@0x%x=UNREADABLE", label, Long.valueOf(ptrSym.cleanOffset())));
            return;
        }
        long tablePtr = u32le(ptrBytes, 0);
        StringBuilder sb = new StringBuilder();
        sb.append(String.format(Locale.US, "%s@0x%x -> ptr=0x%x(rel=0x%x)",
                label, Long.valueOf(ptrSym.cleanOffset()), Long.valueOf(tablePtr),
                Long.valueOf(tablePtr > loadBias ? tablePtr - loadBias : 0L)));
        if (tablePtr > 0x10000L) {
            byte[] words = mem.read(tablePtr, numWords * 4);
            if (words != null && words.length >= numWords * 4) {
                sb.append(" words=[");
                for (int i = 0; i < numWords; i++) {
                    if (i > 0) sb.append(", ");
                    long w = u32le(words, i * 4);
                    if (w >= loadBias && w < loadBias + 0x400000L) {
                        sb.append(String.format(Locale.US, "bplus+0x%x", Long.valueOf(w - loadBias)));
                    } else {
                        sb.append(String.format(Locale.US, "0x%x", Long.valueOf(w)));
                    }
                }
                sb.append(']');
            }
        }
        out.add(sb.toString());
    }

    private static void inspectInterfaceGetter(List<String> out, SafeProcMem mem, long loadBias,
                                               SymEntry getterSym, String label, int numWords) {
        if (getterSym == null) return;
        long fnAddr = loadBias + getterSym.cleanOffset();
        Thumb2GetterSim.SimResult res = Thumb2GetterSim.simulate(
                fnAddr, (int) Math.max(getterSym.stSize, 16L), 0L, mem);
        if (!res.ok || res.r0 <= 0x10000L) {
            out.add(label + ": sim_ok=" + res.ok + " reason=" + res.stopReason);
            return;
        }
        byte[] words = mem.read(res.r0, numWords * 4);
        StringBuilder sb = new StringBuilder();
        sb.append(String.format(Locale.US, "%s@rel=0x%x words=[",
                label, Long.valueOf(res.r0 - loadBias)));
        if (words != null) {
            int n = words.length / 4;
            for (int i = 0; i < n; i++) {
                if (i > 0) sb.append(", ");
                long w = u32le(words, i * 4);
                if (w >= loadBias && w < loadBias + 0x400000L) {
                    sb.append(String.format(Locale.US, "bplus+0x%x", Long.valueOf(w - loadBias)));
                } else {
                    sb.append(String.format(Locale.US, "0x%x", Long.valueOf(w)));
                }
            }
        }
        sb.append(']');
        out.add(sb.toString());
    }

    public static String decodeLmpFeatures(byte[] feat) {
        if (feat == null || feat.length < 8) return "INVALID";
        boolean brcmEdr = (feat[3] & 0x06) != 0;
        boolean leController = (feat[4] & 0x40) != 0;
        boolean simulLeBrEdr = (feat[6] & 0x02) != 0;
        boolean extFeatures = (feat[7] & 0x80) != 0;
        return "[LE_SUPPORTED_CONTROLLER=" + leController
                + ", SIMUL_LE_BR_EDR=" + simulLeBrEdr
                + ", EDR=" + brcmEdr
                + ", EXT_FEAT=" + extFeatures + "]";
    }

    public static String decodeSupportedLeCommands(byte[] cmds) {
        if (cmds == null || cmds.length < 29) return "INVALID";
        List<String> names = new ArrayList<String>();
        if ((cmds[5] & 0x40) != 0) names.add("Set_Event_Mask");
        if ((cmds[22] & 0x04) != 0) names.add("Set_Event_Mask_Page2");
        if ((cmds[24] & 0x20) != 0) names.add("Read_LE_Host_Support");
        if ((cmds[24] & 0x40) != 0) names.add("Write_LE_Host_Support");
        if ((cmds[25] & 0x01) != 0) names.add("LE_Set_Event_Mask");
        if ((cmds[25] & 0x02) != 0) names.add("LE_Read_Buffer_Size");
        if ((cmds[25] & 0x04) != 0) names.add("LE_Read_Local_Features");
        if ((cmds[25] & 0x10) != 0) names.add("LE_Set_Random_Addr");
        if ((cmds[25] & 0x20) != 0) names.add("LE_Set_Adv_Params");
        if ((cmds[26] & 0x02) != 0) names.add("LE_Set_Adv_Enable");
        if ((cmds[26] & 0x04) != 0) names.add("LE_Set_Scan_Params");
        if ((cmds[26] & 0x08) != 0) names.add("LE_Set_Scan_Enable");
        if ((cmds[26] & 0x10) != 0) names.add("LE_Create_Conn");
        if ((cmds[26] & 0x20) != 0) names.add("LE_Create_Conn_Cancel");
        if ((cmds[26] & 0x40) != 0) names.add("LE_Read_White_List_Size");
        if ((cmds[27] & 0x02) != 0) names.add("LE_Conn_Update");
        if ((cmds[27] & 0x10) != 0) names.add("LE_Read_Remote_Features");
        if ((cmds[27] & 0x80) != 0) names.add("LE_Read_Supported_States");
        return names.isEmpty() ? "<NONE>" : names.toString();
    }

    private static String decodeVersionScratch(byte[] s) {
        if (s == null || s.length < 10) return "";
        // Bluedroid tBTM_VERSION_INFO: uint8 hci_version, uint16 hci_revision, uint8 lmp_version, uint16 manufacturer, uint16 lmp_subversion
        // Note: with 2-byte struct alignment: [0]=hci_ver, [2..3]=hci_rev, [4]=lmp_ver, [6..7]=manufacturer, [8..9]=lmp_subver
        int hciVer = s[0] & 0xFF;
        int hciRev = (s[2] & 0xFF) | ((s[3] & 0xFF) << 8);
        int lmpVer = s[4] & 0xFF;
        int mfg = (s[6] & 0xFF) | ((s[7] & 0xFF) << 8);
        int lmpSub = (s[8] & 0xFF) | ((s[9] & 0xFF) << 8);
        return String.format(Locale.US,
                "(aligned: hci_ver=%d hci_rev=0x%04x lmp_ver=%d mfg=0x%04x lmp_subver=0x%04x)",
                Integer.valueOf(hciVer), Integer.valueOf(hciRev), Integer.valueOf(lmpVer),
                Integer.valueOf(mfg), Integer.valueOf(lmpSub));
    }

    static List<Vma> parseProcSelfMaps() {
        List<Vma> list = new ArrayList<Vma>();
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader("/proc/self/maps"));
            String line;
            while ((line = br.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.isEmpty()) continue;
                String[] parts = trimmed.split("\\s+", 6);
                if (parts.length < 5) continue;
                int dash = parts[0].indexOf('-');
                if (dash <= 0) continue;
                long start = Long.parseLong(parts[0].substring(0, dash), 16);
                long end = Long.parseLong(parts[0].substring(dash + 1), 16);
                String perms = parts[1];
                long off = Long.parseLong(parts[2], 16);
                String path = (parts.length >= 6) ? parts[5].trim() : "";
                list.add(new Vma(start, end, perms, off, path));
            }
        } catch (Throwable ignored) {
        } finally {
            if (br != null) {
                try { br.close(); } catch (Throwable ignored) {}
            }
        }
        return list;
    }

    static final class SafeProcMem implements Thumb2GetterSim.MemReader {
        private final List<Vma> vmas;
        private RandomAccessFile procMemRaf;
        private Method bridgePeekMethod;

        SafeProcMem(List<Vma> vmas) {
            this.vmas = vmas;
            try {
                File f = new File("/proc/self/mem");
                if (f.exists()) {
                    procMemRaf = new RandomAccessFile(f, "r");
                }
            } catch (Throwable ignored) {
                procMemRaf = null;
            }
            try {
                Class<?> bridgeCls = Class.forName("hmgapi.hook.Bridge", false, ModContext.class.getClassLoader());
                Method m = bridgeCls.getDeclaredMethod("peekNative", long.class, int.class);
                m.setAccessible(true);
                bridgePeekMethod = m;
            } catch (Throwable ignored) {
                bridgePeekMethod = null;
            }
        }

        String describeBackend() {
            if (procMemRaf != null && bridgePeekMethod != null) return "proc_self_mem+bridge_peek";
            if (procMemRaf != null) return "proc_self_mem";
            if (bridgePeekMethod != null) return "bridge_peek";
            return "none";
        }

        boolean isRangeSafeReadable(long addr, int len) {
            if (addr < 0x10000L || len <= 0 || len > 4096) return false;
            long cur = addr;
            long targetEnd = addr + len;
            while (cur < targetEnd) {
                boolean covered = false;
                for (int i = 0; i < vmas.size(); i++) {
                    Vma v = vmas.get(i);
                    if (cur >= v.start && cur < v.end) {
                        if (!v.isSafeReadable()) return false;
                        cur = Math.min(targetEnd, v.end);
                        covered = true;
                        break;
                    }
                }
                if (!covered) return false;
            }
            return true;
        }

        @Override
        public byte[] read(long addr, int len) {
            if (!isRangeSafeReadable(addr, len)) {
                return null;
            }
            if (procMemRaf != null) {
                try {
                    byte[] buf = new byte[len];
                    procMemRaf.seek(addr);
                    procMemRaf.readFully(buf);
                    return buf;
                } catch (Throwable ignored) {
                    // Fall through to Bridge.peekNative if /proc/self/mem read is restricted
                }
            }
            if (bridgePeekMethod != null) {
                try {
                    return (byte[]) bridgePeekMethod.invoke(null, Long.valueOf(addr), Integer.valueOf(len));
                } catch (Throwable ignored) {
                    return null;
                }
            }
            return null;
        }

        void close() {
            if (procMemRaf != null) {
                try { procMemRaf.close(); } catch (Throwable ignored) {}
                procMemRaf = null;
            }
        }
    }

    private static Map<String, SymEntry> loadTargetSymbols(File elfFile) {
        Map<String, SymEntry> map = new HashMap<String, SymEntry>();
        if (elfFile == null || !elfFile.isFile() || !elfFile.canRead() || elfFile.length() > MAX_ELF_BYTES) {
            return map;
        }
        byte[] elf = null;
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(elfFile);
            ByteArrayOutputStream bos = new ByteArrayOutputStream((int) elfFile.length());
            byte[] buf = new byte[16384];
            int n;
            while ((n = fis.read(buf)) > 0) {
                bos.write(buf, 0, n);
            }
            elf = bos.toByteArray();
        } catch (Throwable ignored) {
            return map;
        } finally {
            if (fis != null) {
                try { fis.close(); } catch (Throwable ignored) {}
            }
        }

        if (elf.length < 52 || elf[0] != 0x7F || elf[1] != 'E' || elf[2] != 'L' || elf[3] != 'F' || elf[4] != 1) {
            return map;
        }
        ByteBuffer b = ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);
        int shoff = b.getInt(32);
        int shentsize = b.getShort(46) & 0xFFFF;
        int shnum = b.getShort(48) & 0xFFFF;
        if (shoff <= 0 || shentsize < 40 || shnum <= 0 || (long) shoff + (long) shentsize * shnum > elf.length) {
            return map;
        }

        for (int i = 0; i < shnum; i++) {
            int sh = shoff + i * shentsize;
            int shType = b.getInt(sh + 4);
            if (shType != 11) continue; // SHT_DYNSYM
            int symOff = b.getInt(sh + 16);
            int symSize = b.getInt(sh + 20);
            int strLink = b.getInt(sh + 24);
            int entSize = b.getInt(sh + 36);
            if (entSize < 16 || strLink <= 0 || strLink >= shnum) continue;
            int strSh = shoff + strLink * shentsize;
            int strOff = b.getInt(strSh + 16);
            int strSize = b.getInt(strSh + 20);
            if (symOff <= 0 || strOff <= 0 || symOff + symSize > elf.length || strOff + strSize > elf.length) {
                continue;
            }
            int count = symSize / entSize;
            for (int s = 0; s < count; s++) {
                int so = symOff + s * entSize;
                int stName = b.getInt(so);
                long stVal = b.getInt(so + 4) & 0xFFFFFFFFL;
                long stSz = b.getInt(so + 8) & 0xFFFFFFFFL;
                int stInfo = elf[so + 12] & 0xFF;
                int stShndx = b.getShort(so + 14) & 0xFFFF;
                if (stShndx == 0 || stName <= 0 || stName >= strSize) continue;
                int nameStart = strOff + stName;
                int nameEnd = nameStart;
                int maxEnd = strOff + strSize;
                while (nameEnd < maxEnd && elf[nameEnd] != 0) nameEnd++;
                String symName = new String(elf, nameStart, nameEnd - nameStart, UTF8);
                if (isTargetSymbol(symName)) {
                    map.put(symName, new SymEntry(symName, stVal, stSz, stInfo));
                }
            }
        }
        return map;
    }

    private static boolean isTargetSymbol(String s) {
        return "BTM_ReadLocalFeatures".equals(s)
                || "BTM_ReadLocalSupportedCommands".equals(s)
                || "BTM_ReadLocalExtendedFeatures".equals(s)
                || "BTM_ReadLocalVersion".equals(s)
                || "BTM_ReadBrcmFeatures".equals(s)
                || "btm_get_hci_version".equals(s)
                || "btm_cb".equals(s)
                || "btu_cb".equals(s)
                || "bt_hc_cbacks".equals(s)
                || "bt_vendor_cbacks".equals(s)
                || "bt_hc_get_interface".equals(s)
                || "bluetooth__get_bluetooth_interface".equals(s);
    }

    private static long u32le(byte[] b, int off) {
        return ((long) (b[off] & 0xFF))
                | (((long) (b[off + 1] & 0xFF)) << 8)
                | (((long) (b[off + 2] & 0xFF)) << 16)
                | (((long) (b[off + 3] & 0xFF)) << 24);
    }

    private static String toHex(byte[] b) {
        if (b == null) return "null";
        return toHexSlice(b, 0, b.length);
    }

    private static String toHexSlice(byte[] b, int off, int len) {
        if (b == null || off < 0 || off >= b.length) return "null";
        int n = Math.min(len, b.length - off);
        StringBuilder sb = new StringBuilder(n * 2);
        for (int i = 0; i < n; i++) {
            int v = b[off + i] & 0xFF;
            if (v < 0x10) sb.append('0');
            sb.append(Integer.toHexString(v));
        }
        return sb.toString();
    }
}
