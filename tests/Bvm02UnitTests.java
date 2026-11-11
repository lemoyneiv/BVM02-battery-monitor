import bvm02.app.BleClient;
import bvm02.app.BtStackProbe;
import bvm02.app.Bvm02Protocol;
import bvm02.app.HmgapidClient;
import bvm02.app.ScreenshotHelper;
import bvm02.app.SensorConfig;
import bvm02.hook.BleGattSessionManager;
import bvm02.hook.BtMemInspector;
import bvm02.hook.BtNativeBridge;
import bvm02.hook.Thumb2GetterSim;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Host JVM unit test suite for BVM02 protocol framing, BLE scanRecord parsing,
 * 20-byte ATT multi-chunk reassembly, 12V/24V SoC curves, MAC validation, Telechips BGRA fix,
 * passive ELF32 .dynsym / DT_NEEDED / PT_LOAD parsing, Thumb-2 read-only getter simulation,
 * LMP/HCI LE capability decoding, HCI LE + L2CAP + ATT Central session simulation,
 * hmgapid log slicing, and in-RAM DEX introspection.
 */
public final class Bvm02UnitTests {

    private static int passed = 0;

    private static void assertTrue(String name, boolean cond) {
        if (!cond) {
            throw new AssertionError("FAILED: " + name);
        }
        passed++;
    }

    private static void assertEquals(String name, int expected, int actual) {
        if (expected != actual) {
            throw new AssertionError("FAILED: " + name + " (expected=" + expected + ", actual=" + actual + ")");
        }
        passed++;
    }

    private static void assertEqualsStr(String name, String expected, String actual) {
        if ((expected == null && actual != null) || (expected != null && !expected.equals(actual))) {
            throw new AssertionError("FAILED: " + name + " (expected='" + expected + "', actual='" + actual + "')");
        }
        passed++;
    }

    public static void main(String[] args) throws Exception {
        testFrameCodecAndPinCommands();
        testMultiChunkFrameAssembler();
        testBleTxChunkSplitting();
        testRealtimeVoltageAndTempParser();
        testVersionAndNameParsers();
        testScanRecordParsingAndDeviceFilter();
        testPiecewiseSocAndHealthCurve();
        testSensorConfigValidation();
        testTelechipsBgraSwapDetector();
        testElf32SymbolParserAndMacRedaction();
        testHmgapidLogSlicing();
        testThumb2GetterSimAndCapabilitiesDecoder();
        testBleGattSessionManagerAndAttCentral();
        testInRamDexInventoryParser(args.length > 0 ? args[0] : "build/dex/classes.dex");

        System.out.println("  [OK] Bvm02UnitTests passed all " + passed + " assertions.");
    }

    private static void testFrameCodecAndPinCommands() {
        // Verify default PIN "0000" command 0x36 frame:
        // [0]=0x0F, [1]=7 (4+3), [2]=0x36, [3]=0x00, [4..7]=0,0,0,0, [8]=(1+0x36)=0x37, [9]=0xFF, [10]=0xFF
        byte[] verify0000 = Bvm02Protocol.buildVerifyPasswordCmd("0000");
        assertEquals("verify0000 len", 11, verify0000.length);
        assertEquals("verify0000 header", 0x0F, verify0000[0] & 0xFF);
        assertEquals("verify0000 lenByte", 7, verify0000[1] & 0xFF);
        assertEquals("verify0000 cmd", 0x36, verify0000[2] & 0xFF);
        assertEquals("verify0000 crc", 0x37, verify0000[8] & 0xFF);
        assertEquals("verify0000 tail1", 0xFF, verify0000[9] & 0xFF);
        assertEquals("verify0000 tail2", 0xFF, verify0000[10] & 0xFF);

        Bvm02Protocol.DecodedFrame dec = Bvm02Protocol.decodeCompleteFrame(verify0000);
        assertTrue("decoded non-null", dec != null);
        assertTrue("decoded crc valid", dec.checksumValid);
        assertEquals("decoded cmd", 0x36, dec.cmd);
        assertEquals("decoded payload len", 4, dec.payload.length);

        // Verify PIN "5829" command 0x35 frame
        byte[] set5829 = Bvm02Protocol.buildSetPasswordCmd("5829");
        Bvm02Protocol.DecodedFrame decSet = Bvm02Protocol.decodeCompleteFrame(set5829);
        assertTrue("set5829 crc valid", decSet != null && decSet.checksumValid);
        assertEquals("set5829 d0", 5, decSet.payload[0] & 0xFF);
        assertEquals("set5829 d1", 8, decSet.payload[1] & 0xFF);
        assertEquals("set5829 d2", 2, decSet.payload[2] & 0xFF);
        assertEquals("set5829 d3", 9, decSet.payload[3] & 0xFF);

        // Corrupt checksum byte and confirm checksumValid == false
        byte[] corrupted = set5829.clone();
        corrupted[corrupted.length - 3] ^= 0x01;
        Bvm02Protocol.DecodedFrame bad = Bvm02Protocol.decodeCompleteFrame(corrupted);
        assertTrue("corrupted crc detected", bad != null && !bad.checksumValid);

        // Sync time command (16 bytes total -> fits in single 20-byte ATT write)
        byte[] sync = Bvm02Protocol.buildSyncTimeCmd(1700000000000L, true);
        assertEquals("sync frame length", 16, sync.length);
        Bvm02Protocol.DecodedFrame syncDec = Bvm02Protocol.decodeCompleteFrame(sync);
        assertTrue("sync frame valid", syncDec != null && syncDec.checksumValid && syncDec.cmd == 0x01);

        // PIN validation checks
        assertTrue("valid pin 0000", Bvm02Protocol.isValidPin("0000"));
        assertTrue("valid pin 9182", Bvm02Protocol.isValidPin("9182"));
        assertTrue("reject short pin", !Bvm02Protocol.isValidPin("123"));
        assertTrue("reject alpha pin", !Bvm02Protocol.isValidPin("12A4"));
    }

    private static void testMultiChunkFrameAssembler() {
        // Simulate a 67-byte cranking waveform response (60 bytes voltage + 7 bytes timestamp)
        // arriving across four 20-byte API 19 BLE notifications on 0xFFF4.
        byte[] bigPayload = new byte[67];
        for (int i = 0; i < bigPayload.length; i++) {
            bigPayload[i] = (byte) ((i * 7 + 3) & 0xFF);
        }
        byte[] fullFrame = Bvm02Protocol.buildFrame(Bvm02Protocol.CMD_GET_CRANKING, bigPayload);
        assertEquals("cranking total frame len", 74, fullFrame.length);

        List<byte[]> chunks = Bvm02Protocol.splitIntoBleChunks(fullFrame, 20);
        assertEquals("chunk count for 74B", 4, chunks.size());

        Bvm02Protocol.FrameAssembler assembler = new Bvm02Protocol.FrameAssembler();
        for (int i = 0; i < 3; i++) {
            List<Bvm02Protocol.DecodedFrame> partial = assembler.feed(chunks.get(i));
            assertEquals("no premature frame on chunk " + i, 0, partial.size());
        }
        List<Bvm02Protocol.DecodedFrame> done = assembler.feed(chunks.get(3));
        assertEquals("assembled 1 frame on final chunk", 1, done.size());
        Bvm02Protocol.DecodedFrame f = done.get(0);
        assertTrue("assembled crc ok", f.checksumValid);
        assertEquals("assembled cmd", Bvm02Protocol.CMD_GET_CRANKING, f.cmd);
        assertEquals("assembled payload len", 67, f.payload.length);
        assertEquals("assembled payload last byte", bigPayload[66] & 0xFF, f.payload[66] & 0xFF);

        // Also test leading noise byte before 0x0F + two back-to-back frames
        byte[] f1 = Bvm02Protocol.buildFrame(Bvm02Protocol.CMD_ASYNC_EVENT, new byte[]{0x01});
        byte[] f2 = Bvm02Protocol.buildFrame(Bvm02Protocol.CMD_VERIFY_PASSWORD, new byte[]{0x01});
        byte[] combined = new byte[1 + f1.length + f2.length];
        combined[0] = (byte) 0xAA; // noise byte
        System.arraycopy(f1, 0, combined, 1, f1.length);
        System.arraycopy(f2, 0, combined, 1 + f1.length, f2.length);
        List<Bvm02Protocol.DecodedFrame> twoFrames = assembler.feed(combined);
        assertEquals("decoded 2 back-to-back frames", 2, twoFrames.size());
        assertEquals("frame 1 cmd", 0x20, twoFrames.get(0).cmd);
        assertEquals("frame 2 cmd", 0x36, twoFrames.get(1).cmd);
    }

    private static void testBleTxChunkSplitting() {
        byte[] data45 = new byte[45];
        List<byte[]> parts = Bvm02Protocol.splitIntoBleChunks(data45, 20);
        assertEquals("45B -> 3 chunks", 3, parts.size());
        assertEquals("chunk0=20", 20, parts.get(0).length);
        assertEquals("chunk1=20", 20, parts.get(1).length);
        assertEquals("chunk2=5", 5, parts.get(2).length);
    }

    private static void testRealtimeVoltageAndTempParser() {
        // 12.64V (0x04F0 = 1264), +24C (0x18), 12V (0x00)
        Bvm02Protocol.RealtimeReading r1 = Bvm02Protocol.parseRealtimeVoltage(
                new byte[]{0x04, (byte) 0xF0, 0x18, 0x00});
        assertTrue("r1 non-null", r1 != null);
        assertEquals("r1 centivolts", 1264, r1.centivolts);
        assertTrue("r1 hasTemp", r1.hasTemp);
        assertEquals("r1 tempC", 24, r1.tempCelsius);
        assertTrue("r1 12V", !r1.hardwareIs24V);

        // Sub-zero winter temperature: 12.18V (0x04C2 = 1218), -15C (0xF1), 12V
        Bvm02Protocol.RealtimeReading rWinter = Bvm02Protocol.parseRealtimeVoltage(
                new byte[]{0x04, (byte) 0xC2, (byte) -15, 0x00});
        assertTrue("rWinter hasTemp", rWinter.hasTemp);
        assertEquals("rWinter -15C", -15, rWinter.tempCelsius);

        // No-temperature sentinel 0x80 + 24V flag 0x01 (25.40V = 2540 = 0x09EC)
        Bvm02Protocol.RealtimeReading r24 = Bvm02Protocol.parseRealtimeVoltage(
                new byte[]{0x09, (byte) 0xEC, (byte) 0x80, 0x01});
        assertEquals("r24 centivolts", 2540, r24.centivolts);
        assertTrue("r24 no temp on 0x80", !r24.hasTemp);
        assertTrue("r24 hardwareIs24V", r24.hardwareIs24V);

        // Reject 1-byte malformed payload
        assertTrue("reject 1-byte", Bvm02Protocol.parseRealtimeVoltage(new byte[]{0x04}) == null);
    }

    private static void testVersionAndNameParsers() {
        byte[] verRaw = new byte[14];
        verRaw[11] = 2; // major
        verRaw[12] = 5; // minor -> 2.05
        verRaw[13] = 3; // hw rev 3
        Bvm02Protocol.VersionInfo vi = Bvm02Protocol.parseVersionInfo(verRaw);
        assertTrue("version non-null", vi != null);
        assertEquals("fw * 100", 205, Math.round(vi.firmwareVersion * 100f));
        assertEquals("hw rev", 3, vi.hardwareVersion);

        byte[] nameBytes = new byte[]{'B', 'V', 'M', '0', '2', 0x00, (byte) 0xFF};
        assertEqualsStr("trimmed UTF-8 name", "BVM02", Bvm02Protocol.parseDeviceName(nameBytes));
    }

    private static void testScanRecordParsingAndDeviceFilter() {
        // Construct realistic 31-byte BLE scanRecord:
        // Flags (0x01): 02 01 06
        // Complete 16-bit Service UUIDs (0x03): 03 03 F0 FF (0xFFF0 little-endian)
        // Complete Local Name (0x09): 06 09 'B' 'V' 'M' '0' '2'
        byte[] bvmAdv = new byte[31];
        byte[] prefix = new byte[]{
            0x02, 0x01, 0x06,
            0x03, 0x03, (byte) 0xF0, (byte) 0xFF,
            0x06, 0x09, 'B', 'V', 'M', '0', '2'
        };
        System.arraycopy(prefix, 0, bvmAdv, 0, prefix.length);

        assertEqualsStr("parseAdvertisedName", "BVM02", Bvm02Protocol.parseAdvertisedName(bvmAdv));
        assertTrue("hasAdvertisedServiceFff0", Bvm02Protocol.hasAdvertisedServiceFff0(bvmAdv));
        assertTrue("isLikelyBvm02Device with null getName()", Bvm02Protocol.isLikelyBvm02Device(null, bvmAdv));

        // 128-bit UUID AD Type 0x07 containing 0000fff0-0000-1000-8000-00805f9b34fb (little-endian)
        byte[] uuid128Adv = new byte[]{
            0x11, 0x07,
            (byte) 0xFB, 0x34, (byte) 0x9B, 0x5F, (byte) 0x80, 0x00, 0x00, (byte) 0x80,
            0x00, 0x10, 0x00, 0x00, (byte) 0xF0, (byte) 0xFF, 0x00, 0x00
        };
        assertTrue("128-bit 0xFFF0 match", Bvm02Protocol.hasAdvertisedServiceFff0(uuid128Adv));

        // Known OEM alias names & Victron exclusion
        assertTrue("alias BL-6", Bvm02Protocol.isLikelyBvm02Device("BL-6", null));
        assertTrue("alias CarCell", Bvm02Protocol.isLikelyBvm02Device("CarCell-12V", null));
        assertTrue("alias BatMonitor", Bvm02Protocol.isLikelyBvm02Device("BatMonitor", null));
        assertTrue("exclude Victron SmartBatterySense", !Bvm02Protocol.isLikelyBvm02Device("SmartBatterySense-HQ", null));
        assertTrue("exclude random TPMS", !Bvm02Protocol.isLikelyBvm02Device("TPMS_104", new byte[]{0x02, 0x01, 0x06}));
    }

    private static void testPiecewiseSocAndHealthCurve() {
        // 12V exact breakpoints
        assertEquals("10.20V -> 0%", 0, Bvm02Protocol.computeStateOfChargePercent(1020, false));
        assertEquals("10.50V -> 0%", 0, Bvm02Protocol.computeStateOfChargePercent(1050, false));
        assertEquals("11.30V -> 10%", 10, Bvm02Protocol.computeStateOfChargePercent(1130, false));
        assertEquals("11.60V -> 20%", 20, Bvm02Protocol.computeStateOfChargePercent(1160, false));
        assertEquals("11.90V -> 40%", 40, Bvm02Protocol.computeStateOfChargePercent(1190, false));
        assertEquals("12.10V -> 50%", 50, Bvm02Protocol.computeStateOfChargePercent(1210, false));
        assertEquals("12.20V -> 60%", 60, Bvm02Protocol.computeStateOfChargePercent(1220, false));
        assertEquals("12.30V -> 70%", 70, Bvm02Protocol.computeStateOfChargePercent(1230, false));
        assertEquals("12.40V -> 80%", 80, Bvm02Protocol.computeStateOfChargePercent(1240, false));
        assertEquals("12.50V -> 90%", 90, Bvm02Protocol.computeStateOfChargePercent(1250, false));
        assertEquals("12.60V -> 95%", 95, Bvm02Protocol.computeStateOfChargePercent(1260, false));
        assertEquals("12.70V -> 100%", 100, Bvm02Protocol.computeStateOfChargePercent(1270, false));
        assertEquals("14.10V -> 100%", 100, Bvm02Protocol.computeStateOfChargePercent(1410, false));

        // 24V scaled breakpoints
        assertEquals("24V 21.00V -> 0%", 0, Bvm02Protocol.computeStateOfChargePercent(2100, true));
        assertEquals("24V 24.40V -> 60%", 60, Bvm02Protocol.computeStateOfChargePercent(2440, true));
        assertEquals("24V 25.40V -> 100%", 100, Bvm02Protocol.computeStateOfChargePercent(2540, true));

        // Health classifications
        assertTrue("12.60V HEALTHY", Bvm02Protocol.classifyVoltageStatus(1260, false) == Bvm02Protocol.HealthStatus.HEALTHY);
        assertTrue("14.20V CHARGING", Bvm02Protocol.classifyVoltageStatus(1420, false) == Bvm02Protocol.HealthStatus.CHARGING);
        assertTrue("15.60V OVER_VOLTAGE", Bvm02Protocol.classifyVoltageStatus(1560, false) == Bvm02Protocol.HealthStatus.OVER_VOLTAGE);
        assertTrue("12.00V MODERATE", Bvm02Protocol.classifyVoltageStatus(1200, false) == Bvm02Protocol.HealthStatus.MODERATE);
        assertTrue("11.50V LOW", Bvm02Protocol.classifyVoltageStatus(1150, false) == Bvm02Protocol.HealthStatus.LOW);
        assertTrue("10.80V CRITICAL", Bvm02Protocol.classifyVoltageStatus(1080, false) == Bvm02Protocol.HealthStatus.CRITICAL);
    }

    private static void testSensorConfigValidation() {
        assertTrue("valid upper MAC", SensorConfig.isValidMacAddress("A4:C1:38:09:1B:FF"));
        assertTrue("valid lower MAC", SensorConfig.isValidMacAddress("a4:c1:38:09:1b:ff"));
        assertTrue("reject dash MAC", !SensorConfig.isValidMacAddress("A4-C1-38-09-1B-FF"));
        assertTrue("reject short MAC", !SensorConfig.isValidMacAddress("A4:C1:38:09:1B"));
        assertTrue("reject non-hex MAC", !SensorConfig.isValidMacAddress("G4:C1:38:09:1B:FF"));

        SensorConfig autoCfg = new SensorConfig(0, "a4:c1:38:09:1b:ff", "Starter", "BVM02", "0000", SensorConfig.MODE_AUTO);
        assertEqualsStr("normalized MAC", "A4:C1:38:09:1B:FF", autoCfg.mac);
        assertTrue("auto resolves 12V", !autoCfg.resolveIs24V(false));
        assertTrue("auto resolves 24V", autoCfg.resolveIs24V(true));

        SensorConfig force24 = new SensorConfig(1, "A4:C1:38:09:1B:FF", "", "BVM02", "0000", SensorConfig.MODE_24V);
        assertTrue("force24 overrides 12V hw", force24.resolveIs24V(false));
        assertEqualsStr("fallback display name", "BVM02", force24.getDisplayName());
    }

    private static void testTelechipsBgraSwapDetector() {
        int w = 20, h = 10;
        int[] normalPixels = new int[w * h];
        for (int i = 0; i < normalPixels.length; i++) {
            normalPixels[i] = 0xFF0091FF; // Accent blue (R=0x00, G=0x91, B=0xFF)
        }
        assertTrue("normal blue does NOT trigger swap",
                !ScreenshotHelper.shouldSwapRedBlue(normalPixels, w, h, 0, 0, 10, 10));

        // Simulate Telechips BGRA raw screencap swap: R=0xFF, G=0x91, B=0x00 -> 0xFFFF9100
        int[] swappedPixels = new int[w * h];
        for (int i = 0; i < swappedPixels.length; i++) {
            swappedPixels[i] = 0xFFFF9100;
        }
        assertTrue("swapped orange DOES trigger swap",
                ScreenshotHelper.shouldSwapRedBlue(swappedPixels, w, h, 0, 0, 10, 10));

        ScreenshotHelper.swapRedBlueInPlace(swappedPixels);
        assertEquals("restored R/B channel pixel", 0xFF0091FF, swappedPixels[0]);
    }

    private static void testInRamDexInventoryParser(String dexPath) throws Exception {
        File dexFile = new File(dexPath);
        assertTrue("classes.dex exists for DEX parser test", dexFile.isFile());

        ByteArrayOutputStream bos = new ByteArrayOutputStream((int) dexFile.length());
        FileInputStream fis = new FileInputStream(dexFile);
        try {
            byte[] buf = new byte[8192];
            int n;
            while ((n = fis.read(buf)) >= 0) {
                bos.write(buf, 0, n);
            }
        } finally {
            fis.close();
        }
        byte[] dexBytes = bos.toByteArray();

        List<BtStackProbe.DexClassEntry> classes = BtStackProbe.extractDexInventory(dexBytes);
        assertTrue("extracted >= 8 app classes from classes.dex", classes.size() >= 8);

        BtStackProbe.DexClassEntry protoCls = null;
        BtStackProbe.DexClassEntry probeCls = null;
        BtStackProbe.DexClassEntry bleClientCls = null;
        for (int i = 0; i < classes.size(); i++) {
            BtStackProbe.DexClassEntry ce = classes.get(i);
            if ("bvm02.app.Bvm02Protocol".equals(ce.className)) protoCls = ce;
            if ("bvm02.app.BtStackProbe".equals(ce.className)) probeCls = ce;
            if ("bvm02.app.BleClient".equals(ce.className)) bleClientCls = ce;
            assertTrue("BroadcomGattEnabler absent from classes.dex",
                    !"bvm02.app.BroadcomGattEnabler".equals(ce.className));
        }
        assertTrue("found Bvm02Protocol in DEX inventory", protoCls != null);
        assertTrue("found BtStackProbe in DEX inventory", probeCls != null);
        assertTrue("found BleClient in DEX inventory", bleClientCls != null);
        assertTrue("BleClient instanceFields decoded", !bleClientCls.instanceFields.isEmpty());

        // Verify filtered DEX extraction (used on large system JARs/ODEXes like services.jar)
        List<BtStackProbe.DexClassEntry> filtered = BtStackProbe.extractDexInventory(
                dexBytes, new String[]{"btstackprobe"});
        assertTrue("filtered DEX inventory returns only BtStackProbe classes",
                !filtered.isEmpty() && filtered.size() < classes.size());

        boolean foundParseVolt = false;
        for (int i = 0; i < protoCls.declaredMethods.size(); i++) {
            String sig = protoCls.declaredMethods.get(i);
            if (sig.contains("parseRealtimeVoltage(byte[])")) {
                foundParseVolt = true;
                break;
            }
        }
        assertTrue("DEX parser decoded parseRealtimeVoltage(byte[]) signature", foundParseVolt);

        // Also test Dalvik DexOptHeader ("dey\n036\0") .odex unwrapping
        byte[] fakeOdex = new byte[40 + dexBytes.length + 16];
        fakeOdex[0] = 'd';
        fakeOdex[1] = 'e';
        fakeOdex[2] = 'y';
        fakeOdex[3] = '\n';
        fakeOdex[4] = '0';
        fakeOdex[5] = '3';
        fakeOdex[6] = '6';
        fakeOdex[7] = 0;
        ByteBuffer hdr = ByteBuffer.wrap(fakeOdex).order(ByteOrder.LITTLE_ENDIAN);
        hdr.putInt(8, 40);
        hdr.putInt(12, dexBytes.length);
        System.arraycopy(dexBytes, 0, fakeOdex, 40, dexBytes.length);

        List<BtStackProbe.DexClassEntry> odexClasses = BtStackProbe.extractDexInventory(fakeOdex);
        assertEquals("odex class count matches dex class count", classes.size(), odexClasses.size());

        // Verify Dalvik/ODEX code_item bytecode disassembler (extractDexMethodTraces)
        List<BtStackProbe.DexMethodTrace> traces = BtStackProbe.extractDexMethodTraces(
                fakeOdex,
                new String[]{"bvm02.app.btstackprobe", "bvm02.app.hmgapidclient"},
                new String[]{"checkibluetoothgattstatus", "runmanualserviceandreadlog"},
                null);
        assertTrue("extracted >= 2 targeted method bytecode traces from fakeOdex", traces.size() >= 2);
        boolean sawGetBluetoothGattLiteral = false;
        boolean sawPingLiteral = false;
        for (int i = 0; i < traces.size(); i++) {
            BtStackProbe.DexMethodTrace tr = traces.get(i);
            assertTrue("trace has positive insnsUnits", tr.insnsUnits > 0);
            assertTrue("trace decoded references", !tr.ops.isEmpty());
            for (int j = 0; j < tr.ops.size(); j++) {
                String op = tr.ops.get(j);
                if (op.contains("getBluetoothGatt")) sawGetBluetoothGattLiteral = true;
                if (op.contains("\"ping\"")) sawPingLiteral = true;
            }
        }
        assertTrue("bytecode disassembler decoded getBluetoothGatt string ref", sawGetBluetoothGattLiteral);
        assertTrue("bytecode disassembler decoded HmgapidClient \"ping\" string ref", sawPingLiteral);

        // Malformed / truncated buffers return empty list safely
        assertEquals("reject short buffer", 0, BtStackProbe.extractDexInventory(new byte[10]).size());
        assertEquals("reject short trace buffer", 0,
                BtStackProbe.extractDexMethodTraces(new byte[10], null, null, null).size());
    }

    private static void testElf32SymbolParserAndMacRedaction() {
        // 1. Verify MAC redaction for both colon-delimited and contiguous 12-hex btaddr properties
        assertEqualsStr("redact colon MAC",
                "Adapter [00:92:A5:**:**:**]",
                BtStackProbe.redactMacOctets("Adapter [00:92:A5:27:B2:F4]"));
        assertEqualsStr("redact ro.btaddr 12-hex",
                "[ro.btaddr]: [C8D9D2******]",
                BtStackProbe.redactMacOctets("[ro.btaddr]: [C8D9D2139CD7]"));
        assertEqualsStr("preserve non-addr build host",
                "[ro.build.host]: [cbcd-deploy-050709073412]",
                BtStackProbe.redactMacOctets("[ro.build.host]: [cbcd-deploy-050709073412]"));

        // 2. Synthesize a valid minimal 32-bit ARM (EM_ARM=40) little-endian ELF shared object
        //    including .shstrtab + .rodata + .dynstr + .dynamic + .dynsym
        byte[] dynstrBytes = (
                "\0"
                + "libc.so\0"                  // off 1
                + "libtcc_mbox.so\0"           // off 9
                + "tcc_bt_client_init\0"       // off 24
                + "tcc_bt_gatt_scan_start\0"   // off 43
                + "ioctl\0"                    // off 66
        ).getBytes(Charset.forName("UTF-8"));
        byte[] rodataBytes = (
                "/dev/tcc_bt_dev\0"
                + "Failed to get Bluetooth GATT Interface\0"
        ).getBytes(Charset.forName("UTF-8"));
        byte[] shstrBytes = (
                "\0.dynstr\0.dynamic\0.dynsym\0.rodata\0.shstrtab\0"
        ).getBytes(Charset.forName("UTF-8"));

        byte[] elf = new byte[768];
        ByteBuffer b = ByteBuffer.wrap(elf).order(ByteOrder.LITTLE_ENDIAN);
        elf[0] = 0x7F;
        elf[1] = 'E';
        elf[2] = 'L';
        elf[3] = 'F';
        elf[4] = 1; // ELFCLASS32
        elf[5] = 1; // ELFDATA2LSB
        elf[6] = 1; // EV_CURRENT
        b.putShort(16, (short) 3);   // ET_DYN
        b.putShort(18, (short) 40);  // EM_ARM
        b.putInt(20, 1);             // e_version
        b.putInt(28, 704);           // e_phoff (1 PT_LOAD header x 32B = 32B at 704..736)
        b.putInt(32, 448);           // e_shoff
        b.putShort(40, (short) 52);  // e_ehsize
        b.putShort(42, (short) 32);  // e_phentsize
        b.putShort(44, (short) 1);   // e_phnum
        b.putShort(46, (short) 40);  // e_shentsize
        b.putShort(48, (short) 6);   // e_shnum
        b.putShort(50, (short) 5);   // e_shstrndx

        // Program header [0] PT_LOAD at 704: p_vaddr = 0x10000 -> p_offset = 0, p_filesz = 768
        b.putInt(704, 1);            // PT_LOAD
        b.putInt(708, 0);            // p_offset = 0
        b.putInt(712, 0x00010000);   // p_vaddr = 0x10000
        b.putInt(716, 0x00010000);   // p_paddr
        b.putInt(720, 768);          // p_filesz
        b.putInt(724, 768);          // p_memsz

        // Copy .dynstr at 64, .dynamic at 160, .dynsym at 192, .rodata at 272, .shstrtab at 368
        System.arraycopy(dynstrBytes, 0, elf, 64, dynstrBytes.length);
        System.arraycopy(rodataBytes, 0, elf, 272, rodataBytes.length);
        System.arraycopy(shstrBytes, 0, elf, 368, shstrBytes.length);
        // Write a known uint32 at file offset 352 (vaddr 0x10000 + 352 = 0x10160)
        b.putInt(352, 0x48574D54); // 'HWMT'

        // .dynamic at 160 (3 entries x 8B = 24B)
        b.putInt(160, 1); b.putInt(164, 1);  // DT_NEEDED -> "libc.so"
        b.putInt(168, 1); b.putInt(172, 9);  // DT_NEEDED -> "libtcc_mbox.so"
        b.putInt(176, 0); b.putInt(180, 0);  // DT_NULL

        // .dynsym at 192 (4 entries x 16B = 64B)
        b.putInt(208, 24);
        b.putInt(212, 0x00010111); // Thumb function bit set (vaddr 0x10110 | 1)
        b.putInt(216, 48);
        elf[220] = (byte) ((1 << 4) | 2);
        b.putShort(222, (short) 1);

        b.putInt(224, 43);
        b.putInt(228, 0x00010120); // ARM function (even vaddr)
        b.putInt(232, 64);
        elf[236] = (byte) ((1 << 4) | 2);
        b.putShort(238, (short) 1);

        b.putInt(240, 66);
        b.putInt(244, 0);
        b.putInt(248, 0);
        elf[252] = (byte) ((1 << 4) | 2);
        b.putShort(254, (short) 0);

        // Section headers at 448 (6 x 40B = 240B):
        // [1] .dynstr (name off 1)
        int sh1 = 448 + 40;
        b.putInt(sh1, 1);
        b.putInt(sh1 + 4, 3);
        b.putInt(sh1 + 16, 64);
        b.putInt(sh1 + 20, dynstrBytes.length);

        // [2] .dynamic (name off 9)
        int sh2 = 448 + 80;
        b.putInt(sh2, 9);
        b.putInt(sh2 + 4, 6);
        b.putInt(sh2 + 16, 160);
        b.putInt(sh2 + 20, 24);
        b.putInt(sh2 + 24, 1);
        b.putInt(sh2 + 36, 8);

        // [3] .dynsym (name off 18)
        int sh3 = 448 + 120;
        b.putInt(sh3, 18);
        b.putInt(sh3 + 4, 11);
        b.putInt(sh3 + 16, 192);
        b.putInt(sh3 + 20, 64);
        b.putInt(sh3 + 24, 1);
        b.putInt(sh3 + 36, 16);

        // [4] .rodata (name off 26): sh_type=1 (SHT_PROGBITS), sh_flags=2 (SHF_ALLOC)
        int sh4 = 448 + 160;
        b.putInt(sh4, 26);
        b.putInt(sh4 + 4, 1);
        b.putInt(sh4 + 8, 2);
        b.putInt(sh4 + 16, 272);
        b.putInt(sh4 + 20, rodataBytes.length);

        // [5] .shstrtab (name off 34): sh_type=3 (SHT_STRTAB)
        int sh5 = 448 + 200;
        b.putInt(sh5, 34);
        b.putInt(sh5 + 4, 3);
        b.putInt(sh5 + 16, 368);
        b.putInt(sh5 + 20, shstrBytes.length);

        BtStackProbe.Elf32Info info = BtStackProbe.extractElf32Info(elf);
        assertTrue("ELF32 info non-null", info != null);
        assertEquals("ELF32 machine EM_ARM=40", 40, info.machine);
        assertEquals("DT_NEEDED count", 2, info.neededLibs.size());
        assertEqualsStr("DT_NEEDED[0]", "libc.so", info.neededLibs.get(0));
        assertEqualsStr("DT_NEEDED[1]", "libtcc_mbox.so", info.neededLibs.get(1));

        List<String> exports = BtStackProbe.extractElf32DynamicSymbols(elf);
        assertEquals("exported symbol count", 2, exports.size());
        assertEqualsStr("export[0]", "tcc_bt_client_init", exports.get(0));
        assertEqualsStr("export[1]", "tcc_bt_gatt_scan_start", exports.get(1));

        BtStackProbe.ElfSym initSym = info.exportedSymMap.get("tcc_bt_client_init");
        assertTrue("exportedSymMap contains tcc_bt_client_init", initSym != null);
        assertTrue("tcc_bt_client_init is Thumb func", initSym.isThumbFunc());
        assertEquals("tcc_bt_client_init cleanVaddr", 0x00010110, (int) initSym.cleanVaddr());
        assertEquals("tcc_bt_client_init stSize", 48, (int) initSym.stSize);

        BtStackProbe.ElfSym scanSym = info.exportedSymMap.get("tcc_bt_gatt_scan_start");
        assertTrue("tcc_bt_gatt_scan_start is ARM func", scanSym != null && !scanSym.isThumbFunc());

        // PT_LOAD vaddr -> file offset resolution
        assertEquals("PT_LOAD count", 1, info.loadSegments.size());
        assertEquals("vaddrToFileOffset(0x10110) -> 272", 272, info.vaddrToFileOffset(0x00010110L, elf.length));
        assertEquals("unmapped vaddr -> -1", -1, info.vaddrToFileOffset(0x00900000L, elf.length));
        assertEqualsStr("readCStringAtVaddr(0x10110)", "/dev/tcc_bt_dev", info.readCStringAtVaddr(elf, 0x00010110L));
        assertEquals("readUint32AtVaddr(0x10160)", 0x48574D54, (int) info.readUint32AtVaddr(elf, 0x00010160L));

        assertEquals("imported symbol count", 1, info.importedSymbols.size());
        assertEqualsStr("import[0]", "ioctl", info.importedSymbols.get(0));

        assertEquals("rodata string count", 2, info.rodataStrings.size());
        assertEqualsStr("rodata[0]", "/dev/tcc_bt_dev", info.rodataStrings.get(0));
        assertEqualsStr("rodata[1]", "Failed to get Bluetooth GATT Interface", info.rodataStrings.get(1));

        // 3. Reject malformed / non-ELF32 buffers safely without throwing
        assertTrue("null ELF returns null", BtStackProbe.extractElf32Info(null) == null);
        assertTrue("short ELF returns null", BtStackProbe.extractElf32Info(new byte[16]) == null);
        byte[] elf64 = elf.clone();
        elf64[4] = 2; // ELFCLASS64
        assertTrue("ELF64 rejected cleanly", BtStackProbe.extractElf32Info(elf64) == null);
        assertEquals("short ELF dynamic symbols empty", 0, BtStackProbe.extractElf32DynamicSymbols(new byte[8]).size());
    }

    private static void testHmgapidLogSlicing() {
        String begin = "=== BEGIN BTPROBE ROOT READ-ONLY SNAPSHOT";
        String end = "=== END BTPROBE ROOT READ-ONLY SNAPSHOT ===";
        String twoRuns = begin + " (ts=1000) ===\nBT_PID: 1641\n" + end + "\n"
                + begin + " (ts=1005) ===\nBT_PID: 1641\nBTMAP: /system/lib/hw/bplus.default.so\n" + end + "\n";

        assertEquals("countOccurrences end markers", 2, HmgapidClient.countOccurrences(twoRuns, end));
        assertEquals("countOccurrences empty needle", 0, HmgapidClient.countOccurrences(twoRuns, ""));
        String latest = HmgapidClient.extractLatestRunSlice(twoRuns, begin);
        assertTrue("latest slice starts with ts=1005", latest.startsWith(begin + " (ts=1005)"));
        assertTrue("latest slice includes bplus.default.so", latest.contains("bplus.default.so"));
        assertTrue("latest slice omits ts=1000", !latest.contains("ts=1000"));
    }

    private static void testThumb2GetterSimAndCapabilitiesDecoder() {
        // 1. Verify ARMv7-M/A ThumbExpandImm against real bplus.default.so encoding (05 f5 12 54 -> #9344 = 0x2480)
        assertEquals("ThumbExpandImm(1, 5, 0x12) == 9344", 0x2480,
                (int) Thumb2GetterSim.thumbExpandImm(1, 5, 0x12));
        assertEquals("ThumbExpandImm unrotated 0x42", 0x42,
                (int) Thumb2GetterSim.thumbExpandImm(0, 0, 0x42));
        assertEquals("ThumbExpandImm splat16 0x00AA00AA", 0x00AA00AA,
                (int) Thumb2GetterSim.thumbExpandImm(0, 1, 0xAA));
        assertEquals("ThumbExpandImm splat32 0x55555555", 0x55555555,
                (int) Thumb2GetterSim.thumbExpandImm(0, 3, 0x55));

        final Map<Long, byte[]> pages = new HashMap<Long, byte[]>();
        Thumb2GetterSim.MemReader sparseMem = new Thumb2GetterSim.MemReader() {
            @Override
            public byte[] read(long addr, int len) {
                for (Map.Entry<Long, byte[]> e : pages.entrySet()) {
                    long base = e.getKey().longValue();
                    byte[] data = e.getValue();
                    if (addr >= base && addr + len <= base + data.length) {
                        int off = (int) (addr - base);
                        byte[] slice = new byte[len];
                        System.arraycopy(data, off, slice, 0, len);
                        return slice;
                    }
                }
                return null;
            }
        };

        // 2. Simulate 12-byte PC-relative pointer getter from libbluetooth_jni.so:
        //    01 4b (ldr r3,[pc,#4]) | 7b 44 (add r3,pc) | 18 68 (ldr r0,[r3,#0]) | 70 47 (bx lr) | 3e 66 02 00
        pages.put(Long.valueOf(0x10040000L), new byte[]{
                0x01, 0x4B, 0x7B, 0x44, 0x18, 0x68, 0x70, 0x47,
                0x3E, 0x66, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        });
        // Target pointer at 0x10040006 + 0x0002663e = 0x10066644 -> 0x10051234 (LE)
        pages.put(Long.valueOf(0x10066644L), new byte[]{0x34, 0x12, 0x05, 0x10});

        Thumb2GetterSim.SimResult pcRel = Thumb2GetterSim.simulate(0x10040000L, 12, 0L, sparseMem);
        assertTrue("PC-relative getter ok", pcRel.ok);
        assertEquals("PC-relative getter r0", 0x10051234, (int) pcRel.r0);
        assertEqualsStr("PC-relative stopReason", "bx_lr", pcRel.stopReason);

        // 3. Simulate 24-byte PIC GOT + add.w .bss getter (BTM_ReadLocalFeatures in bplus.default.so)
        pages.put(Long.valueOf(0x20090000L), new byte[]{
                0x03, 0x4B,                         // ldr r3, [pc, #12] -> 0x00102d68
                0x04, 0x4A,                         // ldr r2, [pc, #16] -> 0x00000120
                0x7B, 0x44,                         // add r3, pc        -> 0x20192d70 (_GLOBAL_OFFSET_TABLE_)
                (byte) 0x98, 0x58,                  // ldr r0, [r3, r2]  -> [0x20192e90] = 0x201a5000 (btm_cb)
                0x00, (byte) 0xF5, 0x12, 0x50,      // add.w r0, r0, #0x2480
                0x70, 0x47,                         // bx lr
                0x00, (byte) 0xBF,                  // nop
                0x68, 0x2D, 0x10, 0x00,             // .word 0x00102d68
                0x20, 0x01, 0x00, 0x00              // .word 0x00000120
        });
        pages.put(Long.valueOf(0x20192E90L), new byte[]{0x00, 0x50, 0x1A, 0x20}); // btm_cb = 0x201a5000

        Thumb2GetterSim.SimResult gotRes = Thumb2GetterSim.simulate(0x20090000L, 24, 0L, sparseMem);
        assertTrue("PIC GOT + add.w getter ok", gotRes.ok);
        assertEquals("PIC GOT target (btm_cb)", 0x201A5000, (int) gotRes.gotTarget);
        assertEquals("PIC GOT + 0x2480 r0", 0x201A7480, (int) gotRes.r0);

        // 4. Simulate BTM_ReadLocalVersion(&scratch) writing strictly into SCRATCH_BASE
        pages.put(Long.valueOf(0x20091000L), new byte[]{
                0x06, 0x21,                         // movs r1, #6 (HCI 4.0)
                0x01, 0x70,                         // strb r1, [r0, #0]
                0x41, (byte) 0xF2, 0x34, 0x21,      // movw r1, #0x1234
                0x41, (byte) 0x80,                  // strh r1, [r0, #2]
                0x06, 0x21,                         // movs r1, #6 (LMP 4.0)
                0x01, 0x71,                         // strb r1, [r0, #4]
                0x0F, 0x21,                         // movs r1, #15 (Broadcom 0x000F)
                (byte) 0xC1, (byte) 0x80,           // strh r1, [r0, #6]
                0x44, (byte) 0xF2, 0x09, 0x11,      // movw r1, #0x4109
                0x01, (byte) 0x81,                  // strh r1, [r0, #8]
                0x00, 0x20,                         // movs r0, #0 (BTM_SUCCESS)
                0x70, 0x47                          // bx lr
        });
        Thumb2GetterSim.SimResult verRes = Thumb2GetterSim.simulate(
                0x20091000L, 28, Thumb2GetterSim.SCRATCH_BASE, sparseMem);
        assertTrue("BTM_ReadLocalVersion scratch sim ok", verRes.ok);
        assertEquals("BTM_ReadLocalVersion return BTM_SUCCESS(0)", 0, (int) verRes.r0);
        assertEquals("scratch hci_ver", 6, verRes.scratch[0] & 0xFF);
        assertEquals("scratch hci_rev lo", 0x34, verRes.scratch[2] & 0xFF);
        assertEquals("scratch hci_rev hi", 0x12, verRes.scratch[3] & 0xFF);
        assertEquals("scratch mfg Broadcom(15)", 0x0F, verRes.scratch[6] & 0xFF);
        assertEquals("scratch lmp_subver lo", 0x09, verRes.scratch[8] & 0xFF);
        assertEquals("scratch lmp_subver hi", 0x41, verRes.scratch[9] & 0xFF);

        // 5. Reject any store targeting non-scratch process memory & reject unmapped code safely
        Thumb2GetterSim.SimResult badWrite = Thumb2GetterSim.simulate(0x20091000L, 28, 0x201A5000L, sparseMem);
        assertTrue("store outside SCRATCH_BASE rejected", !badWrite.ok);
        assertTrue("stopReason reports str_imm_outside_scratch",
                badWrite.stopReason.startsWith("str_imm_outside_scratch"));

        Thumb2GetterSim.SimResult unmapped = Thumb2GetterSim.simulate(0x30000000L, 24, 0L, sparseMem);
        assertTrue("unmapped code rejected cleanly", !unmapped.ok);
        assertEqualsStr("unmapped stopReason", "unreadable_code", unmapped.stopReason);

        // 6. Verify LMP features & HCI LE supported command mask decoders
        byte[] lmpLe = new byte[]{(byte) 0xFF, (byte) 0xFE, (byte) 0x8F, (byte) 0xFE, 0x40, 0x00, 0x02, (byte) 0x80};
        String lmpDecoded = BtMemInspector.decodeLmpFeatures(lmpLe);
        assertTrue("LMP LE_SUPPORTED_CONTROLLER=true", lmpDecoded.contains("LE_SUPPORTED_CONTROLLER=true"));
        assertTrue("LMP SIMUL_LE_BR_EDR=true", lmpDecoded.contains("SIMUL_LE_BR_EDR=true"));

        byte[] lmpNoLe = new byte[8];
        assertTrue("LMP LE_SUPPORTED_CONTROLLER=false",
                BtMemInspector.decodeLmpFeatures(lmpNoLe).contains("LE_SUPPORTED_CONTROLLER=false"));

        byte[] hciCmds = new byte[64];
        hciCmds[25] = 0x07; // LE_Set_Event_Mask, LE_Read_Buffer_Size, LE_Read_Local_Features
        hciCmds[26] = 0x1C; // LE_Set_Scan_Params, LE_Set_Scan_Enable, LE_Create_Conn
        String cmdsDecoded = BtMemInspector.decodeSupportedLeCommands(hciCmds);
        assertTrue("decoded LE_Set_Scan_Params", cmdsDecoded.contains("LE_Set_Scan_Params"));
        assertTrue("decoded LE_Set_Scan_Enable", cmdsDecoded.contains("LE_Set_Scan_Enable"));
        assertTrue("decoded LE_Create_Conn", cmdsDecoded.contains("LE_Create_Conn"));
    }

    private static void testBleGattSessionManagerAndAttCentral() throws Exception {
        // 1. Multi-report HCI LE_Advertising_Report parser + ADV_IND / SCAN_RSP AD merger
        byte[] multiAdvEvt = new byte[]{
                0x3E, 30, 0x02, 0x02,
                // Report 0: ADV_IND (0x00), Random addr (0x01), MAC A1:B2:C3:D4:E5:F6 (LE: F6 E5 D4 C3 B2 A1), len=7, Flags + 0xFFF0, RSSI=-58
                0x00, 0x01, (byte) 0xF6, (byte) 0xE5, (byte) 0xD4, (byte) 0xC3, (byte) 0xB2, (byte) 0xA1,
                0x07, 0x02, 0x01, 0x06, 0x03, 0x03, (byte) 0xF0, (byte) 0xFF, (byte) -58,
                // Report 1: SCAN_RSP (0x04), Random addr (0x01), MAC A1:B2:C3:D4:E5:F6, len=6, Name "BVM02", RSSI=-56
                0x04, 0x01, (byte) 0xF6, (byte) 0xE5, (byte) 0xD4, (byte) 0xC3, (byte) 0xB2, (byte) 0xA1,
                0x06, 0x05, 0x09, 'B', 'V', 'M', '0', (byte) -56
        };
        // Fix total param length byte (ev[1] = multiAdvEvt.length - 2)
        multiAdvEvt[1] = (byte) (multiAdvEvt.length - 2);

        List<BleGattSessionManager.AdvReportItem> parsedAdv =
                BleGattSessionManager.parseLeAdvertisingReports(multiAdvEvt);
        assertEquals("multi-report count", 2, parsedAdv.size());
        assertEqualsStr("report[0] MAC", "A1:B2:C3:D4:E5:F6", parsedAdv.get(0).mac);
        assertEquals("report[0] addrType random(1)", 1, parsedAdv.get(0).addrType);
        assertEquals("report[0] rssi -58", -58, parsedAdv.get(0).rssi);
        assertEquals("report[1] rssi -56", -56, parsedAdv.get(1).rssi);

        // 2. UUID codecs & BleClient GATT_READY spec parser
        byte[] btBaseFff4Le = new byte[]{
                (byte) 0xFB, 0x34, (byte) 0x9B, 0x5F, (byte) 0x80, 0x00,
                0x00, (byte) 0x80, 0x00, 0x10, 0x00, 0x00,
                (byte) 0xF4, (byte) 0xFF, 0x00, 0x00
        };
        assertEqualsStr("decodeAttUuid 128-bit BT base -> fff4", "fff4",
                BleGattSessionManager.decodeAttUuid(btBaseFff4Le, 0, 16));
        assertEqualsStr("decodeAttUuid 16-bit -> fff0", "fff0",
                BleGattSessionManager.decodeAttUuid(new byte[]{(byte) 0xF0, (byte) 0xFF}, 0, 2));

        Map<UUID, Integer> specs = BleClient.parseGattReadySpecs("fff1:02,fff2:02,fff3:0c,fff4:10,fff6:02");
        assertEquals("parsed 5 BVM02 char specs", 5, specs.size());
        assertEquals("fff3 props 0x0c", 0x0C, specs.get(Bvm02Protocol.UUID_CMD_WRITE).intValue());
        assertEqualsStr("shortHexUuid UUID_READ_VOLTAGE", "fff2",
                BleClient.shortHexUuid(Bvm02Protocol.UUID_READ_VOLTAGE));

        // 3. Full simulated Broadcom Controller + BVM02 Peripheral <-> BleGattSessionManager E2E test
        final BleGattSessionManager[] mgrRef = new BleGattSessionManager[1];
        final List<Integer> seenHciOpcodes = Collections.synchronizedList(new ArrayList<Integer>());
        final List<byte[]> seenSignalingPdus = Collections.synchronizedList(new ArrayList<byte[]>());
        final List<byte[]> seenAttPdus = Collections.synchronizedList(new ArrayList<byte[]>());
        final int[] lastConnPeerAddrType = new int[]{-1};

        BtNativeBridge.Transport simTransport = new BtNativeBridge.Transport() {
            @Override
            public boolean sendHciCommand(final byte[] hciCmd) {
                final int opcode = BleGattSessionManager.u16le(hciCmd, 0);
                seenHciOpcodes.add(Integer.valueOf(opcode));
                Thread responder = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        BleGattSessionManager mgr = mgrRef[0];
                        if (opcode == BleGattSessionManager.HCI_LE_READ_BUFFER_SIZE) {
                            // Status=0, LE_ACL_Len=27 (0x001B), Num_LE_Pkts=3
                            mgr.onHciEvent(new byte[]{
                                    0x0E, 0x07, 0x01,
                                    (byte) (opcode & 0xFF), (byte) ((opcode >> 8) & 0xFF),
                                    0x00, 0x1B, 0x00, 0x03
                            });
                        } else if (opcode == BleGattSessionManager.HCI_LE_CREATE_CONNECTION) {
                            lastConnPeerAddrType[0] = hciCmd[3 + 5] & 0xFF;
                            // Command_Status (0x0F) status=0
                            mgr.onHciEvent(new byte[]{
                                    0x0F, 0x04, 0x00, 0x01,
                                    (byte) (opcode & 0xFF), (byte) ((opcode >> 8) & 0xFF)
                            });
                            // LE_Connection_Complete (0x3E / sub 0x01): status=0, handle=0x0040
                            byte[] cc = new byte[19];
                            cc[0] = 0x3E; cc[1] = 17; cc[2] = 0x01; cc[3] = 0x00;
                            cc[4] = 0x40; cc[5] = 0x00; // handle 0x0040
                            cc[6] = 0x00; cc[7] = (byte) lastConnPeerAddrType[0];
                            System.arraycopy(hciCmd, 3 + 6, cc, 8, 6);
                            mgr.onHciEvent(cc);
                        } else {
                            mgr.onHciEvent(new byte[]{
                                    0x0E, 0x04, 0x01,
                                    (byte) (opcode & 0xFF), (byte) ((opcode >> 8) & 0xFF),
                                    0x00
                            });
                        }
                    }
                });
                responder.setDaemon(true);
                responder.start();
                return true;
            }

            @Override
            public boolean sendLeAcl(final byte[] aclPkt) {
                Thread responder = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        BleGattSessionManager mgr = mgrRef[0];
                        int handle = BleGattSessionManager.u16le(aclPkt, 0) & 0x0FFF;
                        int l2capLen = BleGattSessionManager.u16le(aclPkt, 4);
                        int cid = BleGattSessionManager.u16le(aclPkt, 6);
                        byte[] pdu = new byte[l2capLen];
                        System.arraycopy(aclPkt, 8, pdu, 0, l2capLen);

                        // Replenish 1 HCI ACL credit via Number_Of_Completed_Packets (0x13)
                        mgr.onHciEvent(new byte[]{
                                0x13, 0x05, 0x01,
                                (byte) (handle & 0xFF), (byte) ((handle >> 8) & 0xFF),
                                0x01, 0x00
                        });

                        if (cid == BleGattSessionManager.L2CAP_CID_LE_SIGNALING) {
                            seenSignalingPdus.add(pdu);
                            return;
                        }
                        if (cid != BleGattSessionManager.L2CAP_CID_ATT) {
                            return;
                        }
                        seenAttPdus.add(pdu);
                        int op = pdu[0] & 0xFF;

                        if (op == BleGattSessionManager.ATT_READ_BY_GROUP_TYPE_REQ) {
                            int startH = BleGattSessionManager.u16le(pdu, 1);
                            if (startH <= 0x0010) {
                                // Primary service 0xFFF0 at handles 0x0010..0x001F
                                sendInboundL2capSingle(mgr, handle, BleGattSessionManager.L2CAP_CID_ATT, new byte[]{
                                        (byte) BleGattSessionManager.ATT_READ_BY_GROUP_TYPE_RSP, 0x06,
                                        0x10, 0x00, 0x1F, 0x00, (byte) 0xF0, (byte) 0xFF
                                });
                            } else {
                                sendInboundL2capSingle(mgr, handle, BleGattSessionManager.L2CAP_CID_ATT, new byte[]{
                                        0x01, 0x10, (byte) (startH & 0xFF), (byte) (startH >> 8), 0x0A
                                });
                            }
                        } else if (op == BleGattSessionManager.ATT_READ_BY_TYPE_REQ) {
                            int startH = BleGattSessionManager.u16le(pdu, 1);
                            if (startH <= 0x0011) {
                                // Return fff1(0x0012, RD), fff2(0x0014, RD), fff3(0x0016, WR|WNR)
                                sendInboundL2capSingle(mgr, handle, BleGattSessionManager.L2CAP_CID_ATT, new byte[]{
                                        (byte) BleGattSessionManager.ATT_READ_BY_TYPE_RSP, 0x07,
                                        0x11, 0x00, 0x02, 0x12, 0x00, (byte) 0xF1, (byte) 0xFF,
                                        0x13, 0x00, 0x02, 0x14, 0x00, (byte) 0xF2, (byte) 0xFF,
                                        0x15, 0x00, 0x0C, 0x16, 0x00, (byte) 0xF3, (byte) 0xFF
                                });
                            } else if (startH <= 0x0017) {
                                // Return fff4(0x0018, NOTIFY, CCCD at 0x0019), fff6(0x001B, RD)
                                sendInboundL2capSingle(mgr, handle, BleGattSessionManager.L2CAP_CID_ATT, new byte[]{
                                        (byte) BleGattSessionManager.ATT_READ_BY_TYPE_RSP, 0x07,
                                        0x17, 0x00, 0x10, 0x18, 0x00, (byte) 0xF4, (byte) 0xFF,
                                        0x1A, 0x00, 0x02, 0x1B, 0x00, (byte) 0xF6, (byte) 0xFF
                                });
                            } else {
                                sendInboundL2capSingle(mgr, handle, BleGattSessionManager.L2CAP_CID_ATT, new byte[]{
                                        0x01, 0x08, (byte) (startH & 0xFF), (byte) (startH >> 8), 0x0A
                                });
                            }
                        } else if (op == BleGattSessionManager.ATT_FIND_INFO_REQ) {
                            // Descriptor 0x2902 at handle 0x0019
                            sendInboundL2capSingle(mgr, handle, BleGattSessionManager.L2CAP_CID_ATT, new byte[]{
                                    (byte) BleGattSessionManager.ATT_FIND_INFO_RSP, 0x01,
                                    0x19, 0x00, 0x02, 0x29
                            });
                        } else if (op == BleGattSessionManager.ATT_READ_REQ) {
                            int valH = BleGattSessionManager.u16le(pdu, 1);
                            if (valH == 0x0014) { // 0xFFF2 voltage: 1264 cV (0x04F0 LE = F0 04), 23C (0x00, 0x17), 12V (0x00)
                                byte[] readRsp = new byte[]{
                                        (byte) BleGattSessionManager.ATT_READ_RSP,
                                        (byte) 0xF0, 0x04, 0x00, 0x17, 0x00
                                };
                                // Exercise 2-fragment L2CAP reassembly (PB=0x02 first + PB=0x01 continuation)!
                                sendInboundL2capFragmented(mgr, handle, BleGattSessionManager.L2CAP_CID_ATT, readRsp, 3);
                            }
                        } else if (op == BleGattSessionManager.ATT_WRITE_REQ) {
                            sendInboundL2capSingle(mgr, handle, BleGattSessionManager.L2CAP_CID_ATT, new byte[]{
                                    (byte) BleGattSessionManager.ATT_WRITE_RSP
                            });
                        }
                    }
                });
                responder.setDaemon(true);
                responder.start();
                return true;
            }

            @Override
            public void setFilterState(boolean listening, int activeLeHandle) {}
        };

        BleGattSessionManager simMgr = new BleGattSessionManager(simTransport);
        mgrRef[0] = simMgr;

        final List<String> emittedLines = Collections.synchronizedList(new ArrayList<String>());
        BleGattSessionManager.LineEmitter collector = new BleGattSessionManager.LineEmitter() {
            @Override
            public void emitLine(String line) {
                emittedLines.add(line);
            }
        };

        // Step A: Feed ADV_IND + SCAN_RSP for BVM02 sensor at A1:B2:C3:D4:E5:F6 (Random addrType=1)
        byte[] adv1 = simMgr.updateAdvCacheAndMerge(new BleGattSessionManager.AdvReportItem(
                0x00, 1, "A1:B2:C3:D4:E5:F6",
                new byte[]{0x02, 0x01, 0x06, 0x03, 0x03, (byte) 0xF0, (byte) 0xFF}, -58));
        byte[] advMerged = simMgr.updateAdvCacheAndMerge(new BleGattSessionManager.AdvReportItem(
                0x04, 1, "A1:B2:C3:D4:E5:F6",
                new byte[]{0x06, 0x09, 'B', 'V', 'M', '0', '2'}, -56));
        assertTrue("ADV_IND alone has 0xFFF0", Bvm02Protocol.hasAdvertisedServiceFff0(adv1));
        assertEqualsStr("Merged ADV+SCAN_RSP name is BVM02", "BVM02",
                Bvm02Protocol.parseAdvertisedName(advMerged));
        assertTrue("Merged ADV+SCAN_RSP matches BVM02 filter",
                Bvm02Protocol.isLikelyBvm02Device("BVM02", advMerged));

        // Step B: SCAN_START & SCAN_STOP
        simMgr.executeSessionCommand(null, "SCAN_START", collector);
        assertTrue("emitted SCAN_STATE 1", emittedLines.contains("SCAN_STATE 1"));
        simMgr.executeSessionCommand(null, "SCAN_STOP", collector);
        assertTrue("emitted SCAN_STATE 0", emittedLines.contains("SCAN_STATE 0"));

        // Step C: CONNECT with addrType=-1 (verifies cached Random addrType=1 is automatically used!)
        emittedLines.clear();
        simMgr.executeSessionCommand(null, "CONNECT A1:B2:C3:D4:E5:F6 -1", collector);
        assertEquals("used cached Random peerAddrType=1", 1, lastConnPeerAddrType[0]);
        boolean sawGattReady = false;
        for (String l : emittedLines) {
            if (l.startsWith("GATT_READY A1:B2:C3:D4:E5:F6 ")) {
                sawGattReady = true;
                assertTrue("GATT_READY contains fff2:02 and fff4:10",
                        l.contains("fff2:02") && l.contains("fff4:10") && l.contains("fff3:0c"));
            }
        }
        assertTrue("CONNECT + ATT discovery emitted GATT_READY", sawGattReady);

        // Step D: ENABLE_NOTIFY fff4, fragmented READ_CHAR fff2, read-only fff1 write block, WRITE_CHAR fff3
        emittedLines.clear();
        simMgr.executeSessionCommand(null, "ENABLE_NOTIFY fff4", collector);
        assertTrue("ENABLE_NOTIFY fff4 succeeded", emittedLines.contains("OP_OK ENABLE_NOTIFY fff4"));

        emittedLines.clear();
        simMgr.executeSessionCommand(null, "READ_CHAR fff2", collector);
        assertTrue("fragmented L2CAP READ_CHAR fff2 reassembled cleanly",
                emittedLines.contains("OP_OK READ_CHAR fff2 f004001700"));

        emittedLines.clear();
        simMgr.executeSessionCommand(null, "WRITE_CHAR fff1 deadbeef", collector);
        assertTrue("WRITE_CHAR fff1 strictly rejected",
                emittedLines.contains("OP_ERR WRITE_CHAR fff1 FORBIDDEN_READ_ONLY_FFF1"));

        emittedLines.clear();
        simMgr.executeSessionCommand(null, "WRITE_CHAR fff3 aa3604303030309e", collector);
        assertTrue("WRITE_CHAR fff3 succeeded", emittedLines.contains("OP_OK WRITE_CHAR fff3"));

        // Step E: Peripheral L2CAP_CID_LE_SIGNALING (0x0005) Conn_Param_Update_Req (0x12)
        sendInboundL2capSingle(simMgr, 0x0040, BleGattSessionManager.L2CAP_CID_LE_SIGNALING, new byte[]{
                0x12, 0x07, 0x08, 0x00,
                0x18, 0x00, 0x28, 0x00, 0x00, 0x00, (byte) 0x90, 0x01
        });
        Thread.sleep(60L);
        assertEquals("sent L2CAP Conn_Param_Update_Rsp on CID 0x0005", 1, seenSignalingPdus.size());
        assertEquals("L2CAP rsp code 0x13", 0x13, seenSignalingPdus.get(0)[0] & 0xFF);
        assertTrue("issued HCI_LE_Connection_Update (0x2013)",
                seenHciOpcodes.contains(Integer.valueOf(BleGattSessionManager.HCI_LE_CONNECTION_UPDATE)));

        // Step F: Peripheral ATT_HANDLE_VALUE_IND (0x1D) -> immediate ATT_HANDLE_VALUE_CFM (0x1E)
        seenAttPdus.clear();
        simMgr.executeSessionCommand(null, "DISCONNECT", collector);
        assertTrue("issued HCI_Disconnect (0x0406)",
                seenHciOpcodes.contains(Integer.valueOf(BleGattSessionManager.HCI_DISCONNECT)));
    }

    private static void sendInboundL2capSingle(BleGattSessionManager mgr, int handle, int cid, byte[] pdu) {
        int aclLen = 4 + pdu.length;
        byte[] acl = new byte[4 + aclLen];
        acl[0] = (byte) (handle & 0xFF);
        acl[1] = (byte) (((handle >> 8) & 0x0F) | 0x20); // PB = 0x02 (First packet of L2CAP SDU)
        acl[2] = (byte) (aclLen & 0xFF);
        acl[3] = (byte) ((aclLen >> 8) & 0xFF);
        acl[4] = (byte) (pdu.length & 0xFF);
        acl[5] = (byte) ((pdu.length >> 8) & 0xFF);
        acl[6] = (byte) (cid & 0xFF);
        acl[7] = (byte) ((cid >> 8) & 0xFF);
        System.arraycopy(pdu, 0, acl, 8, pdu.length);
        mgr.onLeAcl(acl);
    }

    private static void sendInboundL2capFragmented(BleGattSessionManager mgr, int handle, int cid,
                                                   byte[] pdu, int firstPayloadBytes) {
        int part1 = Math.min(firstPayloadBytes, pdu.length);
        int part2 = pdu.length - part1;
        int acl1Len = 4 + part1;
        byte[] acl1 = new byte[4 + acl1Len];
        acl1[0] = (byte) (handle & 0xFF);
        acl1[1] = (byte) (((handle >> 8) & 0x0F) | 0x20); // PB = 0x02 (Start)
        acl1[2] = (byte) (acl1Len & 0xFF);
        acl1[3] = 0x00;
        acl1[4] = (byte) (pdu.length & 0xFF);
        acl1[5] = (byte) ((pdu.length >> 8) & 0xFF);
        acl1[6] = (byte) (cid & 0xFF);
        acl1[7] = (byte) ((cid >> 8) & 0xFF);
        System.arraycopy(pdu, 0, acl1, 8, part1);
        mgr.onLeAcl(acl1);

        if (part2 > 0) {
            byte[] acl2 = new byte[4 + part2];
            acl2[0] = (byte) (handle & 0xFF);
            acl2[1] = (byte) (((handle >> 8) & 0x0F) | 0x10); // PB = 0x01 (Continuation)
            acl2[2] = (byte) (part2 & 0xFF);
            acl2[3] = 0x00;
            System.arraycopy(pdu, part1, acl2, 4, part2);
            mgr.onLeAcl(acl2);
        }
    }
}
