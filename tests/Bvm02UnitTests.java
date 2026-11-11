import bvm02.app.BroadcomGattEnabler;
import bvm02.app.BtStackProbe;
import bvm02.app.Bvm02Protocol;
import bvm02.app.ScreenshotHelper;
import bvm02.app.SensorConfig;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Host JVM unit test suite for BVM02 protocol framing, BLE scanRecord parsing,
 * 20-byte ATT multi-chunk reassembly, 12V/24V SoC curves, MAC validation, Telechips BGRA fix,
 * Broadcom RadioManager dynamic Proxy safety, and in-RAM Dalvik DEX / ODEX introspection.
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
        testBroadcomProxyAndMacRedaction();
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
        assertTrue("extracted >= 9 app classes from classes.dex", classes.size() >= 9);

        BtStackProbe.DexClassEntry protoCls = null;
        BtStackProbe.DexClassEntry probeCls = null;
        BtStackProbe.DexClassEntry enablerCls = null;
        for (int i = 0; i < classes.size(); i++) {
            BtStackProbe.DexClassEntry ce = classes.get(i);
            if ("bvm02.app.Bvm02Protocol".equals(ce.className)) protoCls = ce;
            if ("bvm02.app.BtStackProbe".equals(ce.className)) probeCls = ce;
            if ("bvm02.app.BroadcomGattEnabler".equals(ce.className)) enablerCls = ce;
        }
        assertTrue("found Bvm02Protocol in DEX inventory", protoCls != null);
        assertTrue("found BtStackProbe in DEX inventory", probeCls != null);
        assertTrue("found BroadcomGattEnabler in DEX inventory", enablerCls != null);
        assertTrue("BroadcomGattEnabler instanceFields decoded", !enablerCls.instanceFields.isEmpty());

        // Verify filtered DEX extraction (used on large system JARs/ODEXes like services.jar)
        List<BtStackProbe.DexClassEntry> filtered = BtStackProbe.extractDexInventory(
                dexBytes, new String[]{"broadcomgattenabler"});
        assertTrue("filtered DEX inventory returns only BroadcomGattEnabler classes",
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

        // Malformed / truncated buffers return empty list safely
        assertEquals("reject short buffer", 0, BtStackProbe.extractDexInventory(new byte[10]).size());
    }

    public interface MockRadioCallback {
        void onRadioStateChange(boolean enabled);
        boolean checkFlag();
        int getCode();
    }

    private static void testBroadcomProxyAndMacRedaction() {
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

        // 2. Verify BroadcomGattEnabler dynamic Proxy Object identity semantics in ArrayList & HashMap
        ClassLoader cl = Bvm02UnitTests.class.getClassLoader();
        MockRadioCallback p1 = (MockRadioCallback) BroadcomGattEnabler.createDetachedCallbackProxy(
                cl, MockRadioCallback.class, "TestRadioCb");
        MockRadioCallback p2 = (MockRadioCallback) BroadcomGattEnabler.createDetachedCallbackProxy(
                cl, MockRadioCallback.class, "TestRadioCb");

        assertTrue("proxy equals self", p1.equals(p1));
        assertTrue("proxy not equal to distinct proxy", !p1.equals(p2));
        assertTrue("proxy not equal to null", !p1.equals(null));
        assertTrue("proxy toString contains label", p1.toString().startsWith("TestRadioCb@"));

        List<MockRadioCallback> list = new ArrayList<MockRadioCallback>();
        list.add(p1);
        assertTrue("ArrayList contains p1", list.contains(p1));
        assertTrue("ArrayList does not contain p2", !list.contains(p2));

        Map<MockRadioCallback, String> map = new HashMap<MockRadioCallback, String>();
        map.put(p1, "BLE");
        assertEqualsStr("HashMap lookup p1", "BLE", map.get(p1));
        assertTrue("HashMap lookup p2 is null", map.get(p2) == null);

        // Primitive return safety (never throws NullPointerException on unboxing)
        p1.onRadioStateChange(true);
        assertTrue("primitive boolean default false", !p1.checkFlag());
        assertEquals("primitive int default 0", 0, p1.getCode());
    }
}
