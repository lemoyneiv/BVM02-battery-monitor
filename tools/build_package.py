#!/usr/bin/env python3
"""BVM02 Battery Monitor for Gen5W — Cross-Platform APK & Mod Build Pipeline."""
import glob
import os
import shutil
import subprocess
import sys
import zipfile

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

is_win = sys.platform.startswith("win")
exe_suffix = ".exe" if is_win else ""

java_home = os.environ.get("JAVA_HOME")
if not java_home or not os.path.isdir(java_home):
    candidate_homes = [
        os.path.abspath(os.path.join(BASE_DIR, "..", "tools", "jdk-17")),
        os.path.expanduser("~/tools/jdk-17"),
        r"C:\Program Files\Microsoft\jdk-17.0.21.21-hotspot",
    ]
    java_home = next((d for d in candidate_homes if os.path.isdir(d)), "")

JDK_BIN = os.path.join(java_home, "bin") if java_home else ""
JAVA = (
    os.path.join(JDK_BIN, f"java{exe_suffix}")
    if JDK_BIN and os.path.isfile(os.path.join(JDK_BIN, f"java{exe_suffix}"))
    else (shutil.which("java") or "java")
)
JAVAC = (
    os.path.join(JDK_BIN, f"javac{exe_suffix}")
    if JDK_BIN and os.path.isfile(os.path.join(JDK_BIN, f"javac{exe_suffix}"))
    else (shutil.which("javac") or "javac")
)
KEYTOOL = (
    os.path.join(JDK_BIN, f"keytool{exe_suffix}")
    if JDK_BIN and os.path.isfile(os.path.join(JDK_BIN, f"keytool{exe_suffix}"))
    else (shutil.which("keytool") or "keytool")
)

SDK_DIR = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
if not SDK_DIR or not os.path.isdir(SDK_DIR):
    candidate_sdk = [
        os.path.abspath(os.path.join(BASE_DIR, "..", "tools", "android-sdk")),
        os.path.expanduser("~/tools/android-sdk"),
    ]
    SDK_DIR = next((d for d in candidate_sdk if os.path.isdir(d)), candidate_sdk[0])

ANDROID_JAR = os.path.join(SDK_DIR, "platforms", "android-19", "android.jar")
BT_DIR = os.path.join(SDK_DIR, "build-tools", "30.0.3")

if not os.path.isfile(ANDROID_JAR) or not os.path.isdir(BT_DIR):
    print("Android SDK API 19 / Build-Tools 30.0.3 not found; bootstrapping...")
    subprocess.run([sys.executable, os.path.join(BASE_DIR, "tools", "setup_android_sdk.py")], check=True)

AAPT = os.path.join(BT_DIR, f"aapt{exe_suffix}")
ZIPALIGN = os.path.join(BT_DIR, f"zipalign{exe_suffix}")
D8_JAR = os.path.join(BT_DIR, "lib", "d8.jar")
APKSIGNER_JAR = os.path.join(BT_DIR, "lib", "apksigner.jar")

KEYS_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "build", "keys"))
AUTHOR_KEY = os.path.join(KEYS_DIR, "author.key")
APP_KEYSTORE = os.path.join(KEYS_DIR, "bvm02-app.keystore")

BUILD_DIR = os.path.join(BASE_DIR, "build")
DIST_DIR = os.path.join(BASE_DIR, "dist")

if java_home:
    os.environ["JAVA_HOME"] = java_home
path_parts = [p for p in [JDK_BIN, BT_DIR, os.environ.get("PATH", "")] if p]
os.environ["PATH"] = os.pathsep.join(path_parts)

print("=== BVM02 Battery Monitor Gen5W Build System ===")
print("Base directory:", BASE_DIR)
print("Android JAR:   ", ANDROID_JAR)
print("Build Tools:   ", BT_DIR)

shutil.rmtree(BUILD_DIR, ignore_errors=True)
os.makedirs(os.path.join(BUILD_DIR, "gen"), exist_ok=True)
os.makedirs(os.path.join(BUILD_DIR, "classes"), exist_ok=True)
os.makedirs(os.path.join(BUILD_DIR, "dex"), exist_ok=True)
os.makedirs(DIST_DIR, exist_ok=True)

# Ensure icons exist
if not os.path.isfile(os.path.join(BASE_DIR, "mod", "icons", "tile.png")):
    subprocess.run([sys.executable, os.path.join(BASE_DIR, "tools", "generate_icons.py")], check=True)

# 1. Generate R.java with aapt
print("\n[1/6] Generating R.java via aapt...")
cmd_gen_r = [
    AAPT,
    "package",
    "-m",
    "-J",
    os.path.join(BUILD_DIR, "gen"),
    "-M",
    os.path.join(BASE_DIR, "app", "AndroidManifest.xml"),
    "-S",
    os.path.join(BASE_DIR, "app", "res"),
    "-I",
    ANDROID_JAR,
]
subprocess.run(cmd_gen_r, check=True)
r_java_files = glob.glob(os.path.join(BUILD_DIR, "gen", "**", "R.java"), recursive=True)
print("  Generated R.java:", r_java_files)

# 2. Compile Java Sources
print("\n[2/6] Compiling Java sources with javac (target: Java 8)...")
java_srcs = sorted(glob.glob(os.path.join(BASE_DIR, "app", "src", "**", "*.java"), recursive=True)) + r_java_files
lib_jars = sorted(glob.glob(os.path.join(BASE_DIR, "app", "libs", "*.jar")))
classpath = ANDROID_JAR
if lib_jars:
    classpath = classpath + os.pathsep + os.pathsep.join(lib_jars)
    print("  Classpath libraries:", lib_jars)

cmd_javac = [
    JAVAC,
    "--release",
    "8",
    "-nowarn",
    "-Xlint:-options",
    "-cp",
    classpath,
    "-d",
    os.path.join(BUILD_DIR, "classes"),
] + java_srcs
subprocess.run(cmd_javac, check=True)
print("  Compiled", len(java_srcs), "Java source files.")

# 3. Shrink, optimize & convert class files to Dalvik dex (min-api 19) via R8
print("\n[3/6] Shrinking & converting bytecode to Dalvik DEX via R8 (min-api 19)...")
class_files = []
for root, _, files in os.walk(os.path.join(BUILD_DIR, "classes")):
    for f in sorted(files):
        if f.endswith(".class"):
            class_files.append(os.path.join(root, f))

proguard_rules = os.path.join(BASE_DIR, "tools", "proguard-rules.pro")
cmd_r8 = [
    JAVA,
    "-cp",
    D8_JAR,
    "com.android.tools.r8.R8",
    "--release",
    "--min-api",
    "19",
    "--lib",
    ANDROID_JAR,
    "--pg-conf",
    proguard_rules,
    "--output",
    os.path.join(BUILD_DIR, "dex"),
] + lib_jars + class_files
subprocess.run(cmd_r8, check=True)
dex_file = os.path.join(BUILD_DIR, "dex", "classes.dex")
print("  Generated classes.dex (", os.path.getsize(dex_file), "bytes)")

# 4. Package resources with aapt
print("\n[4/6] Packaging APK resources via aapt...")
unsigned_apk = os.path.join(BUILD_DIR, "unsigned.apk")
cmd_aapt = [
    AAPT,
    "package",
    "-f",
    "-M",
    os.path.join(BASE_DIR, "app", "AndroidManifest.xml"),
    "-S",
    os.path.join(BASE_DIR, "app", "res"),
    "-I",
    ANDROID_JAR,
    "-F",
    unsigned_apk,
]
subprocess.run(cmd_aapt, check=True)

with zipfile.ZipFile(unsigned_apk, "a", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    z.write(dex_file, "classes.dex", compress_type=zipfile.ZIP_DEFLATED)
print("  Injected classes.dex into APK.")

# 5. Zipalign & Sign APK (strictly v1 JAR signature for Android 4.4.2 KitKat)
print("\n[5/6] Zipaligning & signing APK (v1 JAR signature)...")
aligned_apk = os.path.join(BUILD_DIR, "aligned.apk")
subprocess.run([ZIPALIGN, "-f", "4", unsigned_apk, aligned_apk], check=True)

if not os.path.isfile(APP_KEYSTORE):
    os.makedirs(os.path.dirname(APP_KEYSTORE), exist_ok=True)
    cmd_keytool = [
        KEYTOOL,
        "-genkeypair",
        "-keystore",
        APP_KEYSTORE,
        "-storepass",
        "bvm02-app",
        "-keypass",
        "bvm02-app",
        "-alias",
        "bvm02",
        "-keyalg",
        "RSA",
        "-keysize",
        "2048",
        "-validity",
        "15000",
        "-dname",
        "CN=BVM02 Gen5W",
    ]
    subprocess.run(cmd_keytool, check=True)

final_apk = os.path.join(BUILD_DIR, "Bvm02Monitor.apk")
cmd_sign = [
    JAVA,
    "-jar",
    APKSIGNER_JAR,
    "sign",
    "--ks",
    APP_KEYSTORE,
    "--ks-pass",
    "pass:bvm02-app",
    "--min-sdk-version",
    "19",
    "--v1-signing-enabled",
    "true",
    "--v2-signing-enabled",
    "false",
    "--v3-signing-enabled",
    "false",
    "--out",
    final_apk,
    aligned_apk,
]
subprocess.run(cmd_sign, check=True)
print("  Successfully signed Bvm02Monitor.apk (", os.path.getsize(final_apk), "bytes)")

# 6. Package HMG-API Mod & NEMESIS Packages
print("\n[6/6] Packaging and signing HMG-API Mod & NEMESIS USB archives...")
mod_stage = os.path.join(BUILD_DIR, "mod")
os.makedirs(os.path.join(mod_stage, "app"), exist_ok=True)
os.makedirs(os.path.join(mod_stage, "icons"), exist_ok=True)

shutil.copy2(os.path.join(BASE_DIR, "mod", "mod.json"), mod_stage)
if os.path.isfile(os.path.join(BASE_DIR, "mod", "open.sh")):
    shutil.copy2(os.path.join(BASE_DIR, "mod", "open.sh"), mod_stage)
svc_dir = os.path.join(BASE_DIR, "mod", "svc")
if os.path.isdir(svc_dir):
    shutil.copytree(svc_dir, os.path.join(mod_stage, "svc"), dirs_exist_ok=True)
shutil.copy2(final_apk, os.path.join(mod_stage, "app", "Bvm02Monitor.apk"))
for icon in glob.glob(os.path.join(BASE_DIR, "mod", "icons", "*.png")):
    shutil.copy2(icon, os.path.join(mod_stage, "icons"))

sys.path.insert(0, os.path.join(BASE_DIR, "tools"))
import sign  # noqa: E402

for old_pkg in glob.glob(os.path.join(DIST_DIR, "bvm02-gen5w-v*.zip")):
    os.remove(old_pkg)

hmgapi_candidates = [
    os.environ.get("HMGAPI_DIR", ""),
    os.path.abspath(os.path.join(BASE_DIR, "third_party", "HMG-API")),
    os.path.abspath(os.path.join(BASE_DIR, "..", "third_party", "HMG-API")),
    os.path.abspath(os.path.join(BASE_DIR, "..", "..", "HMG-API")),
    "/tmp/HMG-API",
]
hmgapi_dir = next((d for d in hmgapi_candidates if d and os.path.isdir(d)), hmgapi_candidates[1])
sign.build(mod_stage, DIST_DIR, AUTHOR_KEY, hmgapi_dir)

print("\n================ BUILD SUCCESSFUL! ================")
print("Generated packages in:", DIST_DIR)
for f in sorted(os.listdir(DIST_DIR)):
    p = os.path.join(DIST_DIR, f)
    print(f"  {f} ({os.path.getsize(p):,} bytes)")
