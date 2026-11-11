#!/usr/bin/env python3
"""Cross-platform Android SDK setup helper (API 19 platform + Build-Tools 30.0.3)."""
import os
import sys
import urllib.request
import zipfile

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_SDK = os.path.abspath(os.path.join(BASE_DIR, "..", "tools", "android-sdk"))
SDK_DIR = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or DEFAULT_SDK
os.makedirs(SDK_DIR, exist_ok=True)

is_win = sys.platform.startswith("win")
is_mac = sys.platform == "darwin"
exe_suffix = ".exe" if is_win else ""
bat_suffix = ".bat" if is_win else ""

if is_win:
    bt_os_tag = "windows"
elif is_mac:
    bt_os_tag = "macosx"
else:
    bt_os_tag = "linux"

# 1. Download Android-19 platform (android.jar)
PLATFORM_DIR = os.path.join(SDK_DIR, "platforms", "android-19")
if not os.path.isfile(os.path.join(PLATFORM_DIR, "android.jar")):
    print("Downloading Android API 19 platform (android.jar)...")
    url = "https://dl.google.com/android/repository/android-19_r04.zip"
    zip_path = os.path.join(SDK_DIR, "android-19.zip")
    urllib.request.urlretrieve(url, zip_path)
    print("Extracting android-19...")
    with zipfile.ZipFile(zip_path, "r") as z:
        for member in z.infolist():
            parts = member.filename.split("/", 1)
            if len(parts) > 1 and parts[1]:
                target = os.path.join(PLATFORM_DIR, parts[1])
                if member.is_dir():
                    os.makedirs(target, exist_ok=True)
                else:
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with open(target, "wb") as f:
                        f.write(z.read(member))
    os.remove(zip_path)
    print("android-19 platform installed successfully.")
else:
    print("android.jar already exists.")

# 2. Download Build-Tools 30.0.3
BT_DIR = os.path.join(SDK_DIR, "build-tools", "30.0.3")
aapt_bin = os.path.join(BT_DIR, f"aapt{exe_suffix}")
if not os.path.isfile(aapt_bin):
    print(f"Downloading Android Build-Tools 30.0.3 for {bt_os_tag}...")
    url = f"https://dl.google.com/android/repository/build-tools_r30.0.3-{bt_os_tag}.zip"
    zip_path = os.path.join(SDK_DIR, "build-tools.zip")
    urllib.request.urlretrieve(url, zip_path)
    print("Extracting build-tools...")
    with zipfile.ZipFile(zip_path, "r") as z:
        for member in z.infolist():
            parts = member.filename.split("/", 1)
            if len(parts) > 1 and parts[1]:
                target = os.path.join(BT_DIR, parts[1])
                if member.is_dir():
                    os.makedirs(target, exist_ok=True)
                else:
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with open(target, "wb") as f:
                        f.write(z.read(member))
                    if not is_win and ("/" not in parts[1] or parts[1].endswith(".sh")):
                        os.chmod(target, 0o755)
    os.remove(zip_path)
    print("build-tools 30.0.3 installed successfully.")
else:
    print("build-tools already exists.")

print("SDK Setup Complete:")
print("  SDK_DIR:    ", SDK_DIR)
print("  android.jar:", os.path.join(PLATFORM_DIR, "android.jar"))
print("  aapt:       ", aapt_bin)
print("  d8:         ", os.path.join(BT_DIR, f"d8{bat_suffix}"))
print("  zipalign:   ", os.path.join(BT_DIR, f"zipalign{exe_suffix}"))
