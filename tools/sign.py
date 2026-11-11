#!/usr/bin/env python3
"""Sign a staged mod folder and zip it as an HMG-API & NEMESIS package.

    tools/sign.py <mod dir> <dist dir> <key> <hmg-api checkout>
        writes <id>-v<version>.hmgapi.zip and, for a flash drive, <id>-v<version>-hmgapi-usb.zip
        (HMGAPI/updates/<id>-v<version>.zip inside) and <id>-v<version>-nemesis-usb.zip, and for the
        NEMESIS Package Store <id>-v<version>-nemesis-package.zip.

Same files and manifest as `hmgapi.engine.Signing sign`: SHA256withECDSA over
META-HMGAPI/manifest.json, with the uuid derived from the public key.
"""
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

TESTED_OS = "CVEV.USA.*.*,NEEV.USA.*.*,NEEV23.USA.*.*,NEEV23SE.USA.*.*,CEEV.USA.*.*"
TESTED_MODELS = "cvev_us,neev_us,neev23_us,neev23se_us,ceev_us"

META = "META-HMGAPI"


def openssl(*args, data=None):
    return subprocess.run(["openssl", *args], input=data, capture_output=True, check=True).stdout


def ensure_keypair(key_path: str) -> None:
    """Generate an HMG-API compatible ECDSA secp256r1 PKCS#8 DER keypair if missing."""
    pub_path = key_path + ".pub"
    if os.path.isfile(key_path) and os.path.isfile(pub_path):
        return
    if os.path.isfile(key_path) != os.path.isfile(pub_path):
        sys.exit(f"Incomplete keypair at {key_path} / {pub_path}")
    os.makedirs(os.path.dirname(os.path.abspath(key_path)), exist_ok=True)
    if shutil.which("openssl"):
        ec_pem = openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout")
        priv_der = openssl("pkcs8", "-topk8", "-nocrypt", "-outform", "DER", data=ec_pem)
        pub_der = openssl("pkey", "-pubout", "-outform", "DER", data=ec_pem)
    else:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        priv = ec.generate_private_key(ec.SECP256R1())
        priv_der = priv.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        pub_der = priv.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(base64.b64encode(priv_der) + b"\n")
    with open(pub_path, "wb") as f:
        f.write(base64.b64encode(pub_der) + b"\n")
    print(f"Generated new HMG-API author keypair at {key_path} (uuid {uuid_of(pub_der)})")


def der_of(path):
    with open(path) as f:
        return base64.b64decode(f.read().strip())


def uuid_of(pub_der):
    d = bytearray(hashlib.sha256(pub_der).digest())
    d[6] = (d[6] & 15) | 128
    d[8] = (d[8] & 63) | 128
    h = d[:16].hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def files_of(root):
    out = []
    for dirpath, dirs, names in os.walk(root):
        rel = os.path.relpath(dirpath, root).replace("\\", "/")
        dirs[:] = [d for d in dirs if not (rel == "." and d == META)]
        for n in names:
            if n == ".DS_Store" or (rel == "." and n == ".disabled"):
                continue
            out.append(n if rel == "." else f"{rel}/{n}")
    return sorted(out)


def swap_in_zip(path, name, change):
    """Rewrite one member of a zip, keeping the others and every member's attributes."""
    with zipfile.ZipFile(path) as z:
        items = [(i, z.read(i)) for i in z.infolist()]
    with zipfile.ZipFile(path, "w") as z:
        for i, d in items:
            z.writestr(i, change(d) if i.filename == name else d)


def tested_on(descriptor):
    for k, v in (("os", TESTED_OS), ("models", TESTED_MODELS)):
        any_ = f'{k}="any"'.encode()
        if descriptor.count(any_) != 1:
            sys.exit(f'NEMESIS.data has no {k}="any" to replace')
        descriptor = descriptor.replace(any_, f'{k}="{v}"'.encode())
    return descriptor


def nemesis_usb_py(signed, mod, mod_dir, hmgapi, dist):
    """Pure-Python equivalent of HMG-API's tools/mknemesismod.sh when sh/zip are unavailable."""
    hmgapi = os.path.abspath(hmgapi)
    mid, ver = mod["id"], mod["version"]
    pkg = "hmgapi." + mid

    def text(s, n):
        s = " ".join(str(s).replace('"', "'").split())
        return s if len(s) <= n else s[: n - 3].rstrip() + "..."

    name = text(mod.get("name") or mid, 64)
    short = text("HMG-API mod: " + name, 64)
    raw_desc = mod.get("description", "")
    detail = text(f"{name} {ver}, a HMG-API mod (needs HMG-API). {raw_desc}", 256)
    pv = subprocess.run(
        [sys.executable, os.path.join(hmgapi, "tools", "nemesis-version.py"), ver],
        cwd=hmgapi,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    extra_deps = mod.get("depends", "")
    if isinstance(extra_deps, list):
        extra_deps = ",".join(extra_deps)
    needs = "hmgapi@>=1.0" + (("," + extra_deps) if extra_deps else "")
    mod_json_path = os.path.join(os.path.abspath(mod_dir), "mod.json")
    dep = subprocess.run(
        [sys.executable, os.path.join(hmgapi, "tools", "nemesis-meta.py"), "depends", pkg, needs, "--mod", mod_json_path],
        cwd=hmgapi,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    repl = {
        "ID": mid,
        "VERSION": ver,
        "PACKAGE_ID": pkg,
        "PACKAGE_VERSION": pv,
        "NAME": name,
        "SHORT_DESC": short,
        "DETAILED_DESC": detail,
        "OS": "any",
        "DEPENDS": dep,
    }

    def fill(tpl_rel):
        t = open(os.path.join(hmgapi, tpl_rel), encoding="utf-8").read()
        for k, v in repl.items():
            t = t.replace(f"@{k}@", v)
        return t.encode("utf-8")

    def add_entry(z, arcname, data, exec_bit=False):
        zi = zipfile.ZipInfo(arcname, (2026, 1, 1, 0, 0, 0))
        zi.compress_type = zipfile.ZIP_DEFLATED
        zi.external_attr = (0o755 if exec_bit else 0o644) << 16
        z.writestr(zi, data)

    open_sh = os.path.join(mod_dir, "open.sh")
    if not os.path.isfile(open_sh):
        open_sh = os.path.join(hmgapi, "install/nemesis/bin/open.sh")
    store = os.path.join(dist, f"{mid}-v{ver}-nemesis-package.zip")
    out = os.path.join(dist, f"{mid}-v{ver}-nemesis-usb.zip")
    pkg_entries = {
        "NEMESIS.data": (tested_on(fill("install/nemesis/mod/NEMESIS.data.in")), False),
        "bin/open.sh": (open(open_sh, "rb").read(), True),
        "mod/id": ((mid + "\n").encode("utf-8"), False),
        "mod/package.zip": (open(signed, "rb").read(), False),
    }
    scripts_dir = os.path.join(hmgapi, "install/nemesis/mod/scripts")
    for fn in sorted(os.listdir(scripts_dir)):
        p = os.path.join(scripts_dir, fn)
        if os.path.isfile(p):
            pkg_entries[f"scripts/{fn}"] = (open(p, "rb").read(), fn.endswith(".sh"))
    with zipfile.ZipFile(store, "w", zipfile.ZIP_DEFLATED) as z:
        for k in sorted(pkg_entries):
            add_entry(z, k, *pkg_entries[k])

    packed = open(store, "rb").read()
    stick_entries = {
        "NEMESIS.data": (f"[nemesis]\nversion=1.1\ntype=install\npath=packages/{pkg}.zip\n".encode("utf-8"), False),
        "README.txt": (fill("install/nemesis/mod/README.txt"), False),
        f"packages/{pkg}.zip": (packed, False),
    }
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for k in sorted(stick_entries):
            add_entry(z, k, *stick_entries[k])
    return out, store


def nemesis_usb(signed, mod, mod_dir, hmgapi, dist):
    """Wrap the signed HMG-API zip into NEMESIS USB & Package Store archives."""
    if not shutil.which("sh") or not shutil.which("zip") or not shutil.which("unzip"):
        return nemesis_usb_py(signed, mod, mod_dir, hmgapi, dist)
    tool = os.path.join(os.path.abspath(hmgapi), "tools", "mknemesismod.sh")
    with tempfile.TemporaryDirectory() as t:
        subprocess.run(["sh", tool, os.path.abspath(signed), t], check=True, capture_output=True)
        out = os.path.join(dist, f"{mod['id']}-v{mod['version']}-nemesis-usb.zip")
        store = os.path.join(dist, f"{mod['id']}-v{mod['version']}-nemesis-package.zip")
        shutil.move(os.path.join(t, f"{mod['id']}-{mod['version']}-nemesis.zip"), out)
        shutil.move(os.path.join(t, f"{mod['id']}-{mod['version']}-nemesis-package.zip"), store)
    swap_in_zip(store, "NEMESIS.data", tested_on)
    open_sh = os.path.join(mod_dir, "open.sh")
    if os.path.isfile(open_sh):
        open_bytes = open(open_sh, "rb").read()
        swap_in_zip(store, "bin/open.sh", lambda _: open_bytes)
    packed = open(store, "rb").read()
    swap_in_zip(out, f"packages/hmgapi.{mod['id']}.zip", lambda _: packed)
    swap_in_zip(out, "NEMESIS.data", lambda d: d.replace(b"version=1.0", b"version=1.1"))
    return out, store


def sign_manifest(key, pub, manifest):
    if shutil.which("openssl"):
        with tempfile.TemporaryDirectory() as tmp:
            kpem = os.path.join(tmp, "k.pem")
            fd = os.open(kpem, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(openssl("pkey", "-inform", "DER", data=der_of(key)))
            sig = openssl("dgst", "-sha256", "-sign", kpem, data=manifest)
            ppem = os.path.join(tmp, "p.pem")
            sigf = os.path.join(tmp, "sig")
            open(ppem, "wb").write(openssl("pkey", "-pubin", "-inform", "DER", data=pub))
            open(sigf, "wb").write(sig)
            openssl("dgst", "-sha256", "-verify", ppem, "-signature", sigf, data=manifest)
            return sig
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    priv_key = serialization.load_der_private_key(der_of(key), password=None)
    pub_key = serialization.load_der_public_key(pub)
    sig = priv_key.sign(manifest, ec.ECDSA(hashes.SHA256()))
    pub_key.verify(sig, manifest, ec.ECDSA(hashes.SHA256()))
    return sig


EMBEDDED_NEMESIS_PREINSTALL_SH = """#!/system/bin/sh
# NEMESIS preinstall for a HMG-API mod package (full root, cwd the staged package).
# A failure here stops the install before NEMESIS copies or registers anything.
# depends="hmgapi" already needs HMG-API's NEMESIS package; this also catches an
# HMG-API install that didn't finish, or one done over adb or the DSP OTA.
if [ ! -x "${ROOT:-}/system/bin/hmgapid" ] || [ ! -f "${ROOT:-}/data/hmgapi/uninstall.sh" ]; then
    echo "HMG-API isn't installed on this unit: install HMG-API first, then this mod"
    exit 1
fi
[ -f mod/id ] && { [ -f mod/package.zip ] || [ -f registered ]; } || { echo "not a HMG-API mod package (no mod/package.zip)"; exit 1; }
exit 0
"""

EMBEDDED_NEMESIS_POSTINSTALL_SH = """#!/system/bin/sh
# NEMESIS postinstall for a HMG-API mod package (full root, cwd
# /data/nemesis/apps/hmgapi.<mod id>): installs the mod it carries (mod/package.zip,
# signed by its author) with HMG-API's own engine, then applies it, as the HMG-API
# app's Check USB updates and Apply changes do.
umask 077
H=${ROOT:-}/system/bin/hmgapid
ID=$(cat mod/id)
if [ "$HMGAPI_NEMESIS_SYNC" = 1 ]; then echo "listed by HMG-API: nothing to install"; exit 0; fi
if [ ! -f mod/package.zip ]; then
    if [ -d "${ROOT:-}/data/hmgapi/mods/$ID" ]; then echo "$ID is installed in HMG-API: listed"; exit 0; fi
    echo "this package only lists the HMG-API mod $ID, and it isn't installed: install the mod in HMG-API, or its own NEMESIS package"
    exit 1
fi
say() { echo "HMG-API mod $ID: $1"; }
toast() {
    [ "$(getprop sys.boot_completed)" = 1 ] || return 0
    am broadcast -a com.hkmc.intent.action.TOAST -e com.hkmc.intent.extra.TOAST_MESSAGE "$1" --ez com.hkmc.intent.extra.TOAST_POPUPSHOWING true >/dev/null 2>&1
}
[ -x "$H" ] || { say "HMG-API isn't installed on this unit: install HMG-API first"; exit 1; }
"$H" ping >/dev/null 2>&1 || "$H" daemon >/dev/null 2>&1
any=
for d in ${HMGAPI_USB_DIRS:-/storage/usb0 /storage/usb1 /storage/usb2}; do [ -f "$d/HMGAPI/ANY-CAR" ] && any=--any-car; done
new=yes
[ -d "${ROOT:-}/data/hmgapi/mods/$ID" ] && new=no
if ! "$H" engine install "$PWD/mod/package.zip" $any --from-nemesis; then
    say "HMG-API didn't install it (see above): nothing changed. Uninstall this package in NEMESIS Manager."
    toast "HMG-API didn't install $ID: see NEMESIS's log"
    exit 1
fi
if ! r=$("$H" engine apply 2>&1); then
    echo "$r"
    if [ $new = yes ]; then
        "$H" engine remove "$ID" --from-nemesis >/dev/null 2>&1
        say "HMG-API couldn't apply it (see above), so it's not installed: nothing changed. Uninstall this package in NEMESIS Manager."
    else
        say "the update is in HMG-API, but it couldn't apply it (see above): the HMG-API app shows the problem; Apply changes there once it's fixed."
    fi
    toast "HMG-API couldn't apply $ID: see the HMG-API app"
    exit 1
fi
echo "$r"
case $r in
    *"restart the head unit"*) say "installed: restart the head unit to use it"; toast "$ID installed: restart the head unit" ;;
    *) say "installed"; toast "$ID installed" ;;
esac
exit 0
"""

EMBEDDED_NEMESIS_PREUNINSTALL_SH = """#!/system/bin/sh
# NEMESIS preuninstall for a HMG-API mod package (full root, a child of the nemesis
# process): removes the mod from HMG-API and applies, so everything it changed goes
# back to stock.
umask 077
H=${ROOT:-}/system/bin/hmgapid
ID=$(cat mod/id)
if [ "$HMGAPI_NEMESIS_SYNC" = 1 ]; then echo "HMG-API's NEMESIS sync: list only, $ID stays as it is in HMG-API"; exit 0; fi
PKG=hmgapi.$ID
STAGE=${ROOT:-}/data/local/tmp/nemesis/stage/$PKG
caller=$(cat /proc/$PPID/cmdline 2>/dev/null)
case $caller in
    *uninstall*) ;;
    *)
        if grep -q "^id=$PKG\\$" "$STAGE/NEMESIS.data" 2>/dev/null; then
            echo "update: $ID stays installed, the new package updates it"
            exit 0
        fi ;;
esac
M=${ROOT:-}/data/hmgapi/mods/$ID
[ -d "$M" ] || { echo "$ID isn't installed in HMG-API (removed in the app?): nothing to do"; exit 0; }
if [ ! -x "$H" ]; then
    rm -rf "$M"
    echo "HMG-API isn't installed: removed $ID from /data/hmgapi/mods"
    exit 0
fi
"$H" ping >/dev/null 2>&1 || "$H" daemon >/dev/null 2>&1
"$H" engine remove "$ID" --from-nemesis || { echo "HMG-API didn't remove $ID (see above): nothing changed, the package stays"; exit 1; }
if ! "$H" engine apply; then
    echo "WARNING: $ID is removed from HMG-API, but its files aren't back to stock yet (see above): open the HMG-API app and tap Apply changes"
    exit 0
fi
echo "removed $ID; restart the head unit if HMG-API says so above"
exit 0
"""


def nemesis_usb_standalone(signed, mod, mod_dir, dist):
    """Self-contained pure-Python NEMESIS package builder when external HMG-API repo is absent."""
    mid, ver = mod["id"], mod["version"]
    pkg = "hmgapi." + mid

    def text(s, n):
        s = " ".join(str(s).replace('"', "'").split())
        return s if len(s) <= n else s[: n - 3].rstrip() + "..."

    name = text(mod.get("name") or mid, 64)
    short = text("HMG-API mod: " + name, 64)
    raw_desc = mod.get("description", "")
    detail = text(f"{name} {ver}, a HMG-API mod (needs HMG-API). {raw_desc}", 256)
    extra_deps = mod.get("depends", "")
    if isinstance(extra_deps, list):
        extra_deps = ",".join(extra_deps)
    dep = "hmgapi@>=1.0" + (("," + extra_deps) if extra_deps else "")

    nemesis_data_in = (
        "[nemesis]\n"
        "version=1.1\n"
        f"id={pkg}\n"
        f"name={name}\n"
        "type=application\n"
        f"package-version={ver}\n"
        f'short-desc="{short}"\n'
        f'detailed-desc="{detail}"\n'
        'os="any"\n'
        'models="any"\n'
        f'depends="{dep}"\n'
        "preinstall=scripts/preinstall.sh\n"
        "postinstall=scripts/postinstall.sh\n"
        "preuninstall=scripts/preuninstall.sh\n"
        "\n"
        "[app.0]\n"
        "kind=sh\n"
        "path=bin/open.sh\n"
        "uid=root\n"
    ).encode("utf-8")

    readme_txt = (
        f"{name} {ver} (a HMG-API mod) - install with NEMESIS\n"
        "=======================================================\n\n"
        "Needs HMG-API on the head unit first: NEMESIS Manager says so if it isn't, and\n"
        "offers to install it when it can find it (on the stick, then online).\n\n"
        "1. Unzip this file onto the top level of a USB stick (FAT32 or exFAT), so the\n"
        "   stick has NEMESIS.data and the packages folder at its root. Only one NEMESIS\n"
        "   package on the stick at a time.\n"
        "2. Plug the stick into the car's USB port once Android is up, and confirm the\n"
        f'   install of "{name}".\n'
        "3. Restart the head unit if it says so, and take the stick out.\n\n"
        "HMG-API installs the mod and applies it, as its app does. Updating the same way\n"
        "keeps the mod's settings. A mod that doesn't list your car isn't installed; to\n"
        "install it anyway, at your own risk, add an empty file HMGAPI/ANY-CAR to the stick.\n\n"
        "Uninstall from NEMESIS Manager (everything the mod changed goes back to stock), or:\n"
        f"    nemesis uninstall {pkg}\n"
        "Removing the mod in the HMG-API app works too; then uninstall this package as well.\n"
    ).encode("utf-8")

    def add_entry(z, arcname, data, exec_bit=False):
        zi = zipfile.ZipInfo(arcname, (2026, 1, 1, 0, 0, 0))
        zi.compress_type = zipfile.ZIP_DEFLATED
        zi.external_attr = (0o755 if exec_bit else 0o644) << 16
        z.writestr(zi, data)

    open_sh = os.path.join(mod_dir, "open.sh")
    store = os.path.join(dist, f"{mid}-v{ver}-nemesis-package.zip")
    out = os.path.join(dist, f"{mid}-v{ver}-nemesis-usb.zip")

    pkg_entries = {
        "NEMESIS.data": (tested_on(nemesis_data_in), False),
        "bin/open.sh": (open(open_sh, "rb").read(), True),
        "mod/id": ((mid + "\n").encode("utf-8"), False),
        "mod/package.zip": (open(signed, "rb").read(), False),
        "scripts/postinstall.sh": (EMBEDDED_NEMESIS_POSTINSTALL_SH.encode("utf-8"), True),
        "scripts/preinstall.sh": (EMBEDDED_NEMESIS_PREINSTALL_SH.encode("utf-8"), True),
        "scripts/preuninstall.sh": (EMBEDDED_NEMESIS_PREUNINSTALL_SH.encode("utf-8"), True),
    }
    with zipfile.ZipFile(store, "w", zipfile.ZIP_DEFLATED) as z:
        for k in sorted(pkg_entries):
            add_entry(z, k, *pkg_entries[k])

    packed = open(store, "rb").read()
    stick_entries = {
        "NEMESIS.data": (f"[nemesis]\nversion=1.1\ntype=install\npath=packages/{pkg}.zip\n".encode("utf-8"), False),
        "README.txt": (readme_txt, False),
        f"packages/{pkg}.zip": (packed, False),
    }
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for k in sorted(stick_entries):
            add_entry(z, k, *stick_entries[k])
    return out, store


def build(mod_dir, dist, key, hmgapi):
    ensure_keypair(key)
    pub_path = key + ".pub"
    if not os.path.isfile(pub_path):
        sys.exit(f"no {pub_path}")
    pub = der_of(pub_path)
    mod = json.load(open(os.path.join(mod_dir, "mod.json")))
    files = {n: hashlib.sha256(open(os.path.join(mod_dir, n), "rb").read()).hexdigest() for n in files_of(mod_dir)}
    manifest = (
        json.dumps(
            {
                "format": 1,
                "id": mod["id"],
                "version": mod["version"],
                "uuid": uuid_of(pub),
                "key": base64.b64encode(pub).decode(),
                "files": files,
            },
            indent=2,
        ).encode()
        + b"\n"
    )

    sig = sign_manifest(key, pub, manifest)

    os.makedirs(dist, exist_ok=True)
    out = os.path.join(dist, f"{mod['id']}-v{mod['version']}.hmgapi.zip")
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"{META}/manifest.json", manifest)
        z.writestr(f"{META}/signature", base64.b64encode(sig).decode() + "\n")
        for n in files:
            info = zipfile.ZipInfo.from_file(os.path.join(mod_dir, n), n)
            if n.endswith(".sh"):
                info.external_attr = 0o755 << 16
            z.writestr(info, open(os.path.join(mod_dir, n), "rb").read(), zipfile.ZIP_DEFLATED)
    usb = os.path.join(dist, f"{mod['id']}-v{mod['version']}-hmgapi-usb.zip")
    with zipfile.ZipFile(usb, "w", zipfile.ZIP_STORED) as z:
        z.write(out, f"HMGAPI/updates/{mod['id']}-v{mod['version']}.zip")
    print(f"signed {mod['id']} {mod['version']}: {len(files)} files, uuid {uuid_of(pub)}")
    print(out)
    print(usb)
    if os.path.isdir(hmgapi):
        print(*nemesis_usb(out, mod, mod_dir, hmgapi, dist), sep="\n")
    else:
        print(*nemesis_usb_standalone(out, mod, mod_dir, dist), sep="\n")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    build(*sys.argv[1:])
