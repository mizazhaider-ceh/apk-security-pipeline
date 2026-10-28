"""Generate clean and vulnerable test APKs for the pipeline.

Both APKs are synthetic, built by this script, with fake test data only.
No real app, no real secret, no real user data is inside them. The
vulnerable APK plants issues on purpose so the scanner has something
to find. The clean APK is the passing counterpart.

Run: python3 samples/generate_samples.py
Output: samples/clean.apk and samples/vulnerable.apk
"""

import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from apk_pipeline.axml_write import build_axml


def _comp(kind, name, exported, permission=None, intent=False):
    attrs = [("android:name", name)]
    if exported is not None:
        attrs.append(("android:exported", exported))
    if permission:
        attrs.append(("android:permission", permission))
    children = []
    if intent:
        children.append({"name": "intent-filter", "attrs": [], "children": [
            {"name": "action", "attrs": [("android:name", "android.intent.action.MAIN")], "children": []},
        ]})
    return {"name": kind, "attrs": attrs, "children": children}


def manifest_clean():
    return {
        "name": "manifest",
        "attrs": [("package", "com.example.cleanapp"),
                  ("android:versionCode", 1),
                  ("android:versionName", "1.0")],
        "children": [
            {"name": "uses-permission", "attrs": [("android:name", "android.permission.INTERNET")], "children": []},
            {"name": "uses-sdk", "attrs": [("android:minSdkVersion", 26), ("android:targetSdkVersion", 34)], "children": []},
            {"name": "application", "attrs": [
                ("android:name", ".CleanApp"),
                ("android:debuggable", False),
                ("android:allowBackup", False),
                ("android:usesCleartextTraffic", False)],
             "children": [
                 _comp("activity", ".MainActivity", False, intent=True),
                 _comp("service", ".SyncService", False),
             ]},
        ],
    }


def manifest_vuln():
    return {
        "name": "manifest",
        "attrs": [("package", "com.example.vulnapp"),
                  ("android:versionCode", 1),
                  ("android:versionName", "1.0")],
        "children": [
            {"name": "uses-permission", "attrs": [("android:name", "android.permission.INTERNET")], "children": []},
            {"name": "uses-permission", "attrs": [("android:name", "android.permission.READ_CONTACTS")], "children": []},
            {"name": "uses-permission", "attrs": [("android:name", "android.permission.ACCESS_FINE_LOCATION")], "children": []},
            {"name": "uses-permission", "attrs": [("android:name", "android.permission.SEND_SMS")], "children": []},
            {"name": "uses-permission", "attrs": [("android:name", "android.permission.CAMERA")], "children": []},
            {"name": "uses-sdk", "attrs": [("android:minSdkVersion", 26), ("android:targetSdkVersion", 34)], "children": []},
            {"name": "application", "attrs": [
                ("android:name", ".VulnApp"),
                ("android:debuggable", True),
                ("android:allowBackup", True),
                ("android:usesCleartextTraffic", True)],
             "children": [
                 _comp("activity", ".MainActivity", True, intent=True),
                 _comp("activity", ".AdminActivity", True),
                 _comp("service", ".DataService", True),
                 _comp("receiver", ".BootReceiver", True),
                 _comp("provider", ".DataProvider", True),
             ]},
        ],
    }


CLEAN_DEX = b"hello world clean app code, no risky patterns here\n"
VULN_DEX = (
    b"setJavaScriptEnabled setAllowUniversalAccessFromFileURLs "
    b"ALLOW_ALL_HOSTNAME_VERIFIER AES/ECB "
    b'MessageDigest.getInstance("MD5" java/util/Random Log.d( '
    b"http://example.test/api\n"
)
VULN_CONFIG = (
    b'api_key = "FAKEDEMO123456"\n'
    b"aws_key = \"AKIAIOSFODNN7EXAMPLE\"\n"
    b"-----BEGIN PRIVATE KEY-----\n"
    b"token = \"eyJmYWtl.eyJmYWtl.ZmFrZQ\"\n"
)


def _write_apk(path, manifest_tree, dex_bytes, extra_files):
    manifest_bytes = build_axml(manifest_tree)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", manifest_bytes)
        archive.writestr("classes.dex", dex_bytes)
        for name, data in extra_files:
            archive.writestr(name, data)


def build_sample_apks(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    clean_path = os.path.join(out_dir, "clean.apk")
    vuln_path = os.path.join(out_dir, "vulnerable.apk")
    _write_apk(clean_path, manifest_clean(), CLEAN_DEX,
               [("assets/notes.txt", b"clean test app notes\n")])
    _write_apk(vuln_path, manifest_vuln(), VULN_DEX,
               [("assets/config.txt", VULN_CONFIG)])
    return clean_path, vuln_path


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    clean, vuln = build_sample_apks(here)
    print("Wrote %s" % clean)
    print("Wrote %s" % vuln)
