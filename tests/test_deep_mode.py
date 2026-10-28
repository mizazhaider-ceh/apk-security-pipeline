"""Tests for deep mode: smali, Java, network config, deep links, signing.

Run: python3 -m unittest discover -s tests -v
Deep stages that need apktool or jadx are tested through synthetic
decoded directories, so the suite runs without those tools installed.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from apk_pipeline.cli import main as cli_main
from apk_pipeline.deep import (deep_link_findings, parse_network_security_config,
                               scan_java_dir, scan_smali_dir, signing_findings,
                               strings_summary, native_inventory)
from apk_pipeline.scanner import run_scan
from apk_pipeline.tools import detect_tools

SMALI_SAMPLE = """
.class public Lcom/example/Main;
.super Ljava/lang/Object;

.method public onCreate()V
    .locals 2
    const-string v0, "http://example.test/api"
    invoke-virtual {v0}, Landroid/webkit/WebView;->setJavaScriptEnabled(Z)V
    return-void
.end method

.method private hashIt(Ljava/lang/String;)Ljava/lang/String;
    .locals 2
    const-string v0, "MD5"
    invoke-static {v0}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;
    move-result-object v0
    return-object v0
.end method

.method private other(Ljava/lang/String;)V
    .locals 1
    const-string v0, "SHA1"
    return-void
.end method
"""

JAVA_SAMPLE = """package com.example;
import android.webkit.WebView;
public class Main {
    public void setup(WebView w) {
        w.setJavaScriptEnabled(true);
        Log.d("TAG", "hello");
    }
    private void load() {
        DexClassLoader loader = new DexClassLoader();
    }
}
"""

PLAIN_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.deep" android:versionCode="1" android:versionName="1.0">
  <application>
    <activity android:name=".Main" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="https" android:host="example.test" />
      </intent-filter>
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <data android:scheme="myapp" android:host="open" />
      </intent-filter>
    </activity>
    <activity android:name=".Other" android:exported="false" />
  </application>
</manifest>
"""


class TestSmali(unittest.TestCase):
    def test_method_scoped_findings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "Main.smali")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(SMALI_SAMPLE)
            findings, stats = scan_smali_dir(tmpdir)
            ids = [f.rule_id for f in findings]
            self.assertIn("SMALI_JS_ENABLED", ids)
            self.assertIn("SMALI_MD5", ids)
            self.assertIn("SMALI_CLEARTEXT_URL", ids)
            # SHA1 string alone in another method must NOT flag MD5/SHA1,
            # because the getInstance call is not in that method.
            self.assertNotIn("SMALI_SHA1", ids)
            js = [f for f in findings if f.rule_id == "SMALI_JS_ENABLED"][0]
            self.assertIn("onCreate", js.location)
            url = [f for f in findings if f.rule_id == "SMALI_CLEARTEXT_URL"][0]
            self.assertIn("example.test", url.evidence)
            self.assertNotIn("/api", url.evidence)
            self.assertEqual(stats["smali_files"], 1)


class TestJava(unittest.TestCase):
    def test_line_and_method_context(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "Main.java")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(JAVA_SAMPLE)
            findings, stats = scan_java_dir(tmpdir)
            ids = [f.rule_id for f in findings]
            self.assertIn("JAVA_JS_ENABLED", ids)
            self.assertIn("JAVA_LOG", ids)
            self.assertIn("JAVA_DEXLOADER", ids)
            js = [f for f in findings if f.rule_id == "JAVA_JS_ENABLED"][0]
            self.assertIn("Main.java:5", js.location)
            self.assertIn("setup", js.location)
            self.assertEqual(stats["java_files"], 1)


class TestNetworkConfig(unittest.TestCase):
    def test_cleartext_pinning_debug(self):
        xml = (b'<network-security-config>'
               b'<base-config cleartextTrafficPermitted="true">'
               b'<trust-anchors><certificates src="system" /></trust-anchors>'
               b'</base-config>'
               b'<domain-config><domain>example.test</domain>'
               b'<pin-set><pin digest="SHA-256">abc=</pin></pin-set>'
               b'</domain-config>'
               b'<debug-overrides><trust-anchors><certificates src="user" />'
               b'</trust-anchors></debug-overrides>'
               b'</network-security-config>')
        findings, summary = parse_network_security_config(xml)
        ids = [f.rule_id for f in findings]
        self.assertIn("NETCFG_CLEARTEXT", ids)
        self.assertIn("NETCFG_DEBUG_OVERRIDE", ids)
        self.assertIn("NETCFG_PINNING", ids)
        self.assertTrue(summary["cleartext_permitted"])
        self.assertTrue(summary["pinning"])

    def test_bad_xml_does_not_crash(self):
        findings, summary = parse_network_security_config(b"not xml at all {{{")
        self.assertEqual(findings, [])
        self.assertIn("error", summary)


class TestDeepLinks(unittest.TestCase):
    def test_links_extracted(self):
        from apk_pipeline.manifest import parse_manifest_bytes
        info = parse_manifest_bytes(PLAIN_MANIFEST.encode("utf-8"))
        findings, links = deep_link_findings(info)
        self.assertIn("https://example.test", links)
        self.assertIn("myapp://open", links)
        ids = [f.rule_id for f in findings]
        self.assertIn("DEEPLINK_HTTP", ids)
        self.assertIn("DEEPLINK_CUSTOM_SCHEME", ids)


class TestSigningAndStrings(unittest.TestCase):
    def test_debug_cert_flagged(self):
        files = [("META-INF/CERT.RSA", b"fake cert bytes Android Debug more bytes"),
                 ("META-INF/CERT.SF", b"signature file")]
        findings, inv = signing_findings(files)
        self.assertTrue(inv["debug_cert"])
        self.assertIn("CERT_DEBUG", [f.rule_id for f in findings])

    def test_no_signature_note(self):
        findings, inv = signing_findings([("classes.dex", b"nothing")])
        self.assertEqual(findings, [])
        self.assertIn("note", inv)

    def test_native_and_strings(self):
        files = [("lib/arm64-v8a/libfoo.so", b"x" * 100),
                 ("assets/a.txt", b"visit https://example.test/page and 8.8.8.8 and 192.168.1.5 and http://schemas.android.com/apk/res/android")]
        libs = native_inventory(files)
        self.assertEqual(len(libs), 1)
        self.assertEqual(libs[0]["abi"], "arm64-v8a")
        summary = strings_summary(files)
        self.assertIn("example.test", summary["url_hosts"])
        self.assertNotIn("schemas.android.com", summary["url_hosts"])
        self.assertIn("192.168.1.5", summary["private_ips"])
        self.assertEqual(summary["public_ip_count"], 1)

    def test_androguard_stage_never_crashes(self):
        import sys as _sys
        _sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples"))
        from generate_samples import build_sample_apks
        from apk_pipeline.deep import androguard_stage
        with tempfile.TemporaryDirectory() as tmpdir:
            _clean, vuln = build_sample_apks(tmpdir)
            findings, inv, skip = androguard_stage(vuln)
            self.assertIsInstance(findings, list)
            self.assertIsInstance(inv, dict)
            if not skip:
                self.assertEqual(inv.get("package"), "com.example.vulnapp")


class TestDeepEndToEnd(unittest.TestCase):
    def test_decoded_directory_deep_scan(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "AndroidManifest.xml"), "w", encoding="utf-8") as handle:
                handle.write(PLAIN_MANIFEST)
            smali_dir = os.path.join(tmpdir, "smali", "com", "example")
            os.makedirs(smali_dir)
            with open(os.path.join(smali_dir, "Main.smali"), "w", encoding="utf-8") as handle:
                handle.write(SMALI_SAMPLE)
            net_dir = os.path.join(tmpdir, "res", "xml")
            os.makedirs(net_dir)
            with open(os.path.join(net_dir, "network_security_config.xml"), "wb") as handle:
                handle.write(b'<network-security-config><base-config cleartextTrafficPermitted="true" /></network-security-config>')
            result = run_scan(tmpdir, static_only=True, deep=True,
                              skip_apktool=True, skip_jadx=True, skip_androguard=True,
                              work_root=os.path.join(tmpdir, "work"))
            ids = [f["id"] for f in result["findings"]]
            self.assertIn("SMALI_JS_ENABLED", ids)
            self.assertIn("NETCFG_CLEARTEXT", ids)
            self.assertIn("DEEPLINK_HTTP", ids)
            self.assertTrue(result["deep"])
            self.assertIn("deep_links", result["deep_inventory"])
            stages = [s["stage"] for s in result["stage_log"]]
            self.assertIn("Smali analysis (decoded dir)", stages)
            self.assertIn("Network security config", stages)

    def test_tools_command(self):
        self.assertEqual(cli_main(["tools"]), 0)

    def test_detect_tools_structure(self):
        tools = detect_tools()
        for name in ("java", "apktool", "jadx", "androguard"):
            self.assertIn(name, tools)
            self.assertIn("found", tools[name])
            self.assertIn("install", tools[name])


if __name__ == "__main__":
    unittest.main()
