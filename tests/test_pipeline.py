"""Unit tests for APK Security Pipeline. Run: python3 -m unittest discover -s tests -v"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples"))

from apk_pipeline.cli import main as cli_main
from apk_pipeline.manifest import parse_manifest_bytes
from apk_pipeline.report import write_reports
from apk_pipeline.scanner import run_scan
from generate_samples import build_sample_apks, manifest_clean

PLAIN_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.plain" android:versionCode="2" android:versionName="1.1">
  <uses-permission android:name="android.permission.INTERNET" />
  <application android:debuggable="false" android:allowBackup="false">
    <activity android:name=".Main" android:exported="false">
      <intent-filter><action android:name="android.intent.action.MAIN" /></intent-filter>
    </activity>
  </application>
</manifest>
"""


class TestManifestParsing(unittest.TestCase):
    def test_plain_xml_manifest(self):
        info = parse_manifest_bytes(PLAIN_MANIFEST.encode("utf-8"))
        self.assertEqual(info["package"], "com.example.plain")
        self.assertEqual(info["permissions"], ["android.permission.INTERNET"])
        self.assertEqual(info["components"][0]["name"], ".Main")
        self.assertIs(info["components"][0]["exported"], False)

    def test_binary_manifest_roundtrip(self):
        from apk_pipeline.axml_write import build_axml
        data = build_axml(manifest_clean())
        info = parse_manifest_bytes(data)
        self.assertEqual(info["package"], "com.example.cleanapp")
        self.assertIn("android.permission.INTERNET", info["permissions"])
        self.assertIs(info["application"]["debuggable"], False)
        self.assertIs(info["application"]["allow_backup"], False)


class TestScans(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.clean, self.vuln = build_sample_apks(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_clean_scores_high(self):
        result = run_scan(self.clean, static_only=True)
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["grade"], "A")
        self.assertEqual(result["findings"], [])

    def test_vulnerable_finds_critical_and_high(self):
        result = run_scan(self.vuln, static_only=True)
        severities = [item["severity"] for item in result["findings"]]
        self.assertIn("critical", severities)
        self.assertIn("high", severities)
        ids = [item["id"] for item in result["findings"]]
        self.assertIn("MANIFEST_DEBUGGABLE", ids)
        self.assertIn("MANIFEST_CLEARTEXT", ids)
        self.assertIn("MANIFEST_EXPORTED_NO_PERMISSION", ids)
        self.assertLess(result["score"], 60)

    def test_secrets_are_masked(self):
        result = run_scan(self.vuln, static_only=True)
        blob = json.dumps(result)
        self.assertNotIn("FAKEDEMO123456", blob)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", blob)
        self.assertNotIn("eyJmYWtl", blob)

    def test_reports_written(self):
        result = run_scan(self.vuln, static_only=True)
        out_dir = os.path.join(self.tmp.name, "out")
        written = write_reports(result, out_dir, ("html", "json"))
        self.assertTrue(os.path.isfile(written["html"]))
        self.assertTrue(os.path.isfile(written["json"]))
        with open(written["html"], encoding="utf-8") as handle:
            page = handle.read()
        self.assertIn("Score:", page)
        self.assertIn("MANIFEST_DEBUGGABLE", page)

    def test_baseline_no_new_on_repeat(self):
        first = run_scan(self.vuln, static_only=True)
        base_path = os.path.join(self.tmp.name, "base.json")
        with open(base_path, "w", encoding="utf-8") as handle:
            json.dump(first, handle)
        second = run_scan(self.vuln, static_only=True, baseline_path=base_path)
        self.assertEqual(second["baseline"]["new"], [])
        self.assertEqual(len(second["baseline"]["unchanged"]), len(first["findings"]))

    def test_cli_exit_codes(self):
        out_dir = os.path.join(self.tmp.name, "cli-out")
        code_ok = cli_main(["scan", self.clean, "-o", out_dir, "--fail-on", "never"])
        self.assertEqual(code_ok, 0)
        code_fail = cli_main(["scan", self.vuln, "-o", out_dir, "--fail-on", "high"])
        self.assertEqual(code_fail, 2)


if __name__ == "__main__":
    unittest.main()
