"""Deep tests for APK Security Pipeline: edge cases, failures, CLI, reports.

Run: python3 -m unittest discover -s tests -v
These tests hunt for crashes, leaks, and wrong answers, not just happy paths.
"""

import json
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples"))

from apk_pipeline.axml_write import build_axml
from apk_pipeline.cli import main as cli_main
from apk_pipeline.manifest import parse_manifest_bytes
from apk_pipeline.report import write_reports
from apk_pipeline.rules import (Finding, mask_url, mask_value,
                                score_findings)
from apk_pipeline.scanner import run_scan, ScanError
from generate_samples import (build_sample_apks, manifest_clean,
                              manifest_vuln)


def _manifest_tree(package="com.example.edge", app_attrs=(), components=(),
                   permissions=()):
    children = []
    for perm in permissions:
        children.append({"name": "uses-permission",
                         "attrs": [("android:name", perm)], "children": []})
    children.append({"name": "application", "attrs": list(app_attrs),
                     "children": list(components)})
    return {"name": "manifest",
            "attrs": [("package", package)],
            "children": children}


def _comp(kind, name, exported=None, permission=None, intent=False):
    attrs = [("android:name", name)]
    if exported is not None:
        attrs.append(("android:exported", exported))
    if permission:
        attrs.append(("android:permission", permission))
    children = []
    if intent:
        children.append({"name": "intent-filter", "attrs": [], "children": []})
    return {"name": kind, "attrs": attrs, "children": children}


def _zip_with_manifest(tmpdir, name, manifest_bytes, extra=()):
    path = os.path.join(tmpdir, name)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", manifest_bytes)
        for entry, data in extra:
            archive.writestr(entry, data)
    return path


class TestManifestVariants(unittest.TestCase):
    def test_exported_with_permission_is_not_flagged(self):
        tree = _manifest_tree(components=[
            _comp("activity", ".Safe", True, permission="com.example.SAFE")])
        info = parse_manifest_bytes(build_axml(tree))
        from apk_pipeline.rules import manifest_findings
        findings, _notes = manifest_findings(info)
        self.assertEqual([f for f in findings if f.rule_id == "MANIFEST_EXPORTED_NO_PERMISSION"], [])

    def test_implicit_export_flagged(self):
        tree = _manifest_tree(components=[_comp("activity", ".Main", None, intent=True)])
        info = parse_manifest_bytes(build_axml(tree))
        from apk_pipeline.rules import manifest_findings
        findings, _notes = manifest_findings(info)
        self.assertIn("MANIFEST_IMPLICIT_EXPORT", [f.rule_id for f in findings])

    def test_all_component_kinds_parse(self):
        tree = _manifest_tree(components=[
            _comp("activity", ".A", False),
            _comp("service", ".S", False),
            _comp("receiver", ".R", False),
            _comp("provider", ".P", False)])
        info = parse_manifest_bytes(build_axml(tree))
        self.assertEqual(len(info["components"]), 4)
        self.assertEqual([c["kind"] for c in info["components"]],
                         ["activity", "service", "receiver", "provider"])

    def test_plain_xml_apk_zip_parses(self):
        plain = (b'<?xml version="1.0"?><manifest xmlns:android='
                 b'"http://schemas.android.com/apk/res/android" package="com.example.plainzip">'
                 b'<application android:debuggable="true"></application></manifest>')
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _zip_with_manifest(tmpdir, "plain.apk", plain)
            result = run_scan(path, static_only=True)
            self.assertEqual(result["package"], "com.example.plainzip")
            self.assertIn("MANIFEST_DEBUGGABLE", [f["id"] for f in result["findings"]])

    def test_bad_magic_manifest_is_clean_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _zip_with_manifest(tmpdir, "bad.apk", b"THIS IS NOT XML AT ALL {{{")
            with self.assertRaises(ScanError):
                run_scan(path, static_only=True)

    def test_truncated_binary_manifest_is_clean_error(self):
        good = build_axml(manifest_clean())
        for cut in (10, 30, len(good) // 2, len(good) - 5):
            with tempfile.TemporaryDirectory() as tmpdir:
                path = _zip_with_manifest(tmpdir, "cut.apk", good[:cut])
                with self.assertRaises(ScanError):
                    run_scan(path, static_only=True)

    def test_empty_manifest_is_clean_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = _zip_with_manifest(tmpdir, "empty.apk", b"")
            with self.assertRaises(ScanError):
                run_scan(path, static_only=True)


class TestInputHandling(unittest.TestCase):
    def test_missing_file_is_clean_error(self):
        with self.assertRaises(ScanError):
            run_scan("/tmp/does-not-exist-xyz.apk", static_only=True)

    def test_not_a_zip_is_clean_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "note.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("hello, not an apk\n")
            with self.assertRaises(ScanError):
                run_scan(path, static_only=True)

    def test_zip_without_manifest_is_clean_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "nomanifest.apk")
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("classes.dex", b"nothing here")
            with self.assertRaises(ScanError):
                run_scan(path, static_only=True)

    def test_directory_without_manifest_is_clean_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(ScanError):
                run_scan(tmpdir, static_only=True)

    def test_decoded_directory_scan(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            plain = (b'<?xml version="1.0"?><manifest xmlns:android='
                     b'"http://schemas.android.com/apk/res/android" package="com.example.decoded">'
                     b'<application android:debuggable="true">'
                     b'<activity android:name=".Main" android:exported="true" />'
                     b'</application></manifest>')
            with open(os.path.join(tmpdir, "AndroidManifest.xml"), "wb") as handle:
                handle.write(plain)
            smali_dir = os.path.join(tmpdir, "smali")
            os.makedirs(smali_dir)
            with open(os.path.join(smali_dir, "Main.smali"), "wb") as handle:
                handle.write(b"setJavaScriptEnabled AES/ECB\n")
            result = run_scan(tmpdir, static_only=True)
            ids = [f["id"] for f in result["findings"]]
            self.assertIn("MANIFEST_DEBUGGABLE", ids)
            self.assertIn("MANIFEST_EXPORTED_NO_PERMISSION", ids)
            self.assertIn("CODE_JS_ENABLED", ids)
            self.assertIn("CODE_ECB", ids)

    def test_single_manifest_file_input(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "AndroidManifest.xml")
            with open(path, "wb") as handle:
                handle.write(b'<?xml version="1.0"?><manifest xmlns:android='
                             b'"http://schemas.android.com/apk/res/android" package="com.example.single">'
                             b'<application android:allowBackup="true"></application></manifest>')
            result = run_scan(path, static_only=True)
            self.assertEqual(result["package"], "com.example.single")
            self.assertIn("MANIFEST_ALLOW_BACKUP", [f["id"] for f in result["findings"]])


class TestScoringAndMasking(unittest.TestCase):
    def test_score_math(self):
        items = [
            Finding("X1", "t", "critical", "c", "l", "e", "x", "f"),
            Finding("X2", "t", "high", "c", "l", "e", "x", "f"),
            Finding("X3", "t", "medium", "c", "l", "e", "x", "f"),
            Finding("X4", "t", "low", "c", "l", "e", "x", "f"),
            Finding("X5", "t", "info", "c", "l", "e", "x", "f"),
        ]
        score, grade, counts = score_findings(items)
        self.assertEqual(score, 50)
        self.assertEqual(grade, "D")
        self.assertEqual(counts["critical"], 1)

    def test_score_floor_at_zero(self):
        items = [Finding("X%d" % i, "t", "critical", "c", "l", "e", "x", "f")
                 for i in range(10)]
        score, grade, _counts = score_findings(items)
        self.assertEqual(score, 0)
        self.assertEqual(grade, "F")

    def test_masking(self):
        self.assertNotIn("SECRETVALUE123", mask_value("SECRETVALUE123"))
        self.assertIn("SECR", mask_value("SECRETVALUE123"))
        self.assertEqual(mask_url("http://example.test/path?token=abc"),
                         "http://example.test/***")
        self.assertEqual(mask_url("https://example.test/a/b"),
                         "https://example.test/***")

    def test_namespace_url_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            plain = (b'<?xml version="1.0"?><manifest xmlns:android='
                     b'"http://schemas.android.com/apk/res/android" package="com.example.ns">'
                     b'<application></application></manifest>')
            path = _zip_with_manifest(tmpdir, "ns.apk", plain)
            result = run_scan(path, static_only=True)
            self.assertNotIn("URL_CLEARTEXT", [f["id"] for f in result["findings"]])


class TestCustomRulesAndBaseline(unittest.TestCase):
    def test_custom_rule_found(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            clean, _vuln = build_sample_apks(tmpdir)
            rules_path = os.path.join(tmpdir, "rules.json")
            with open(rules_path, "w", encoding="utf-8") as handle:
                json.dump({"patterns": [{"id": "MY_MARKER", "pattern": "clean app code",
                                        "explanation": "My marker.",
                                        "fix": "Review it."}]}, handle)
            with open(rules_path, "r", encoding="utf-8") as handle:
                custom = json.load(handle)["patterns"]
            result = run_scan(clean, static_only=True, custom_rules=custom)
            self.assertIn("MY_MARKER", [f["id"] for f in result["findings"]])

    def test_bad_regex_custom_rule_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            clean, _vuln = build_sample_apks(tmpdir)
            custom = [{"id": "BAD_REGEX", "pattern": "([unclosed",
                       "explanation": "Bad.", "fix": "Fix."}]
            result = run_scan(clean, static_only=True, custom_rules=custom)
            self.assertEqual(result["score"], 100)

    def test_missing_baseline_is_clean_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            clean, _vuln = build_sample_apks(tmpdir)
            with self.assertRaises(ScanError):
                run_scan(clean, static_only=True,
                         baseline_path=os.path.join(tmpdir, "nope.json"))

    def test_baseline_detects_fixed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            _clean, vuln = build_sample_apks(tmpdir)
            first = run_scan(vuln, static_only=True)
            base_path = os.path.join(tmpdir, "base.json")
            with open(base_path, "w", encoding="utf-8") as handle:
                json.dump(first, handle)
            clean2, _v = build_sample_apks(tmpdir)
            second = run_scan(clean2, static_only=True, baseline_path=base_path)
            self.assertEqual(second["baseline"]["new"], [])
            self.assertTrue(len(second["baseline"]["fixed"]) > 0)


class TestReportsAndCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.clean, self.vuln = build_sample_apks(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_report_escapes_markup_in_names(self):
        plain = (b'<?xml version="1.0"?><manifest xmlns:android='
                 b'"http://schemas.android.com/apk/res/android" package="com.example.xss">'
                 b'<application>'
                 b'<activity android:name=".Main&lt;script&gt;alert(1)&lt;/script&gt;" android:exported="true" />'
                 b'</application></manifest>')
        path = _zip_with_manifest(self.tmp.name, "xss.apk", plain)
        result = run_scan(path, static_only=True)
        out_dir = os.path.join(self.tmp.name, "xss-out")
        write_reports(result, out_dir, ("html",))
        with open(os.path.join(out_dir, "report.html"), encoding="utf-8") as handle:
            page = handle.read()
        self.assertNotIn("<script>alert", page)
        self.assertIn("&lt;script&gt;", page)

    def test_determinism(self):
        first = run_scan(self.vuln, static_only=True)
        second = run_scan(self.vuln, static_only=True)
        self.assertEqual(json.dumps(first, sort_keys=True),
                         json.dumps(second, sort_keys=True))

    def test_cli_formats(self):
        out_json = os.path.join(self.tmp.name, "json-only")
        code = cli_main(["scan", self.clean, "-o", out_json, "--format", "json",
                         "--fail-on", "never"])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.isfile(os.path.join(out_json, "report.json")))
        self.assertFalse(os.path.isfile(os.path.join(out_json, "report.html")))
        out_html = os.path.join(self.tmp.name, "html-only")
        code = cli_main(["scan", self.clean, "-o", out_html, "--format", "html",
                         "--fail-on", "never"])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.isfile(os.path.join(out_html, "report.html")))
        self.assertFalse(os.path.isfile(os.path.join(out_html, "report.json")))

    def test_cli_fail_on_thresholds(self):
        out_dir = os.path.join(self.tmp.name, "thr")
        self.assertEqual(cli_main(["scan", self.vuln, "-o", out_dir,
                                   "--fail-on", "critical"]), 2)
        self.assertEqual(cli_main(["scan", self.vuln, "-o", out_dir,
                                   "--fail-on", "never"]), 0)
        self.assertEqual(cli_main(["scan", self.clean, "-o", out_dir,
                                   "--fail-on", "low"]), 0)

    def test_cli_missing_input_exits_1_not_crash(self):
        code = cli_main(["scan", "/tmp/does-not-exist-xyz.apk",
                         "-o", os.path.join(self.tmp.name, "bad")])
        self.assertEqual(code, 1)

    def test_cli_missing_rules_file_exits_1(self):
        code = cli_main(["scan", self.clean, "-o", os.path.join(self.tmp.name, "r"),
                         "--rules", "/tmp/does-not-exist-xyz.json"])
        self.assertEqual(code, 1)

    def test_cli_missing_dynamic_log_exits_1(self):
        code = cli_main(["scan", self.clean, "-o", os.path.join(self.tmp.name, "d"),
                         "--dynamic-log", "/tmp/does-not-exist-xyz.jsonl"])
        self.assertEqual(code, 1)


class TestDynamicLog(unittest.TestCase):
    def test_bad_lines_and_bad_severity(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            clean, _vuln = build_sample_apks(tmpdir)
            log_path = os.path.join(tmpdir, "log.jsonl")
            with open(log_path, "w", encoding="utf-8") as handle:
                handle.write("this is not json\n")
                handle.write('{"tag": "network", "detail": "host", "severity": "banana"}\n')
                handle.write('{"tag": "crypto", "detail": "AES/ECB", "severity": "high"}\n')
            result = run_scan(clean, static_only=True, dynamic_log_path=log_path)
            ids = [f["id"] for f in result["findings"]]
            self.assertIn("DYNAMIC_NETWORK", ids)
            self.assertIn("DYNAMIC_CRYPTO", ids)
            network = [f for f in result["findings"] if f["id"] == "DYNAMIC_NETWORK"][0]
            self.assertEqual(network["severity"], "low")

    def test_empty_dynamic_log(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            clean, _vuln = build_sample_apks(tmpdir)
            log_path = os.path.join(tmpdir, "empty.jsonl")
            with open(log_path, "w", encoding="utf-8") as handle:
                handle.write("")
            result = run_scan(clean, static_only=True, dynamic_log_path=log_path)
            self.assertEqual(result["findings"], [])


class TestRealApkShape(unittest.TestCase):
    """Regression tests for the real APK attributeStart bug (2026-10-28).

    Real toolchains store attributeStart=20, relative to the end of
    the node header. An earlier parser version read attributes from
    chunk start + attributeStart, which garbled every attribute on
    real APKs while the project's own writer (which wrongly stored 36)
    kept roundtrip tests green.
    """

    def test_spec_attribute_start_is_20(self):
        import struct
        from apk_pipeline.axml_write import build_axml
        data = build_axml(manifest_clean())
        pos = 8
        while pos + 8 <= len(data):
            ctype, _hsize, csize = struct.unpack_from("<HHI", data, pos)
            if ctype == 0x0102:
                (attr_start,) = struct.unpack_from("<H", data, pos + 24)
                self.assertEqual(attr_start, 20)
                return
            pos += csize
        self.fail("no StartElement chunk found")

    def test_utf16_pool_parses(self):
        from apk_pipeline.axml_write import build_axml
        info = parse_manifest_bytes(build_axml(manifest_clean(), utf16=True))
        self.assertEqual(info["package"], "com.example.cleanapp")
        self.assertIn("android.permission.INTERNET", info["permissions"])
        self.assertEqual(len(info["components"]), 2)

    def test_resource_map_chunk_skipped(self):
        import struct
        from apk_pipeline.axml_write import build_axml
        data = build_axml(manifest_clean())
        _ctype, _hsize, pool_size = struct.unpack_from("<HHI", data, 8)
        resmap = struct.pack("<HHI", 0x0180, 8, 16) + struct.pack("<II", 0x01010000, 0x01010001)
        spliced = data[:8 + pool_size] + resmap + data[8 + pool_size:]
        spliced = struct.pack("<II", 0x00080003, len(spliced)) + spliced[8:]
        info = parse_manifest_bytes(spliced)
        self.assertEqual(info["package"], "com.example.cleanapp")
        self.assertEqual(len(info["components"]), 2)

    def test_many_root_attributes_parse(self):
        from apk_pipeline.axml_write import build_axml
        tree = {
            "name": "manifest",
            "attrs": [("package", "com.example.real"),
                      ("android:versionCode", 42),
                      ("android:versionName", "2.3"),
                      ("android:compileSdkVersion", 34),
                      ("android:platformBuildVersionCode", 34)],
            "children": [
                {"name": "uses-permission",
                 "attrs": [("android:name", "android.permission.INTERNET")],
                 "children": []},
                {"name": "application", "attrs": [], "children": []},
            ],
        }
        info = parse_manifest_bytes(build_axml(tree))
        self.assertEqual(info["package"], "com.example.real")
        self.assertEqual(info["version_code"], "42")
        self.assertEqual(info["version_name"], "2.3")
        self.assertEqual(info["permissions"], ["android.permission.INTERNET"])


if __name__ == "__main__":
    unittest.main()
