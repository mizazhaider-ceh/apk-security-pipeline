"""Tests for auto install setup, per tool files, and colorful CLI.

Run: python3 -m unittest discover -s tests -v
Install tests use mocks, never the network, except the real Java
binary check on the host (Java is present on the test machine).
"""

import contextlib
import io
import os
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from apk_pipeline import tools as tools_mod
from apk_pipeline.cli import _c, _color_enabled, main as cli_main
from apk_pipeline.report import write_reports
from apk_pipeline.scanner import run_scan

CLEAN_ENV = {"APKTOOL_JAR": "", "JADX_BIN": "", "APK_PIPELINE_TOOLS_DIR": ""}


class FakeArgs:
    def __init__(self, color=False, no_color=False):
        self.color = color
        self.no_color = no_color


class TestColor(unittest.TestCase):
    def test_plain_when_disabled(self):
        self.assertEqual(_c("hello", "red", False), "hello")

    def test_wrapped_when_enabled(self):
        out = _c("hello", "red", True)
        self.assertTrue(out.startswith("\033[31m"))
        self.assertTrue(out.endswith("\033[0m"))
        self.assertIn("hello", out)

    def test_flags_win(self):
        self.assertTrue(_color_enabled(FakeArgs(color=True)))
        self.assertFalse(_color_enabled(FakeArgs(no_color=True)))


class TestSetup(unittest.TestCase):
    def _found(self, name, found):
        return {"found": found, "path": "/fake/" + name if found else "",
                "version": "1.0" if found else "", "install": "install " + name}

    def test_all_present_means_nothing_installed(self):
        before = {name: self._found(name, True)
                  for name in ("java", "apktool", "jadx", "androguard", "frida")}
        after = dict(before)
        with mock.patch.object(tools_mod, "detect_tools", side_effect=[before, after]):
            with mock.patch.object(tools_mod, "install_java", side_effect=AssertionError("must not run")):
                with mock.patch.object(tools_mod, "install_apktool", side_effect=AssertionError("must not run")):
                    with mock.patch.object(tools_mod, "install_jadx", side_effect=AssertionError("must not run")):
                        result = tools_mod.setup_tools(directory="/tmp/nope", with_frida=True)
        self.assertTrue(all(s["status"] == "already present" for s in result["steps"]))
        self.assertEqual(len(result["steps"]), 5)

    def test_missing_tool_gets_installed_and_present_tools_untouched(self):
        before = {"java": self._found("java", True),
                  "apktool": self._found("apktool", False),
                  "jadx": self._found("jadx", True),
                  "androguard": self._found("androguard", True),
                  "frida": self._found("frida", True)}
        after = {"java": self._found("java", True),
                 "apktool": self._found("apktool", True),
                 "jadx": self._found("jadx", True),
                 "androguard": self._found("androguard", True),
                 "frida": self._found("frida", True)}
        with mock.patch.object(tools_mod, "detect_tools", side_effect=[before, after]):
            with mock.patch.object(tools_mod, "install_apktool",
                                   return_value=(True, "installed fake apktool")) as installer:
                result = tools_mod.setup_tools(directory="/tmp/nope", with_frida=True)
        by_tool = {s["tool"]: s for s in result["steps"]}
        self.assertEqual(by_tool["apktool"]["status"], "installed")
        self.assertEqual(by_tool["java"]["status"], "already present")
        self.assertEqual(by_tool["jadx"]["status"], "already present")
        installer.assert_called_once()

    def test_find_frida_checks_local_bin(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            local_bin = os.path.join(tmpdir, ".local", "bin")
            os.makedirs(local_bin)
            script = os.path.join(local_bin, "frida")
            with open(script, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\necho 1.0\n")
            os.chmod(script, 0o755)
            with mock.patch.dict(os.environ, {"PATH": "/nonexistent", "HOME": tmpdir}):
                self.assertEqual(tools_mod._find_frida(), script)
            with mock.patch.dict(os.environ, {"PATH": "/nonexistent", "HOME": "/nonexistent-home"}):
                self.assertIsNone(tools_mod._find_frida())

    def test_jadx_download_and_unzip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            def fake_download(url, dest):
                with zipfile.ZipFile(dest, "w") as archive:
                    archive.writestr("bin/jadx", "#!/bin/sh\necho 9.9.9\n")
                return 100
            with mock.patch.dict(os.environ, CLEAN_ENV):
                with mock.patch.object(tools_mod, "_github_latest_asset",
                                       return_value=("v9.9.9", "jadx-9.9.9.zip", "http://example.test/jadx.zip")):
                    with mock.patch.object(tools_mod, "_download", side_effect=fake_download):
                        ok, detail = tools_mod.install_jadx(tmpdir)
            self.assertTrue(ok, detail)
            binary = os.path.join(tmpdir, "jadx", "bin", "jadx")
            self.assertTrue(os.path.isfile(binary))
            self.assertTrue(os.access(binary, os.X_OK))

    def test_apktool_download_and_verify(self):
        def fake_download(url, dest):
            with open(dest, "wb") as handle:
                handle.write(b"fake jar bytes")
            return 14
        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch.dict(os.environ, CLEAN_ENV):
                with mock.patch.object(tools_mod, "_github_latest_asset",
                                       return_value=("v9.9.9", "apktool_9.9.9.jar", "http://example.test/apktool.jar")):
                    with mock.patch.object(tools_mod, "_download", side_effect=fake_download):
                        with mock.patch.object(tools_mod, "run_command",
                                               return_value=(0, "9.9.9\n", "")):
                            ok, detail = tools_mod.install_apktool(tmpdir)
            self.assertTrue(ok, detail)
            self.assertTrue(os.path.isfile(os.path.join(tmpdir, "apktool.jar")))


class TestPerToolFiles(unittest.TestCase):
    def test_contents_breakdown_and_per_tool_jsons(self):
        from test_deep_mode import PLAIN_MANIFEST, SMALI_SAMPLE
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "AndroidManifest.xml"), "w", encoding="utf-8") as handle:
                handle.write(PLAIN_MANIFEST)
            smali_dir = os.path.join(tmpdir, "smali", "com", "example")
            os.makedirs(smali_dir)
            with open(os.path.join(smali_dir, "Main.smali"), "w", encoding="utf-8") as handle:
                handle.write(SMALI_SAMPLE)
            result = run_scan(tmpdir, static_only=True, deep=True,
                              skip_apktool=True, skip_jadx=True, skip_androguard=True,
                              work_root=os.path.join(tmpdir, "work"))
            contents = result["deep_inventory"]["contents"]
            self.assertEqual(contents["manifest"]["count"], 1)
            out_dir = os.path.join(tmpdir, "out")
            written = write_reports(result, out_dir, ("html", "json"))
            self.assertIn("apktool", written)
            self.assertIn("deep-inventory", written)
            import json
            with open(written["apktool"], encoding="utf-8") as handle:
                apktool_data = json.load(handle)
            ids = [f["id"] for f in apktool_data["findings"]]
            self.assertIn("SMALI_JS_ENABLED", ids)
            with open(written["html"], encoding="utf-8") as handle:
                html_text = handle.read()
            self.assertIn("Apktool: smali and resources", html_text)
            self.assertIn("APK contents, each part separate", html_text)

    def test_cli_color_forced(self):
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sample = os.path.join(repo, "samples", "vulnerable.apk")
        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, "out")
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = cli_main(["scan", sample, "--static-only",
                                 "-o", out, "--format", "json", "--fail-on", "never",
                                 "--color"])
            self.assertEqual(code, 0)
            self.assertIn("\033[", buffer.getvalue())
            buffer2 = io.StringIO()
            with contextlib.redirect_stdout(buffer2):
                code = cli_main(["scan", sample, "--static-only",
                                 "-o", out, "--format", "json", "--fail-on", "never",
                                 "--no-color"])
            self.assertEqual(code, 0)
            self.assertNotIn("\033[", buffer2.getvalue())


if __name__ == "__main__":
    unittest.main()
