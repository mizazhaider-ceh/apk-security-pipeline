"""Real tool detection for deep mode: apktool, jadx, androguard.

Deep mode uses real tools when they exist and explains clearly when
they do not, including how to install them. Nothing here is required
for a basic scan: the basic pipeline is pure Python on purpose.
"""

import os
import shutil
import subprocess

INSTALL_NOTES = {
    "apktool": "Install: download apktool.jar from github.com/iBotPeaches/Apktool/releases and run it with Java, or install your distro package. Then make sure `apktool` is on PATH or set APKTOOL_JAR to the jar path.",
    "jadx": "Install: download jadx from github.com/skylot/jadx/releases, unzip it, and put its bin directory on PATH, or set JADX_BIN to the jadx executable.",
    "androguard": "Install: pip install androguard. It is optional: the basic pipeline does not need it.",
    "java": "Install: a Java runtime (for example openjdk-17-jre-headless) so apktool and jadx can run.",
}


def _version_of(cmd, args=("--version",), timeout=20):
    try:
        proc = subprocess.run(cmd + list(args), capture_output=True,
                              text=True, timeout=timeout)
        text = (proc.stdout + proc.stderr).strip().splitlines()
        return text[0].strip() if text else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _candidate_paths(env_var, extra):
    paths = []
    value = os.environ.get(env_var, "")
    if value:
        paths.append(value)
    paths.extend(extra)
    return paths


def detect_tools():
    """Detect real tools. Returns a dict of tool info dicts."""
    tools = {}
    java_bin = shutil.which("java")
    tools["java"] = {
        "found": bool(java_bin),
        "path": java_bin or "",
        "version": _version_of([java_bin], ("-version",)) if java_bin else "",
        "install": INSTALL_NOTES["java"],
    }
    apktool_bin = shutil.which("apktool")
    apktool_jar = ""
    if not apktool_bin:
        for candidate in _candidate_paths("APKTOOL_JAR", [
                os.path.expanduser("~/workspace/tools-apk/apktool.jar"),
                os.path.expanduser("~/.local/share/apk-tools/apktool.jar"),
                "./tools/apktool.jar"]):
            if candidate and os.path.isfile(candidate):
                apktool_jar = candidate
                break
    if apktool_bin:
        version = _version_of([apktool_bin])
        tools["apktool"] = {"found": True, "path": apktool_bin,
                            "version": version, "kind": "binary",
                            "install": INSTALL_NOTES["apktool"]}
    elif apktool_jar and java_bin:
        version = _version_of([java_bin, "-jar", apktool_jar], ("--version",))
        tools["apktool"] = {"found": True, "path": apktool_jar,
                            "version": version, "kind": "jar",
                            "install": INSTALL_NOTES["apktool"]}
    else:
        tools["apktool"] = {"found": False, "path": apktool_jar,
                            "version": "", "kind": "",
                            "install": INSTALL_NOTES["apktool"]}
    jadx_bin = shutil.which("jadx")
    if not jadx_bin:
        for candidate in _candidate_paths("JADX_BIN", [
                os.path.expanduser("~/workspace/tools-apk/jadx/bin/jadx"),
                os.path.expanduser("~/.local/share/apk-tools/jadx/bin/jadx"),
                "./tools/jadx/bin/jadx"]):
            if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                jadx_bin = candidate
                break
    tools["jadx"] = {
        "found": bool(jadx_bin),
        "path": jadx_bin or "",
        "version": _version_of([jadx_bin], ("--version",)) if jadx_bin else "",
        "install": INSTALL_NOTES["jadx"],
    }
    try:
        import androguard  # noqa: F401
        tools["androguard"] = {"found": True, "path": "python package",
                               "version": getattr(androguard, "__version__", ""),
                               "install": INSTALL_NOTES["androguard"]}
    except ImportError:
        tools["androguard"] = {"found": False, "path": "",
                               "version": "", "install": INSTALL_NOTES["androguard"]}
    return tools


def apktool_command(tools):
    """Return the command list to run apktool, or None when unavailable."""
    info = tools.get("apktool", {})
    if not info.get("found"):
        return None
    if info.get("kind") == "jar":
        return ["java", "-jar", info["path"]]
    return [info["path"]]


def jadx_command(tools):
    """Return the command list to run jadx, or None when unavailable."""
    info = tools.get("jadx", {})
    if not info.get("found"):
        return None
    return [info["path"]]


def run_command(cmd, timeout=300):
    """Run a tool command. Returns (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return None, "", "command timed out after %d seconds" % timeout
    except OSError as exc:
        return None, "", "could not run command: %s" % exc
