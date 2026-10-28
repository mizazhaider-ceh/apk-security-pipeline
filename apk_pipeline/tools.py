"""Real tool detection and automatic installation for deep mode.

Rules, in order:
1. If a tool is already present, leave it alone. Never reinstall,
   overwrite, or downgrade a working tool.
2. Install only the missing tools, one at a time, then verify each
   one by running it (version check) or importing it.
3. Report honestly: already present, installed, or failed with the
   manual steps. A failed install never blocks the rest of the setup,
   and never fakes a tool as present.

Install sources: apktool and jadx come from their official GitHub
releases, Java comes from the system package manager when available,
androguard and frida-tools come from pip. The tools directory can be
overridden with APK_PIPELINE_TOOLS_DIR; the default is
~/workspace/tools-apk.
"""

import json
import os
import shutil
import stat
import subprocess
import sys
import urllib.request
import zipfile

INSTALL_NOTES = {
    "apktool": "Install: download apktool.jar from github.com/iBotPeaches/Apktool/releases and run it with Java, or install your distro package. Then make sure `apktool` is on PATH or set APKTOOL_JAR to the jar path.",
    "jadx": "Install: download jadx from github.com/skylot/jadx/releases, unzip it, and put its bin directory on PATH, or set JADX_BIN to the jadx executable.",
    "androguard": "Install: pip install androguard. It is optional: the basic pipeline does not need it.",
    "frida": "Install: pip install frida-tools, then connect an emulator or device you own for dynamic runs.",
    "java": "Install: a Java runtime (for example openjdk-17-jre-headless on Linux, or Temurin from adoptium.net on Windows and macOS) so apktool and jadx can run.",
}


def tools_dir(custom=None):
    """Resolve the tools directory, honoring the environment override."""
    if custom:
        return os.path.expanduser(custom)
    override = os.environ.get("APK_PIPELINE_TOOLS_DIR", "")
    if override:
        return os.path.expanduser(override)
    return os.path.expanduser("~/workspace/tools-apk")


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


def _find_apktool(directory):
    """Return (kind, path) for apktool, or (None, None) when absent."""
    binary = shutil.which("apktool")
    if binary:
        return "binary", binary
    for candidate in _candidate_paths("APKTOOL_JAR", [
            os.path.join(directory, "apktool.jar"),
            os.path.expanduser("~/.local/share/apk-tools/apktool.jar"),
            "./tools/apktool.jar"]):
        if candidate and os.path.isfile(candidate):
            return "jar", candidate
    return None, None


def _find_frida():
    """Return the frida executable path, or None when absent.

    pip --user installs scripts into ~/.local/bin, which is often not
    on PATH, so check there explicitly too.
    """
    binary = shutil.which("frida")
    if binary:
        return binary
    candidate = os.path.expanduser("~/.local/bin/frida")
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate
    return None


def _find_jadx(directory):
    """Return the jadx executable path, or None when absent."""
    binary = shutil.which("jadx")
    if binary:
        return binary
    for candidate in _candidate_paths("JADX_BIN", [
            os.path.join(directory, "jadx", "bin", "jadx"),
            os.path.expanduser("~/.local/share/apk-tools/jadx/bin/jadx"),
            "./tools/jadx/bin/jadx"]):
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def detect_tools(directory=None):
    """Detect real tools. Returns a dict of tool info dicts."""
    directory = tools_dir(directory)
    tools = {}
    java_bin = shutil.which("java")
    tools["java"] = {
        "found": bool(java_bin),
        "path": java_bin or "",
        "version": _version_of([java_bin], ("-version",)) if java_bin else "",
        "install": INSTALL_NOTES["java"],
    }
    kind, apktool_path = _find_apktool(directory)
    if apktool_path and kind == "binary":
        version = _version_of([apktool_path])
        tools["apktool"] = {"found": True, "path": apktool_path,
                            "version": version, "kind": "binary",
                            "install": INSTALL_NOTES["apktool"]}
    elif apktool_path and java_bin:
        version = _version_of([java_bin, "-jar", apktool_path], ("--version",))
        tools["apktool"] = {"found": True, "path": apktool_path,
                            "version": version, "kind": "jar",
                            "install": INSTALL_NOTES["apktool"]}
    else:
        tools["apktool"] = {"found": False, "path": apktool_path or "",
                            "version": "", "kind": kind or "",
                            "install": INSTALL_NOTES["apktool"]}
    jadx_bin = _find_jadx(directory)
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
    frida_bin = _find_frida()
    tools["frida"] = {
        "found": bool(frida_bin),
        "path": frida_bin or "",
        "version": _version_of([frida_bin], ("--version",)) if frida_bin else "",
        "install": INSTALL_NOTES["frida"],
    }
    tools["tools_dir"] = {"found": os.path.isdir(directory),
                          "path": directory, "version": "",
                          "install": ""}
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


# ---------------------------------------------------------------------------
# Automatic installation
# ---------------------------------------------------------------------------

def _download(url, dest, timeout=300):
    """Download a URL to a file. Returns the byte count. Raises on failure."""
    request = urllib.request.Request(url, headers={"User-Agent": "apk-security-pipeline"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read()
    with open(dest, "wb") as handle:
        handle.write(data)
    return len(data)


def _github_latest_asset(repo, predicate):
    """Return (tag, asset name, download URL) for a release asset.

    repo is like "iBotPeaches/Apktool". predicate picks the asset.
    """
    url = "https://api.github.com/repos/%s/releases/latest" % repo
    request = urllib.request.Request(url, headers={"User-Agent": "apk-security-pipeline"})
    with urllib.request.urlopen(request, timeout=60) as response:
        release = json.loads(response.read().decode("utf-8"))
    for asset in release.get("assets", []):
        name = asset.get("name", "")
        if predicate(name):
            return release.get("tag_name", ""), name, asset["browser_download_url"]
    raise ValueError("no matching asset found in latest %s release" % repo)


def _pip_install(package):
    """Install a pip package for the current Python. Returns (ok, detail)."""
    base = [sys.executable, "-m", "pip", "install", "--user", package]
    for args in (base + ["--break-system-packages"], base):
        code, _out, err = run_command(args, timeout=600)
        if code == 0:
            return True, "pip installed %s" % package
        last_error = (err.strip().splitlines() or ["pip failed"])[-1]
    return False, last_error


def install_java(allow_apt=True):
    """Install Java when missing. Returns (ok, detail)."""
    if shutil.which("java"):
        return True, "already present"
    if sys.platform == "win32":
        return False, "automatic Java install is not supported on Windows. " + INSTALL_NOTES["java"]
    apt = shutil.which("apt-get")
    if allow_apt and apt and os.geteuid() == 0:
        code, _out, err = run_command(
            [apt, "update", "-qq"], timeout=600)
        if code != 0:
            return False, "apt update failed: %s" % (err.strip().splitlines() or ["unknown error"])[-1]
        code, _out, err = run_command(
            [apt, "install", "-y", "-qq", "openjdk-17-jre-headless"],
            timeout=900)
        if code == 0 and shutil.which("java"):
            return True, "installed openjdk-17-jre-headless via apt"
        return False, "apt install failed: %s" % (err.strip().splitlines() or ["unknown error"])[-1]
    return False, "automatic Java install needs root with apt. " + INSTALL_NOTES["java"]


def install_apktool(directory=None):
    """Download apktool when missing. Returns (ok, detail)."""
    directory = tools_dir(directory)
    kind, path = _find_apktool(directory)
    if path:
        return True, "already present at %s" % path
    if not shutil.which("java"):
        return False, "Java is required first. Run setup again after Java is installed."
    os.makedirs(directory, exist_ok=True)
    try:
        _tag, name, url = _github_latest_asset(
            "iBotPeaches/Apktool",
            lambda n: n.startswith("apktool_") and n.endswith(".jar"))
        dest = os.path.join(directory, "apktool.jar")
        size = _download(url, dest)
    except Exception as exc:  # noqa: BLE001 - download errors vary
        return False, "download failed: %s" % exc
    code, out, _err = run_command(["java", "-jar", dest, "--version"], timeout=60)
    if code == 0 and out.strip():
        return True, "installed %s (%d bytes), version %s" % (name, size, out.strip().splitlines()[0])
    return False, "downloaded jar did not run. Delete %s and try again." % dest


def install_jadx(directory=None):
    """Download and unzip jadx when missing. Returns (ok, detail)."""
    directory = tools_dir(directory)
    path = _find_jadx(directory)
    if path:
        return True, "already present at %s" % path
    os.makedirs(directory, exist_ok=True)
    try:
        _tag, name, url = _github_latest_asset(
            "skylot/jadx",
            lambda n: n.startswith("jadx-") and n.endswith(".zip")
            and "gui" not in n and "win" not in n)
        zip_path = os.path.join(directory, "jadx-download.zip")
        _download(url, zip_path)
        dest = os.path.join(directory, "jadx")
        with zipfile.ZipFile(zip_path) as archive:
            archive.extractall(dest)
        os.remove(zip_path)
        binary = os.path.join(dest, "bin", "jadx")
        os.chmod(binary, os.stat(binary).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception as exc:  # noqa: BLE001 - download and unzip errors vary
        return False, "download failed: %s" % exc
    code, out, _err = run_command([binary, "--version"], timeout=60)
    if code == 0 and out.strip():
        return True, "installed %s, version %s" % (name, out.strip().splitlines()[0])
    return False, "downloaded jadx did not run. Delete %s and try again." % dest


def install_androguard():
    """Install androguard when missing. Returns (ok, detail)."""
    try:
        import androguard  # noqa: F401
        return True, "already present"
    except ImportError:
        pass
    ok, detail = _pip_install("androguard")
    if not ok:
        return False, detail
    try:
        import androguard  # noqa: F401
        return True, "installed androguard via pip"
    except ImportError:
        return False, "pip reported success but androguard still does not import."


def install_frida():
    """Install frida-tools when missing. Returns (ok, detail)."""
    if _find_frida():
        return True, "already present"
    ok, detail = _pip_install("frida-tools")
    if not ok:
        return False, detail
    found = _find_frida()
    if found:
        if os.path.dirname(found) not in os.environ.get("PATH", ""):
            return True, ("installed frida-tools via pip at %s, but that "
                          "directory is not on PATH" % found)
        return True, "installed frida-tools via pip"
    return False, "pip reported success but the frida command is still missing (check PATH)."


def setup_tools(directory=None, with_frida=True, allow_apt=True):
    """Install every missing tool, leaving present tools alone.

    Returns a dict with per tool steps (already present, installed, or
    failed with detail) plus before and after detection results.
    Order matters: Java first, because apktool and jadx need it.
    """
    directory = tools_dir(directory)
    before = detect_tools(directory)
    installers = [
        ("java", lambda: install_java(allow_apt=allow_apt)),
        ("apktool", lambda: install_apktool(directory)),
        ("jadx", lambda: install_jadx(directory)),
        ("androguard", install_androguard),
    ]
    if with_frida:
        installers.append(("frida", install_frida))
    steps = []
    for name, installer in installers:
        if before[name]["found"]:
            steps.append({"tool": name, "status": "already present",
                          "detail": before[name]["path"] or before[name]["version"]})
            continue
        try:
            ok, detail = installer()
        except Exception as exc:  # noqa: BLE001 - installers vary
            ok, detail = False, "install crashed: %s" % exc
        steps.append({"tool": name,
                      "status": "installed" if ok else "failed",
                      "detail": detail})
    after = detect_tools(directory)
    return {"steps": steps, "before": before, "after": after,
            "tools_dir": directory}
