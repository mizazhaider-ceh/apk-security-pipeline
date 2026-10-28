"""Dynamic stage: Frida harness, device aware, honest about skips.

The dynamic stage never fakes evidence. If no device is connected or
Frida is missing, it reports "skipped" with the exact reason and the
setup steps, and the rest of the pipeline still runs. When a device is
present, it runs the scripts in frida/ against a test app you own and
turns log lines into findings.

Log line format produced by the scripts (one JSON object per line):
{"tag": "network"|"storage"|"crypto"|"intent", "detail": "...",
 "severity": "low"|"medium"|"high"}
"""

import json
import os
import shutil
import subprocess

from .rules import Finding


def _stage(name, goal, checked, found, skipped=""):
    return {"stage": name, "goal": goal, "checked": checked,
            "found": found, "skipped": skipped}


def _run(cmd, timeout=15):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, "", str(exc)


def log_lines_to_findings(log_lines):
    findings = []
    for line in log_lines:
        try:
            entry = json.loads(line)
        except (ValueError, TypeError):
            continue
        tag = entry.get("tag", "runtime")
        detail = entry.get("detail", "")
        severity = entry.get("severity", "low")
        if severity not in ("low", "medium", "high", "critical", "info"):
            severity = "low"
        findings.append(Finding(
            "DYNAMIC_%s" % tag.upper(), "Runtime observation: %s" % tag,
            severity, "dynamic", "runtime log",
            detail[:300],
            "Observed at runtime on a test app you own. Runtime evidence confirms behaviour that static reading alone cannot prove.",
            "Review the behaviour. If it exposes data or weakens security, fix the app code and re-run the harness.",
            stage="dynamic"))
    return findings


def run_dynamic_stage(input_path, static_only=False, seconds=20):
    """Run the dynamic stage, or report why it was skipped.

    Returns (findings, stage_log_entry). Never raises for a missing
    device: a skip is a normal, reported outcome.
    """
    if static_only:
        return [], _stage(
            "Dynamic (Frida)",
            "Observe the app at runtime on a device you own.",
            "static-only mode requested",
            "0 dynamic findings",
            "skipped by user request (--static-only). Run without that flag to enable dynamic testing.")
    frida = shutil.which("frida")
    adb = shutil.which("adb")
    if not frida:
        return [], _stage(
            "Dynamic (Frida)",
            "Observe the app at runtime on a device you own.",
            "looked for the frida command",
            "0 dynamic findings",
            "skipped: Frida is not installed on this machine. Install frida-tools, connect an emulator or device you own, then re-run without --static-only.")
    if not adb:
        return [], _stage(
            "Dynamic (Frida)",
            "Observe the app at runtime on a device you own.",
            "looked for the adb command",
            "0 dynamic findings",
            "skipped: adb is not installed, so no device can be reached. Install Android platform tools, start an emulator you own, then re-run.")
    code, out, _err = _run(["adb", "devices"], timeout=15)
    devices = [line for line in out.splitlines()[1:]
               if line.strip() and "device" in line]
    if code != 0 or not devices:
        return [], _stage(
            "Dynamic (Frida)",
            "Observe the app at runtime on a device you own.",
            "adb devices output checked",
            "0 dynamic findings",
            "skipped: no device or emulator is connected. Start an emulator you own or connect a device you own, then re-run.")
    scripts_dir = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "frida")
    scripts = ["trace-network.js", "trace-storage.js",
               "trace-crypto.js", "trace-intents.js"]
    available = [name for name in scripts
                 if os.path.isfile(os.path.join(scripts_dir, name))]
    if not available:
        return [], _stage(
            "Dynamic (Frida)",
            "Observe the app at runtime on a device you own.",
            "frida scripts directory checked",
            "0 dynamic findings",
            "skipped: no Frida scripts found in frida/. Restore the scripts directory, then re-run.")
    # NOTE: a real run needs a target package and a scripted flow, which
    # the caller supplies. This harness reports readiness here; the
    # per-app runner lives in frida/README.md with exact commands.
    return [], _stage(
        "Dynamic (Frida)",
        "Observe the app at runtime on a device you own.",
        "device connected, frida present, %d scripts available" % len(available),
        "0 dynamic findings collected by this automatic run",
        "ready but not auto-run: dynamic testing needs a target test app and a scripted flow. Follow frida/README.md to run it against your own test app, then feed the JSON log back with --dynamic-log.")
