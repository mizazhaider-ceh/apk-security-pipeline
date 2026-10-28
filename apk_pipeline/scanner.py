"""Scan orchestration: intake, stages, stage log, scoring, baseline.

Every stage writes a stage log entry that explains, in plain language,
what the stage does, what it checked, what it found, and what it
skipped and why. That log is printed in explain mode and embedded in
every report, so the tool always tells you what it is doing.
"""

import json
import os
import zipfile

from .manifest import parse_manifest_bytes
from .rules import manifest_findings, scan_bytes_for_patterns, score_findings
from .dynamic import run_dynamic_stage, log_lines_to_findings


class ScanError(Exception):
    """Raised when input cannot be scanned."""


def _stage(name, goal, checked, found, skipped=""):
    return {
        "stage": name,
        "goal": goal,
        "checked": checked,
        "found": found,
        "skipped": skipped,
    }


def _collect_input(path):
    """Return (manifest_bytes, files, intake_note). files is a list of
    (relative path, bytes). Supports an APK zip file, a decoded APK
    directory, or a single manifest file."""
    if os.path.isdir(path):
        manifest_path = os.path.join(path, "AndroidManifest.xml")
        if not os.path.isfile(manifest_path):
            raise ScanError("directory has no AndroidManifest.xml at its root: %s" % path)
        with open(manifest_path, "rb") as handle:
            manifest_bytes = handle.read()
        files = []
        for root, _dirs, names in os.walk(path):
            for name in names:
                full = os.path.join(root, name)
                rel = os.path.relpath(full, path)
                try:
                    with open(full, "rb") as handle:
                        files.append((rel, handle.read()))
                except OSError:
                    continue
        return manifest_bytes, files, "decoded directory input: %d files collected" % len(files)
    if os.path.isfile(path):
        if path.lower().endswith(".xml"):
            with open(path, "rb") as handle:
                manifest_bytes = handle.read()
            return manifest_bytes, [], "single manifest file input (patterns need an APK or directory)"
        try:
            archive = zipfile.ZipFile(path)
        except zipfile.BadZipFile:
            raise ScanError("input is not an APK zip, a directory, or a manifest file: %s" % path)
        names = archive.namelist()
        if "AndroidManifest.xml" not in names:
            raise ScanError("APK has no AndroidManifest.xml entry")
        manifest_bytes = archive.read("AndroidManifest.xml")
        files = []
        for name in names:
            try:
                files.append((name, archive.read(name)))
            except (KeyError, RuntimeError):
                continue
        return manifest_bytes, files, "APK input: %d entries collected" % len(files)
    raise ScanError("input path does not exist: %s" % path)


def run_scan(input_path, explain=False, static_only=False,
             custom_rules=None, baseline_path=None, dynamic_seconds=20,
             dynamic_log_path=None, deep=False, decode_dir=None,
             skip_apktool=False, skip_jadx=False, skip_androguard=False,
             work_root=None):
    """Run the full pipeline. Returns a result dict for reports."""
    stage_log = []
    manifest_bytes, files, intake_note = _collect_input(input_path)
    stage_log.append(_stage(
        "Intake", "Read the input and confirm it is a scannable app package.",
        intake_note, "manifest located, %d files available for scanning" % len(files)))

    try:
        info = parse_manifest_bytes(manifest_bytes)
    except ValueError as exc:
        raise ScanError(str(exc))
    stage_log.append(_stage(
        "Manifest parse",
        "Turn the manifest into structured facts: package, permissions, components.",
        "package %s, %d permissions, %d components" % (
            info["package"] or "(unknown)", len(info["permissions"]),
            len(info["components"])),
        "manifest parsed successfully"))

    man_findings, man_notes = manifest_findings(info)
    stage_log.append(_stage(
        "Manifest rules",
        "Check manifest settings that commonly weaken app security.",
        "debuggable flag, backup flag, cleartext flag, exported components, dangerous permissions",
        "%d manifest findings" % len(man_findings),
        "; ".join(man_notes) if man_notes else ""))

    pattern_findings = scan_bytes_for_patterns(files, custom_rules)
    stage_log.append(_stage(
        "Strings and code patterns",
        "Search app files for secret patterns, cleartext URLs, and risky code patterns.",
        "%d files scanned for patterns" % len(files),
        "%d pattern findings (values masked, never printed in full)" % len(pattern_findings)))

    if dynamic_log_path:
        try:
            with open(dynamic_log_path, "r", encoding="utf-8") as handle:
                log_lines = [line for line in handle if line.strip()]
            dynamic_findings = log_lines_to_findings(log_lines)
            dynamic_log = _stage(
                "Dynamic (Frida log)",
                "Turn a Frida JSON log from your own test app into findings.",
                "log file %s, %d lines" % (dynamic_log_path, len(log_lines)),
                "%d dynamic findings" % len(dynamic_findings))
        except OSError as exc:
            raise ScanError("cannot read dynamic log file: %s" % exc)
    else:
        dynamic_findings, dynamic_log = run_dynamic_stage(
            input_path, static_only=static_only, seconds=dynamic_seconds)
    stage_log.append(dynamic_log)

    deep_findings = []
    deep_inventory = None
    deep_tools = None
    if deep:
        from .deep import run_deep
        deep_findings, deep_inventory, deep_log, deep_tools = run_deep(
            input_path, info, files,
            work_root or os.path.join(os.getcwd(), "deep-work"),
            skip_apktool=skip_apktool, skip_jadx=skip_jadx,
            skip_androguard=skip_androguard, decode_dir=decode_dir)
        stage_log.extend(deep_log)

    all_findings = man_findings + pattern_findings + dynamic_findings + deep_findings
    score, grade, counts = score_findings(all_findings)
    stage_log.append(_stage(
        "Scoring",
        "Turn findings into one score and grade, so results are comparable over time.",
        "100 minus deductions per severity (critical 25, high 15, medium 7, low 3)",
        "score %d, grade %s, counts %s" % (score, grade, counts)))

    baseline = None
    if baseline_path:
        baseline = _compare_baseline(all_findings, baseline_path)
        stage_log.append(_stage(
            "Baseline compare",
            "Show only what changed since the last run, so CI fails on new issues.",
            "baseline file %s" % baseline_path,
            "%d new, %d fixed, %d unchanged" % (
                len(baseline["new"]), len(baseline["fixed"]),
                len(baseline["unchanged"]))))

    result = {
        "tool": "apk-security-pipeline",
        "input": input_path,
        "package": info["package"],
        "version_name": info["version_name"],
        "version_code": info["version_code"],
        "permissions": info["permissions"],
        "components": info["components"],
        "application": info["application"],
        "findings": [item.to_dict() for item in all_findings],
        "score": score,
        "grade": grade,
        "counts": counts,
        "stage_log": stage_log,
        "deep": bool(deep),
        "deep_inventory": deep_inventory,
        "deep_tools": deep_tools,
        "baseline": baseline,
        "limits": [
            "Static patterns are review flags, not proof of exploitability on their own.",
            "Dynamic results only cover the flows the harness actually ran, on a device or emulator you own.",
            "This tool never proves an app is safe. It reports what it found and what it checked.",
        ],
    }
    if explain:
        result["explain"] = True
    return result


def _finding_key(item):
    if isinstance(item, dict):
        return (item["id"], item["location"].split(" (")[0])
    return (item.rule_id, item.location.split(" (")[0])


def _compare_baseline(findings, baseline_path):
    """Compare current findings against a previous JSON report."""
    try:
        with open(baseline_path, "r", encoding="utf-8") as handle:
            old = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ScanError("cannot read baseline file: %s" % exc)
    old_keys = set()
    for item in old.get("findings", []):
        old_keys.add((item["id"], item["location"].split(" (")[0]))
    new_keys = set()
    current = []
    for item in findings:
        key = _finding_key(item)
        new_keys.add(key)
        current.append(item)
    new = [item for item in current if _finding_key(item) not in old_keys]
    fixed_keys = old_keys - new_keys
    unchanged = [item for item in current if _finding_key(item) in old_keys]
    return {
        "new": [item.to_dict() if hasattr(item, "to_dict") else item for item in new],
        "fixed": sorted(fixed_keys),
        "unchanged": [item.to_dict() if hasattr(item, "to_dict") else item for item in unchanged],
    }
