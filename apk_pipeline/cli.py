"""Command line interface for APK Security Pipeline.

Usage:
  python3 -m apk_pipeline scan app.apk --explain
  python3 -m apk_pipeline scan decoded_dir -o out --format both
  python3 -m apk_pipeline scan app.apk --static-only --fail-on high
  python3 -m apk_pipeline scan app.apk --dynamic-log frida-log.jsonl
  python3 -m apk_pipeline scan app.apk --deep --explain
  python3 -m apk_pipeline setup
  python3 -m apk_pipeline scan app.apk --deep --setup
  python3 -m apk_pipeline tools
  python3 -m apk_pipeline rules
  python3 -m apk_pipeline version

Exit codes for scan: 0 = clean at the chosen threshold, 2 = findings at
or above the threshold, 1 = input or scan error. CI systems should use
--fail-on to decide what fails a build.
"""

import argparse
import json
import os
import sys

from . import __version__
from .report import write_reports
from .rules import SEVERITY_ORDER
from .scanner import run_scan, ScanError

THRESHOLDS = ["critical", "high", "medium", "low", "never"]

# ANSI colors for CLI output. Colors are used only on a real terminal,
# never when output is piped, and never when NO_COLOR is set. --color
# forces colors, --no-color disables them.
ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "cyan": "\033[36m",
    "gray": "\033[90m",
    "bold_red": "\033[1;31m",
}
SEVERITY_COLOR = {
    "critical": "bold_red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "gray",
}
GRADE_COLOR = {
    "A": "green",
    "B": "cyan",
    "C": "yellow",
    "D": "red",
    "F": "bold_red",
}


def _color_enabled(args):
    if getattr(args, "no_color", False):
        return False
    if getattr(args, "color", False):
        return True
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def _c(text, code, enabled):
    if not enabled or code not in ANSI:
        return text
    return "%s%s%s" % (ANSI[code], text, ANSI["reset"])


def _add_color_flags(parser):
    parser.add_argument("--color", action="store_true",
                        help="Force colorful CLI output")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable colorful CLI output")


def _load_custom_rules(path):
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if isinstance(data, dict):
        return data.get("patterns", [])
    return data


def _print_explain(result, color=False):
    print(_c("== APK Security Pipeline: what each stage did ==", "bold", color))
    for entry in result["stage_log"]:
        print(_c("- %s" % entry["stage"], "cyan", color))
        print("  Goal: %s" % entry["goal"])
        print("  Checked: %s" % entry["checked"])
        print("  Found: %s" % entry["found"])
        if entry["skipped"]:
            print("  " + _c("Skipped: %s" % entry["skipped"], "yellow", color))
    grade = _c(result["grade"], GRADE_COLOR.get(result["grade"], "bold"), color)
    print("Score: %d / 100, grade %s" % (result["score"], grade))
    counts = ", ".join(
        "%s: %s" % (_c(sev, SEVERITY_COLOR[sev], color), num)
        for sev, num in sorted(result["counts"].items()) if num)
    print("Counts: %s" % (counts or "none"))


def _print_setup_result(setup, color=False):
    for step in setup["steps"]:
        if step["status"] == "already present":
            mark = _c("already present", "cyan", color)
        elif step["status"] == "installed":
            mark = _c("installed", "green", color)
        else:
            mark = _c("failed", "red", color)
        print("%s: %s (%s)" % (step["tool"], mark, step["detail"]))
    missing = [name for name, info in setup["after"].items()
               if name != "tools_dir" and not info["found"]]
    if missing:
        print(_c("Still missing: %s. See the install notes above." % ", ".join(missing), "yellow", color))
    else:
        print(_c("All tools ready.", "green", color))


def _cmd_setup(args):
    from .tools import setup_tools
    color = _color_enabled(args)
    setup = setup_tools(directory=args.tools_dir, with_frida=not args.no_frida,
                        allow_apt=not args.no_apt)
    print("Tools directory: %s" % setup["tools_dir"])
    _print_setup_result(setup, color)
    missing = [name for name, info in setup["after"].items()
               if name != "tools_dir" and not info["found"]]
    return 0 if not missing else 1


def _cmd_scan(args):
    color = _color_enabled(args)
    if getattr(args, "setup", False):
        from .tools import setup_tools
        print(_c("== Installing missing tools first ==", "bold", color))
        setup = setup_tools(with_frida=not args.static_only, allow_apt=True)
        _print_setup_result(setup, color)
    custom = None
    if args.rules:
        try:
            custom = _load_custom_rules(args.rules)
        except (OSError, ValueError) as exc:
            print("error: cannot load custom rules: %s" % exc, file=sys.stderr)
            return 1
    try:
        result = run_scan(
            args.input, explain=args.explain,
            static_only=args.static_only, custom_rules=custom,
            baseline_path=args.baseline,
            dynamic_log_path=args.dynamic_log,
            deep=args.deep, decode_dir=args.decode_dir,
            skip_apktool=args.skip_apktool, skip_jadx=args.skip_jadx,
            skip_androguard=args.skip_androguard,
            work_root=os.path.join(args.output, "deep-work"))
    except ScanError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    formats = []
    if args.format in ("html", "both"):
        formats.append("html")
    if args.format in ("json", "both"):
        formats.append("json")
    written = write_reports(result, args.output, tuple(formats))
    grade = _c(result["grade"], GRADE_COLOR.get(result["grade"], "bold"), color)
    if args.explain:
        _print_explain(result, color)
    else:
        print("Score: %d / 100, grade %s, findings: %d"
              % (result["score"], grade, len(result["findings"])))
    for kind, path in sorted(written.items()):
        if kind in ("json", "html"):
            print("Wrote %s report: %s" % (kind, path))
        else:
            print("Wrote deep file: %s" % path)
    if args.baseline and result.get("baseline"):
        base = result["baseline"]
        print("Baseline: %d new, %d fixed, %d unchanged"
              % (len(base["new"]), len(base["fixed"]), len(base["unchanged"])))
    if args.fail_on == "never":
        return 0
    threshold = SEVERITY_ORDER[args.fail_on]
    worst = max((SEVERITY_ORDER[item["severity"]] for item in result["findings"]),
                default=-1)
    if worst >= threshold:
        print(_c("Failing: findings at or above threshold '%s' found." % args.fail_on, "red", color))
        return 2
    return 0


def _cmd_rules(_args):
    from .rules import (DANGEROUS_PERMISSIONS, STRING_PATTERNS,
                        CODE_PATTERNS)
    print("Manifest rules: debuggable flag, backup flag, cleartext flag,")
    print("  exported component without permission, implicit export,")
    print("  dangerous permissions (%d mapped)." % len(DANGEROUS_PERMISSIONS))
    print("String patterns:")
    for rule_id, _pat, explanation, _fix in STRING_PATTERNS:
        print("  %s: %s" % (rule_id, explanation))
    print("Code patterns (dex and smali only):")
    for rule_id, _pat, explanation, _fix in CODE_PATTERNS:
        print("  %s: %s" % (rule_id, explanation))
    return 0


def _cmd_tools(args):
    from .tools import detect_tools
    color = _color_enabled(args)
    tools = detect_tools()
    print("Tools directory: %s" % tools["tools_dir"]["path"])
    for name in ("java", "apktool", "jadx", "androguard", "frida"):
        info = tools[name]
        if info["found"]:
            status = _c("found", "green", color)
        else:
            status = _c("MISSING", "red", color)
        print("%s: %s %s" % (name, status, info["path"] or info["version"] or ""))
        if info["version"]:
            print("  version: %s" % info["version"])
        if not info["found"]:
            print("  install: %s" % info["install"])
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="apk-security-pipeline",
        description="Static plus dynamic security checks for Android apps you own.")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Scan an APK, decoded directory, or manifest file.")
    scan.add_argument("input", help="APK file, decoded APK directory, or AndroidManifest.xml")
    scan.add_argument("-o", "--output", default="out",
                      help="Output directory for reports (default: out)")
    scan.add_argument("--format", choices=["html", "json", "both"], default="both",
                      help="Report formats to write (default: both)")
    scan.add_argument("--explain", action="store_true",
                      help="Print what every stage does, checks, finds, and skips")
    scan.add_argument("--static-only", action="store_true",
                      help="Skip the dynamic stage entirely")
    scan.add_argument("--dynamic-log", default=None,
                      help="JSON lines log from a manual Frida run (see frida/README.md)")
    scan.add_argument("--rules", default=None,
                      help="JSON file with extra string patterns")
    scan.add_argument("--baseline", default=None,
                      help="Previous report.json to compare against")
    scan.add_argument("--fail-on", choices=THRESHOLDS, default="high",
                      help="Fail (exit 2) when findings at or above this severity exist")
    scan.add_argument("--deep", action="store_true",
                      help="Deep mode: apktool decode, jadx decompile, androguard, deep links, network config, signing, native libs (uses real tools when installed, reports skips otherwise)")
    scan.add_argument("--decode-dir", default=None,
                      help="Use an existing apktool decoded directory instead of decoding again")
    scan.add_argument("--skip-apktool", action="store_true",
                      help="Deep mode: skip the apktool stage")
    scan.add_argument("--skip-jadx", action="store_true",
                      help="Deep mode: skip the jadx stage")
    scan.add_argument("--skip-androguard", action="store_true",
                      help="Deep mode: skip the androguard stage")
    scan.add_argument("--setup", action="store_true",
                      help="Install missing tools first (present tools are left alone), then scan")
    _add_color_flags(scan)
    scan.set_defaults(func=_cmd_scan)
    tools_cmd = sub.add_parser("tools", help="List detected real tools for deep mode and how to install missing ones.")
    _add_color_flags(tools_cmd)
    tools_cmd.set_defaults(func=_cmd_tools)
    setup_cmd = sub.add_parser("setup", help="Auto install missing tools (apktool, jadx, androguard, frida, Java). Present tools are left alone.")
    setup_cmd.add_argument("--tools-dir", default=None,
                           help="Tools directory (default: ~/workspace/tools-apk, or APK_PIPELINE_TOOLS_DIR)")
    setup_cmd.add_argument("--no-frida", action="store_true",
                           help="Skip installing frida-tools")
    setup_cmd.add_argument("--no-apt", action="store_true",
                           help="Do not use apt for Java; print manual steps instead")
    _add_color_flags(setup_cmd)
    setup_cmd.set_defaults(func=_cmd_setup)
    rules = sub.add_parser("rules", help="List built-in rules.")
    rules.set_defaults(func=_cmd_rules)
    version = sub.add_parser("version", help="Print the tool version.")
    version.set_defaults(func=lambda _a: (print(__version__), 0)[1])
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
