"""Report writers: JSON (for scripts and CI) and single file HTML (for humans).

The HTML report is self contained: inline CSS, no external requests,
no JavaScript. Secret values are never printed: the scanner masks them
before they reach this module.
"""

import html
import json
import os

SEVERITY_COLORS = {
    "critical": "#B91C1C",
    "high": "#D97706",
    "medium": "#A16207",
    "low": "#4E7A12",
    "info": "#5A45D6",
}


def write_json(result, path):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
    return path


def _finding_card(item):
    color = SEVERITY_COLORS.get(item["severity"], "#5C6068")
    return (
        '<div style="border:1px solid #DDD6FE;border-left:6px solid %s;'
        'border-radius:12px;padding:14px 16px;margin:12px 0;background:#fff">'
        '<div><span style="background:%s;color:#fff;border-radius:999px;'
        'padding:2px 10px;font-size:13px;font-weight:700">%s</span> '
        '<b>%s</b> <code>%s</code> '
        '<span style="color:#5C6068">(%s, %s stage)</span></div>'
        '<div style="margin-top:6px"><b>Where:</b> %s</div>'
        '<div><b>Evidence:</b> <code>%s</code></div>'
        '<div><b>Why it matters:</b> %s</div>'
        '<div><b>Fix:</b> %s</div></div>'
        % (color, color, html.escape(item["severity"].upper()),
           html.escape(item["title"]), html.escape(item["id"]),
           html.escape(item["category"]),
           html.escape(item["stage"]), html.escape(item["location"]),
           html.escape(str(item["evidence"])),
           html.escape(item["explanation"]), html.escape(item["fix"]))
    )


def write_html(result, path):
    findings = result["findings"]
    by_severity = {}
    for item in findings:
        by_severity.setdefault(item["severity"], []).append(item)
    order = ["critical", "high", "medium", "low", "info"]
    cards = []
    for severity in order:
        for item in by_severity.get(severity, []):
            cards.append(_finding_card(item))
    stages = "".join(
        "<tr><td><b>%s</b></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
        % (html.escape(entry["stage"]), html.escape(entry["goal"]),
           html.escape(entry["checked"]), html.escape(entry["found"]),
           html.escape(entry["skipped"] or "-"))
        for entry in result["stage_log"]
    )
    limits = "".join("<li>%s</li>" % html.escape(item) for item in result["limits"])
    deep_html = ""
    deep_inv = result.get("deep_inventory") or {}
    if result.get("deep"):
        tool_rows = ""
        for name, info in (result.get("deep_tools") or {}).items():
            if name == "tools_dir":
                continue
            tool_rows += "<tr><td><b>%s</b></td><td>%s</td><td>%s</td></tr>" % (
                html.escape(name),
                "found" if info.get("found") else "missing",
                html.escape(info.get("path") or info.get("version") or info.get("install", "")))

        def _count(prefix):
            return sum(1 for f in findings
                       if isinstance(f, dict) and f.get("id", "").startswith(prefix))

        sections = ["<h2>Deep mode: tools</h2><table><tr><th>Tool</th><th>Status</th><th>Path, version, or install note</th></tr>%s</table>" % tool_rows]
        sections.append("<h2>Deep mode: results per tool</h2>")
        if deep_inv.get("smali") is not None:
            sections.append(
                "<h3>Apktool: smali and resources</h3>"
                "<p>Decoded directory: %s</p>"
                "<p>Smali: %s, smali findings: %d, network config findings: %d</p>"
                "<p>Resources by folder: %s</p>"
                % (html.escape(str((deep_inv.get("apktool") or {}).get("decoded_dir", ""))),
                   html.escape(json.dumps(deep_inv.get("smali", {}), sort_keys=True)),
                   _count("SMALI_"), _count("NETCFG_"),
                   html.escape(json.dumps(deep_inv.get("resources", {}), sort_keys=True))))
        if deep_inv.get("jadx") is not None:
            sections.append(
                "<h3>Jadx: Java sources</h3>"
                "<p>Java: %s, Java findings: %d</p>"
                % (html.escape(json.dumps(deep_inv.get("jadx", {}), sort_keys=True)),
                   _count("JAVA_")))
        if deep_inv.get("androguard") is not None:
            sections.append(
                "<h3>Androguard: dex facts</h3>"
                "<p>%s, androguard findings: %d</p>"
                % (html.escape(json.dumps(deep_inv.get("androguard", {}), sort_keys=True)),
                   _count("AG_")))
        links = deep_inv.get("deep_links", [])
        sections.append(
            "<h3>Deep links</h3><p>%s</p>"
            % (html.escape(", ".join(links)) if links else "none"))
        sections.append(
            "<h3>Signing</h3><p>%s</p>"
            % html.escape(json.dumps(deep_inv.get("signing", {}), sort_keys=True)))
        libs = deep_inv.get("native_libs", [])
        lib_rows = "".join("<li>%s (%s, %d bytes)</li>" % (
            html.escape(item["path"]), html.escape(item["abi"]), item["size"]) for item in libs)
        sections.append(
            "<h3>Native libraries (%d)</h3><ul>%s</ul>"
            % (len(libs), lib_rows if lib_rows else "<li>none</li>"))
        strings = deep_inv.get("strings", {})
        hosts = strings.get("url_hosts", {}) if isinstance(strings, dict) else {}
        host_rows = "".join("<li>%s (x%d)</li>" % (html.escape(h), c) for h, c in sorted(hosts.items()))
        sections.append(
            "<h3>URL hosts and IPs</h3><ul>%s</ul><p>Private IPs: %s, public IP matches: %s</p>"
            % (host_rows if host_rows else "<li>none</li>",
               html.escape(", ".join(strings.get("private_ips", [])) or "none"),
               strings.get("public_ip_count", 0)))
        sections.append(
            "<h3>Network config</h3><p>%s</p>"
            % html.escape(json.dumps(deep_inv.get("network_config", {}), sort_keys=True)))
        contents = deep_inv.get("contents", {})
        if contents:
            content_rows = "".join(
                "<tr><td><b>%s</b></td><td>%d</td><td>%d</td><td>%s</td></tr>" % (
                    html.escape(category), entry["count"], entry["bytes"],
                    html.escape(", ".join(entry["files"][:20])) +
                    (" and %d more" % (len(entry["files"]) - 20) if len(entry["files"]) > 20 else ""))
                for category, entry in sorted(contents.items()))
            sections.append(
                "<h3>APK contents, each part separate</h3>"
                "<table><tr><th>Part</th><th>Files</th><th>Bytes</th><th>Files (first 20)</th></tr>%s</table>"
                % content_rows)
        sections.append(
            "<p>Per tool detail files: deep-work/apktool.json, deep-work/jadx.json, "
            "deep-work/androguard.json, deep-work/deep-inventory.json</p>")
        deep_html = "".join(sections)
    baseline_html = ""
    if result.get("baseline"):
        baseline = result["baseline"]
        baseline_html = (
            "<h2>Baseline compare</h2><p>New: %d, fixed: %d, unchanged: %d.</p>"
            % (len(baseline["new"]), len(baseline["fixed"]),
               len(baseline["unchanged"])))
    page = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>APK Security Pipeline report</title>
<style>body{font-family:system-ui,Arial,sans-serif;max-width:960px;margin:0 auto;
padding:24px;color:#17191C;background:#FAF9F5}h1{font-size:32px}
.bar{height:18px;background:#E5E7EB;border-radius:999px;overflow:hidden}
.bar div{height:18px;background:#5A45D6}table{border-collapse:collapse;width:100%%}
td,th{border:1px solid #DDD6FE;padding:8px;text-align:left;vertical-align:top}
code{background:#EEE8FF;padding:1px 6px;border-radius:6px}</style></head>
<body>
<h1>APK Security Pipeline report</h1>
<p><b>Package:</b> %s &nbsp; <b>Version:</b> %s (%s) &nbsp; <b>Input:</b> %s</p>
<h2>Score: %d / 100, grade %s</h2>
<div class="bar"><div style="width:%d%%"></div></div>
<p>Counts: %s</p>
<h2>What each stage did</h2>
<table><tr><th>Stage</th><th>Goal</th><th>Checked</th><th>Found</th><th>Skipped and why</th></tr>%s</table>
%s
%s
<h2>Findings (%d)</h2>
%s
<h2>Limits, read these</h2><ul>%s</ul>
<p>Generated by apk-security-pipeline. Only run against apps you own or have explicit permission to test.</p>
</body></html>""" % (
        html.escape(str(result["package"])),
        html.escape(str(result["version_name"])),
        html.escape(str(result["version_code"])),
        html.escape(str(result["input"])),
        result["score"], html.escape(str(result["grade"])), result["score"],
        html.escape(json.dumps(result["counts"], sort_keys=True)),
        stages, baseline_html, deep_html, len(findings),
        "\n".join(cards) if cards else "<p>No findings. That means none of the rules matched, not that the app is proven safe.</p>",
        limits)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(page)
    return path


def write_deep_files(result, out_dir):
    """Write one detail file per deep tool, plus the full deep inventory.

    Each file is separate, so a reader can open just the apktool part,
    just the jadx part, or just the androguard part.
    """
    deep_inv = result.get("deep_inventory") or {}
    if not result.get("deep"):
        return {}
    deep_dir = os.path.join(out_dir, "deep-work")
    os.makedirs(deep_dir, exist_ok=True)
    findings = result["findings"]

    def _by_prefix(prefixes):
        return [f for f in findings
                if any(f.get("id", "").startswith(p) for p in prefixes)]

    parts = {
        "apktool": {"findings": _by_prefix(("SMALI_", "NETCFG_")),
                    "smali": deep_inv.get("smali"),
                    "resources": deep_inv.get("resources"),
                    "network_config": deep_inv.get("network_config"),
                    "decoded_dir": (deep_inv.get("apktool") or {}).get("decoded_dir")},
        "jadx": {"findings": _by_prefix(("JAVA_",)),
                 "java": deep_inv.get("jadx")},
        "androguard": {"findings": _by_prefix(("AG_",)),
                       "dex": deep_inv.get("androguard")},
    }
    written = {}
    for name, data in parts.items():
        if data["findings"] or any(v is not None for k, v in data.items() if k != "findings"):
            path = os.path.join(deep_dir, "%s.json" % name)
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2, sort_keys=True)
            written[name] = path
    inv_path = os.path.join(deep_dir, "deep-inventory.json")
    with open(inv_path, "w", encoding="utf-8") as handle:
        json.dump({"deep_inventory": deep_inv,
                   "deep_tools": result.get("deep_tools")},
                  handle, indent=2, sort_keys=True)
    written["deep-inventory"] = inv_path
    return written


def write_reports(result, out_dir, formats=("html", "json")):
    os.makedirs(out_dir, exist_ok=True)
    written = {}
    if "json" in formats:
        written["json"] = write_json(result, os.path.join(out_dir, "report.json"))
    if "html" in formats:
        written["html"] = write_html(result, os.path.join(out_dir, "report.html"))
    written.update(write_deep_files(result, out_dir))
    return written
