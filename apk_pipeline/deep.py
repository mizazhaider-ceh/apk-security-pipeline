"""Deep analysis engine: real decompilation and method level reading.

Deep mode opens the app for real:
- apktool decodes resources and smali (when apktool is installed),
- jadx decompiles dex to Java sources (when jadx is installed),
- androguard reads dex structure and referenced APIs (when installed),
- plus manifest deep links, network security config, signing cert
  checks, native library inventory, and classified strings, all of
  which work without any extra tool.

Every deep stage reports what it did, what it found, and what it
skipped and why, exactly like the basic stages. A missing tool is a
reported skip with install steps, never a silent gap and never faked
evidence.
"""

import os
import re
import subprocess
import xml.etree.ElementTree as ET

from .rules import Finding, mask_url
from .tools import (apktool_command, detect_tools, jadx_command,
                    run_command)
from .manifest import parse_manifest_bytes

# (substring in method text, rule id, title, severity, explanation, fix)
SMALI_PATTERNS = [
    ("Landroid/webkit/WebView;->setJavaScriptEnabled", "SMALI_JS_ENABLED",
     "WebView JavaScript enabled", "low",
     "WebView JavaScript is enabled in this method. Review what content the WebView loads.",
     "Only enable JavaScript where needed, never expose native bridges to untrusted content."),
    ("setAllowUniversalAccessFromFileURLs", "SMALI_UNIVERSAL_ACCESS",
     "WebView universal file access", "medium",
     "Universal access from file URLs can let web content read local files.",
     "Do not enable universal access from file URLs for untrusted content."),
    ("ALLOW_ALL_HOSTNAME_VERIFIER", "SMALI_HOSTNAME_ALL",
     "Hostname verification disabled", "medium",
     "Hostname verification is disabled, so TLS host checks are skipped.",
     "Use default hostname verification."),
    ("Ldalvik/system/DexClassLoader;-><init>", "SMALI_DEXLOADER",
     "Dynamic code loading with DexClassLoader", "medium",
     "Code is loaded dynamically at runtime. Review what code is loaded and from where.",
     "Avoid loading code from untrusted sources. If you must, verify integrity first."),
    ("Ldalvik/system/PathClassLoader;-><init>", "SMALI_DEXLOADER",
     "Dynamic code loading with PathClassLoader", "medium",
     "Code is loaded dynamically at runtime. Review what code is loaded and from where.",
     "Avoid loading code from untrusted sources. If you must, verify integrity first."),
    ("Ljava/lang/Runtime;->exec", "SMALI_RUNTIME_EXEC",
     "Runtime command execution", "medium",
     "The app executes system commands at runtime. Review the command and its inputs.",
     "Avoid shell commands with user controlled input. Prefer proper APIs."),
    ("Ljava/lang/System;->loadLibrary", "SMALI_NATIVE_LOAD",
     "Native library loaded", "low",
     "A native library is loaded. Check the library source and what it does.",
     "Only load native libraries you trust and ship yourself."),
    ("Ljava/lang/Class;->forName", "SMALI_REFLECTION",
     "Reflection use", "low",
     "Reflection is used. Review what class is loaded and why.",
     "Avoid reflection on untrusted class names."),
    ("Landroid/util/Log;->d", "SMALI_LOG",
     "Debug logging call", "low",
     "Debug logging is used. Logs can leak data on user devices.",
     "Remove debug logs from release builds and never log sensitive data."),
    ("Landroid/util/Log;->e", "SMALI_LOG",
     "Error logging call", "low",
     "Error logging is used. Check that logged data is not sensitive.",
     "Never log sensitive data, even in error logs."),
]

# (substring, rule id, title, severity, explanation, fix) for Java sources.
JAVA_PATTERNS = [
    ("setJavaScriptEnabled", "JAVA_JS_ENABLED",
     "WebView JavaScript enabled", "low",
     "WebView JavaScript is enabled. Review what content the WebView loads.",
     "Only enable JavaScript where needed."),
    ("setAllowUniversalAccessFromFileURLs", "JAVA_UNIVERSAL_ACCESS",
     "WebView universal file access", "medium",
     "Universal access from file URLs can let web content read local files.",
     "Do not enable universal access from file URLs for untrusted content."),
    ("ALLOW_ALL_HOSTNAME_VERIFIER", "JAVA_HOSTNAME_ALL",
     "Hostname verification disabled", "medium",
     "Hostname verification is disabled, so TLS host checks are skipped.",
     "Use default hostname verification."),
    ("DexClassLoader", "JAVA_DEXLOADER",
     "Dynamic code loading", "medium",
     "Code is loaded dynamically at runtime. Review what code is loaded and from where.",
     "Avoid loading code from untrusted sources."),
    ("Runtime.getRuntime().exec", "JAVA_RUNTIME_EXEC",
     "Runtime command execution", "medium",
     "The app executes system commands at runtime. Review the command and its inputs.",
     "Avoid shell commands with user controlled input."),
    ("System.loadLibrary", "JAVA_NATIVE_LOAD",
     "Native library loaded", "low",
     "A native library is loaded. Check the library source and what it does.",
     "Only load native libraries you trust and ship yourself."),
    ("Class.forName", "JAVA_REFLECTION",
     "Reflection use", "low",
     "Reflection is used. Review what class is loaded and why.",
     "Avoid reflection on untrusted class names."),
    ("Log.d(", "JAVA_LOG",
     "Debug logging call", "low",
     "Debug logging is used. Logs can leak data on user devices.",
     "Remove debug logs from release builds."),
]


def _stage(name, goal, checked, found, skipped=""):
    return {"stage": name, "goal": goal, "checked": checked,
            "found": found, "skipped": skipped}


def _split_smali_methods(text):
    """Yield (method_header, method_body) pairs from one smali file."""
    current_header = None
    current_lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(".method"):
            if current_header is not None:
                yield current_header, "\n".join(current_lines)
            current_header = stripped
            current_lines = []
        elif stripped.startswith(".end method"):
            if current_header is not None:
                yield current_header, "\n".join(current_lines)
            current_header = None
            current_lines = []
        elif current_header is not None:
            current_lines.append(line)
    if current_header is not None:
        yield current_header, "\n".join(current_lines)


def _smali_method_findings(rel_path, text):
    """Method level smali findings. Returns a list of Findings."""
    findings = []
    seen = set()
    for header, body in _split_smali_methods(text):
        method_name = header
        for pattern, rule_id, title, severity, explanation, fix in SMALI_PATTERNS:
            if pattern not in body:
                continue
            key = (rule_id, rel_path, method_name)
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                rule_id, title, severity, "smali",
                "%s in method %s" % (rel_path, method_name),
                "pattern %s found in method" % pattern.split(";->")[-1],
                explanation, fix, stage="deep"))
        # Method scoped crypto and URL checks: the const string and the
        # API call must appear in the same method to count.
        if "Ljava/security/MessageDigest;->getInstance" in body:
            if '"MD5"' in body:
                findings.append(Finding(
                    "SMALI_MD5", "MD5 digest use", "low", "smali",
                    "%s in method %s" % (rel_path, method_name),
                    "MessageDigest MD5 in method",
                    "MD5 is broken for integrity and passwords. Use SHA-256 or stronger.",
                    "Use SHA-256 or stronger, and proper password hashing for passwords.",
                    stage="deep"))
            if '"SHA1"' in body or '"SHA-1"' in body:
                findings.append(Finding(
                    "SMALI_SHA1", "SHA-1 digest use", "low", "smali",
                    "%s in method %s" % (rel_path, method_name),
                    "MessageDigest SHA-1 in method",
                    "SHA-1 is weak for integrity. Use SHA-256 or stronger.",
                    "Use SHA-256 or stronger.", stage="deep"))
        if "Ljavax/crypto/Cipher;->getInstance" in body and "AES/ECB" in body:
            findings.append(Finding(
                "SMALI_ECB", "ECB cipher mode", "medium", "smali",
                "%s in method %s" % (rel_path, method_name),
                "Cipher AES/ECB in method",
                "ECB leaks plaintext patterns. Use AES-GCM with a random nonce.",
                "Use AES-GCM with a random nonce, never ECB for real data.",
                stage="deep"))
        for match in re.finditer(r"http://[A-Za-z0-9.\-]+", body):
            url = match.group(0)
            if url.startswith("http://schemas.android.com"):
                continue
            findings.append(Finding(
                "SMALI_CLEARTEXT_URL", "Cleartext http URL in code", "medium",
                "smali", "%s in method %s" % (rel_path, method_name),
                mask_url(url),
                "Cleartext http traffic can be read and changed on the network.",
                "Use https for every endpoint.", stage="deep"))
            break
    return findings


def scan_smali_dir(root):
    """Scan a decoded smali tree. Returns (findings, stats dict)."""
    findings = []
    files = 0
    methods = 0
    classes = 0
    for dirpath, _dirs, names in os.walk(root):
        for name in names:
            if not name.endswith(".smali"):
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as handle:
                    text = handle.read()
            except OSError:
                continue
            files += 1
            file_findings = _smali_method_findings(rel, text)
            methods += text.count(".method ")
            if ".class " in text:
                classes += 1
            findings.extend(file_findings)
    stats = {"smali_files": files, "smali_methods_seen": methods,
             "smali_classes": classes}
    return findings, stats


_METHOD_RE = re.compile(
    r"^\s*(?:public|private|protected|static|final|synchronized|abstract|native|\s)+"
    r"(?:[\w<>\[\],.?]+\s+)?(\w+)\s*\([^;]*\)\s*(?:throws\s+[\w.,\s]+)?\s*\{?\s*$")


def scan_java_dir(root):
    """Scan jadx Java sources with line numbers and method context."""
    findings = []
    files = 0
    for dirpath, _dirs, names in os.walk(root):
        for name in names:
            if not name.endswith(".java"):
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as handle:
                    lines = handle.readlines()
            except OSError:
                continue
            files += 1
            current_method = "unknown"
            for lineno, line in enumerate(lines, start=1):
                match = _METHOD_RE.match(line)
                if match and "(" in line and "if (" not in line and "for (" not in line and "while (" not in line and "switch (" not in line and "return " not in line:
                    current_method = match.group(1)
                for pattern, rule_id, title, severity, explanation, fix in JAVA_PATTERNS:
                    if pattern in line:
                        findings.append(Finding(
                            rule_id, title, severity, "java",
                            "%s:%d in method %s" % (rel, lineno, current_method),
                            "pattern %s on line %d" % (pattern, lineno),
                            explanation, fix, stage="deep"))
                url_match = re.search(r"http://[A-Za-z0-9.\-]+", line)
                if url_match and not url_match.group(0).startswith("http://schemas.android.com"):
                    findings.append(Finding(
                        "JAVA_CLEARTEXT_URL", "Cleartext http URL in code",
                        "medium", "java",
                        "%s:%d in method %s" % (rel, lineno, current_method),
                        mask_url(url_match.group(0)),
                        "Cleartext http traffic can be read and changed on the network.",
                        "Use https for every endpoint.", stage="deep"))
    stats = {"java_files": files}
    return findings, stats


def _local(tag):
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def parse_network_security_config(data):
    """Parse a network security config XML. Returns (findings, summary)."""
    findings = []
    summary = {"cleartext_permitted": None, "pinning": False,
               "debug_overrides": False, "domains": []}
    try:
        root = ET.fromstring(data.decode("utf-8"))
    except (ET.ParseError, UnicodeDecodeError) as exc:
        return findings, {"error": "network security config parse failed: %s" % exc}
    for elem in root.iter():
        tag = _local(elem.tag)
        if tag == "base-config":
            value = elem.attrib.get("cleartextTrafficPermitted")
            if value is not None:
                summary["cleartext_permitted"] = value.lower() == "true"
        elif tag == "domain-config":
            value = elem.attrib.get("cleartextTrafficPermitted")
            for child in elem:
                if _local(child.tag) == "domain":
                    summary["domains"].append(
                        "%s (cleartext=%s)" % (child.text or "", value))
        elif tag == "pin-set":
            summary["pinning"] = True
        elif tag == "debug-overrides":
            summary["debug_overrides"] = True
    if summary["cleartext_permitted"] is True:
        findings.append(Finding(
            "NETCFG_CLEARTEXT", "Network config permits cleartext traffic",
            "high", "network-config", "network_security_config.xml",
            "base-config cleartextTrafficPermitted=true",
            "Cleartext traffic is permitted by the network security config.",
            "Remove the cleartext permission and use https everywhere.",
            stage="deep"))
    if summary["debug_overrides"]:
        findings.append(Finding(
            "NETCFG_DEBUG_OVERRIDE", "Network config has debug overrides",
            "medium", "network-config", "network_security_config.xml",
            "debug-overrides present",
            "Debug overrides change trust rules on debuggable builds. If shipped, they weaken release builds.",
            "Remove debug overrides from release builds.", stage="deep"))
    if summary["pinning"]:
        findings.append(Finding(
            "NETCFG_PINNING", "Certificate pinning configured",
            "info", "network-config", "network_security_config.xml",
            "pin-set present",
            "Certificate pinning is configured. This is a good hardening sign; keep pins updated.",
            "Keep pins updated and test pin rotation before expiry.", stage="deep"))
    return findings, summary


def deep_link_findings(manifest_info):
    """Extract deep links from manifest intent filters."""
    findings = []
    links = []
    for comp in manifest_info.get("components", []):
        for intent in comp.get("intent_filters", []):
            actions = intent.get("actions", [])
            categories = intent.get("categories", [])
            if "android.intent.action.VIEW" not in actions:
                continue
            browsable = "android.intent.category.BROWSABLE" in categories
            for data in intent.get("data", []):
                scheme = data.get("scheme", "")
                host = data.get("host", "")
                if not scheme:
                    continue
                link = "%s://%s" % (scheme, host) if host else "%s://" % scheme
                links.append(link)
                location = "%s %s" % (comp["kind"], comp["name"])
                if scheme in ("http", "https") and browsable:
                    findings.append(Finding(
                        "DEEPLINK_HTTP", "Web deep link (http/https, browsable)",
                        "medium", "deep-links", location, link,
                        "A web deep link can open app screens from browsers. Check verified app links, export settings, and auth checks on the target screen.",
                        "Verify app links with assetlinks, and require auth for sensitive screens.",
                        stage="deep"))
                elif scheme not in ("http", "https"):
                    findings.append(Finding(
                        "DEEPLINK_CUSTOM_SCHEME", "Custom scheme deep link",
                        "low", "deep-links", location, link,
                        "A custom scheme deep link can be claimed by other apps. Check export settings and input validation on the target screen.",
                        "Validate deep link input and require auth for sensitive screens.",
                        stage="deep"))
    return findings, links


def signing_findings(files):
    """Check APK signing files. files is a list of (path, bytes)."""
    findings = []
    inventory = {"signature_files": [], "debug_cert": False}
    for path, data in files:
        if not path.startswith("META-INF/"):
            continue
        if path.endswith((".RSA", ".DSA", ".EC")):
            inventory["signature_files"].append(path)
            if b"Android Debug" in data:
                inventory["debug_cert"] = True
                findings.append(Finding(
                    "CERT_DEBUG", "APK signed with Android debug certificate",
                    "high", "signing", path, "certificate subject contains Android Debug",
                    "A debug certificate is not a release identity. Anyone can create one, so it proves nothing about the publisher.",
                    "Sign release builds with a private release key kept outside the repo.",
                    stage="deep"))
    if not inventory["signature_files"]:
        inventory["note"] = "No v1 signature files found in META-INF. v2/v3 signing block not checked."
    return findings, inventory


def native_inventory(files):
    """Inventory native libraries shipped in the APK."""
    libs = []
    for path, data in files:
        if path.startswith("lib/") and path.endswith(".so"):
            parts = path.split("/")
            abi = parts[1] if len(parts) > 2 else "unknown"
            libs.append({"path": path, "abi": abi, "size": len(data)})
    return libs


def strings_summary(files):
    """Classify strings found in app files: URL hosts and IP shapes.

    Public IPs are masked to the first octet. Private and loopback IPs
    are test addresses by definition, so they are shown in full.
    """
    hosts = {}
    public_ips = 0
    private_ips = []
    namespace_hosts = ("schemas.android.com", "www.w3.org")
    for _path, data in files:
        text = data.decode("utf-8", errors="ignore")
        for match in re.finditer(r"https?://([A-Za-z0-9.\-]+)", text):
            host = match.group(1)
            if host in namespace_hosts:
                continue
            hosts[host] = hosts.get(host, 0) + 1
        for match in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
            ip = match.group(0)
            if ip.startswith(("10.", "127.", "192.168.")) or re.match(r"172\.(1[6-9]|2\d|3[01])\.", ip):
                if ip not in private_ips:
                    private_ips.append(ip)
            else:
                public_ips += 1
    return {"url_hosts": hosts, "private_ips": private_ips,
            "public_ip_count": public_ips}


def androguard_stage(apk_path):
    """Deep dex facts via androguard, when installed.

    Returns (findings, inventory, skipped_reason). Referenced API
    names come from the dex method table: they show which risky APIs
    the app references, not which method calls them. Smali and Java
    stages give the method level proof.
    """
    try:
        from androguard.core.apk import APK
    except ImportError:
        return [], {}, "androguard not installed. Install: pip install androguard."
    try:
        # Silence androguard's own debug logging so CLI output stays clean.
        from loguru import logger as _loguru_logger
        _loguru_logger.remove()
    except Exception:  # noqa: BLE001 - logging setup is best effort only
        pass
    try:
        apk = APK(apk_path)
        raw_dex = apk.get_dex()
        if hasattr(raw_dex, "get_classes"):
            dex = raw_dex
        else:
            # androguard 4 returns raw dex bytes: parse them explicitly.
            from androguard.core.dex import DEX
            dex = DEX(raw_dex)
    except Exception as exc:  # noqa: BLE001 - androguard errors vary
        return [], {}, "androguard could not read this APK: %s" % exc
    inventory = {
        "package": apk.get_package(),
        "permissions": len(apk.get_permissions()),
        "activities": len(apk.get_activities()),
        "services": len(apk.get_services()),
        "receivers": len(apk.get_receivers()),
        "providers": len(apk.get_providers()),
    }
    findings = []
    try:
        classes = dex.get_classes()
        inventory["dex_classes"] = len(classes)
        methods = dex.get_methods()
        inventory["dex_methods"] = len(methods)
        names = set()
        for method in methods:
            try:
                names.add(method.get_name())
            except Exception:  # noqa: BLE001
                continue
        api_map = [
            ("setJavaScriptEnabled", "AG_JS_ENABLED", "low"),
            ("setAllowUniversalAccessFromFileURLs", "AG_UNIVERSAL_ACCESS", "medium"),
            ("ALLOW_ALL_HOSTNAME_VERIFIER", "AG_HOSTNAME_ALL", "medium"),
            ("DexClassLoader", "AG_DEXLOADER", "medium"),
        ]
        for needle, rule_id, severity in api_map:
            hits = [name for name in names if needle in name]
            if hits:
                findings.append(Finding(
                    rule_id, "Dex references API: %s" % needle, severity,
                    "dex", "dex method table",
                    "%d referenced methods match %s" % (len(hits), needle),
                    "The dex references this API. Confirm the call site in the smali or Java stage.",
                    "Review the call site and apply the matching fix from the smali finding.",
                    stage="deep"))
    except Exception as exc:  # noqa: BLE001
        inventory["dex_note"] = "dex detail read failed: %s" % exc
    return findings, inventory, ""


def run_apktool(apk_path, out_dir, tools):
    """Decode an APK with apktool. Returns (ok, message)."""
    cmd = apktool_command(tools)
    if cmd is None:
        return False, "apktool not found. " + tools["apktool"]["install"]
    code, _out, err = run_command(cmd + ["d", "-f", "-o", out_dir, apk_path],
                                  timeout=600)
    if code == 0 and os.path.isfile(os.path.join(out_dir, "AndroidManifest.xml")):
        return True, "apktool decoded the APK"
    detail = (err.strip().splitlines() or ["unknown error"])[-1]
    return False, "apktool failed: %s" % detail


def run_jadx(apk_path, out_dir, tools):
    """Decompile an APK with jadx. Returns (ok, message)."""
    cmd = jadx_command(tools)
    if cmd is None:
        return False, "jadx not found. " + tools["jadx"]["install"]
    code, _out, err = run_command(cmd + ["-d", out_dir, apk_path], timeout=900)
    java_found = False
    for _dirpath, _dirs, names in os.walk(out_dir):
        if any(name.endswith(".java") for name in names):
            java_found = True
            break
    if code == 0 and java_found:
        return True, "jadx decompiled the APK to Java sources"
    detail = (err.strip().splitlines() or ["unknown error"])[-1]
    return False, "jadx failed or produced no Java sources: %s" % detail


def run_deep(input_path, manifest_info, files, work_root,
             skip_apktool=False, skip_jadx=False, skip_androguard=False,
             decode_dir=None):
    """Run all deep stages. Returns (findings, inventory, stage_log, tools)."""
    tools = detect_tools()
    findings = []
    inventory = {"tools": tools}
    log = []

    # Deep links come from the manifest alone, no extra tool needed.
    link_findings, links = deep_link_findings(manifest_info)
    findings.extend(link_findings)
    inventory["deep_links"] = links
    log.append(_stage(
        "Deep links",
        "List every deep link the app exposes and flag risky ones.",
        "intent filters in the manifest",
        "%d deep links, %d deep link findings" % (len(links), len(link_findings))))

    # Signing and native inventory come from the APK entries directly.
    sign_findings, sign_info = signing_findings(files)
    findings.extend(sign_findings)
    inventory["signing"] = sign_info
    inventory["native_libs"] = native_inventory(files)
    log.append(_stage(
        "Signing and native libs",
        "Check the signing certificate and list shipped native libraries.",
        "META-INF entries and lib/ entries",
        "%d signature files, debug cert: %s, %d native libs" % (
            len(sign_info["signature_files"]), sign_info["debug_cert"],
            len(inventory["native_libs"]))))

    inventory["strings"] = strings_summary(files)
    log.append(_stage(
        "Strings classification",
        "Classify URLs and IP shapes in app files, with masking rules.",
        "%d files" % len(files),
        "%d URL hosts, %d private IPs, %d public IP matches" % (
            len(inventory["strings"]["url_hosts"]),
            len(inventory["strings"]["private_ips"]),
            inventory["strings"]["public_ip_count"])))

    # Decoded directory input: analyze it directly, no apktool needed.
    decoded_dir = decode_dir
    if decoded_dir is None and os.path.isdir(input_path):
        decoded_dir = input_path
    if decoded_dir and os.path.isdir(decoded_dir):
        manifest_path = os.path.join(decoded_dir, "AndroidManifest.xml")
        if os.path.isfile(manifest_path):
            try:
                with open(manifest_path, "rb") as handle:
                    decoded_info = parse_manifest_bytes(handle.read())
                dlink_findings, dlinks = deep_link_findings(decoded_info)
                for item in dlink_findings:
                    if item.location not in [f.location for f in findings]:
                        findings.append(item)
            except ValueError:
                pass
        smali_root = decoded_dir
        smali_findings, smali_stats = scan_smali_dir(smali_root)
        findings.extend(smali_findings)
        inventory["smali"] = smali_stats
        log.append(_stage(
            "Smali analysis (decoded dir)",
            "Read smali method by method and flag risky APIs with method context.",
            "decoded directory %s" % decoded_dir,
            "%d smali findings in %d files" % (len(smali_findings), smali_stats["smali_files"])))
        net_path = os.path.join(decoded_dir, "res", "xml", "network_security_config.xml")
        if os.path.isfile(net_path):
            with open(net_path, "rb") as handle:
                net_findings, net_summary = parse_network_security_config(handle.read())
            findings.extend(net_findings)
            inventory["network_config"] = net_summary
            log.append(_stage(
                "Network security config",
                "Read cleartext, pinning, and debug override settings.",
                "res/xml/network_security_config.xml",
                "%d network config findings" % len(net_findings)))
        else:
            log.append(_stage(
                "Network security config",
                "Read cleartext, pinning, and debug override settings.",
                "looked for res/xml/network_security_config.xml",
                "0 network config findings",
                "skipped: no network security config file in the decoded directory."))

    # APK input: androguard, apktool, jadx stages.
    if os.path.isfile(input_path) and input_path.lower().endswith(".apk"):
        if skip_androguard:
            log.append(_stage(
                "Androguard dex facts",
                "Read dex structure and referenced APIs with androguard.",
                "skipped by user request", "0 androguard findings",
                "skipped: --skip-androguard was given."))
        else:
            ag_findings, ag_info, ag_skip = androguard_stage(input_path)
            findings.extend(ag_findings)
            inventory["androguard"] = ag_info
            log.append(_stage(
                "Androguard dex facts",
                "Read dex structure and referenced APIs with androguard.",
                "androguard present: %s" % tools["androguard"]["found"],
                "%d androguard findings" % len(ag_findings),
                ag_skip))
        if decoded_dir is None and not skip_apktool:
            apktool_dir = os.path.join(work_root, "apktool-out")
            ok, message = run_apktool(input_path, apktool_dir, tools)
            if ok:
                sub_findings, sub_inventory, sub_log, _tools = run_deep(
                    apktool_dir, manifest_info, files, work_root,
                    skip_apktool=True, skip_jadx=True, skip_androguard=True,
                    decode_dir=apktool_dir)
                # Only take the decoded-dir stages, not the repeated ones.
                take = [e for e in sub_log if e["stage"].startswith(
                    ("Smali analysis", "Network security config"))]
                log.extend(take)
                findings.extend([f for f in sub_findings if f.stage == "deep"
                                 and f.rule_id.startswith(
                                     ("SMALI_", "NETCFG_"))])
                inventory["apktool"] = {"decoded_dir": apktool_dir}
                inventory.update({k: v for k, v in sub_inventory.items()
                                  if k in ("smali", "network_config")})
            else:
                log.append(_stage(
                    "Apktool decode",
                    "Decode resources and smali with apktool.",
                    "apktool present: %s" % tools["apktool"]["found"],
                    "0 apktool findings", message))
        if not skip_jadx:
            jadx_dir = os.path.join(work_root, "jadx-out")
            ok, message = run_jadx(input_path, jadx_dir, tools)
            if ok:
                java_findings, java_stats = scan_java_dir(jadx_dir)
                findings.extend(java_findings)
                inventory["jadx"] = java_stats
                log.append(_stage(
                    "Jadx decompile",
                    "Decompile dex to Java and scan with line numbers and method context.",
                    "jadx present: %s" % tools["jadx"]["found"],
                    "%d Java findings in %d files" % (len(java_findings), java_stats["java_files"])))
            else:
                log.append(_stage(
                    "Jadx decompile",
                    "Decompile dex to Java and scan with line numbers and method context.",
                    "jadx present: %s" % tools["jadx"]["found"],
                    "0 Java findings", message))
    return findings, inventory, log, tools
