"""Rules engine: manifest rules, permission risk, string and code patterns.

Every finding carries: id, title, severity, category, location,
evidence (redacted, never a full secret value), explanation (why it
matters), and fix (what to do). Static patterns are flagged as
"review needed" where a pattern alone cannot prove a vulnerability.
"""

import re

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SCORE_DEDUCT = {"critical": 25, "high": 15, "medium": 7, "low": 3, "info": 0}


class Finding:
    def __init__(self, rule_id, title, severity, category, location,
                 evidence, explanation, fix, stage="static"):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.category = category
        self.location = location
        self.evidence = evidence
        self.explanation = explanation
        self.fix = fix
        self.stage = stage

    def to_dict(self):
        return {
            "id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "location": self.location,
            "evidence": self.evidence,
            "explanation": self.explanation,
            "fix": self.fix,
            "stage": self.stage,
        }


def mask_value(value, keep_start=4):
    """Mask a secret-like value: keep a short prefix, hide the rest."""
    text = str(value)
    if len(text) <= keep_start:
        return "*** (length %d)" % len(text)
    return "%s***REDACTED*** (length %d)" % (text[:keep_start], len(text))


def mask_url(url):
    """Keep scheme plus host only, drop path and query."""
    match = re.match(r"(https?://[^/?#]+)", url)
    if match:
        return match.group(1) + "/***"
    return "***"


# Dangerous permissions with plain language risk notes.
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS": "reads the user's contacts",
    "android.permission.WRITE_CONTACTS": "changes the user's contacts",
    "android.permission.ACCESS_FINE_LOCATION": "reads precise location",
    "android.permission.ACCESS_COARSE_LOCATION": "reads approximate location",
    "android.permission.RECORD_AUDIO": "records audio from the microphone",
    "android.permission.CAMERA": "uses the camera",
    "android.permission.READ_EXTERNAL_STORAGE": "reads shared storage files",
    "android.permission.WRITE_EXTERNAL_STORAGE": "writes shared storage files",
    "android.permission.READ_MEDIA_IMAGES": "reads the user's images",
    "android.permission.READ_MEDIA_VIDEO": "reads the user's videos",
    "android.permission.READ_MEDIA_AUDIO": "reads the user's audio",
    "android.permission.SEND_SMS": "sends text messages, possibly at cost",
    "android.permission.READ_SMS": "reads text messages",
    "android.permission.RECEIVE_SMS": "receives text messages",
    "android.permission.CALL_PHONE": "places phone calls, possibly at cost",
    "android.permission.READ_CALL_LOG": "reads call history",
    "android.permission.BODY_SENSORS": "reads body sensor data",
    "android.permission.ACTIVITY_RECOGNITION": "reads physical activity",
    "android.permission.POST_NOTIFICATIONS": "posts notifications",
    "android.permission.BLUETOOTH_CONNECT": "connects to bluetooth devices",
    "android.permission.NEARBY_WIFI_DEVICES": "sees nearby wifi devices",
}

# String patterns searched as bytes. Evidence never shows the full match.
STRING_PATTERNS = [
    ("SECRET_AWS_KEY", rb"AKIA[0-9A-Z]{16}",
     "Looks like an AWS access key id pattern.",
     "Remove hard coded cloud keys. Load keys from a secure store or backend, rotate any exposed key."),
    ("SECRET_PRIVATE_KEY", rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
     "Private key material marker found in app files.",
     "Never ship private keys in an app. Move signing and secrets to a backend."),
    ("SECRET_GENERIC_ASSIGN", rb"(?i)(api[_-]?key|secret|password|passwd|pwd)\s*[:=]\s*[\"'][^\"'\n]{4,}[\"']",
     "A key, secret, or password appears assigned to a literal value.",
     "Review the match. If it is a real secret, remove it, rotate it, and load it securely."),
    ("SECRET_JWT", rb"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
     "Looks like a JSON Web Token pattern.",
     "Tokens must be short lived and fetched at runtime, never baked into the app."),
    ("URL_CLEARTEXT", rb"http://[A-Za-z0-9.\-]+",
     "Cleartext http URL found. Traffic on http can be read and changed.",
     "Use https for every endpoint. Keep a cleartext exception only for a documented test host."),
]

# Code patterns searched as bytes in dex and smali files. These are
# review flags, not proof of exploitability on their own.
CODE_PATTERNS = [
    ("CODE_JS_ENABLED", b"setJavaScriptEnabled",
     "WebView JavaScript enable call found. Review the WebView settings.",
     "Only enable JavaScript where needed, never expose native bridges to untrusted content."),
    ("CODE_UNIVERSAL_ACCESS", b"setAllowUniversalAccessFromFileURLs",
     "WebView universal file access call found. This can let web content read local files.",
     "Do not enable universal access from file URLs for untrusted content."),
    ("CODE_HOSTNAME_ALL", b"ALLOW_ALL_HOSTNAME_VERIFIER",
     "Hostname verification disabled pattern found. TLS host checks are skipped.",
     "Use default hostname verification. Pin certificates properly if you need extra checks."),
    ("CODE_ECB", b"AES/ECB",
     "ECB cipher mode pattern found. ECB leaks plaintext patterns.",
     "Use AES-GCM with a random nonce, never ECB for real data."),
    ("CODE_MD5", b"MessageDigest.getInstance(\"MD5\"",
     "MD5 digest use found. MD5 is broken for integrity and passwords.",
     "Use SHA-256 or stronger, and proper password hashing for passwords."),
    ("CODE_SHA1", b"MessageDigest.getInstance(\"SHA1\"",
     "SHA-1 digest use found. SHA-1 is weak for integrity.",
     "Use SHA-256 or stronger."),
    ("CODE_WEAK_RANDOM", b"java/util/Random",
     "Plain Random use found. Plain Random is predictable and unfit for security.",
     "Use SecureRandom for tokens, keys, and anything security related."),
    ("CODE_INSECURE_LOG", b"Log.d(",
     "Debug logging call found. Logs can leak data on user devices.",
     "Remove debug logs from release builds and never log sensitive data."),
]


def manifest_findings(info):
    """Run manifest rules. Returns (findings, checked_notes)."""
    findings = []
    notes = []
    app = info["application"]
    if app["debuggable"] is True:
        findings.append(Finding(
            "MANIFEST_DEBUGGABLE", "App is debuggable", "critical",
            "manifest", "AndroidManifest.xml application",
            "debuggable=true",
            "A debuggable app lets anyone inspect runtime state and data on a device.",
            "Set debuggable to false for release builds."))
    else:
        notes.append("debuggable flag: not set to true (good).")
    if app["allow_backup"] is True:
        findings.append(Finding(
            "MANIFEST_ALLOW_BACKUP", "App allows backup", "medium",
            "manifest", "AndroidManifest.xml application",
            "allowBackup=true",
            "Backups can copy app private data to another machine for inspection.",
            "Set allowBackup to false unless backup is a real feature, then protect backup data."))
    if app["cleartext"] is True:
        findings.append(Finding(
            "MANIFEST_CLEARTEXT", "Cleartext traffic allowed", "high",
            "manifest", "AndroidManifest.xml application",
            "usesCleartextTraffic=true",
            "Cleartext traffic can be read and changed on the network.",
            "Remove the cleartext flag and use https everywhere."))
    for comp in info["components"]:
        loc = "AndroidManifest.xml %s %s" % (comp["kind"], comp["name"])
        exported = comp["exported"]
        if exported is True and not comp["permission"]:
            findings.append(Finding(
                "MANIFEST_EXPORTED_NO_PERMISSION",
                "Exported %s without a permission" % comp["kind"], "high",
                "manifest", loc, "exported=true, no permission set",
                "Any other app on the device may reach this component.",
                "Set exported to false, or protect it with a permission only trusted apps hold."))
        elif exported is None and comp["has_intent_filter"]:
            findings.append(Finding(
                "MANIFEST_IMPLICIT_EXPORT",
                "Component implicitly exported via intent filter", "medium",
                "manifest", loc,
                "intent-filter present, exported attribute missing",
                "A component with an intent filter can be reachable by other apps unless exported is set explicitly.",
                "Set exported explicitly to true or false for every component with an intent filter."))
        elif exported is False:
            notes.append("%s %s: exported=false (good)." % (comp["kind"], comp["name"]))
    for perm in info["permissions"]:
        risk = DANGEROUS_PERMISSIONS.get(perm)
        if risk:
            findings.append(Finding(
                "PERMISSION_DANGEROUS", "Dangerous permission declared: %s" % perm,
                "low", "permissions", "AndroidManifest.xml uses-permission",
                perm, "This permission %s. Check the app actually needs it, and confirm runtime use in the dynamic stage." % risk,
                "Remove the permission if unused. Request it only when the feature runs, with a clear user explanation."))
        else:
            notes.append("permission declared: %s." % perm)
    return findings, notes


def scan_bytes_for_patterns(files, custom_patterns=None):
    """Scan file bytes for string and code patterns. files is a list of
    (path, bytes). Returns findings. Evidence is always masked."""
    findings = []
    patterns = list(STRING_PATTERNS)
    if custom_patterns:
        for item in custom_patterns:
            try:
                patterns.append((item["id"], item["pattern"].encode("utf-8"),
                                 item.get("explanation", "Custom pattern match."),
                                 item.get("fix", "Review the match.")))
            except (KeyError, AttributeError, UnicodeEncodeError):
                continue
    # Namespace URIs look like http URLs but are not network calls.
    namespace_urls = (b"http://schemas.android.com", b"http://www.w3.org")
    for path, data in files:
        is_code = path.endswith(".dex") or path.endswith(".smali")
        for rule_id, pattern, explanation, fix in patterns:
            if rule_id.startswith("CODE_") and not is_code:
                continue
            try:
                if rule_id == "URL_CLEARTEXT":
                    match = None
                    for candidate in re.finditer(pattern, data):
                        if candidate.group(0).startswith(namespace_urls):
                            continue
                        match = candidate
                        break
                else:
                    match = re.search(pattern, data)
            except re.error:
                continue
            if not match:
                continue
            raw = match.group(0)
            if rule_id == "URL_CLEARTEXT":
                evidence = "%s offset %d: %s" % (
                    path, match.start(), mask_url(raw.decode("utf-8", "replace")))
                severity = "medium"
                category = "network"
            elif rule_id.startswith("CODE_"):
                evidence = "%s offset %d: pattern %s found" % (path, match.start(), rule_id)
                severity = "medium" if rule_id in (
                    "CODE_UNIVERSAL_ACCESS", "CODE_HOSTNAME_ALL", "CODE_ECB") else "low"
                category = "code"
            else:
                evidence = "%s offset %d: %s" % (path, match.start(), mask_value(raw.decode("utf-8", "replace")))
                severity = "high" if rule_id in ("SECRET_AWS_KEY", "SECRET_PRIVATE_KEY") else "medium"
                category = "secrets"
            findings.append(Finding(rule_id, explanation.split(".")[0] + ".",
                                    severity, category,
                                    "%s (offset %d)" % (path, match.start()),
                                    evidence, explanation, fix))
    for rule_id, pattern, explanation, fix in CODE_PATTERNS:
        for path, data in files:
            if not (path.endswith(".dex") or path.endswith(".smali")):
                continue
            idx = data.find(pattern)
            if idx < 0:
                continue
            severity = "medium" if rule_id in (
                "CODE_UNIVERSAL_ACCESS", "CODE_HOSTNAME_ALL", "CODE_ECB") else "low"
            findings.append(Finding(rule_id, explanation.split(".")[0] + ".",
                                    severity, "code",
                                    "%s (offset %d)" % (path, idx),
                                    "%s offset %d: pattern found" % (path, idx),
                                    explanation, fix))
    # Deduplicate by (rule, location file) keeping the first hit.
    seen = set()
    unique = []
    for item in findings:
        key = (item.rule_id, item.location.split(" (")[0])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def score_findings(findings):
    """Score from 100, deduct per severity. Returns (score, grade, counts)."""
    score = 100
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in findings:
        counts[item.severity] = counts.get(item.severity, 0) + 1
        score -= SCORE_DEDUCT.get(item.severity, 0)
    score = max(0, score)
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"
    return score, grade, counts
