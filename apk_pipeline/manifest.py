"""Manifest extraction: binary AXML or plain XML into one clean dict.

Output shape:
{
  "package": str, "version_code": str, "version_name": str,
  "min_sdk": str, "target_sdk": str,
  "permissions": [str, ...],
  "application": {"debuggable": bool|None, "allow_backup": bool|None,
                  "cleartext": bool|None, "network_config": str|None,
                  "name": str|None},
  "components": [{"kind": "activity"|"service"|"receiver"|"provider",
                  "name": str, "exported": bool|None,
                  "permission": str|None, "has_intent_filter": bool}, ...],
}
"""

import xml.etree.ElementTree as ET

from .axml import parse_axml, is_axml, AxmlError


def _local(tag):
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _as_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.strip().lower()
        if low == "true":
            return True
        if low == "false":
            return False
    return None


def _from_tree(root):
    info = {
        "package": root["attrs"].get("package", ""),
        "version_code": str(root["attrs"].get("versionCode", "")),
        "version_name": str(root["attrs"].get("versionName", "")),
        "min_sdk": "",
        "target_sdk": "",
        "permissions": [],
        "application": {"debuggable": None, "allow_backup": None,
                        "cleartext": None, "network_config": None,
                        "name": None},
        "components": [],
    }
    for child in root.get("children", []):
        if child["name"] == "uses-permission":
            name = child["attrs"].get("name", "")
            if name:
                info["permissions"].append(name)
        elif child["name"] == "uses-sdk":
            info["min_sdk"] = str(child["attrs"].get("minSdkVersion", ""))
            info["target_sdk"] = str(child["attrs"].get("targetSdkVersion", ""))
        elif child["name"] == "application":
            app = child["attrs"]
            info["application"] = {
                "debuggable": _as_bool(app.get("debuggable")),
                "allow_backup": _as_bool(app.get("allowBackup")),
                "cleartext": _as_bool(app.get("usesCleartextTraffic")),
                "network_config": app.get("networkSecurityConfig"),
                "name": app.get("name"),
            }
            for comp in child.get("children", []):
                if comp["name"] in ("activity", "service", "receiver", "provider"):
                    attrs = comp["attrs"]
                    info["components"].append({
                        "kind": comp["name"],
                        "name": attrs.get("name", ""),
                        "exported": _as_bool(attrs.get("exported")),
                        "permission": attrs.get("permission"),
                        "has_intent_filter": any(
                            c["name"] == "intent-filter"
                            for c in comp.get("children", [])),
                    })
    return info


def _et_to_tree(elem):
    node = {"name": _local(elem.tag), "attrs": {}, "children": [], "text": ""}
    for key, value in elem.attrib.items():
        node["attrs"][_local(key)] = value
    for child in elem:
        node["children"].append(_et_to_tree(child))
    return node


def parse_manifest_bytes(data):
    """Parse manifest bytes (binary or plain XML) into the info dict."""
    if is_axml(data):
        try:
            root = parse_axml(data)
        except AxmlError as exc:
            raise ValueError("binary manifest parse failed: %s" % exc)
        return _from_tree(root)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("manifest is neither binary nor UTF-8 XML: %s" % exc)
    try:
        root_elem = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError("plain XML manifest parse failed: %s" % exc)
    return _from_tree(_et_to_tree(root_elem))
