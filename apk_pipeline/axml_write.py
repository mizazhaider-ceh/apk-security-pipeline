"""Build minimal valid binary XML (AXML) manifests for test fixtures.

Used by the sample APK generator and by unit tests. This writer only
needs to produce manifests our own parser can read, plus any parser
that follows the standard chunk layout. Strings are UTF-8, ASCII only
in fixtures.

Element spec: {"name": str, "attrs": [(name, value), ...],
"children": [...]}. Attribute values may be str, bool, or int.
Attributes named like "android:name" use the Android namespace URI.
"""

import struct

ANDROID_NS = "http://schemas.android.com/apk/res/android"

TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_BOOLEAN = 0x12


def _encode_len(n):
    if n < 0x80:
        return bytes([n])
    return bytes([((n >> 8) & 0x7F) | 0x80, n & 0xFF])


def _collect_strings(node, pool, index):
    def add(text):
        if text not in index:
            index[text] = len(pool)
            pool.append(text)
        return index[text]
    add(node["name"])
    for name, value in node.get("attrs", []):
        if ":" in name:
            add(ANDROID_NS)
            add(name.split(":")[0])
        add(name.split(":")[-1])
        if isinstance(value, str):
            add(value)
    for child in node.get("children", []):
        _collect_strings(child, pool, index)


def _string_pool_chunk(pool):
    entries = []
    for text in pool:
        raw = text.encode("utf-8")
        entries.append(_encode_len(len(raw)) + _encode_len(len(raw)) + raw + b"\x00")
    offsets = []
    pos = 0
    for entry in entries:
        offsets.append(pos)
        pos += len(entry)
    strings_start = 28 + 4 * len(pool)
    body = struct.pack("<IIIII", len(pool), 0, 0x100, strings_start, 0)
    for off in offsets:
        body += struct.pack("<I", off)
    for entry in entries:
        body += entry
    while len(body) % 4:
        body += b"\x00"
    size = 8 + len(body)
    return struct.pack("<HHI", 0x0001, 28, size) + body


def _namespace_chunk(chunk_type, prefix_idx, uri_idx):
    return struct.pack("<HHIIIII", chunk_type, 16, 24, 0, 0xFFFFFFFF,
                       prefix_idx, uri_idx)


def _start_element_chunk(node, index):
    attrs = node.get("attrs", [])
    out = bytearray()
    name_idx = index[node["name"]]
    out += struct.pack("<HHI", 0x0102, 16, 36 + 20 * len(attrs))
    out += struct.pack("<IIII", 0, 0xFFFFFFFF, 0xFFFFFFFF, name_idx)
    out += struct.pack("<HHHHHH", 36, 20, len(attrs), 0xFFFF, 0xFFFF, 0xFFFF)
    for name, value in attrs:
        short = name.split(":")[-1]
        ns_idx = index[ANDROID_NS] if ":" in name else 0xFFFFFFFF
        name_i = index[short]
        if isinstance(value, bool):
            raw = 0xFFFFFFFF
            dtype, data = TYPE_INT_BOOLEAN, 1 if value else 0
        elif isinstance(value, int):
            raw = 0xFFFFFFFF
            dtype, data = TYPE_INT_DEC, value
        else:
            raw = index[value]
            dtype, data = TYPE_STRING, index[value]
        out += struct.pack("<III", ns_idx, name_i, raw)
        out += struct.pack("<HBBI", 8, 0, dtype, data)
    return bytes(out)


def _end_element_chunk(node, index):
    name_idx = index[node["name"]]
    return struct.pack("<HHIIIII", 0x0103, 16, 24, 0, 0xFFFFFFFF,
                       0xFFFFFFFF, name_idx)


def _emit(node, index, out):
    out.append(_start_element_chunk(node, index))
    for child in node.get("children", []):
        _emit(child, index, out)
    out.append(_end_element_chunk(node, index))


def build_axml(root):
    """Build AXML bytes for one manifest tree."""
    pool = []
    index = {}
    _collect_strings(root, pool, index)
    if ANDROID_NS not in index:
        index[ANDROID_NS] = len(pool)
        pool.append(ANDROID_NS)
    chunks = [_string_pool_chunk(pool)]
    chunks.append(_namespace_chunk(0x0100, index["android"] if "android" in index else 0, index[ANDROID_NS]))
    parts = []
    _emit(root, index, parts)
    chunks.extend(parts)
    chunks.append(_namespace_chunk(0x0101, 0, index[ANDROID_NS]))
    body = b"".join(chunks)
    header = struct.pack("<II", 0x00080003, 8 + len(body))
    return header + body
