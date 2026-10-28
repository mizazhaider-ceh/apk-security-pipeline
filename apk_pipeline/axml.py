"""Minimal Android binary XML (AXML) parser, standard library only.

Reads AndroidManifest.xml in binary form and returns a plain element tree
of dicts: {"name": str, "attrs": {name: value}, "children": [...]}.
Also handles plain text XML manifests through the manifest module.

Binary format notes (little endian):
- File header: magic 0x00080003, total size.
- Every chunk: type (u16), header size (u16), size (u32).
- String pool (0x0001): counts, flags, offsets, then string data.
  UTF-8 flag is 0x100. UTF-16 is the default when the flag is absent.
- Start element (0x0102): namespace ref, name ref, then attributes.
  Each attribute is 20 bytes: ns ref, name ref, raw value ref, then a
  typed value (size u16, res0 u8, data type u8, data u32).
- Data types we care about: 0x03 string, 0x10 int, 0x11 hex int,
  0x12 boolean. Anything else falls back to the raw value string.
"""

import struct

CHUNK_STRING_POOL = 0x0001
CHUNK_RESOURCE_MAP = 0x0180
CHUNK_START_NAMESPACE = 0x0100
CHUNK_END_NAMESPACE = 0x0101
CHUNK_START_ELEMENT = 0x0102
CHUNK_END_ELEMENT = 0x0103
CHUNK_CDATA = 0x0104

TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

UTF8_FLAG = 0x100


class AxmlError(ValueError):
    """Raised when binary XML cannot be parsed."""


def _read_varint(data, pos):
    """Read an AXML length: one byte, or two bytes when high bit is set."""
    first = data[pos]
    if first & 0x80:
        second = data[pos + 1]
        return ((first & 0x7F) << 8) | second, pos + 2
    return first, pos + 1


def _decode_string_pool(data, chunk_start, chunk_size):
    """Decode one string pool chunk into a list of strings."""
    # Chunk header is 8 bytes (type, header size, size), then 5 u32
    # fields: string count, style count, flags, strings start, styles start.
    (string_count, _style_count, flags,
     strings_start, _styles_start) = struct.unpack_from(
        "<IIIII", data, chunk_start + 8)
    offsets_base = chunk_start + strings_start
    strings = []
    # Offsets live right after the 28 byte pool header.
    offsets_pos = chunk_start + 28
    for i in range(string_count):
        (off,) = struct.unpack_from("<I", data, offsets_pos + 4 * i)
        pos = offsets_base + off
        if flags & UTF8_FLAG:
            _char_len, pos = _read_varint(data, pos)
            byte_len, pos = _read_varint(data, pos)
            raw = data[pos:pos + byte_len]
            strings.append(raw.decode("utf-8", errors="replace"))
        else:
            (length,) = struct.unpack_from("<H", data, pos)
            pos += 2
            if length & 0x8000:
                (extra,) = struct.unpack_from("<H", data, pos)
                pos += 2
                length = ((length & 0x7FFF) << 16) | extra
            raw = data[pos:pos + length * 2]
            strings.append(raw.decode("utf-16-le", errors="replace"))
    return strings


def _parse_typed_value(data, pos, strings):
    """Parse one 8 byte typed value. Returns (python value, raw index)."""
    size, _res0, data_type, value = struct.unpack_from("<HBBI", data, pos)
    _ = size
    if data_type == TYPE_STRING:
        if 0 <= value < len(strings):
            return strings[value], value
        return "", value
    if data_type == TYPE_INT_BOOLEAN:
        return bool(value), None
    if data_type in (TYPE_INT_DEC, TYPE_INT_HEX):
        return value, None
    return value, None


def parse_axml(data):
    """Parse AXML bytes into an element tree dict. Raises AxmlError."""
    if len(data) < 8:
        raise AxmlError("file too small to be binary XML")
    magic, _total = struct.unpack_from("<II", data, 0)
    if magic != 0x00080003:
        raise AxmlError("bad magic, not binary XML")
    strings = []
    root = None
    stack = []
    pos = 8
    while pos + 8 <= len(data):
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, pos)
        if chunk_size < 8 or pos + chunk_size > len(data):
            raise AxmlError("bad chunk size at offset %d" % pos)
        if chunk_type == CHUNK_STRING_POOL:
            strings = _decode_string_pool(data, pos, chunk_size)
        elif chunk_type == CHUNK_START_ELEMENT:
            (_line, _comment, ns_idx, name_idx) = struct.unpack_from(
                "<IIII", data, pos + 8)
            (attr_start, attr_size, attr_count,
             _id_idx, _cls_idx, _style_idx) = struct.unpack_from(
                "<HHHHHH", data, pos + 24)
            name = strings[name_idx] if 0 <= name_idx < len(strings) else ""
            _ = ns_idx
            attrs = {}
            # attributeStart is relative to the end of the node header
            # (chunk header 8 bytes + line/comment 8 bytes = header_size),
            # NOT relative to the chunk start. Real files store 20 here,
            # so attributes begin at chunk start + header_size + 20 = 36.
            base = pos + header_size + attr_start
            for i in range(attr_count):
                a = base + i * attr_size
                (_ans, aname_idx, raw_idx) = struct.unpack_from("<III", data, a)
                value, _ = _parse_typed_value(data, a + 12, strings)
                if value == "" and raw_idx != 0xFFFFFFFF and 0 <= raw_idx < len(strings):
                    value = strings[raw_idx]
                aname = strings[aname_idx] if 0 <= aname_idx < len(strings) else ""
                if aname:
                    attrs[aname] = value
            node = {"name": name, "attrs": attrs, "children": [], "text": ""}
            if stack:
                stack[-1]["children"].append(node)
            else:
                root = node
            stack.append(node)
        elif chunk_type == CHUNK_END_ELEMENT:
            if stack:
                stack.pop()
        elif chunk_type == CHUNK_CDATA:
            (_line, _comment, _ns, _name) = struct.unpack_from("<IIII", data, pos + 8)
            # CDATA text lives after the 28 byte header; kept simple:
            # most manifests carry no CDATA, so we only record raw text
            # when the chunk is well formed.
            if chunk_size >= 36 and stack:
                (_size2, _r0, dtype, val) = struct.unpack_from("<HBBI", data, pos + 28)
                if dtype == TYPE_STRING and 0 <= val < len(strings):
                    stack[-1]["text"] += strings[val]
        # Other chunks (resource map, namespaces) are skipped by size.
        pos += chunk_size
    if root is None:
        raise AxmlError("no root element found")
    return root


def is_axml(data):
    """True when bytes look like binary XML."""
    if len(data) < 4:
        return False
    (magic,) = struct.unpack_from("<I", data, 0)
    return magic == 0x00080003
