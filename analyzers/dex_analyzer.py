from __future__ import annotations

import struct
from pathlib import Path
from typing import Any


def _uleb128(data: bytes, offset: int) -> tuple[int, int]:
    value = 0; shift = 0
    while offset < len(data) and shift <= 28:
        byte = data[offset]; offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
    raise ValueError("invalid DEX uleb128")


def analyze_dex(path: Path) -> dict[str, Any]:
    """Inventory DEX strings and class descriptors without claiming method semantics.

    Full bytecode decompilation is deliberately outside this parser. Method and
    JNI relationships must come from explicit registration evidence or a later
    analyzer fixture.
    """
    data = path.read_bytes()
    if len(data) < 0x70 or data[:4] != b"dex\n" or data[7] != 0:
        raise ValueError("unsupported DEX header")
    version = data[4:7].decode("ascii", "replace")
    endian_tag = struct.unpack_from("<I", data, 0x28)[0]
    if endian_tag != 0x12345678:
        raise ValueError("unsupported DEX endian tag")
    file_size, header_size = struct.unpack_from("<II", data, 0x20)
    string_count, string_off = struct.unpack_from("<II", data, 0x38)
    if file_size > len(data) or header_size != 0x70 or string_off + string_count * 4 > len(data):
        raise ValueError("truncated DEX string table")
    strings: list[str] = []
    for index in range(string_count):
        item_offset = struct.unpack_from("<I", data, string_off + index * 4)[0]
        _, cursor = _uleb128(data, item_offset)
        end = data.find(b"\0", cursor)
        if end < 0:
            raise ValueError(f"unterminated DEX string {index}")
        strings.append(data[cursor:end].decode("utf-8", "replace"))
    descriptors = sorted({value for value in strings if value.startswith("L") and value.endswith(";") and "/" in value})
    method_like = sorted({value for value in strings if "(" in value and ")" in value})
    return {"format": "dex", "version": version, "strings": strings, "class_descriptors": descriptors,
            "method_signature_candidates": method_like,
            "semantic_status": "INDEXED_ONLY", "limitations": ["RegisterNatives and method bodies require explicit static evidence"]}
