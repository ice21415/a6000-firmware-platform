from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any


def _uleb128(data: bytes, offset: int) -> tuple[int, int]:
    """Decode one bounded DEX uleb128 (at most five bytes)."""
    result = 0
    for shift in range(0, 35, 7):
        if offset >= len(data):
            raise ValueError("truncated DEX uleb128")
        byte = data[offset]
        offset += 1
        if shift == 28 and byte > 0x0F:
            raise ValueError("DEX uleb128 overflow")
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, offset
    raise ValueError("invalid DEX uleb128")


def _table(data: bytes, offset: int, count: int, width: int, label: str) -> None:
    """Check a DEX table without trusting unbounded counts from the header."""
    if count and (offset < 0x70 or offset > len(data) or count > (len(data) - offset) // width):
        raise ValueError(f"truncated DEX {label} table")
    if not count and offset and offset > len(data):
        raise ValueError(f"invalid DEX {label} offset")


def analyze_dex(path: Path) -> dict[str, Any]:
    """Inventory DEX types, defined classes, and method *references*.

    Method IDs do not prove the named method has a body or even belongs to a
    class defined in this DEX. JNI registration remains explicit evidence only.
    """
    data = path.read_bytes()
    if len(data) < 0x70 or data[:4] != b"dex\n" or data[7] != 0:
        raise ValueError("unsupported DEX header")
    version = data[4:7].decode("ascii", "replace")
    endian_tag = struct.unpack_from("<I", data, 0x28)[0]
    if endian_tag != 0x12345678:
        raise ValueError("unsupported DEX endian tag")
    file_size, header_size = struct.unpack_from("<II", data, 0x20)
    if file_size != len(data) or header_size != 0x70:
        raise ValueError("invalid DEX file or header size")

    string_count, string_off = struct.unpack_from("<II", data, 0x38)
    type_count, type_off = struct.unpack_from("<II", data, 0x40)
    proto_count, proto_off = struct.unpack_from("<II", data, 0x48)
    method_count, method_off = struct.unpack_from("<II", data, 0x58)
    class_count, class_off = struct.unpack_from("<II", data, 0x60)
    for off, count, width, label in (
        (string_off, string_count, 4, "string_id"),
        (type_off, type_count, 4, "type_id"),
        (proto_off, proto_count, 12, "proto_id"),
        (method_off, method_count, 8, "method_id"),
        (class_off, class_count, 32, "class_def"),
    ):
        _table(data, off, count, width, label)

    strings: list[str] = []
    for index in range(string_count):
        item_offset = struct.unpack_from("<I", data, string_off + index * 4)[0]
        if item_offset >= len(data):
            raise ValueError(f"DEX string[{index}] offset outside file")
        _, cursor = _uleb128(data, item_offset)
        end = data.find(b"\0", cursor)
        if end < 0:
            raise ValueError(f"unterminated DEX string {index}")
        # This is a conservative text index, not a full MUTF-8 decoder.
        strings.append(data[cursor:end].decode("utf-8", "replace"))

    types: list[str] = []
    for index in range(type_count):
        string_idx = struct.unpack_from("<I", data, type_off + index * 4)[0]
        if string_idx >= len(strings):
            raise ValueError(f"DEX type_id[{index}] has invalid string index")
        types.append(strings[string_idx])

    def type_at(index: int, label: str) -> str:
        if index >= len(types):
            raise ValueError(f"DEX {label} has invalid type index")
        return types[index]

    prototypes: list[str] = []
    for index in range(proto_count):
        shorty_idx, ret_idx, params_off = struct.unpack_from("<III", data, proto_off + index * 12)
        if shorty_idx >= len(strings):
            raise ValueError(f"DEX proto_id[{index}] has invalid shorty index")
        signature = "("
        if params_off:
            if params_off > len(data) - 4:
                raise ValueError(f"DEX proto_id[{index}] has invalid parameters offset")
            length = struct.unpack_from("<I", data, params_off)[0]
            if length > (len(data) - params_off - 4) // 2:
                raise ValueError(f"DEX proto_id[{index}] has truncated parameters")
            for parameter_index in range(length):
                type_idx = struct.unpack_from("<H", data, params_off + 4 + parameter_index * 2)[0]
                signature += type_at(type_idx, f"proto_id[{index}].parameter")
        prototypes.append(signature + ")" + type_at(ret_idx, f"proto_id[{index}].return"))

    defined_classes: list[dict[str, Any]] = []
    defined_type_ids: set[int] = set()
    for index in range(class_count):
        class_idx = struct.unpack_from("<I", data, class_off + index * 32)[0]
        descriptor = type_at(class_idx, f"class_def[{index}]")
        if not (descriptor.startswith("L") and descriptor.endswith(";")):
            raise ValueError(f"DEX class_def[{index}] is not a class descriptor")
        if class_idx in defined_type_ids:
            raise ValueError(f"DEX duplicate class_def[{index}]")
        defined_type_ids.add(class_idx)
        defined_classes.append({
            "index": index, "type_index": class_idx, "descriptor": descriptor,
        })

    method_references: list[dict[str, Any]] = []
    for index in range(method_count):
        class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", data, method_off + index * 8)
        if proto_idx >= len(prototypes) or name_idx >= len(strings):
            raise ValueError(f"DEX method_id[{index}] has invalid proto/name index")
        method_references.append({
            "index": index,
            "class_descriptor": type_at(class_idx, f"method_id[{index}].class"),
            "method_name": strings[name_idx],
            "signature": prototypes[proto_idx],
            "class_defined_in_dex": class_idx in defined_type_ids,
        })

    descriptors = sorted({
        value for value in strings if value.startswith("L") and value.endswith(";") and "/" in value
    })
    method_like = sorted({value for value in strings if "(" in value and ")" in value})
    return {
        "format": "dex", "version": version, "sha256": hashlib.sha256(data).hexdigest(),
        "strings": strings,
        "class_descriptors": descriptors,
        "method_signature_candidates": method_like,
        "type_descriptors": types,
        "defined_classes": defined_classes,
        "method_references": method_references,
        "semantic_status": "INDEXED_ONLY",
        "limitations": [
            "DEX method_id entries are references, not proof of method implementations",
            "JNI RegisterNatives and method bodies require independent evidence",
            "String data uses UTF-8 replacement rather than full DEX MUTF-8 decoding",
        ],
    }
