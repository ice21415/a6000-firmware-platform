"""Evidence-gated probe for the ParamBase ABI foundation.

This module records only bounded, SHA-pinned ELF facts.  It keeps the base
vtable and constructor/destructor observations separate from source-level C++
types, ownership, runtime relocation and callable SDK claims.
"""
from __future__ import annotations

import hashlib
import re
import struct
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from capstone.arm import ARM_OP_IMM
from elftools.elf.elffile import ELFFile

from .elf_plt import resolve_plt_binding
from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA


BASE_RTTI_VMA = 0xFE6E24
BASE_VTABLE_VMA = 0xFE6E30
BASE_VTABLE_GOT = 0x1033A60
BASE_VTABLE_ADDRESS_POINT = BASE_VTABLE_VMA + 8
BASE_CONSTRUCTOR_ENTRY = 0xE50B4
BASE_CONSTRUCTOR_SYMBOL = "_ZN9ParamBaseC2Em"
BASE_DESTRUCTOR_ENTRY = 0xE4734
BASE_DELETING_DESTRUCTOR_ENTRY = 0xE4854
KEY_SETTER_ENTRY = 0x7EDA84
KEY_SETTER_SIZE = 8
DELETE_PLT = 0xDD620

EXPECTED_DERIVED_NAMES = frozenset({
    "PrmBool",
    "PrmNumber",
    "PrmString",
    "PrmPoint",
    "PrmDimension",
    "PrmStruct",
    "PrmSet",
    "PrmNumberList",
    "PrmCntInfoList",
    "PrmObjMsg",
})


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_data(elf: ELFFile, address: int, size: int) -> bytes:
    for section in elf.iter_sections():
        start = int(section["sh_addr"])
        end = start + int(section["sh_size"])
        if start <= address and address + size <= end:
            offset = address - start
            return section.data()[offset : offset + size]
    raise ValueError(f"ELF_VMA 0x{address:x} is not mapped")


def _read_u32(elf: ELFFile, address: int) -> int:
    return struct.unpack("<I", _read_data(elf, address, 4))[0]


def _read_exec_range(stream: Any, elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > 0x100:
        raise ValueError("ParamBase bounded read exceeds probe limit")
    offsets: list[int] = []
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD" or not (int(segment["p_flags"]) & 1):
            continue
        base = int(segment["p_vaddr"])
        length = int(segment["p_filesz"])
        if base <= start and start + size <= base + length:
            offsets.append(int(segment["p_offset"]) + start - base)
    if len(offsets) != 1:
        raise ValueError(f"ELF_VMA 0x{start:x} is not uniquely executable")
    stream.seek(offsets[0])
    data = stream.read(size)
    if len(data) != size:
        raise ValueError("truncated executable range")
    return data


def _decode(stream: Any, elf: ELFFile, entry: int, size: int) -> dict[int, Any]:
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    rows = list(decoder.disasm(_read_exec_range(stream, elf, entry, size), entry))
    if not rows:
        raise ValueError(f"no Thumb instructions at 0x{entry:x}")
    return {int(row.address): row for row in rows}


def _symbols(elf: ELFFile) -> dict[str, tuple[int, int]]:
    result: dict[str, tuple[int, int]] = {}
    for section_name in (".dynsym", ".symtab"):
        section = elf.get_section_by_name(section_name)
        if section is None:
            continue
        for symbol in section.iter_symbols():
            if symbol.name and symbol.name not in result:
                result[symbol.name] = (int(symbol["st_value"]), int(symbol["st_size"]))
    return result


def _relocations(elf: ELFFile) -> dict[int, dict[str, Any]]:
    result: dict[int, dict[str, Any]] = {}
    for section in elf.iter_sections():
        if not hasattr(section, "iter_relocations"):
            continue
        symbols = elf.get_section(section["sh_link"])
        for relocation in section.iter_relocations():
            symbol = symbols.get_symbol(relocation["r_info_sym"])
            offset = int(relocation["r_offset"])
            candidate = {
                "type": int(relocation["r_info_type"]),
                "symbol": symbol.name or None,
                "symbol_value": int(symbol["st_value"]),
            }
            existing = result.get(offset)
            if existing is None or candidate["symbol"] or not existing.get("symbol"):
                result[offset] = candidate
    return result


def _effective_u32(
    elf: ELFFile, relocations: dict[int, dict[str, Any]], address: int,
) -> int:
    value = _read_u32(elf, address)
    if value:
        return value
    return int((relocations.get(address) or {}).get("symbol_value", 0))


def _vma_symbol(symbols: dict[str, tuple[int, int]], name: str) -> int | None:
    row = symbols.get(name)
    return None if row is None else row[0] & ~1


def _immediates(instruction: Any) -> list[int]:
    return [int(operand.imm) for operand in instruction.operands if operand.type == ARM_OP_IMM]


def _require(
    rows: dict[int, Any], address: int, mnemonic: str, *, operands: str | None = None,
    target: int | None = None,
) -> Any:
    instruction = rows.get(address)
    if instruction is None or instruction.mnemonic.lower() != mnemonic.lower():
        raise ValueError(f"unexpected {mnemonic} at 0x{address:x}")
    if operands is not None and instruction.op_str.lower() != operands.lower():
        raise ValueError(f"unexpected operands at 0x{address:x}")
    if target is not None and target not in _immediates(instruction):
        raise ValueError(f"unexpected target at 0x{address:x}")
    return instruction


def _literal_address(instruction: Any, immediate: int) -> int:
    # Thumb literal loads use Align(PC, 4) + imm; all target literals here
    # are positive and reside in the same bounded region.
    return ((int(instruction.address) + 4) & ~3) + immediate


def _find_vtable_for_typeinfo(
    elf: ELFFile, relocations: dict[int, dict[str, Any]], typeinfo: int,
) -> int | None:
    candidates: list[int] = []
    needle = struct.pack("<I", typeinfo)
    for section in elf.iter_sections():
        data = section.data()
        cursor = 0
        while True:
            found = data.find(needle, cursor)
            if found < 0:
                break
            pointer = int(section["sh_addr"]) + found
            vtable = pointer - 4
            if vtable >= 4:
                try:
                    if _read_u32(elf, vtable) == 0:
                        candidates.append(vtable)
                except ValueError:
                    pass
            cursor = found + 1
    # Some loaders leave the typeinfo word zero in the file and carry only a
    # relocation symbol.  Retain that fallback without repeatedly scanning
    # every ELF section for every relocation.
    for offset, relocation in relocations.items():
        if int(relocation.get("symbol_value", 0)) != typeinfo:
            continue
        vtable = offset - 4
        if vtable < 4:
            continue
        try:
            if _read_u32(elf, vtable) == 0:
                candidates.append(vtable)
        except ValueError:
            pass
    return min(candidates) if candidates else None


def _rtti_name(elf: ELFFile, relocations: dict[int, dict[str, Any]], typeinfo: int) -> str:
    name_address = _effective_u32(elf, relocations, typeinfo + 4)
    raw = _read_data(elf, name_address, 96).split(b"\0", 1)[0]
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError(f"non-ASCII RTTI name at 0x{name_address:x}") from exc


def _rtti_class_name(encoded: str) -> str:
    """Strip the Itanium length prefix without treating it as semantic proof."""
    match = re.fullmatch(r"[0-9]+(.+)", encoded)
    return match.group(1) if match else encoded


def _observe_base_vtable(
    elf: ELFFile, relocations: dict[int, dict[str, Any]],
) -> dict[str, Any]:
    words = struct.unpack("<5I", _read_data(elf, BASE_VTABLE_VMA, 20))
    effective_rtti = _effective_u32(elf, relocations, BASE_VTABLE_VMA + 4)
    effective_destructor = _effective_u32(elf, relocations, BASE_VTABLE_VMA + 12)
    effective_deleting = _effective_u32(elf, relocations, BASE_VTABLE_VMA + 16)
    if words[0] != 0 or (effective_rtti & ~1) != BASE_RTTI_VMA:
        raise ValueError("ParamBase vtable header mismatch")
    clone_relocation = relocations.get(BASE_VTABLE_VMA + 8)
    if not clone_relocation or clone_relocation.get("symbol") != "__cxa_pure_virtual":
        raise ValueError("ParamBase clone slot is not bound to __cxa_pure_virtual")
    if (effective_destructor & ~1) != BASE_DESTRUCTOR_ENTRY or (effective_deleting & ~1) != BASE_DELETING_DESTRUCTOR_ENTRY:
        raise ValueError("ParamBase destructor slots mismatch")
    if _rtti_name(elf, relocations, BASE_RTTI_VMA) != "9ParamBase":
        raise ValueError("ParamBase RTTI name mismatch")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "vtable_vma": hex(BASE_VTABLE_VMA),
        "vtable_address_point": hex(BASE_VTABLE_ADDRESS_POINT),
        "rtti_vma": hex(BASE_RTTI_VMA),
        "rtti_name": "9ParamBase",
        "offset_to_top": 0,
        "slot_plus_8_clone": {
            "target": "__cxa_pure_virtual",
            "verification": "PRIMARY_ELF_VERIFIED",
            "source": "ELF relocation",
        },
        "slot_plus_12_destructor": hex(effective_destructor & ~1),
        "slot_plus_16_deleting_destructor": hex(effective_deleting & ~1),
        "address_space": "ELF_VMA",
    }


def _observe_base_constructor(
    stream: Any, elf: ELFFile,
) -> dict[str, Any]:
    rows = _decode(stream, elf, BASE_CONSTRUCTOR_ENTRY, 0x14)
    _require(rows, 0xE50B4, "ldr")
    _require(rows, 0xE50B6, "push")
    _require(rows, 0xE50B8, "add")
    literal_base = _literal_address(rows[0xE50B4], 0x10)
    got_base = (0xE50BC + _read_u32(elf, literal_base)) & 0xFFFFFFFF
    _require(rows, 0xE50BA, "ldr")
    got_offset_address = _literal_address(rows[0xE50BA], 0x10)
    got_offset = _read_u32(elf, got_offset_address)
    vtable_got = (got_base + got_offset) & 0xFFFFFFFF
    if vtable_got != BASE_VTABLE_GOT:
        raise ValueError(f"ParamBase vtable GOT mismatch: 0x{vtable_got:x}")
    if _read_u32(elf, vtable_got) != BASE_VTABLE_VMA:
        raise ValueError("ParamBase vtable GOT does not point at the base vtable")
    _require(rows, 0xE50C0, "str", operands="r1, [r0, #4]")
    _require(rows, 0xE50C2, "adds")
    _require(rows, 0xE50C4, "str", operands="r3, [r0]")
    _require(rows, 0xE50C6, "pop")
    stores = [
        instruction.op_str.lower()
        for instruction in rows.values()
        if instruction.mnemonic.lower().startswith("str")
    ]
    if any(re.search(r"\[r0, #(?:8|0xc)\]", text) for text in stores):
        raise ValueError("ParamBase constructor unexpectedly writes key/payload field")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "entry_vma": hex(BASE_CONSTRUCTOR_ENTRY),
        "symbol": BASE_CONSTRUCTOR_SYMBOL,
        "vtable_got": hex(vtable_got),
        "vtable_target": hex(BASE_VTABLE_VMA),
        "writes": {
            "vptr_plus_00": "r3",
            "discriminator_plus_04": "r1",
            "key_plus_08": "NOT_WRITTEN_IN_BOUNDED_BASE_BODY",
            "payload_plus_0c": "NOT_WRITTEN_IN_BOUNDED_BASE_BODY",
        },
        "address_space": "ELF_VMA",
        "constructor_input": "r0 destination, r1 discriminator word candidate",
    }


def _observe_base_destructor(
    stream: Any, elf: ELFFile, relocations: dict[int, dict[str, Any]],
) -> dict[str, Any]:
    rows = _decode(stream, elf, BASE_DESTRUCTOR_ENTRY, 0x12)
    _require(rows, 0xE4734, "ldr")
    _require(rows, 0xE4736, "ldr")
    _require(rows, 0xE4738, "add")
    _require(rows, 0xE473E, "ldr")
    _require(rows, 0xE4740, "adds")
    _require(rows, 0xE4742, "str", operands="r3, [r0]")
    _require(rows, 0xE4744, "pop")
    literal_base = _literal_address(rows[0xE4734], 0x10)
    got_base = (0xE473C + _read_u32(elf, literal_base)) & 0xFFFFFFFF
    got_offset_address = _literal_address(rows[0xE4736], 0x14)
    got_offset = _read_u32(elf, got_offset_address)
    vtable_got = (got_base + got_offset) & 0xFFFFFFFF
    if vtable_got != BASE_VTABLE_GOT or _read_u32(elf, vtable_got) != BASE_VTABLE_VMA:
        raise ValueError("ParamBase destructor vtable source mismatch")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "entry_vma": hex(BASE_DESTRUCTOR_ENTRY),
        "operation": "restores the ParamBase vptr to the base vtable address point and returns",
        "vtable_got": hex(vtable_got),
        "vtable_target": hex(BASE_VTABLE_VMA),
        "writes": {"vptr_plus_00": hex(BASE_VTABLE_ADDRESS_POINT)},
        "payload_release": "NONE_IN_BASE_BODY",
        "address_space": "ELF_VMA",
    }


def _observe_base_deleting_destructor(
    stream: Any, elf: ELFFile, delete_binding: dict[str, Any],
) -> dict[str, Any]:
    rows = _decode(stream, elf, BASE_DELETING_DESTRUCTOR_ENTRY, 0x14)
    _require(rows, 0xE485A, "bl", target=BASE_DESTRUCTOR_ENTRY)
    _require(rows, 0xE4860, "blx", target=DELETE_PLT)
    _require(rows, 0xE4866, "pop")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "entry_vma": hex(BASE_DELETING_DESTRUCTOR_ENTRY),
        "operation": "calls the non-deleting base destructor then operator-delete",
        "delete_binding": delete_binding,
        "address_space": "ELF_VMA",
    }


def _observe_key_setter(stream: Any, elf: ELFFile) -> dict[str, Any]:
    rows = _decode(stream, elf, KEY_SETTER_ENTRY, KEY_SETTER_SIZE)
    _require(rows, KEY_SETTER_ENTRY, "push")
    _require(rows, KEY_SETTER_ENTRY + 2, "add")
    _require(rows, KEY_SETTER_ENTRY + 4, "str", operands="r1, [r0, #8]")
    _require(rows, KEY_SETTER_ENTRY + 6, "pop")
    return {
        "entry_vma": hex(KEY_SETTER_ENTRY),
        "operation": "stores r1 at receiver +0x08",
        "verification": "PRIMARY_ELF_VERIFIED",
        "address_space": "ELF_VMA",
    }


def _discover_direct_derived(
    elf: ELFFile, relocations: dict[int, dict[str, Any]],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen: set[int] = set()
    for offset, relocation in sorted(relocations.items()):
        if relocation.get("symbol") != "_ZTI9ParamBase" or offset < 8:
            continue
        typeinfo = offset - 8
        if typeinfo in seen:
            continue
        seen.add(typeinfo)
        try:
            if _read_u32(elf, typeinfo) != 8:
                continue
            encoded_name = _rtti_name(elf, relocations, typeinfo)
            name = _rtti_class_name(encoded_name)
            if encoded_name == "9ParamBase":
                continue
            vtable = _find_vtable_for_typeinfo(elf, relocations, typeinfo)
        except (ValueError, struct.error):
            continue
        records.append({
            "name": name,
            "rtti_name": encoded_name,
            "rtti_vma": hex(typeinfo),
            "base_rtti_vma": hex(BASE_RTTI_VMA),
            "vtable_vma": hex(vtable) if vtable is not None else None,
            "relation": "DIRECT_SINGLE_INHERITANCE_CANDIDATE",
            "verification": "PRIMARY_ELF_VERIFIED" if vtable is not None else "STATIC_INFERRED",
            "address_space": "ELF_VMA",
            "source": "RTTI +0x08 relocation to _ZTI9ParamBase and vtable typeinfo relocation",
        })
    return records


def probe_param_base(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Validate bounded ParamBase constructor, vtable and lifetime facts."""
    path = Path(elf_path).resolve()
    if not path.is_file():
        raise ValueError("private ELF is missing")
    if not HEX_SHA.fullmatch(expected_sha256):
        raise ValueError("expected_sha256 must be a lowercase full SHA-256 digest")
    digest = _sha256(path)
    if digest != expected_sha256:
        raise ValueError("full-file ELF SHA-256 mismatch; refusing to decode")
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_ARM":
            raise ValueError("probe accepts only ELF32 little-endian ARM")
        symbols = _symbols(elf)
        constructor_symbol = symbols.get(BASE_CONSTRUCTOR_SYMBOL)
        if constructor_symbol is None or (constructor_symbol[0] & ~1) != BASE_CONSTRUCTOR_ENTRY:
            raise ValueError("ParamBase constructor symbol identity mismatch")
        relocations = _relocations(elf)
        base_vtable = _observe_base_vtable(elf, relocations)
        base_constructor = _observe_base_constructor(stream, elf)
        base_destructor = _observe_base_destructor(stream, elf, relocations)
        delete_binding = resolve_plt_binding(stream, elf, DELETE_PLT, thumb_stub=False)
        if delete_binding.get("status") != "VERIFIED_STATIC":
            raise ValueError("operator-delete PLT binding is not unique")
        base_deleting = _observe_base_deleting_destructor(stream, elf, delete_binding)
        key_setter = _observe_key_setter(stream, elf)
        derived = _discover_direct_derived(elf, relocations)
    return {
        "schema_version": 1,
        "status": "LOCAL_PRIMARY_ELF_PARAMBASE_EVIDENCE_ONLY",
        "binary_file_sha256": digest,
        "address_space": "ELF_VMA",
        "abi": "ARM AAPCS32, Thumb, little endian",
        "base": {
            "rtti": base_vtable,
            "constructor": base_constructor,
            "destructor": base_destructor,
            "deleting_destructor": base_deleting,
            "key_setter": key_setter,
        },
        "direct_derived": derived,
        "expected_direct_derived_names": sorted(EXPECTED_DERIVED_NAMES),
        "runtime_verified": False,
        "callable": False,
        "limitations": [
            "No source-level class hierarchy beyond the direct RTTI relocation is claimed",
            "No constructor ownership, copy, exception, lock or runtime-loader behavior is inferred",
            "The absence of +0x08/+0x0c stores is bounded to the observed base constructor body",
            "Derived payload types remain governed by their family-specific contracts",
            "The offline probe does not execute firmware or access a camera",
        ],
    }


def validate_param_base(report: dict[str, Any]) -> dict[str, Any]:
    """Validate public-safe ParamBase invariants without runtime promotion."""
    errors: list[str] = []
    if report.get("binary_file_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != "ELF_VMA":
        errors.append("address_space")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    base = report.get("base")
    if not isinstance(base, dict):
        errors.append("missing:base")
        base = {}
    for key in ("rtti", "constructor", "destructor", "deleting_destructor", "key_setter"):
        if not isinstance(base.get(key), dict):
            errors.append(f"missing:base:{key}")
    if base.get("rtti", {}).get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("base_vtable_status")
    if base.get("rtti", {}).get("rtti_name") != "9ParamBase":
        errors.append("base_rtti_name")
    if base.get("rtti", {}).get("slot_plus_8_clone", {}).get("target") != "__cxa_pure_virtual":
        errors.append("base_clone_slot")
    if base.get("constructor", {}).get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("base_constructor_status")
    writes = base.get("constructor", {}).get("writes", {})
    if writes.get("key_plus_08") != "NOT_WRITTEN_IN_BOUNDED_BASE_BODY":
        errors.append("base_key_write_scope")
    if writes.get("payload_plus_0c") != "NOT_WRITTEN_IN_BOUNDED_BASE_BODY":
        errors.append("base_payload_write_scope")
    if base.get("destructor", {}).get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("base_destructor_status")
    if base.get("deleting_destructor", {}).get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("base_deleting_destructor_status")
    derived = report.get("direct_derived")
    if not isinstance(derived, list):
        errors.append("missing:direct_derived")
        derived = []
    names = {item.get("name") for item in derived if isinstance(item, dict)}
    if not EXPECTED_DERIVED_NAMES.issubset(names):
        errors.append("missing:expected_direct_derived")
    for item in derived:
        if not isinstance(item, dict):
            errors.append("invalid:direct_derived")
            continue
        if item.get("base_rtti_vma") != hex(BASE_RTTI_VMA):
            errors.append(f"derived_base_rtti:{item.get('name')}")
        if not item.get("vtable_vma"):
            errors.append(f"derived_vtable:{item.get('name')}")
        if item.get("address_space") != "ELF_VMA":
            errors.append(f"derived_address_space:{item.get('name')}")
    key_setter = base.get("key_setter", {})
    if key_setter.get("verification") != "PRIMARY_ELF_VERIFIED":
        errors.append("key_setter_status")
    ghidra = report.get("ghidra_crosscheck")
    if ghidra is not None:
        if ghidra.get("status") != "VERIFIED_STATIC":
            errors.append("ghidra_status")
        if ghidra.get("process_exit") != 0:
            errors.append("ghidra_exit")
        if ghidra.get("address_space") != "ram":
            errors.append("ghidra_address_space")
        if ghidra.get("raw_export_private") is not True:
            errors.append("ghidra_public_raw_export")
    return {
        "valid": not errors,
        "errors": sorted(set(errors)),
        "derived_count": len(derived),
        "expected_derived_count": len(EXPECTED_DERIVED_NAMES),
    }
