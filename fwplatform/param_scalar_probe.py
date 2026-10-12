"""Evidence-gated ParamBase scalar-family lifecycle probe.

The probe closes a small, reusable evidence chain for ``PrmBool`` and
``PrmNumber``: RTTI/vtable identity, the ParamBase constructor call, payload
initialisation from the original AAPCS argument, clone allocation/copy and
both destructor paths.  It deliberately keeps the ParamList key separate:
the constructors do not write ``+0x08`` and the key setter remains the
independent insertion witness.

Only metadata is returned.  The exact SHA-pinned private ELF is read before
decoding, no firmware bytes are emitted, and no firmware code is executed.
The resulting contract is descriptive evidence, never a live C++ wrapper.
"""
from __future__ import annotations

import hashlib
import re
import struct
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG
from elftools.elf.elffile import ELFFile

from .elf_plt import resolve_plt_binding
from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA, MAX_ELF_BYTES


PARAM_BASE_CONSTRUCTOR_PLT = 0xE11A4
PARAM_BASE_CONSTRUCTOR_ENTRY = 0xE11A4
ALLOCATOR_PLT = 0xDC100
DELETE_OBJECT_PLT = 0xDD620
BASE_DESTRUCTOR_ENTRY = 0xE4734
KEY_OFFSET = 0x08
PAYLOAD_OFFSET = 0x0C


SCALAR_PROFILES: tuple[dict[str, Any], ...] = (
    {
        "name": "PrmBool",
        "rtti_name": "7PrmBool",
        "rtti_vma": 0xFE6E18,
        "vtable_vma": 0xFE6E00,
        "base_rtti_vma": 0xFE6E24,
        "constructor": (0xE50E8, 0x20),
        "discriminator": 5,
        "allocation_size": 0x10,
        "payload_width": "byte",
        "payload_kind": "bool_byte",
        "payload_store": (0xE5100, "strb", "r6, [r5, #0xc]"),
        "vptr_store": (0xE5104, "str", "r3, [r5]"),
        "clone": (0xE5110, 0x18),
        "clone_load": (0xE511C, "ldrb", "r1, [r5, #0xc]"),
        "clone_call": (0xE5120, "bl", 0xE50E8),
        "destructor": (0xE4750, 0x1A),
        "destructor_base_call": (0xE4762, "bl", BASE_DESTRUCTOR_ENTRY),
        "deleting_destructor": (0xE4840, 0x14),
        "deleting_call": (0xE4846, "blx", 0xE0570),
        "deleting_call_plt": 0xE0570,
        "deleting_call_symbol": "_ZN7PrmBoolD1Ev",
        "setter": (0x426ACC, 0x08),
        "setter_symbol": "_ZN7PrmBool7setBoolEb",
        "setter_store": (0x426AD0, "strb", "r1, [r0, #0xc]"),
    },
    {
        "name": "PrmNumber",
        "rtti_name": "9PrmNumber",
        "rtti_vma": 0xFE8938,
        "vtable_vma": 0xFE8920,
        "base_rtti_vma": 0xFE6E24,
        "constructor": (0xF0FB0, 0x20),
        "discriminator": 1,
        "allocation_size": 0x10,
        "payload_width": "word",
        "payload_kind": "signed_int32_word",
        "payload_store": (0xF0FC8, "str", "r6, [r5, #0xc]"),
        "vptr_store": (0xF0FCC, "str", "r3, [r5]"),
        "clone": (0xF1034, 0x18),
        "clone_load": (0xF1040, "ldr", "r1, [r5, #0xc]"),
        "clone_call": (0xF1044, "bl", 0xF0FB0),
        "destructor": (0xF0F2C, 0x1A),
        "destructor_base_call": (0xF0F3E, "bl", BASE_DESTRUCTOR_ENTRY),
        "deleting_destructor": (0xF0F5C, 0x14),
        "deleting_call": (0xF0F62, "bl", 0xF0F2C),
        "deleting_call_plt": None,
        "deleting_call_symbol": None,
        "setter": (0x10F9FC, 0x08),
        "setter_symbol": "_ZN9PrmNumber9setNumberEi",
        "setter_store": (0x10FA00, "str", "r1, [r0, #0xc]"),
    },
)


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


def _read_exec(fp: Any, elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > 0x100:
        raise ValueError("scalar probe executable read exceeds bounded limit")
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
    fp.seek(offsets[0])
    data = fp.read(size)
    if len(data) != size:
        raise ValueError("truncated executable range")
    return data


def _decode(fp: Any, elf: ELFFile, start: int, size: int) -> dict[int, Any]:
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    rows = list(decoder.disasm(_read_exec(fp, elf, start, size), start))
    if not rows:
        raise ValueError(f"no Thumb instructions at 0x{start:x}")
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
            current = result.get(offset)
            if current is None or candidate["symbol"] or not current.get("symbol"):
                result[offset] = candidate
    return result


def _effective_u32(
    elf: ELFFile, relocations: dict[int, dict[str, Any]], address: int,
) -> int:
    value = struct.unpack("<I", _read_data(elf, address, 4))[0]
    if value:
        return value
    return int((relocations.get(address) or {}).get("symbol_value", 0))


def _binding(fp: Any, elf: ELFFile, entry: int, symbol: str) -> dict[str, Any]:
    result = resolve_plt_binding(fp, elf, entry, thumb_stub=False)
    candidates = result.get("candidates", [])
    if result.get("status") != "VERIFIED_STATIC" or len(candidates) != 1:
        raise ValueError(f"PLT binding at 0x{entry:x} is not unique")
    if candidates[0].get("symbol") != symbol:
        raise ValueError(f"unexpected PLT symbol at 0x{entry:x}")
    return result


def _immediates(instruction: Any) -> list[int]:
    return [int(operand.imm) for operand in instruction.operands if operand.type == ARM_OP_IMM]


def _require(
    rows: dict[int, Any], address: int, mnemonic: str, *,
    operands: str | None = None, target: int | None = None,
    immediate: int | None = None,
) -> Any:
    instruction = rows.get(address)
    if instruction is None or instruction.mnemonic.lower() != mnemonic.lower():
        raise ValueError(f"unexpected {mnemonic} at 0x{address:x}")
    if operands is not None and instruction.op_str.lower() != operands.lower():
        raise ValueError(f"unexpected operands at 0x{address:x}")
    if target is not None and target not in _immediates(instruction):
        raise ValueError(f"unexpected branch target at 0x{address:x}")
    if immediate is not None and immediate not in _immediates(instruction):
        raise ValueError(f"unexpected immediate at 0x{address:x}")
    return instruction


def _vtable(elf: ELFFile, relocations: dict[int, dict[str, Any]], profile: dict[str, Any]) -> dict[str, Any]:
    vtable = int(profile["vtable_vma"])
    words = struct.unpack("<5I", _read_data(elf, vtable, 20))
    typeinfo = _effective_u32(elf, relocations, vtable + 4)
    name_address = _effective_u32(elf, relocations, typeinfo + 4)
    rtti_name = _read_data(elf, name_address, 96).split(b"\0", 1)[0].decode("ascii")
    base_rtti = _effective_u32(elf, relocations, typeinfo + 8)
    expected = {
        "rtti_name": profile["rtti_name"],
        "typeinfo": int(profile["rtti_vma"]),
        "base_rtti": int(profile["base_rtti_vma"]),
        "clone": int(profile["clone"][0]),
        "destructor": int(profile["destructor"][0]),
        "deleting_destructor": int(profile["deleting_destructor"][0]),
    }
    if words[0] != 0 or typeinfo != expected["typeinfo"] or rtti_name != expected["rtti_name"]:
        raise ValueError(f"{profile['name']} RTTI/vtable header mismatch")
    if base_rtti != expected["base_rtti"]:
        raise ValueError(f"{profile['name']} does not point directly to ParamBase RTTI")
    slots = {
        "clone": _effective_u32(elf, relocations, vtable + 8),
        "destructor": _effective_u32(elf, relocations, vtable + 12),
        "deleting_destructor": _effective_u32(elf, relocations, vtable + 16),
    }
    for role, target in expected.items():
        if role in slots and (slots[role] & ~1) != target:
            raise ValueError(f"{profile['name']} vtable {role} mismatch")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "vtable_vma": hex(vtable),
        "address_point_vma": hex(vtable + 8),
        "rtti_vma": hex(typeinfo),
        "rtti_name": rtti_name,
        "base_rtti_vma": hex(base_rtti),
        "offset_to_top": words[0],
        "slots": {
            role: {"target_vma": hex(value & ~1), "thumb_tag": bool(value & 1)}
            for role, value in slots.items()
        },
        "address_space": "ELF_VMA",
    }


def _has_key_store(rows: dict[int, Any]) -> bool:
    for instruction in rows.values():
        if not instruction.mnemonic.lower().startswith("str"):
            continue
        if re.search(r"\[[^\]]+,\s*#8\]", instruction.op_str.lower()):
            return True
    return False


def _constructor(
    fp: Any, elf: ELFFile, profile: dict[str, Any], base_binding: dict[str, Any],
) -> dict[str, Any]:
    entry, size = profile["constructor"]
    rows = _decode(fp, elf, entry, size)
    _require(rows, entry, "push")
    _require(rows, entry + 2, "mov", operands="r6, r1")
    _require(rows, entry + 6, "movs", immediate=int(profile["discriminator"]))
    _require(rows, int(profile["payload_store"][0]), str(profile["payload_store"][1]), operands=str(profile["payload_store"][2]))
    _require(rows, int(profile["vptr_store"][0]), str(profile["vptr_store"][1]), operands=str(profile["vptr_store"][2]))
    base_call = next(
        (row for row in rows.values()
         if row.mnemonic.lower() == "blx" and PARAM_BASE_CONSTRUCTOR_ENTRY in _immediates(row)),
        None,
    )
    if base_call is None:
        raise ValueError(f"{profile['name']} has no ParamBase constructor call")
    if _has_key_store(rows):
        raise ValueError(f"{profile['name']} constructor writes ParamList key")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "entry_vma": hex(entry),
        "receiver": "r0 destination candidate (saved before base call)",
        "original_payload_argument": "r1 saved to r6 before discriminator setup",
        "discriminator": int(profile["discriminator"]),
        "base_constructor_call": {
            "plt_vma": hex(PARAM_BASE_CONSTRUCTOR_PLT),
            "callsite_vma": hex(int(base_call.address)),
            "binding": base_binding,
        },
        "payload_initialization": {
            "offset": hex(PAYLOAD_OFFSET),
            "width": profile["payload_width"],
            "store_vma": hex(int(profile["payload_store"][0])),
            "source_register": "r6 (original incoming r1)",
            "type_candidate": profile["payload_kind"],
            "verification": "PRIMARY_ELF_VERIFIED",
        },
        "key_initialization": {
            "offset": hex(KEY_OFFSET),
            "constructor_store": "NOT_OBSERVED_IN_BOUNDED_BODY",
            "setter_vma": "0x7eda84",
            "verification": "PRIMARY_ELF_VERIFIED for absence scope; add-path ownership remains separate",
        },
        "vptr_initialization": {
            "store_vma": hex(int(profile["vptr_store"][0])),
            "verification": "PRIMARY_ELF_VERIFIED",
        },
        "address_space": "ELF_VMA",
    }


def _clone(fp: Any, elf: ELFFile, profile: dict[str, Any], allocator_binding: dict[str, Any]) -> dict[str, Any]:
    entry, size = profile["clone"]
    rows = _decode(fp, elf, entry, size)
    _require(rows, entry, "push")
    _require(rows, entry + 6, "movs", immediate=int(profile["allocation_size"]))
    _require(rows, entry + 8, "blx", target=ALLOCATOR_PLT)
    _require(rows, int(profile["clone_load"][0]), str(profile["clone_load"][1]), operands=str(profile["clone_load"][2]))
    _require(rows, int(profile["clone_call"][0]), str(profile["clone_call"][1]), target=int(profile["clone_call"][2]))
    if any(re.search(r"\[[^\]]+,\s*#8\]", row.op_str.lower()) for row in rows.values()):
        raise ValueError(f"{profile['name']} clone unexpectedly reads key")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "entry_vma": hex(entry),
        "allocation_size_bytes": int(profile["allocation_size"]),
        "allocator": allocator_binding,
        "source_payload_load": {
            "load_vma": hex(int(profile["clone_load"][0])),
            "offset": hex(PAYLOAD_OFFSET),
            "verification": "PRIMARY_ELF_VERIFIED",
        },
        "constructor_call": hex(int(profile["clone_call"][2])),
        "key_copy": "NOT_OBSERVED_IN_BOUNDED_BODY",
        "return_semantics": "destination-shaped value remains in r0; source-level clone return type UNKNOWN",
    }


def _destructors(
    fp: Any, elf: ELFFile, profile: dict[str, Any], delete_binding: dict[str, Any],
) -> dict[str, Any]:
    d1_entry, d1_size = profile["destructor"]
    d1_rows = _decode(fp, elf, d1_entry, d1_size)
    _require(d1_rows, d1_entry + 0x10, "str", operands="r3, [r0]")
    _require(d1_rows, int(profile["destructor_base_call"][0]), "bl", target=BASE_DESTRUCTOR_ENTRY)
    if any(re.search(r"\[[^\]]+,\s*#0xc\]", row.op_str.lower()) for row in d1_rows.values()):
        raise ValueError(f"{profile['name']} scalar destructor unexpectedly releases payload")
    d0_entry, d0_size = profile["deleting_destructor"]
    d0_rows = _decode(fp, elf, d0_entry, d0_size)
    _require(d0_rows, int(profile["deleting_call"][0]), str(profile["deleting_call"][1]), target=int(profile["deleting_call"][2]))
    _require(d0_rows, d0_entry + 0x0C, "blx", target=DELETE_OBJECT_PLT)
    d1_binding: dict[str, Any] | None = None
    plt = profile.get("deleting_call_plt")
    symbol = profile.get("deleting_call_symbol")
    if plt is not None and symbol is not None:
        d1_binding = _binding(fp, elf, int(plt), str(symbol))
    return {
        "nondeleting": {
            "status": "PRIMARY_ELF_VERIFIED",
            "entry_vma": hex(d1_entry),
            "base_destructor_call": hex(BASE_DESTRUCTOR_ENTRY),
            "payload_release": "NONE_OBSERVED; scalar is inline",
        },
        "deleting": {
            "status": "PRIMARY_ELF_VERIFIED",
            "entry_vma": hex(d0_entry),
            "nondeleting_dispatch": d1_binding or {"target_vma": hex(int(profile["deleting_call"][2]))},
            "object_delete": delete_binding,
        },
    }


def _setter(fp: Any, elf: ELFFile, profile: dict[str, Any], symbols: dict[str, tuple[int, int]]) -> dict[str, Any]:
    symbol = str(profile["setter_symbol"])
    row = symbols.get(symbol)
    entry, size = profile["setter"]
    if row is None or (row[0] & ~1) != entry:
        raise ValueError(f"{profile['name']} setter symbol mismatch")
    rows = _decode(fp, elf, entry, size)
    _require(rows, int(profile["setter_store"][0]), str(profile["setter_store"][1]), operands=str(profile["setter_store"][2]))
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "symbol": symbol,
        "entry_vma": hex(entry),
        "payload_store": hex(int(profile["setter_store"][0])),
        "payload_offset": hex(PAYLOAD_OFFSET),
        "type_candidate": profile["payload_kind"],
        "key_untouched_in_bounded_body": True,
    }


def probe_param_scalars(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Verify the bounded scalar-family evidence from the private ELF."""
    path = Path(elf_path).resolve()
    if not path.is_file() or path.stat().st_size > MAX_ELF_BYTES:
        raise ValueError("private ELF missing or exceeds analysis limit")
    if not HEX_SHA.fullmatch(expected_sha256):
        raise ValueError("expected_sha256 must be a lowercase full SHA-256 digest")
    digest = _sha256(path)
    if digest != expected_sha256:
        raise ValueError("full-file ELF SHA-256 mismatch; refusing to decode")
    with path.open("rb") as fp:
        elf = ELFFile(fp)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_ARM":
            raise ValueError("probe accepts only ELF32 little-endian ARM")
        symbols = _symbols(elf)
        relocations = _relocations(elf)
        bindings = {
            "param_base_constructor": _binding(fp, elf, PARAM_BASE_CONSTRUCTOR_PLT, "_ZN9ParamBaseC2Em"),
            "allocator": _binding(fp, elf, ALLOCATOR_PLT, "_Znwj"),
            "delete_object": _binding(fp, elf, DELETE_OBJECT_PLT, "_ZdlPv"),
        }
        records: list[dict[str, Any]] = []
        for profile in SCALAR_PROFILES:
            records.append({
                "name": profile["name"],
                "verification": "PRIMARY_ELF_VERIFIED",
                "rtti_vma": hex(int(profile["rtti_vma"])),
                "vtable": _vtable(elf, relocations, profile),
                "constructor": _constructor(fp, elf, profile, bindings["param_base_constructor"]),
                "clone": _clone(fp, elf, profile, bindings["allocator"]),
                "destructors": _destructors(fp, elf, profile, bindings["delete_object"]),
                "setter": _setter(fp, elf, profile, symbols),
                "discriminator": int(profile["discriminator"]),
                "payload": {
                    "offset": hex(PAYLOAD_OFFSET),
                    "width": profile["payload_width"],
                    "type_candidate": profile["payload_kind"],
                    "type_verification": "PRIMARY_ELF_VERIFIED for width/source; semantic domain remains STATIC_INFERRED",
                },
                "key": {
                    "offset": hex(KEY_OFFSET),
                    "constructor": "NOT_WRITTEN_IN_BOUNDED_BODY",
                    "clone": "NOT_COPIED_IN_BOUNDED_BODY",
                    "insertion_witness": "ParamList::add -> 0x7eda84",
                    "verification": "PRIMARY_ELF_VERIFIED for bounded absence/witness",
                },
                "address_space": "ELF_VMA",
                "runtime_verified": False,
                "callable": False,
            })
    return {
        "schema_version": 1,
        "firmware_version": "3.21",
        "status": "LOCAL_PRIMARY_ELF_PARAM_SCALAR_LIFECYCLE_EVIDENCE_ONLY",
        "binary_file_sha256": digest,
        "address_space": "ELF_VMA",
        "abi": "ARM AAPCS32, Thumb, little endian",
        "bindings": bindings,
        "types": records,
        "key_assignment": {
            "offset": hex(KEY_OFFSET),
            "setter_vma": "0x7eda84",
            "scope": "ParamList insertion path; not a constructor action",
            "runtime_owner": "UNKNOWN",
        },
        "raw_instruction_bytes_published": False,
        "runtime_verified": False,
        "callable": False,
        "limitations": [
            "The probe proves bounded instruction/data-flow facts, not a complete C++ type system",
            "ParamList owner, allocator interposition, exceptions, locking and runtime loader behavior remain UNKNOWN",
            "Bool semantic truth representation beyond the stored byte and Number domain/range remain UNKNOWN",
            "No firmware code is executed and no live camera object is accessed",
        ],
    }


def validate_param_scalars(report: dict[str, Any]) -> dict[str, Any]:
    """Fail closed on identity, lifecycle evidence and unsafe promotion."""
    errors: list[str] = []
    if report.get("binary_file_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != "ELF_VMA":
        errors.append("address_space")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    types = report.get("types")
    if not isinstance(types, list):
        errors.append("missing_types")
        types = []
    names = {item.get("name") for item in types if isinstance(item, dict)}
    for profile in SCALAR_PROFILES:
        name = str(profile["name"])
        if name not in names:
            errors.append(f"missing:{name}")
    for item in types:
        if not isinstance(item, dict):
            errors.append("invalid:type")
            continue
        name = item.get("name", "unknown")
        if item.get("verification") != "PRIMARY_ELF_VERIFIED":
            errors.append(f"verification:{name}")
        if item.get("address_space") != "ELF_VMA":
            errors.append(f"address_space:{name}")
        if item.get("vtable", {}).get("status") != "PRIMARY_ELF_VERIFIED":
            errors.append(f"vtable:{name}")
        if item.get("constructor", {}).get("status") != "PRIMARY_ELF_VERIFIED":
            errors.append(f"constructor:{name}")
        if item.get("clone", {}).get("status") != "PRIMARY_ELF_VERIFIED":
            errors.append(f"clone:{name}")
        for phase in ("nondeleting", "deleting"):
            if item.get("destructors", {}).get(phase, {}).get("status") != "PRIMARY_ELF_VERIFIED":
                errors.append(f"destructor:{name}:{phase}")
        if item.get("setter", {}).get("status") != "PRIMARY_ELF_VERIFIED":
            errors.append(f"setter:{name}")
        if item.get("key", {}).get("constructor") != "NOT_WRITTEN_IN_BOUNDED_BODY":
            errors.append(f"key_constructor_scope:{name}")
        if item.get("key", {}).get("clone") != "NOT_COPIED_IN_BOUNDED_BODY":
            errors.append(f"key_clone_scope:{name}")
        if item.get("runtime_verified") is not False or item.get("callable") is not False:
            errors.append(f"unsafe:{name}")
    return {"valid": not errors, "errors": sorted(set(errors)), "type_count": len(types)}
