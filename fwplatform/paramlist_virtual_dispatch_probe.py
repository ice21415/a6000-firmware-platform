"""Evidence-gated ParamList virtual element-destruction dispatch audit.

The probe authenticates the private A6000 3.21 libObj.so before reading
the ParamList clear loop and the ten known ParamBase-derived vtable groups.
It records the direct Thumb load/call sequence and resolves only file-backed
vtable words or unique ELF relocations. It does not execute firmware, infer
runtime dynamic types, or expose a destructor wrapper.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

from .param_family_probe import PARAM_FAMILY_TARGETS, _read_bytes, _symbols
from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA, MAX_ELF_BYTES


ADDRESS_SPACE = "ELF_VMA"
BASE_RTTI_VMA = 0xFE6E24
CLEAR_HELPER_VMA = 0x7EDB40
CLEAR_HELPER_SIZE = 0x36
VTABLE_PREFIX_SIZE = 0x08
CLONE_SLOT_FROM_PREFIX = 0x08
NONDELETING_DESTRUCTOR_SLOT_FROM_PREFIX = 0x0C
DELETING_DESTRUCTOR_SLOT_FROM_PREFIX = 0x10
VIRTUAL_SLOT_FROM_OBJECT_VPTR = 0x08


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _relocations(elf: ELFFile) -> dict[int, dict[str, Any]]:
    result: dict[int, dict[str, Any]] = {}
    for section in elf.iter_sections():
        if not isinstance(section, RelocationSection):
            continue
        symbols = elf.get_section(section["sh_link"])
        for relocation in section.iter_relocations():
            symbol = symbols.get_symbol(relocation["r_info_sym"])
            candidate = {
                "symbol": symbol.name or None,
                "symbol_value": int(symbol["st_value"]),
                "relocation_type": int(relocation["r_info_type"]),
                "section": section.name,
            }
            offset = int(relocation["r_offset"])
            previous = result.get(offset)
            if previous is None or (
                not previous.get("symbol") and candidate.get("symbol")
            ):
                result[offset] = candidate
    return result


def _read_u32(elf: ELFFile, address: int) -> int:
    data = _read_bytes(elf, address, 4)
    if len(data) != 4:
        raise ValueError(f"truncated word at ELF_VMA 0x{address:x}")
    return struct.unpack("<I", data)[0]


def _effective_word(
    elf: ELFFile, relocations: dict[int, dict[str, Any]], address: int,
) -> tuple[int, str]:
    value = _read_u32(elf, address)
    if value:
        return value, "ELF_DATA_WORD"
    relocation = relocations.get(address)
    if relocation and int(relocation.get("symbol_value", 0)):
        return int(relocation["symbol_value"]), "ELF_RELOCATION"
    if relocation:
        return 0, "ELF_RELOCATION_UNRESOLVED_VALUE"
    return 0, "ELF_DATA_ZERO"


def _normalize_target(value: int) -> int:
    return value & ~1


def _vtable_vma(
    spec: dict[str, Any], symbols: dict[str, tuple[int, int]],
) -> tuple[int, str]:
    if spec.get("vtable_vma") is not None:
        return int(spec["vtable_vma"]), "family_profile"
    symbol_name = spec.get("vtable_symbol")
    if not symbol_name:
        raise ValueError(f"missing vtable identity for {spec.get('name')}")
    symbol = symbols.get(symbol_name)
    if symbol is None:
        raise ValueError(f"missing vtable symbol {symbol_name}")
    return symbol[0] & ~1, f"ELF_SYMBOL:{symbol_name}"


def _decode_clear(elf: ELFFile) -> dict[str, Any]:
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    rows = list(decoder.disasm(_read_bytes(elf, CLEAR_HELPER_VMA, CLEAR_HELPER_SIZE), CLEAR_HELPER_VMA))
    by_address = {int(row.address): row for row in rows}
    expected = {
        CLEAR_HELPER_VMA + 0x20: ("ldr", "r3, [r0]"),
        CLEAR_HELPER_VMA + 0x22: ("ldr", "r3, [r3, #8]"),
        CLEAR_HELPER_VMA + 0x24: ("blx", "r3"),
    }
    observations: list[dict[str, Any]] = []
    for address, (mnemonic, operands) in expected.items():
        row = by_address.get(address)
        if row is None or row.mnemonic.lower() != mnemonic or row.op_str.lower() != operands:
            raise ValueError(f"ParamList clear dispatch instruction mismatch at 0x{address:x}")
        observations.append({
            "instruction_vma": hex(address),
            "mnemonic": row.mnemonic.lower(),
            "operands": row.op_str,
            "status": "PRIMARY_ELF_VERIFIED",
        })
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "helper_vma": hex(CLEAR_HELPER_VMA),
        "bounded_extent_bytes": CLEAR_HELPER_SIZE,
        "address_space": ADDRESS_SPACE,
        "receiver_vptr_offset": 0,
        "virtual_slot_from_vptr": VIRTUAL_SLOT_FROM_OBJECT_VPTR,
        "virtual_call_target": "indirect; target is selected from the element vptr",
        "instructions": observations,
        "null_slot_guard": "the preceding cbz skips the call for a null element slot",
        "runtime_dynamic_type": "UNKNOWN",
    }


def _family_row(
    elf: ELFFile,
    relocations: dict[int, dict[str, Any]],
    symbols: dict[str, tuple[int, int]],
    spec: dict[str, Any],
) -> dict[str, Any]:
    name = str(spec["name"])
    vtable_vma, vtable_source = _vtable_vma(spec, symbols)
    offset_to_top, offset_source = _effective_word(elf, relocations, vtable_vma)
    rtti_vma, rtti_source = _effective_word(elf, relocations, vtable_vma + 4)
    if offset_to_top != 0:
        raise ValueError(f"{name} vtable offset-to-top is not zero")
    if rtti_vma == 0:
        raise ValueError(f"{name} vtable RTTI pointer is unresolved")
    base_word, base_source = _effective_word(elf, relocations, rtti_vma + 8)
    if base_word != BASE_RTTI_VMA:
        raise ValueError(f"{name} RTTI base relation mismatch")
    slots: list[dict[str, Any]] = []
    expected = (
        ("clone", CLONE_SLOT_FROM_PREFIX, int(spec["clone_entry"])),
        ("nondeleting_destructor", NONDELETING_DESTRUCTOR_SLOT_FROM_PREFIX, int(spec["destructor_entry"])),
        ("deleting_destructor", DELETING_DESTRUCTOR_SLOT_FROM_PREFIX, int(spec["deleting_destructor_entry"])),
    )
    for role, relative, expected_entry in expected:
        slot_address = vtable_vma + relative
        value, source = _effective_word(elf, relocations, slot_address)
        if _normalize_target(value) != _normalize_target(expected_entry):
            raise ValueError(
                f"{name} {role} slot mismatch: 0x{value:x} != 0x{expected_entry:x}"
            )
        relocation = relocations.get(slot_address)
        slots.append({
            "role": role,
            "slot_vma": hex(slot_address),
            "slot_offset_from_prefix": relative,
            "slot_offset_from_object_vptr": relative - VTABLE_PREFIX_SIZE,
            "target_vma": hex(_normalize_target(value)),
            "thumb_tag_observed": bool(value & 1),
            "source": source,
            "relocation_symbol": relocation.get("symbol") if relocation else None,
            "status": "PRIMARY_ELF_VERIFIED",
        })
    return {
        "name": name,
        "discriminator": int(spec["discriminator"]),
        "vtable_prefix_vma": hex(vtable_vma),
        "object_vptr_address_point": hex(vtable_vma + VTABLE_PREFIX_SIZE),
        "vtable_source": vtable_source,
        "offset_to_top": offset_to_top,
        "offset_to_top_source": offset_source,
        "rtti_vma": hex(rtti_vma),
        "rtti_source": rtti_source,
        "base_rtti_vma": hex(base_word),
        "base_rtti_source": base_source,
        "slots": slots,
        "clear_dispatch_target_role": "deleting_destructor",
        "dispatch_relation_status": "PRIMARY_ELF_VERIFIED",
        "semantic_scope": (
            "The exact vtable words and clear-loop slot arithmetic are verified "
            "for these records; runtime dynamic type, object validity and "
            "ownership remain UNKNOWN"
        ),
    }


def probe_paramlist_virtual_dispatch(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Resolve the known ParamList clear-loop vptr+0x08 slot set."""
    path = Path(elf_path).resolve()
    if not path.is_file() or path.stat().st_size > MAX_ELF_BYTES:
        raise ValueError("private ELF missing or exceeds analysis limit")
    if not HEX_SHA.fullmatch(expected_sha256):
        raise ValueError("expected_sha256 must be a lowercase full SHA-256 digest")
    digest = _sha256(path)
    if digest != expected_sha256:
        raise ValueError("full-file ELF SHA-256 mismatch; refusing analysis")
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_ARM":
            raise ValueError("expected ELF32 little-endian ARM")
        relocations = _relocations(elf)
        symbols = _symbols(elf)
        clear = _decode_clear(elf)
        families = [
            _family_row(elf, relocations, symbols, dict(spec))
            for spec in PARAM_FAMILY_TARGETS
        ]
    return {
        "schema_version": 1,
        "status": "LOCAL_PRIMARY_ELF_PARAMLIST_VIRTUAL_DISPATCH_AUDIT",
        "firmware_version": "3.21",
        "binary_sha256": digest,
        "address_space": ADDRESS_SPACE,
        "abi": "ARM AAPCS32, Thumb, little endian",
        "clear_dispatch": clear,
        "families": families,
        "aggregate": {
            "family_count": len(families),
            "exact_clone_slot_matches": sum(
                row["slots"][0]["status"] == "PRIMARY_ELF_VERIFIED"
                for row in families
            ),
            "exact_nondeleting_slot_matches": sum(
                row["slots"][1]["status"] == "PRIMARY_ELF_VERIFIED"
                for row in families
            ),
            "exact_deleting_slot_matches": sum(
                row["slots"][2]["status"] == "PRIMARY_ELF_VERIFIED"
                for row in families
            ),
            "families_reachable_by_clear_slot": sum(
                row["clear_dispatch_target_role"] == "deleting_destructor"
                for row in families
            ),
        },
        "lifetime_boundary": {
            "clear_operation": (
                "For a non-null element slot, the helper loads the element "
                "vptr at +0x00 and calls the vtable slot at vptr +0x08"
            ),
            "known_slot_resolution": (
                "For the ten verified ParamBase-family vtable records, "
                "vptr +0x08 is the deleting-destructor slot"
            ),
            "dynamic_type_selection": "UNKNOWN",
            "ownership_semantics": "STATIC_INFERRED at most; clear-side deletion does not prove allocation provenance",
            "verification": "PRIMARY_ELF_VERIFIED",
        },
        "runtime_verified": False,
        "callable": False,
        "limitations": [
            "The vtable set covers the ten known direct ParamBase families, not every possible element class",
            "Indirect dispatch is resolved only for exact file-backed vtable records and unique relocations",
            "No runtime dynamic-type, allocation-provenance, double-destroy, locking or concurrent-safety behavior is inferred",
            "The clear helper's surrounding caller synchronization and exception semantics remain UNKNOWN",
            "No firmware code is executed and no camera is accessed",
        ],
    }


def validate_paramlist_virtual_dispatch(report: dict[str, Any]) -> dict[str, Any]:
    """Fail closed on the clear-site and exact vtable-slot mapping."""
    errors: list[str] = []
    if report.get("schema_version") != 1:
        errors.append("schema_version")
    if report.get("status") != "LOCAL_PRIMARY_ELF_PARAMLIST_VIRTUAL_DISPATCH_AUDIT":
        errors.append("status")
    if report.get("binary_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != ADDRESS_SPACE:
        errors.append("address_space")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    clear = report.get("clear_dispatch", {})
    if clear.get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("clear_status")
    if clear.get("helper_vma") != hex(CLEAR_HELPER_VMA):
        errors.append("clear_helper")
    if clear.get("virtual_slot_from_vptr") != VIRTUAL_SLOT_FROM_OBJECT_VPTR:
        errors.append("clear_slot_offset")
    instructions = clear.get("instructions", [])
    expected = [(hex(CLEAR_HELPER_VMA + 0x20), "ldr"), (hex(CLEAR_HELPER_VMA + 0x22), "ldr"), (hex(CLEAR_HELPER_VMA + 0x24), "blx")]
    if [(row.get("instruction_vma"), row.get("mnemonic")) for row in instructions] != expected:
        errors.append("clear_instruction_sequence")
    families = report.get("families")
    if not isinstance(families, list) or len(families) != len(PARAM_FAMILY_TARGETS):
        errors.append("family_count")
        families = []
    expected_names = {str(spec["name"]) for spec in PARAM_FAMILY_TARGETS}
    if {row.get("name") for row in families} != expected_names:
        errors.append("family_identity")
    for row in families:
        name = row.get("name")
        if row.get("dispatch_relation_status") != "PRIMARY_ELF_VERIFIED":
            errors.append(f"dispatch_status:{name}")
        if row.get("base_rtti_vma") != hex(BASE_RTTI_VMA):
            errors.append(f"base_rtti:{name}")
        slots = row.get("slots", [])
        if len(slots) != 3:
            errors.append(f"slot_count:{name}")
            continue
        if [slot.get("role") for slot in slots] != ["clone", "nondeleting_destructor", "deleting_destructor"]:
            errors.append(f"slot_roles:{name}")
        if [slot.get("slot_offset_from_prefix") for slot in slots] != [8, 12, 16]:
            errors.append(f"slot_layout:{name}")
        if [slot.get("slot_offset_from_object_vptr") for slot in slots] != [0, 4, 8]:
            errors.append(f"object_slot_layout:{name}")
        try:
            prefix = int(row.get("vtable_prefix_vma", ""), 16)
            if row.get("object_vptr_address_point") != hex(prefix + VTABLE_PREFIX_SIZE):
                errors.append(f"vptr_address_point:{name}")
            if [slot.get("slot_vma") for slot in slots] != [
                hex(prefix + relative) for relative in (8, 12, 16)
            ]:
                errors.append(f"slot_addresses:{name}")
        except (TypeError, ValueError):
            errors.append(f"vtable_address:{name}")
        if any(slot.get("status") != "PRIMARY_ELF_VERIFIED" for slot in slots):
            errors.append(f"slot_status:{name}")
        if row.get("clear_dispatch_target_role") != "deleting_destructor":
            errors.append(f"clear_target:{name}")
    aggregate = report.get("aggregate", {})
    for key in (
        "family_count",
        "exact_clone_slot_matches",
        "exact_nondeleting_slot_matches",
        "exact_deleting_slot_matches",
        "families_reachable_by_clear_slot",
    ):
        if aggregate.get(key) != len(PARAM_FAMILY_TARGETS):
            errors.append(f"aggregate:{key}")
    ghidra = report.get("ghidra_crosscheck")
    if not isinstance(ghidra, dict):
        errors.append("missing_ghidra_crosscheck")
    else:
        if ghidra.get("status") != "VERIFIED_STATIC_METADATA_CROSSCHECK":
            errors.append("ghidra_status")
        if ghidra.get("tool") != "Ghidra" or ghidra.get("version") != "12.1.3":
            errors.append("ghidra_identity")
        if ghidra.get("profile") != "paramlist-virtual-dispatch-audit":
            errors.append("ghidra_profile")
        if ghidra.get("binary_sha256") != EXPECTED_LIBOBJ_SHA or ghidra.get("program_sha256") != EXPECTED_LIBOBJ_SHA:
            errors.append("ghidra_binary_identity")
        if ghidra.get("language") != "ARM:LE:32:v8" or ghidra.get("compiler_spec") != "default":
            errors.append("ghidra_abi_identity")
        if ghidra.get("image_base") != "0x10000" or ghidra.get("address_space") != "ram":
            errors.append("ghidra_address_identity")
        execution = ghidra.get("execution", {})
        if execution.get("exit_code") != 0 or execution.get("completion_marker") is not True:
            errors.append("ghidra_execution")
        if execution.get("auto_analysis_completed") is not False:
            errors.append("ghidra_auto_analysis_scope")
        if ghidra.get("raw_export_private") is not True or ghidra.get("semantic_names_verified") is not False:
            errors.append("ghidra_publication_scope")
        if ghidra.get("target_count") != 1:
            errors.append("ghidra_target_count")
        if not all(isinstance(ghidra.get(key), int) and ghidra[key] > 0 for key in ("instruction_count", "basic_block_count", "cfg_edge_count")):
            errors.append("ghidra_nonempty_counts")
        records = ghidra.get("target_records")
        if not isinstance(records, list) or len(records) != 1:
            errors.append("ghidra_target_records")
        else:
            record = records[0]
            if record.get("elf_vma") != hex(CLEAR_HELPER_VMA):
                errors.append("ghidra_target_elf_vma")
            if record.get("ghidra_address") != "0x007fdb40":
                errors.append("ghidra_target_address")
            if record.get("address_space") != "ram":
                errors.append("ghidra_target_address_space")
            if record.get("elf_address_space") != ADDRESS_SPACE:
                errors.append("ghidra_target_elf_address_space")
            if record.get("body_range_address_space") != "ram":
                errors.append("ghidra_target_body_range_address_space")
            ranges = record.get("body_ranges")
            if ranges != [{"start": "0x007fdb40", "end": "0x007fdb75"}]:
                errors.append("ghidra_target_body_ranges")
            for key in ("instruction_count", "basic_block_count", "cfg_edge_count"):
                if record.get(key) != ghidra.get(key):
                    errors.append(f"ghidra_target_{key}")
    return {"valid": not errors, "errors": sorted(set(errors))}
