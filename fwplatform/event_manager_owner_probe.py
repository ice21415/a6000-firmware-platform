"""Bounded primary-ELF witness for the owner field at ``+0x10``.

The private ``libObj.so`` body beginning at ``0x7ef254`` allocates a
``0x24``-byte object, passes the returned pointer to the local EventManager
layout initializer at ``0x7ef894``, and stores that pointer in the owner
receiver at ``+0x10``.  The owner function has no unique ELF symbol in the
available symbol tables, so this module deliberately reports a constructor-
like candidate rather than a confirmed C++ class or constructor name.

Only sanitized metadata is returned.  The private ELF is never executed and
no firmware bytes are emitted.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from capstone.arm import ARM_OP_IMM
from elftools.elf.elffile import ELFFile

from .elf_plt import resolve_plt_binding
from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA


TARGET = {
    "name": "event_manager_owner_initializer_candidate",
    "entry": 0x7EF254,
    "size": 0x88,
}
EVENT_INITIALIZER_ENTRY = 0x7EF894
ALLOCATOR_ENTRY = 0xDC100
OWNER_FIELD_OFFSET = 0x10
ADDRESS_SPACE = "ELF_VMA"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_exec_range(fp: Any, elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > 0x200:
        raise ValueError("owner initializer read exceeds bounded probe limit")
    offsets: list[int] = []
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD" or not (int(segment["p_flags"]) & 1):
            continue
        base = int(segment["p_vaddr"])
        count = int(segment["p_filesz"])
        if base <= start and start + size <= base + count:
            offsets.append(int(segment["p_offset"]) + start - base)
    if len(offsets) != 1:
        raise ValueError(f"ELF_VMA 0x{start:x} is not uniquely executable")
    fp.seek(offsets[0])
    data = fp.read(size)
    if len(data) != size:
        raise ValueError("truncated executable range")
    return data


def _decode_at(fp: Any, elf: ELFFile, entry: int, size: int) -> dict[int, Any]:
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    rows = list(decoder.disasm(_read_exec_range(fp, elf, entry, size), entry))
    if not rows:
        raise ValueError("owner initializer did not decode")
    return {int(row.address): row for row in rows}


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


def _binding(fp: Any, elf: ELFFile, entry: int) -> dict[str, Any]:
    result = resolve_plt_binding(fp, elf, entry, thumb_stub=False)
    if result.get("status") != "VERIFIED_STATIC":
        raise ValueError(f"PLT binding at 0x{entry:x} is not unique")
    return result


def _observe(rows: dict[int, Any], allocator_binding: dict[str, Any]) -> dict[str, Any]:
    """Verify the bounded allocation/initializer/store sequence."""
    _require(rows, 0x7EF254, "push.w")
    _require(rows, 0x7EF264, "mov", operands="r4, r0")
    _require(rows, 0x7EF2B4, "movs", immediate=0x24)
    _require(rows, 0x7EF2BA, "blx", target=ALLOCATOR_ENTRY)
    _require(rows, 0x7EF2C0, "ldr", operands="r2, [r4, #0x14]")
    _require(rows, 0x7EF2C2, "ldr.w", operands="r8, [r5, r3]")
    _require(rows, 0x7EF2C6, "mov", operands="r1, r8")
    _require(rows, 0x7EF2C8, "mov", operands="r6, r0")
    _require(rows, 0x7EF2CA, "bl", target=EVENT_INITIALIZER_ENTRY)
    _require(rows, 0x7EF2D4, "str", operands="r6, [r4, #0x10]")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "semantic_level": "STATIC_INFERRED",
        "function_identity": "UNKNOWN; no unique ELF symbol or source-level class identity",
        "bounded_scope": "0x7ef254..0x7ef2db; allocation/initializer/store witness only, not a complete function recovery",
        "abi": {
            "r0": "owner receiver candidate; preserved in r4 before the bounded sequence",
            "r1": "not part of the allocation call; r1=r8 before the local initializer",
            "r2": "owner +0x14 loaded before the local initializer",
            "r3": "used as the indexed base for the r8 load; source value UNKNOWN",
            "return": "not observed in the bounded region; source return type UNKNOWN",
        },
        "allocation": {
            "allocator_entry": "0xdc100",
            "allocator_symbol": "_Znwj",
            "allocator_binding": allocator_binding,
            "size_immediate": "0x24",
            "result_register": "r0",
            "preserved_register": "r6",
            "status": "PRIMARY_ELF_VERIFIED",
        },
        "initializer_call": {
            "entry": "0x7ef894",
            "callsite": "0x7ef2ca",
            "arguments": {
                "r0": "allocated pointer retained from _Znwj result",
                "r1": "r8 loaded from [r5 + r3]; exact source object UNKNOWN",
                "r2": "[owner + 0x14]",
            },
            "status": "PRIMARY_ELF_VERIFIED",
        },
        "owner_store": {
            "callsite": "0x7ef2d4",
            "field_offset": "+0x10",
            "value": "r6, the allocated and initializer-passed pointer",
            "status": "PRIMARY_ELF_VERIFIED",
        },
        "lifetime_pair": {
            "cleanup_callsite": "0x7ef432",
            "cleanup_entry": "0x7efa1e",
            "delete_callsite": "0x7ef438",
            "interpretation": "STATIC_INFERRED; matches the separately verified cleanup-then-_ZdlPv witness",
            "owner_type": "UNKNOWN",
        },
        "safety": {
            "allocation_failure": "UNKNOWN; no bounded null branch is asserted between _Znwj and the initializer call",
            "initializer_failure": "UNKNOWN; local initializer return/exception behavior is not used in the bounded store witness",
            "double_destroy": "UNKNOWN",
            "concurrency": "UNKNOWN",
            "runtime_loader_binding": "UNKNOWN",
        },
        "runtime_verified": False,
        "callable": False,
    }


def probe_event_manager_owner_init(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Validate the bounded owner-field construction witness."""
    path = Path(elf_path).resolve()
    if not path.is_file():
        raise ValueError("private ELF is missing")
    if not HEX_SHA.fullmatch(expected_sha256):
        raise ValueError("expected_sha256 must be a lowercase full SHA-256 digest")
    digest = _sha256(path)
    if digest != expected_sha256:
        raise ValueError("full-file ELF SHA-256 mismatch; refusing to decode")
    with path.open("rb") as fp:
        elf = ELFFile(fp)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_ARM":
            raise ValueError("probe accepts only ELF32 little-endian ARM")
        binding = _binding(fp, elf, ALLOCATOR_ENTRY)
        observation = _observe(_decode_at(fp, elf, TARGET["entry"], TARGET["size"]), binding)
    return {
        "schema_version": 1,
        "status": "LOCAL_PRIMARY_ELF_EVENT_MANAGER_OWNER_INIT_CANDIDATE",
        "firmware_version": "3.21",
        "binary_file_sha256": digest,
        "address_space": ADDRESS_SPACE,
        "target": TARGET,
        "event_initializer_entry": f"0x{EVENT_INITIALIZER_ENTRY:x}",
        "observation": observation,
        "runtime_verified": False,
        "callable": False,
    }


def validate_event_manager_owner_init(report: dict[str, Any]) -> dict[str, Any]:
    """Reject identity, provenance or safety promotion beyond the witness."""
    errors: list[str] = []
    if report.get("schema_version") != 1:
        errors.append("schema_version")
    if report.get("status") != "LOCAL_PRIMARY_ELF_EVENT_MANAGER_OWNER_INIT_CANDIDATE":
        errors.append("status")
    if report.get("firmware_version") != "3.21":
        errors.append("firmware_version")
    if report.get("binary_file_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != ADDRESS_SPACE:
        errors.append("address_space")
    if report.get("target", {}).get("entry") != TARGET["entry"]:
        errors.append("target_entry")
    if report.get("target", {}).get("size") != TARGET["size"]:
        errors.append("target_size")
    if report.get("event_initializer_entry") != "0x7ef894":
        errors.append("event_initializer_entry")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    observation = report.get("observation", {})
    if observation.get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("observation_status")
    if observation.get("semantic_level") != "STATIC_INFERRED":
        errors.append("semantic_level")
    if observation.get("function_identity") != "UNKNOWN; no unique ELF symbol or source-level class identity":
        errors.append("function_identity_scope")
    allocation = observation.get("allocation", {})
    if allocation.get("size_immediate") != "0x24":
        errors.append("allocation_size")
    if allocation.get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("allocation_status")
    binding = allocation.get("allocator_binding", {})
    candidates = binding.get("candidates", [])
    if binding.get("status") != "VERIFIED_STATIC" or len(candidates) != 1 or candidates[0].get("symbol") != "_Znwj":
        errors.append("allocator_binding")
    initializer = observation.get("initializer_call", {})
    if initializer.get("callsite") != "0x7ef2ca" or initializer.get("entry") != "0x7ef894":
        errors.append("initializer_call")
    if initializer.get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("initializer_status")
    owner_store = observation.get("owner_store", {})
    if owner_store.get("callsite") != "0x7ef2d4" or owner_store.get("field_offset") != "+0x10":
        errors.append("owner_store")
    if owner_store.get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("owner_store_status")
    lifetime = observation.get("lifetime_pair", {})
    if lifetime.get("interpretation") != "STATIC_INFERRED; matches the separately verified cleanup-then-_ZdlPv witness":
        errors.append("lifetime_scope")
    if lifetime.get("owner_type") != "UNKNOWN":
        errors.append("owner_type_scope")
    crosscheck = report.get("ghidra_crosscheck")
    if crosscheck is not None:
        if crosscheck.get("status") != "VERIFIED_STATIC":
            errors.append("ghidra_status")
        if crosscheck.get("version") != "12.1.3":
            errors.append("ghidra_version")
        if crosscheck.get("language") != "ARM:LE:32:v8":
            errors.append("ghidra_language")
        if crosscheck.get("compiler_spec") != "default":
            errors.append("ghidra_compiler_spec")
        if crosscheck.get("image_base") != "0x10000" or crosscheck.get("address_space") != "ram":
            errors.append("ghidra_address_space")
        if crosscheck.get("process_exit") != 0 or crosscheck.get("completion_marker") != "COMPLETE_TARGET_EXPORT":
            errors.append("ghidra_completion")
        if crosscheck.get("target_count") != 4:
            errors.append("ghidra_target_count")
        if crosscheck.get("instruction_count") != 157:
            errors.append("ghidra_instruction_count")
        if crosscheck.get("basic_block_count") != 20:
            errors.append("ghidra_basic_block_count")
        if crosscheck.get("cfg_edge_count") != 70:
            errors.append("ghidra_cfg_edge_count")
        if crosscheck.get("raw_export_private") is not True:
            errors.append("ghidra_visibility")
        if crosscheck.get("runtime_verified") is not False or crosscheck.get("callable") is not False:
            errors.append("ghidra_runtime_or_callable_claim")
        if crosscheck.get("semantic_names_verified") is not False:
            errors.append("ghidra_semantic_name_claim")
    return {"valid": not errors, "errors": sorted(set(errors))}
