"""Primary-ELF evidence for ``ParamList::add`` replacement semantics.

The lookup and destruction probes establish that a returned parameter pointer
is borrowed.  This module fills the adjacent mutation gap: it reads bounded
Thumb bodies from the SHA-pinned private ``libObj.so`` and records how an add
operation writes the key, appends a non-null object, and replaces an existing
object with the same key/discriminator.  It deliberately does not expose
firmware bytes or provide a callable wrapper.

The replacement body is unnamed in the stripped ELF.  Its source-level C++
identity and allocator/locking contract therefore remain unknown even though
the instruction-level branch facts are primary-ELF verified.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from capstone.arm import ARM_OP_IMM
from elftools.elf.elffile import ELFFile

from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA


ADD_ENTRY = 0x7EE0E6
ADD_SIZE = 0x30
ADD_SYMBOL = "_ZN9ParamList3addEmP9ParamBase"
REPLACE_ENTRY = 0x7EDEDA
REPLACE_SIZE = 0x90
KEY_SETTER_ENTRY = 0x7EDA84
KEY_SETTER_SIZE = 8
KEY_GETTER_ENTRY = 0x7EDA94
DISCRIMINATOR_GETTER_ENTRY = 0x7EDA8C
REMOVE_ENTRY = 0x7EDE7A
REMOVE_SIZE = 0x60
STORAGE_APPEND_ENTRY = 0x7EE0B8
STORAGE_APPEND_SIZE = 0x2E
MAX_READ_BYTES = 0x200


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_exec_range(stream: Any, elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > MAX_READ_BYTES:
        raise ValueError("ParamList add read exceeds bounded probe limit")
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


def _decode(stream: Any, elf: ELFFile, start: int, size: int) -> dict[int, Any]:
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    rows = list(decoder.disasm(_read_exec_range(stream, elf, start, size), start))
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


def _immediates(instruction: Any) -> list[int]:
    return [int(operand.imm) for operand in instruction.operands if operand.type == ARM_OP_IMM]


def _require(
    rows: dict[int, Any], address: int, mnemonic: str, *,
    operands: str | None = None, target: int | None = None,
) -> Any:
    instruction = rows.get(address)
    if instruction is None or instruction.mnemonic.lower() != mnemonic.lower():
        raise ValueError(f"unexpected {mnemonic} at 0x{address:x}")
    if operands is not None and instruction.op_str.lower() != operands.lower():
        raise ValueError(f"unexpected operands at 0x{address:x}")
    if target is not None and target not in _immediates(instruction):
        raise ValueError(f"unexpected branch target at 0x{address:x}")
    return instruction


def _observe_key_setter(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, KEY_SETTER_ENTRY, "push")
    _require(rows, KEY_SETTER_ENTRY + 2, "add")
    _require(rows, KEY_SETTER_ENTRY + 4, "str", operands="r1, [r0, #8]")
    _require(rows, KEY_SETTER_ENTRY + 6, "pop")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "receiver": "ParamBase-derived object candidate in r0",
        "input": "key word in r1",
        "effect": "stores r1 at object +0x08",
        "address_space": "ELF_VMA",
    }


def _observe_add(rows: dict[int, Any]) -> dict[str, Any]:
    checks = (
        (ADD_ENTRY, "push", None),
        (0x7EE0EC, "mov", None),
        (0x7EE0EE, "mov", None),
        (0x7EE0F0, "str", None),
        (0x7EE0F2, "bl", REPLACE_ENTRY),
        (0x7EE0F6, "cbz", 0x7EE10E),
        (0x7EE0FC, "mov", None),
        (0x7EE0FE, "ldr", None),
        (0x7EE102, "bl", KEY_SETTER_ENTRY),
        (0x7EE106, "ldr", None),
        (0x7EE108, "mov", None),
        (0x7EE10A, "bl", STORAGE_APPEND_ENTRY),
        (0x7EE114, "pop", None),
    )
    for address, mnemonic, target in checks:
        _require(rows, address, mnemonic, target=target)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "registers": {
            "r0": "ParamList receiver",
            "r1": "key forwarded to replacement and ParamBase key setter",
            "r2": "ParamBase-derived object pointer saved in the local frame",
            "r3": "no semantic use in the bounded body",
        },
        "replacement_call": hex(REPLACE_ENTRY),
        "null_or_rejected_path": "zero result from replacement branches directly to return without key write or append",
        "key_initialization": "nonzero replacement result calls the key setter, writing +0x08 before append",
        "payload_behavior": "no write to the incoming object's +0x0c payload occurs in this body",
        "append_call": hex(STORAGE_APPEND_ENTRY),
        "return": "machine-level status is not a declared C++ return type; local body leaves status semantics UNKNOWN",
        "address_space": "ELF_VMA",
    }


def _observe_replacement(rows: dict[int, Any]) -> dict[str, Any]:
    checks = (
        (0x7EDEE8, "cmp", None),
        (0x7EDEEA, "beq", 0x7EDF5A),
        (0x7EDEEC, "ldr", None),
        (0x7EDEEE, "bl", 0x7EDBAA),
        (0x7EDEF4, "ldr", None),
        (0x7EDEF6, "bl", 0x7EDB92),
        (0x7EDF00, "bl", 0x7EDB16),
        (0x7EDF04, "ldr.w", None),
        (0x7EDF08, "cmp", None),
        (0x7EDF0A, "beq", 0x7EDF5E),
        (0x7EDF0E, "bl", KEY_GETTER_ENTRY),
        (0x7EDF14, "bne", 0x7EDF44),
        (0x7EDF18, "bl", DISCRIMINATOR_GETTER_ENTRY),
        (0x7EDF26, "bne", 0x7EDF44),
        (0x7EDF28, "cmp.w", None),
        (0x7EDF2C, "beq", 0x7EDF38),
        (0x7EDF2E, "ldr.w", None),
        (0x7EDF32, "mov", None),
        (0x7EDF34, "ldr", None),
        (0x7EDF36, "blx", None),
        (0x7EDF3C, "bl", REMOVE_ENTRY),
        (0x7EDF40, "movs", None),
        (0x7EDF5A, "mov", None),
        (0x7EDF5E, "movs", None),
        (0x7EDF66, "pop.w", None),
    )
    for address, mnemonic, target in checks:
        _require(rows, address, mnemonic, target=target)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "identity": "unnamed replacement helper; source-level C++ name UNKNOWN",
        "null_new_object": "r2 == 0 returns zero before container traversal",
        "same_object": "existing element pointer equal to incoming pointer returns zero without deletion",
        "match_predicate": "existing element key (+0x08) equals requested key and discriminator (+0x04) equals incoming discriminator",
        "match_effect": "invokes existing element vtable slot +8, removes one pointer slot, then returns nonzero",
        "nonmatch_effect": "advances through the begin/end pointer range and leaves source-level status semantics UNKNOWN",
        "null_element_safety": "no guard before key/discriminator field reads; a later null check occurs only before virtual deletion",
        "borrowed_pointer_effect": "matching replacement destroys the prior element before removing its slot; an earlier get result can become invalid",
        "locking": "no lock or atomic operation observed in this bounded body; thread safety UNKNOWN",
        "address_space": "ELF_VMA",
    }


def _observe_remove(rows: dict[int, Any]) -> dict[str, Any]:
    checks = (
        (0x7EDE84, "str", None),
        (0x7EDE8E, "bl", 0x7EDBE6),
        (0x7EDE96, "bl", 0x7EDB92),
        (0x7EDEA4, "bl", 0x7EDBC8),
        (0x7EDECA, "ldr", None),
        (0x7EDECE, "subs", None),
        (0x7EDED0, "str", None),
        (0x7EDED8, "pop", None),
    )
    for address, mnemonic, target in checks:
        _require(rows, address, mnemonic, target=target)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "effect": "rebuilds the selected pointer range and decrements the container end pointer by four bytes",
        "removed_element_width_bytes": 4,
        "source_element_destructor": "not called by this slot-removal body; caller performs virtual deletion first",
        "address_space": "ELF_VMA",
    }


def _observe_storage_append(rows: dict[int, Any]) -> dict[str, Any]:
    checks = (
        (STORAGE_APPEND_ENTRY, "push", None),
        (STORAGE_APPEND_ENTRY + 2, "mov", None),
        (STORAGE_APPEND_ENTRY + 4, "ldr", None),
        (STORAGE_APPEND_ENTRY + 6, "add", None),
        (STORAGE_APPEND_ENTRY + 8, "ldr", None),
        (STORAGE_APPEND_ENTRY + 0x0A, "mov", None),
        (STORAGE_APPEND_ENTRY + 0x0C, "cmp", None),
        (STORAGE_APPEND_ENTRY + 0x0E, "beq", 0x7EE0D6),
        (STORAGE_APPEND_ENTRY + 0x10, "mov", None),
        (STORAGE_APPEND_ENTRY + 0x12, "bl", 0x7EDC08),
        (STORAGE_APPEND_ENTRY + 0x16, "ldr", None),
        (STORAGE_APPEND_ENTRY + 0x18, "adds", None),
        (STORAGE_APPEND_ENTRY + 0x1A, "str", None),
        (STORAGE_APPEND_ENTRY + 0x1C, "pop", None),
        (STORAGE_APPEND_ENTRY + 0x28, "bl", 0x7EDFF4),
        (STORAGE_APPEND_ENTRY + 0x2C, "pop", None),
    )
    for address, mnemonic, target in checks:
        _require(rows, address, mnemonic, target=target)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "input": "container pointer in r0 and pointer-to-element slot in r1",
        "capacity": "reads container begin/end/capacity words at +0/+4/+8",
        "append": "non-full path copies one pointer and advances end by four bytes",
        "growth": "full path delegates replacement storage to local growth/rebuild helper",
        "allocator_and_exception_behavior": "UNKNOWN",
        "address_space": "ELF_VMA",
    }


def probe_paramlist_add(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Read bounded add/replacement witnesses from the authenticated ELF."""
    path = Path(elf_path).resolve()
    if not path.is_file():
        raise ValueError("private ELF is missing")
    if not isinstance(expected_sha256, str) or not HEX_SHA.fullmatch(expected_sha256):
        raise ValueError("expected_sha256 must be a lowercase full SHA-256 digest")
    digest = _sha256(path)
    if digest != expected_sha256:
        raise ValueError("full-file ELF SHA-256 mismatch; refusing to decode")
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_ARM":
            raise ValueError("probe accepts ELF32 little-endian ARM")
        symbols = _symbols(elf)
        value, size = symbols.get(ADD_SYMBOL, (0, 0))
        if (value & ~1) != ADD_ENTRY or size != ADD_SIZE:
            raise ValueError("ParamList::add symbol identity/size mismatch")
        observations = {
            "key_setter": _observe_key_setter(_decode(stream, elf, KEY_SETTER_ENTRY, KEY_SETTER_SIZE)),
            "add": _observe_add(_decode(stream, elf, ADD_ENTRY, ADD_SIZE)),
            "replacement": _observe_replacement(_decode(stream, elf, REPLACE_ENTRY, REPLACE_SIZE)),
            "remove_slot": _observe_remove(_decode(stream, elf, REMOVE_ENTRY, REMOVE_SIZE)),
            "storage_append": _observe_storage_append(
                _decode(stream, elf, STORAGE_APPEND_ENTRY, STORAGE_APPEND_SIZE)
            ),
        }
    return {
        "schema_version": 1,
        "status": "LOCAL_PRIMARY_ELF_PARAMLIST_ADD_EVIDENCE_ONLY",
        "binary_file_sha256": digest,
        "address_space": "ELF_VMA",
        "abi": "ARM AAPCS32, Thumb, little endian; C++ return type and runtime ABI UNKNOWN",
        "targets": {
            "paramlist_add": {"entry_vma": hex(ADD_ENTRY), "size_bytes": ADD_SIZE, "symbol": ADD_SYMBOL},
            "replacement_candidate": {"entry_vma": hex(REPLACE_ENTRY), "size_bytes": REPLACE_SIZE},
            "key_setter": {"entry_vma": hex(KEY_SETTER_ENTRY), "size_bytes": KEY_SETTER_SIZE},
            "remove_slot": {"entry_vma": hex(REMOVE_ENTRY), "size_bytes": REMOVE_SIZE},
            "storage_append": {"entry_vma": hex(STORAGE_APPEND_ENTRY), "size_bytes": STORAGE_APPEND_SIZE},
        },
        "observations": observations,
        "lifetime": {
            "replacement_invalidates_previous_element": "STATIC_INFERRED from primary deletion-before-removal sequence",
            "new_element_key_initialized": "PRIMARY_ELF_VERIFIED through 0x7eda84 before append",
            "payload_plus_0c_written_by_add": False,
            "container_ownership_transfer": "UNKNOWN",
            "concurrency_verified": False,
            "exception_paths_verified": False,
        },
        "runtime_verified": False,
        "callable": False,
        "limitations": [
            "Replacement helper has no source-level C++ symbol in the stripped ELF",
            "The primary facts do not prove ParamList ownership transfer or allocator pairing",
            "No lock/atomic operation or runtime inter-thread behavior was observed",
            "A later null check is not a null-safe guarantee because key/discriminator reads precede it",
            "No firmware code was executed and no device was accessed",
        ],
    }


def validate_paramlist_add(report: dict[str, Any]) -> dict[str, Any]:
    """Fail closed on identity and unsafe status promotion."""
    errors: list[str] = []
    if report.get("schema_version") != 1:
        errors.append("schema_version")
    if report.get("binary_file_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != "ELF_VMA":
        errors.append("address_space")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    observations = report.get("observations")
    required = {"key_setter", "add", "replacement", "remove_slot", "storage_append"}
    if not isinstance(observations, dict) or not required.issubset(observations):
        errors.append("missing_observations")
    else:
        for name in required:
            if observations[name].get("status") != "PRIMARY_ELF_VERIFIED":
                errors.append(f"observation_status:{name}")
        if observations["add"].get("payload_behavior") != (
            "no write to the incoming object's +0x0c payload occurs in this body"
        ):
            errors.append("payload_scope")
        if observations["replacement"].get("locking") != (
            "no lock or atomic operation observed in this bounded body; thread safety UNKNOWN"
        ):
            errors.append("thread_safety_scope")
    lifetime = report.get("lifetime")
    if not isinstance(lifetime, dict) or lifetime.get("concurrency_verified") is not False:
        errors.append("concurrency_claim")
    return {
        "valid": not errors,
        "errors": sorted(set(errors)),
        "observation_count": len(observations) if isinstance(observations, dict) else 0,
    }
