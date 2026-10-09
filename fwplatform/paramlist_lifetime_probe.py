"""Evidence-gated ParamList construction, sharing and release probe.

This module verifies the small ParamList owner/lifetime region that surrounds
the already recovered lookup and insertion paths.  It records bounded ARM
Thumb instruction facts only; it does not expose firmware bytes, run the ELF,
or turn the observed shared-counter shape into a callable C++ wrapper.

The source-level identity of the shared rebind body at ``0x7edcc6`` is not
present in the public symbol table.  It is therefore reported as a candidate
with primary instruction evidence, while the exported constructor, ``clear``
and destructor retain their ELF symbol identity.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from capstone.arm import ARM_OP_IMM
from elftools.elf.elffile import ELFFile

from .elf_plt import resolve_plt_binding
from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA, MAX_ELF_BYTES


PARAMLIST_CONSTRUCTOR = 0x7EDC3E
PARAMLIST_CONSTRUCTOR_SIZE = 0x2A
PARAMLIST_CLEAR = 0x7EDB76
PARAMLIST_CLEAR_SIZE = 0x0C
CLEAR_HELPER = 0x7EDB40
CLEAR_HELPER_SIZE = 0x36
CONTAINER_INIT = 0x7EDC14
CONTAINER_INIT_SIZE = 0x0E
CONTAINER_INIT_WRAPPER = 0x7EDC22
CONTAINER_INIT_WRAPPER_SIZE = 0x0E
CONTAINER_INIT_FORWARDER = 0x7EDC30
CONTAINER_INIT_FORWARDER_SIZE = 0x0E
CONTAINER_RELEASE = 0x7EDCA2
CONTAINER_RELEASE_SIZE = 0x16
CONTAINER_RELEASE_WRAPPER = 0x7EDCB8
CONTAINER_RELEASE_WRAPPER_SIZE = 0x0E
SHARED_REBIND = 0x7EDCC6
SHARED_REBIND_SIZE = 0x42
PARAMLIST_DESTRUCTOR = 0x7EDD08
PARAMLIST_DESTRUCTOR_SIZE = 0x2E
ALLOCATOR_PLT = 0xDC100
OBJECT_DELETE_PLT = 0xDD620

CONTAINER_OFFSET = 0x00
COUNTER_OFFSET = 0x04
BEGIN_OFFSET = 0x00
END_OFFSET = 0x04
CAPACITY_OFFSET = 0x08


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_exec(stream: Any, elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > 0x200:
        raise ValueError("ParamList lifetime read exceeds bounded limit")
    matches: list[int] = []
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD" or not (int(segment["p_flags"]) & 1):
            continue
        base = int(segment["p_vaddr"])
        filesz = int(segment["p_filesz"])
        if base <= start and start + size <= base + filesz:
            matches.append(int(segment["p_offset"]) + start - base)
    if len(matches) != 1:
        raise ValueError(f"ELF_VMA 0x{start:x} is not uniquely executable")
    stream.seek(matches[0])
    data = stream.read(size)
    if len(data) != size:
        raise ValueError("truncated executable range")
    return data


def _decode(stream: Any, elf: ELFFile, start: int, size: int) -> dict[int, Any]:
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    rows = list(decoder.disasm(_read_exec(stream, elf, start, size), start))
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
    immediate: int | None = None,
) -> Any:
    instruction = rows.get(address)
    if instruction is None or instruction.mnemonic.lower() != mnemonic.lower():
        raise ValueError(f"unexpected {mnemonic} at 0x{address:x}")
    if operands is not None and instruction.op_str.lower() != operands.lower():
        raise ValueError(f"unexpected operands at 0x{address:x}")
    if target is not None and target not in _immediates(instruction):
        raise ValueError(f"unexpected target at 0x{address:x}")
    if immediate is not None and immediate not in _immediates(instruction):
        raise ValueError(f"unexpected immediate at 0x{address:x}")
    return instruction


def _binding(stream: Any, elf: ELFFile, entry: int, symbol: str) -> dict[str, Any]:
    result = resolve_plt_binding(stream, elf, entry, thumb_stub=False)
    candidates = result.get("candidates", [])
    if result.get("status") != "VERIFIED_STATIC" or len(candidates) != 1:
        raise ValueError(f"PLT binding at 0x{entry:x} is not unique")
    if candidates[0].get("symbol") != symbol:
        raise ValueError(f"unexpected PLT symbol at 0x{entry:x}")
    return result


def _symbol_identity(symbols: dict[str, tuple[int, int]], name: str, entry: int, size: int) -> dict[str, Any]:
    value, actual_size = symbols.get(name, (0, 0))
    if (value & ~1) != entry or actual_size != size:
        raise ValueError(f"symbol identity mismatch for {name}")
    return {
        "symbol": name,
        "entry_vma": hex(entry),
        "thumb_value": hex(value),
        "size_bytes": size,
        "address_space": "ELF_VMA",
        "status": "PRIMARY_ELF_VERIFIED",
    }


def _observe_container_init(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, CONTAINER_INIT, "movs", immediate=0)
    _require(rows, CONTAINER_INIT + 2, "str", operands="r2, [r0]")
    _require(rows, CONTAINER_INIT + 8, "str", operands="r2, [r0, #4]")
    _require(rows, CONTAINER_INIT + 0x0A, "str", operands="r2, [r0, #8]")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "container_offsets": {
            "begin": hex(BEGIN_OFFSET),
            "end": hex(END_OFFSET),
            "capacity": hex(CAPACITY_OFFSET),
        },
        "initial_value": 0,
        "source_level_container_type": "UNKNOWN",
    }


def _observe_constructor(
    rows: dict[int, Any], allocator: dict[str, Any], symbols: dict[str, tuple[int, int]],
) -> dict[str, Any]:
    symbol = _symbol_identity(symbols, "_ZN9ParamListC1Ev", PARAMLIST_CONSTRUCTOR, PARAMLIST_CONSTRUCTOR_SIZE)
    _require(rows, PARAMLIST_CONSTRUCTOR + 6, "movs", immediate=0x0C)
    _require(rows, PARAMLIST_CONSTRUCTOR + 8, "blx", target=ALLOCATOR_PLT)
    _require(rows, PARAMLIST_CONSTRUCTOR + 0x0E, "bl", target=CONTAINER_INIT_FORWARDER)
    _require(rows, PARAMLIST_CONSTRUCTOR + 0x14, "str", operands="r5, [r4]")
    _require(rows, PARAMLIST_CONSTRUCTOR + 0x16, "bl", target=0x7EDB32)
    _require(rows, PARAMLIST_CONSTRUCTOR + 0x1A, "movs", immediate=4)
    _require(rows, PARAMLIST_CONSTRUCTOR + 0x1C, "blx", target=ALLOCATOR_PLT)
    _require(rows, PARAMLIST_CONSTRUCTOR + 0x22, "str", operands="r3, [r0]")
    _require(rows, PARAMLIST_CONSTRUCTOR + 0x24, "str", operands="r0, [r4, #4]")
    _require(rows, PARAMLIST_CONSTRUCTOR + 0x26, "mov", operands="r0, r4")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "symbol_identity": symbol,
        "receiver": "r0 destination-shaped ParamList object",
        "return": "r0 restored from receiver before return; source-level constructor safety UNKNOWN",
        "container_allocation": {
            "size_bytes": 0x0C,
            "allocator_plt": hex(ALLOCATOR_PLT),
            "binding": allocator,
            "stored_at_object_offset": hex(CONTAINER_OFFSET),
        },
        "container_initialization": {
            "forwarder_vma": hex(CONTAINER_INIT_FORWARDER),
            "initializer_vma": hex(CONTAINER_INIT),
            "status": "PRIMARY_ELF_VERIFIED",
        },
        "shared_counter": {
            "allocation_size_bytes": 4,
            "initial_value": 1,
            "stored_at_object_offset": hex(COUNTER_OFFSET),
            "interpretation": "shared counter candidate; source-level type UNKNOWN",
        },
        "allocation_failure_handling": "UNKNOWN; no local failure guard observed in this bounded body",
        "address_space": "ELF_VMA",
    }


def _observe_clear(rows: dict[int, Any], symbols: dict[str, tuple[int, int]]) -> dict[str, Any]:
    symbol = _symbol_identity(symbols, "_ZN9ParamList5clearEv", PARAMLIST_CLEAR, PARAMLIST_CLEAR_SIZE)
    _require(rows, PARAMLIST_CLEAR, "push")
    _require(rows, PARAMLIST_CLEAR + 2, "add")
    _require(rows, PARAMLIST_CLEAR + 4, "pop.w")
    _require(rows, PARAMLIST_CLEAR + 8, "b.w", target=CLEAR_HELPER)
    _require(rows, CLEAR_HELPER + 0x0A, "bl", target=0x7EDAB0)
    _require(rows, CLEAR_HELPER + 0x18, "bl", target=0x7EDABE)
    _require(rows, CLEAR_HELPER + 0x1E, "cbz", target=CLEAR_HELPER + 0x26)
    _require(rows, CLEAR_HELPER + 0x20, "ldr", operands="r3, [r0]")
    _require(rows, CLEAR_HELPER + 0x22, "ldr", operands="r3, [r3, #8]")
    _require(rows, CLEAR_HELPER + 0x24, "blx", operands="r3")
    _require(rows, CLEAR_HELPER + 0x2A, "blt", target=CLEAR_HELPER + 0x14)
    _require(rows, CLEAR_HELPER + 0x32, "b.w", target=0x7EDB32)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "symbol_identity": symbol,
        "helper_vma": hex(CLEAR_HELPER),
        "count_source": "(container end - container begin) >> 2 via 0x7edab0",
        "element_width_bytes": 4,
        "null_element": "null slot skips virtual deletion in this bounded loop",
        "virtual_dispatch": {
            "vptr_offset": hex(0),
            "deleting_destructor_slot_offset": hex(8),
            "target": "indirect/unresolved",
        },
        "reset": "container end is reset to begin through 0x7edb32",
        "container_type": "pointer-array candidate; source-level type UNKNOWN",
        "address_space": "ELF_VMA",
    }


def _observe_container_release(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, CONTAINER_RELEASE, "ldr")
    _require(rows, CONTAINER_RELEASE + 2, "ldr")
    _require(rows, CONTAINER_RELEASE + 4, "push")
    _require(rows, CONTAINER_RELEASE + 6, "subs")
    _require(rows, CONTAINER_RELEASE + 0x0C, "asrs", immediate=2)
    _require(rows, CONTAINER_RELEASE + 0x0E, "bl", target=0x7EDC92)
    _require(rows, CONTAINER_RELEASE + 0x12, "mov", operands="r0, r4")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "entry_vma": hex(CONTAINER_RELEASE),
        "range_source": "container begin/end difference, divided by four",
        "deallocator_path": {
            "conditional_helper": hex(0x7EDC92),
            "tail_path": hex(0x7EDC84),
            "final_runtime_binding": "UNKNOWN",
        },
        "source_level_allocator": "UNKNOWN",
        "address_space": "ELF_VMA",
    }


def _observe_shared_rebind(rows: dict[int, Any], delete_binding: dict[str, Any]) -> dict[str, Any]:
    _require(rows, SHARED_REBIND, "cmp", operands="r1, r0")
    _require(rows, SHARED_REBIND + 0x0C, "ldr", operands="r2, [r0, #4]")
    _require(rows, SHARED_REBIND + 0x0E, "ldr", operands="r3, [r2]")
    _require(rows, SHARED_REBIND + 0x10, "subs", immediate=1)
    _require(rows, SHARED_REBIND + 0x12, "str", operands="r3, [r2]")
    _require(rows, SHARED_REBIND + 0x14, "cbnz", target=SHARED_REBIND + 0x30)
    _require(rows, SHARED_REBIND + 0x16, "bl", target=CLEAR_HELPER)
    _require(rows, SHARED_REBIND + 0x20, "bl", target=CONTAINER_RELEASE_WRAPPER)
    _require(rows, SHARED_REBIND + 0x26, "blx", target=OBJECT_DELETE_PLT)
    _require(rows, SHARED_REBIND + 0x2C, "blx", target=OBJECT_DELETE_PLT)
    _require(rows, SHARED_REBIND + 0x30, "ldr", operands="r3, [r5, #4]")
    _require(rows, SHARED_REBIND + 0x34, "str", operands="r3, [r4, #4]")
    _require(rows, SHARED_REBIND + 0x36, "adds", immediate=1)
    _require(rows, SHARED_REBIND + 0x38, "str", operands="r2, [r3]")
    _require(rows, SHARED_REBIND + 0x3A, "ldr", operands="r3, [r5]")
    _require(rows, SHARED_REBIND + 0x3C, "str", operands="r3, [r4]")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "entry_vma": hex(SHARED_REBIND),
        "source_level_identity": "UNKNOWN; unnamed shared-rebind/assignment candidate",
        "receiver_roles": {
            "r0": "destination ParamList candidate",
            "r1": "source ParamList candidate",
        },
        "self_assignment": "equal r0/r1 returns destination without counter mutation",
        "old_owner_release": {
            "decrement_counter_at": "destination +0x04 -> *counter",
            "last_owner_condition": "decremented counter is zero",
            "clear_helper": hex(CLEAR_HELPER),
            "container_release": hex(CONTAINER_RELEASE_WRAPPER),
            "object_delete": delete_binding,
        },
        "new_owner_attach": {
            "counter_increment": "source counter increments before copy",
            "container_pointer_copy": "source +0x00 -> destination +0x00",
            "counter_pointer_copy": "source +0x04 -> destination +0x04",
        },
        "return": "destination-shaped r0 observed; C++ operator/return declaration UNKNOWN",
        "copy_on_write": "UNKNOWN; observed path shares container and counter pointers",
        "concurrency": "UNKNOWN; no lock or atomic operation observed in bounded body",
        "address_space": "ELF_VMA",
    }


def _observe_destructor(
    rows: dict[int, Any], delete_binding: dict[str, Any], symbols: dict[str, tuple[int, int]],
) -> dict[str, Any]:
    symbol = _symbol_identity(symbols, "_ZN9ParamListD1Ev", PARAMLIST_DESTRUCTOR, PARAMLIST_DESTRUCTOR_SIZE)
    _require(rows, PARAMLIST_DESTRUCTOR, "ldr", operands="r2, [r0, #4]")
    _require(rows, PARAMLIST_DESTRUCTOR + 6, "ldr", operands="r3, [r2]")
    _require(rows, PARAMLIST_DESTRUCTOR + 0x0A, "subs", immediate=1)
    _require(rows, PARAMLIST_DESTRUCTOR + 0x0C, "str", operands="r3, [r2]")
    _require(rows, PARAMLIST_DESTRUCTOR + 0x0E, "cbnz", target=PARAMLIST_DESTRUCTOR + 0x2A)
    _require(rows, PARAMLIST_DESTRUCTOR + 0x10, "bl", target=CLEAR_HELPER)
    _require(rows, PARAMLIST_DESTRUCTOR + 0x16, "cbz", target=PARAMLIST_DESTRUCTOR + 0x24)
    _require(rows, PARAMLIST_DESTRUCTOR + 0x1A, "bl", target=CONTAINER_RELEASE_WRAPPER)
    _require(rows, PARAMLIST_DESTRUCTOR + 0x20, "blx", target=OBJECT_DELETE_PLT)
    _require(rows, PARAMLIST_DESTRUCTOR + 0x24, "ldr", operands="r0, [r4, #4]")
    _require(rows, PARAMLIST_DESTRUCTOR + 0x26, "blx", target=OBJECT_DELETE_PLT)
    _require(rows, PARAMLIST_DESTRUCTOR + 0x2A, "mov", operands="r0, r4")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "symbol_identity": symbol,
        "counter_operation": "decrement *counter; nonzero skips container cleanup",
        "last_owner_cleanup": {
            "condition": "decremented counter == 0",
            "clear_helper": hex(CLEAR_HELPER),
            "container_null_guard": "null container skips the container release/delete branch",
            "container_release": hex(CONTAINER_RELEASE_WRAPPER),
            "container_delete_binding": delete_binding,
            "counter_delete_binding": delete_binding,
        },
        "return": "r0 restored from receiver; source-level destructor safety UNKNOWN",
        "null_counter": "UNKNOWN; no local null guard before counter dereference/delete",
        "concurrency": "UNKNOWN; no lock or atomic operation observed in bounded body",
        "address_space": "ELF_VMA",
    }


def probe_paramlist_lifetime(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Verify bounded ParamList shared-counter and owner-release facts."""
    path = Path(elf_path).resolve()
    if not path.is_file() or path.stat().st_size > MAX_ELF_BYTES:
        raise ValueError("private ELF missing or exceeds analysis limit")
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
        allocator = _binding(stream, elf, ALLOCATOR_PLT, "_Znwj")
        delete_binding = _binding(stream, elf, OBJECT_DELETE_PLT, "_ZdlPv")
        constructor = _observe_constructor(
            _decode(stream, elf, PARAMLIST_CONSTRUCTOR, PARAMLIST_CONSTRUCTOR_SIZE),
            allocator, symbols,
        )
        init = _observe_container_init(_decode(stream, elf, CONTAINER_INIT, CONTAINER_INIT_SIZE))
        clear = _observe_clear(
            _decode(stream, elf, PARAMLIST_CLEAR, PARAMLIST_CLEAR_SIZE)
            | _decode(stream, elf, CLEAR_HELPER, CLEAR_HELPER_SIZE),
            symbols,
        )
        release = _observe_container_release(
            _decode(stream, elf, CONTAINER_RELEASE, CONTAINER_RELEASE_SIZE)
        )
        shared = _observe_shared_rebind(
            _decode(stream, elf, SHARED_REBIND, SHARED_REBIND_SIZE), delete_binding,
        )
        destructor = _observe_destructor(
            _decode(stream, elf, PARAMLIST_DESTRUCTOR, PARAMLIST_DESTRUCTOR_SIZE),
            delete_binding, symbols,
        )
    return {
        "schema_version": 1,
        "firmware_version": "3.21",
        "status": "LOCAL_PRIMARY_ELF_PARAMLIST_LIFETIME_EVIDENCE_ONLY",
        "binary_file_sha256": digest,
        "address_space": "ELF_VMA",
        "abi": "ARM AAPCS32, Thumb, little endian; source-level ownership and runtime ABI UNKNOWN",
        "layout": {
            "paramlist_container_pointer_offset": hex(CONTAINER_OFFSET),
            "shared_counter_pointer_offset": hex(COUNTER_OFFSET),
            "container_begin_offset": hex(BEGIN_OFFSET),
            "container_end_offset": hex(END_OFFSET),
            "container_capacity_offset": hex(CAPACITY_OFFSET),
            "element_pointer_width_bytes": 4,
        },
        "bindings": {
            "allocator": allocator,
            "object_delete": delete_binding,
        },
        "observations": {
            "container_initializer": init,
            "constructor": constructor,
            "clear": clear,
            "container_release": release,
            "shared_rebind_candidate": shared,
            "destructor": destructor,
        },
        "lifetime": {
            "shared_counter_model": "STATIC_INFERRED from increment/decrement and last-owner branches",
            "container_aliasing": "STATIC_INFERRED; shared rebind copies container and counter pointers",
            "copy_on_write": "UNKNOWN",
            "borrowed_element_invalidation": "STATIC_INFERRED when clear/replacement destroys elements",
            "concurrency_verified": False,
            "runtime_verified": False,
            "callable": False,
        },
        "raw_instruction_bytes_published": False,
        "runtime_verified": False,
        "callable": False,
        "limitations": [
            "The shared rebind body has no source-level ParamList copy/assignment symbol",
            "Container release at 0x7edc84/0x7edc92 has no uniquely resolved public allocator identity",
            "Reference-count interpretation is static and does not prove thread safety or atomicity",
            "Allocation failure, exception cleanup, loader interposition and runtime ABI remain UNKNOWN",
            "No firmware code was executed and no device was accessed",
        ],
    }


def validate_paramlist_lifetime(report: dict[str, Any]) -> dict[str, Any]:
    """Fail closed on identity, field layout and unsafe promotion."""
    errors: list[str] = []
    if report.get("schema_version") != 1:
        errors.append("schema_version")
    if report.get("binary_file_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != "ELF_VMA":
        errors.append("address_space")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    layout = report.get("layout")
    expected_layout = {
        "paramlist_container_pointer_offset": "0x0",
        "shared_counter_pointer_offset": "0x4",
        "container_begin_offset": "0x0",
        "container_end_offset": "0x4",
        "container_capacity_offset": "0x8",
        "element_pointer_width_bytes": 4,
    }
    if layout != expected_layout:
        errors.append("layout")
    observations = report.get("observations")
    required = {"container_initializer", "constructor", "clear", "container_release", "shared_rebind_candidate", "destructor"}
    if not isinstance(observations, dict) or not required.issubset(observations):
        errors.append("missing_observations")
    else:
        for name in required:
            item = observations.get(name)
            if not isinstance(item, dict) or item.get("status") != "PRIMARY_ELF_VERIFIED":
                errors.append(f"observation_status:{name}")
    lifetime = report.get("lifetime")
    if not isinstance(lifetime, dict):
        errors.append("lifetime")
    else:
        if lifetime.get("concurrency_verified") is not False:
            errors.append("concurrency_claim")
        if lifetime.get("copy_on_write") != "UNKNOWN":
            errors.append("copy_on_write_claim")
    return {
        "valid": not errors,
        "errors": sorted(set(errors)),
        "observation_count": len(observations) if isinstance(observations, dict) else 0,
    }
