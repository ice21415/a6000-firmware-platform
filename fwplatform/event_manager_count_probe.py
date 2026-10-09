"""Primary-ELF evidence probe for ``EventManager::count(unsigned int)``.

The exported symbol gives the method name and the unsigned index parameter,
while Capstone verifies the Thumb register/data-flow shape.  The probe only
emits sanitized metadata: it never exposes firmware bytes and never creates a
callable wrapper.  The indexed state word has no local bounds check in this
bounded body; global container invariants and runtime safety remain unknown.
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
    "name": "EventManager::count",
    "entry": 0x7EF9FC,
    "size": 0x22,
    "symbol": "_ZN12EventManager5countEj",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_exec_range(fp: Any, elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > 0x100:
        raise ValueError("EventManager::count read exceeds bounded probe limit")
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


def _decode(fp: Any, elf: ELFFile) -> dict[int, Any]:
    return _decode_at(fp, elf, TARGET["entry"], TARGET["size"], "EventManager::count")


def _decode_at(fp: Any, elf: ELFFile, entry: int, size: int, label: str) -> dict[int, Any]:
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    rows = list(decoder.disasm(
        _read_exec_range(fp, elf, entry, size),
        entry,
    ))
    if not rows:
        raise ValueError(f"{label} did not decode")
    return {int(row.address): row for row in rows}


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


def _binding(fp: Any, elf: ELFFile, entry: int) -> dict[str, Any]:
    result = resolve_plt_binding(fp, elf, entry, thumb_stub=True)
    if result.get("status") != "VERIFIED_STATIC":
        raise ValueError(f"PLT binding at 0x{entry:x} is not unique")
    return result


def _observe_link_helpers(fp: Any, elf: ELFFile) -> dict[str, Any]:
    """Verify the bounded forward-link distance helper without naming a source type."""
    compare = _decode_at(fp, elf, 0x7F0A32, 0x10, "link compare helper")
    advance = _decode_at(fp, elf, 0x7F0A42, 0x0C, "link advance helper")
    distance = _decode_at(fp, elf, 0x7F0A4E, 0x2C, "link distance helper")
    distance_forwarder = _decode_at(fp, elf, 0x7F0A7A, 0x0A, "link distance forwarder")
    distance_core = _decode_at(fp, elf, 0x7F0A84, 0x1C, "link distance core")
    distance_entry = _decode_at(fp, elf, 0x7F0AA0, 0x0C, "link distance entry")
    first_word = _decode_at(fp, elf, 0x7F096A, 0x1A, "first-word helper")
    identity = _decode_at(fp, elf, 0x7F0984, 0x18, "identity helper")

    _require(compare, 0x7F0A32, "ldr", operands="r3, [r0]")
    _require(compare, 0x7F0A34, "ldr", operands="r0, [r1]")
    _require(compare, 0x7F0A38, "subs", operands="r0, r3, r0")
    _require(compare, 0x7F0A3E, "movne", operands="r0, #1")
    _require(advance, 0x7F0A42, "ldr", operands="r2, [r0]")
    _require(advance, 0x7F0A48, "ldr", operands="r2, [r2]")
    _require(advance, 0x7F0A4A, "str", operands="r2, [r0]")
    _require(distance, 0x7F0A56, "str", operands="r0, [r7, #4]")
    _require(distance, 0x7F0A58, "str", operands="r1, [r7]")
    _require(distance, 0x7F0A60, "bl", target=0x7F0A42)
    _require(distance, 0x7F0A68, "bl", target=0x7F0A32)
    _require(distance, 0x7F0A6E, "bne", target=0x7F0A5C)
    _require(distance, 0x7F0A70, "mov", operands="r0, r4")
    _require(distance_forwarder, 0x7F0A7E, "bl", target=0x7F0A4E)
    _require(distance_core, 0x7F0A8A, "bl", target=0x7F096A)
    _require(distance_core, 0x7F0A92, "bl", target=0x7F0984)
    _require(distance_core, 0x7F0A9A, "bl", target=0x7F0A7A)
    _require(distance_entry, 0x7F0AA8, "b.w", target=0x7F0A84)
    _require(first_word, 0x7F0974, "ldr", operands="r1, [r3]")
    _require(first_word, 0x7F0976, "bl", target=0x7F0962)
    _require(identity, 0x7F098E, "bl", target=0x7F0962)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "semantic_level": "STATIC_INFERRED",
        "operation": (
            "counts forward-link steps from the first word of the input object "
            "to the input object used as the sentinel"
        ),
        "link_layout": {
            "node_next_word": "the current node pointer is replaced with [current_node]",
            "sentinel_compare": "the current pointer is compared with the sentinel pointer",
            "empty_chain": "equal initial pointers return zero",
        },
        "entry": "0x7f0aa0 tail-branches to 0x7f0a84",
        "first_word_helper": "0x7f096a returns [input]",
        "identity_helper": "0x7f0984 returns its input pointer",
        "source_container_type": "UNKNOWN; no source-level class or standard-container identity is proven",
    }


def _observe(rows: dict[int, Any], synchronization: dict[str, Any], link_helpers: dict[str, Any]) -> dict[str, Any]:
    checks = (
        (TARGET["entry"], "push", None, None),
        (0x7EF9FE, "mov", "r4, r0", None),
        (0x7EFA02, "mov", "r5, r1", None),
        (0x7EFA04, "bl", None, 0x7EF8F4),
        (0x7EFA08, "ldr", "r3, [r4]", None),
        (0x7EFA0A, "ldr.w", "r0, [r3, r5, lsl #2]", None),
        (0x7EFA0E, "bl", None, 0x7F0AA0),
        (0x7EFA14, "mov", "r0, r4", None),
        (0x7EFA16, "bl", None, 0x7EF902),
        (0x7EFA1A, "mov", "r0, r5", None),
        (0x7EFA1C, "pop", None, None),
    )
    for address, mnemonic, operands, target in checks:
        _require(rows, address, mnemonic, operands=operands, target=target)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "abi": {
            "r0": "EventManager receiver candidate",
            "r1": "unsigned index, preserved in r5 by the symbol-bound method",
            "return": "machine-level link-count result from 0x7f0aa0; C++ return type is not encoded",
        },
        "control_flow": {
            "pre_access": "calls local 0x7ef8f4 with the receiver",
            "state_base": "loads a state/container pointer from [receiver]",
            "indexed_load": "loads one 32-bit word from [state_base + (index << 2)]",
            "post_access": "passes the loaded word through local 0x7f0aa0",
            "receiver_cleanup": "calls local 0x7ef902 with the receiver before returning",
        },
        "helper": link_helpers,
        "synchronization": synchronization,
        "safety": {
            "local_bounds_check": "no conditional index-bound check observed in this bounded body",
            "global_invariant": "UNKNOWN; state allocation and valid index range are not proven",
            "null_receiver": "UNKNOWN; no runtime execution or general receiver guard is established",
            "container_validity": "UNKNOWN; helper assumes a terminating forward-link chain",
            "concurrency": "lock/unlock calls are statically present, but complete shared-state safety is UNKNOWN",
        },
        "address_space": "ELF_VMA",
        "runtime_verified": False,
        "callable": False,
    }


def probe_event_manager_count(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Decode the bounded symbol-bound count method from the private ELF."""
    path = Path(elf_path).resolve()
    if not path.is_file():
        raise ValueError("private ELF is missing")
    if not isinstance(expected_sha256, str) or not HEX_SHA.fullmatch(expected_sha256):
        raise ValueError("expected_sha256 must be a lowercase full SHA-256 digest")
    digest = _sha256(path)
    if digest != expected_sha256:
        raise ValueError("full-file ELF SHA-256 mismatch; refusing to decode")
    with path.open("rb") as fp:
        elf = ELFFile(fp)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_ARM":
            raise ValueError("probe accepts only ELF32 little-endian ARM")
        value, size = _symbols(elf).get(TARGET["symbol"], (0, 0))
        if (value & ~1) != TARGET["entry"] or size != TARGET["size"]:
            raise ValueError("EventManager::count symbol identity/size mismatch")
        synchronization = {
            "lock_wrapper": {
                "entry": "0x7ef8f4",
                "receiver_field": "+0x0c",
                "tail_target": "0xdcc70",
                "binding": _binding(fp, elf, 0xDCC70),
            },
            "unlock_wrapper": {
                "entry": "0x7ef902",
                "receiver_field": "+0x0c",
                "tail_target": "0xe29e8",
                "binding": _binding(fp, elf, 0xE29E8),
            },
        }
        link_helpers = _observe_link_helpers(fp, elf)
        observation = _observe(_decode(fp, elf), synchronization, link_helpers)
    return {
        "schema_version": 1,
        "status": "LOCAL_PRIMARY_ELF_EVENT_MANAGER_COUNT_EVIDENCE_ONLY",
        "firmware_version": "3.21",
        "binary_file_sha256": digest,
        "address_space": "ELF_VMA",
        "target": TARGET,
        "observation": observation,
        "runtime_verified": False,
        "callable": False,
    }


def validate_event_manager_count(report: dict[str, Any]) -> dict[str, Any]:
    """Reject identity errors and unsafe promotion beyond static evidence."""
    errors: list[str] = []
    if report.get("schema_version") != 1:
        errors.append("schema_version")
    if report.get("binary_file_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != "ELF_VMA":
        errors.append("address_space")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    target = report.get("target") or {}
    if target.get("entry") != TARGET["entry"] or target.get("size") != TARGET["size"]:
        errors.append("target_identity")
    observation = report.get("observation") or {}
    if observation.get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("observation_status")
    safety = observation.get("safety") or {}
    if safety.get("local_bounds_check") != (
        "no conditional index-bound check observed in this bounded body"
    ):
        errors.append("bounds_scope")
    if safety.get("global_invariant") != (
        "UNKNOWN; state allocation and valid index range are not proven"
    ):
        errors.append("global_invariant_scope")
    if safety.get("container_validity") != (
        "UNKNOWN; helper assumes a terminating forward-link chain"
    ):
        errors.append("container_validity_scope")
    synchronization = observation.get("synchronization") or {}
    for role, entry, symbol in (
        ("lock_wrapper", "0x7ef8f4", "pthread_mutex_lock"),
        ("unlock_wrapper", "0x7ef902", "pthread_mutex_unlock"),
    ):
        wrapper = synchronization.get(role) or {}
        if wrapper.get("entry") != entry or wrapper.get("receiver_field") != "+0x0c":
            errors.append(f"synchronization:{role}:wrapper")
        binding = wrapper.get("binding") or {}
        candidates = binding.get("candidates") or []
        if (
            binding.get("status") != "VERIFIED_STATIC"
            or len(candidates) != 1
            or candidates[0].get("symbol") != symbol
        ):
            errors.append(f"synchronization:{role}:binding")
    helper = observation.get("helper") or {}
    if helper.get("status") != "PRIMARY_ELF_VERIFIED" or helper.get("semantic_level") != "STATIC_INFERRED":
        errors.append("helper_evidence")
    return {"valid": not errors, "errors": sorted(set(errors))}
