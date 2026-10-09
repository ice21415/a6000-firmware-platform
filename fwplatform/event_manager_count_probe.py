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
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    rows = list(decoder.disasm(
        _read_exec_range(fp, elf, TARGET["entry"], TARGET["size"]),
        TARGET["entry"],
    ))
    if not rows:
        raise ValueError("EventManager::count did not decode")
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


def _observe(rows: dict[int, Any]) -> dict[str, Any]:
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
            "return": "result returned by post-load helper 0x7f0aa0; C++ return type is not encoded",
        },
        "control_flow": {
            "pre_access": "calls local 0x7ef8f4 with the receiver",
            "state_base": "loads a state/container pointer from [receiver]",
            "indexed_load": "loads one 32-bit word from [state_base + (index << 2)]",
            "post_access": "passes the loaded word through local 0x7f0aa0",
            "receiver_cleanup": "calls local 0x7ef902 with the receiver before returning",
        },
        "safety": {
            "local_bounds_check": "no conditional index-bound check observed in this bounded body",
            "global_invariant": "UNKNOWN; state allocation and valid index range are not proven",
            "null_receiver": "UNKNOWN; no runtime execution or general receiver guard is established",
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
        observation = _observe(_decode(fp, elf))
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
    return {"valid": not errors, "errors": sorted(set(errors))}
