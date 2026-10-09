"""Bounded primary-ELF probe for the Camera prepare parameter envelope.

This records the instruction-level construction and Event::addParameter call
at ``0x125084``.  The final tail target is intentionally left unnamed: a
direct branch target is not enough to prove its C++ identity or delivery
semantics.
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


TARGET = {"name": "camera_prepare_envelope", "entry": 0x125084, "size": 0x34}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_exec_range(fp: Any, elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > 0x100:
        raise ValueError("Camera prepare probe exceeds bounded read limit")
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


def _decode(fp: Any, elf: ELFFile) -> dict[int, Any]:
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    rows = list(decoder.disasm(
        _read_exec_range(fp, elf, TARGET["entry"], TARGET["size"]), TARGET["entry"]
    ))
    if not rows:
        raise ValueError("Camera prepare envelope did not decode")
    return {int(row.address): row for row in rows}


def _immediates(ins: Any) -> list[int]:
    return [int(op.imm) for op in ins.operands if op.type == ARM_OP_IMM]


def _require(
    rows: dict[int, Any], address: int, mnemonic: str, *, target: int | None = None,
    operands: str | None = None, immediate: int | None = None,
) -> Any:
    ins = rows.get(address)
    if ins is None or ins.mnemonic.lower() != mnemonic.lower():
        raise ValueError(f"unexpected {mnemonic} at 0x{address:x}")
    if target is not None and target not in _immediates(ins):
        raise ValueError(f"unexpected branch target at 0x{address:x}")
    if immediate is not None and immediate not in _immediates(ins):
        raise ValueError(f"unexpected immediate at 0x{address:x}")
    if operands is not None and ins.op_str.lower() != operands.lower():
        raise ValueError(f"unexpected operands at 0x{address:x}")
    return ins


def _binding(fp: Any, elf: ELFFile, entry: int) -> dict[str, Any]:
    result = resolve_plt_binding(fp, elf, entry, thumb_stub=False)
    if result.get("status") != "VERIFIED_STATIC":
        raise ValueError(f"PLT binding at 0x{entry:x} is not unique")
    return result


def _observe(rows: dict[int, Any], allocator: dict[str, Any], add_parameter: dict[str, Any]) -> dict[str, Any]:
    _require(rows, 0x125084, "push.w")
    _require(rows, 0x125088, "mov", operands="r5, r0")
    _require(rows, 0x12508C, "movs", immediate=0x10)
    _require(rows, 0x12508E, "blx", target=0xDC100)
    _require(rows, 0x125092, "movs", operands="r1, #0")
    _require(rows, 0x125098, "mov", operands="r6, r0")
    _require(rows, 0x12509A, "bl", target=0xF0FB0)
    _require(rows, 0x12509E, "mov", operands="r0, r5")
    _require(rows, 0x1250A0, "movs", operands="r1, #6")
    _require(rows, 0x1250A2, "mov", operands="r2, r6")
    _require(rows, 0x1250A4, "blx", target=0xDD194)
    _require(rows, 0x1250AA, "mov", operands="r1, r5")
    _require(rows, 0x1250B4, "b.w", target=0x7F25E0)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "receiver": "opaque Camera/Event receiver candidate in r0, preserved in r5",
        "allocation": "16-byte allocation through PLT 0xdc100",
        "parameter_constructor": "direct local call 0xf0fb0 with r1=0; C++ identity is cross-family inferred as PrmNumber constructor",
        "event_parameter": {
            "key": 6,
            "object": "new 16-byte parameter candidate in r2",
            "call": "PLT 0xdd194 resolved statically to Event::addParameter",
        },
        "tail_target": "0x7f25e0 direct branch; local C++ identity and delivery/completion semantics UNKNOWN",
        "bindings": {"allocator": allocator, "event_add_parameter": add_parameter},
        "runtime_verified": False,
        "callable": False,
    }


def probe_camera_prepare_envelope(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Validate the bounded Camera prepare/event envelope path."""
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
        rows = _decode(fp, elf)
        allocator = _binding(fp, elf, 0xDC100)
        add_parameter = _binding(fp, elf, 0xDD194)
        observation = _observe(rows, allocator, add_parameter)
    return {
        "status": "LOCAL_PRIMARY_ELF_CAMERA_PREPARE_EVIDENCE_ONLY",
        "binary_file_sha256": digest,
        "address_space": "ELF_VMA",
        "target": TARGET,
        "observation": observation,
        "runtime_verified": False,
        "callable": False,
    }


def validate_camera_prepare_envelope(report: dict[str, Any]) -> dict[str, Any]:
    """Reject wrong identity or claims beyond static evidence."""
    errors: list[str] = []
    if report.get("binary_file_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != "ELF_VMA":
        errors.append("address_space")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    observation = report.get("observation", {})
    if observation.get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("observation_status")
    bindings = observation.get("bindings", {})
    if bindings.get("allocator", {}).get("status") != "VERIFIED_STATIC":
        errors.append("allocator_binding")
    if bindings.get("event_add_parameter", {}).get("status") != "VERIFIED_STATIC":
        errors.append("event_add_parameter_binding")
    return {"valid": not errors, "errors": sorted(set(errors))}
