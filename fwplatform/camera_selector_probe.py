"""Evidence-gated static probe for the Camera selector helper at 0x12d780.

The probe validates the authenticated private ELF's branch structure without
executing firmware.  It records the directly visible ``@M``/``@V`` mapping
and keeps the normal virtual-dispatch path descriptive and unresolved.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from capstone.arm import ARM_OP_IMM
from elftools.elf.elffile import ELFFile

from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA


TARGET = {"name": "camera_selector_transform", "entry": 0x12D780, "size": 0xD6}
TRANSFORM_TARGET = {"name": "selector_transform_math", "entry": 0x120168, "size": 0x1A}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_exec_range(fp: Any, elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > 0x300:
        raise ValueError("selector read exceeds bounded probe limit")
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


def _decode_range(fp: Any, elf: ELFFile, start: int, size: int) -> dict[int, Any]:
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    rows = list(decoder.disasm(
        _read_exec_range(fp, elf, start, size),
        start,
    ))
    if not rows:
        raise ValueError("selector helper did not decode")
    return {int(row.address): row for row in rows}


def _decode(fp: Any, elf: ELFFile) -> dict[int, Any]:
    return _decode_range(fp, elf, TARGET["entry"], TARGET["size"])


def _immediates(ins: Any) -> list[int]:
    return [int(op.imm) for op in ins.operands if op.type == ARM_OP_IMM]


def _require(
    rows: dict[int, Any], address: int, mnemonic: str,
    *, target: int | None = None, immediate: int | None = None,
    operands: str | None = None,
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


def _observe(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0x12D780, "push")
    _require(rows, 0x12D78A, "ldrb", operands="r3, [r0]")
    _require(rows, 0x12D78C, "cmp", immediate=0x40)
    _require(rows, 0x12D78E, "beq", target=0x12D824)

    # Special @M/@V branch.
    _require(rows, 0x12D824, "blx", target=0xDFFB8)
    _require(rows, 0x12D828, "ldrb", operands="r3, [r4, #1]")
    _require(rows, 0x12D82A, "cmp", immediate=0x4D)
    _require(rows, 0x12D830, "mov.w", immediate=0x12000000)
    _require(rows, 0x12D836, "cmp", immediate=0x56)
    _require(rows, 0x12D83A, "mov.w", immediate=0x13000000)
    _require(rows, 0x12D840, "bl", target=0x120168)
    _require(rows, 0x12D848, "mov.w", immediate=-1)

    # General branch and the visible virtual dispatch gate.
    for address, target in (
        (0x12D79A, 0xE2704), (0x12D79E, 0x12CEBC),
        (0x12D7AC, 0xE1794), (0x12D7BC, 0x12CCE0),
        (0x12D7C4, 0xDEE58), (0x12D7D4, 0xE2704),
        (0x12D7DE, 0x12D4A8), (0x12D7FC, 0xE2704),
    ):
        _require(rows, address, "blx" if address in (0x12D79A, 0x12D7AC, 0x12D7C4, 0x12D7D4, 0x12D7FC) else "bl", target=target)
    _require(rows, 0x12D7EC, "cbz", target=0x12D816)
    _require(rows, 0x12D7F0, "add.w", operands="r0, r7, #0x74")
    _require(rows, 0x12D7F4, "adds", operands="r1, r7, #4")
    _require(rows, 0x12D7F6, "add.w", operands="r2, r7, #0x84")
    _require(rows, 0x12D7FA, "ldr", operands="r4, [r3, #8]")
    _require(rows, 0x12D808, "blx", operands="r4")
    _require(rows, 0x12D816, "mov.w", immediate=-1)
    _require(rows, 0x12D84C, "mov", operands="r0, r4")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "entry": "0x12d780",
        "inputs": {
            "r0": "pointer to a model/name token; first byte is tested",
            "r1": "selector input preserved in r6",
        },
        "special_branch": {
            "guard": "byte [r0] == 0x40",
            "model_id": "calls relocation-bound IdGenerator::Get PLT 0xdffb8 with r0=model token",
            "second_byte": {
                "M_0x4d": "uses base constant 0x12000000",
                "V_0x56": "uses base constant 0x13000000",
                "other": "returns -1",
            },
            "transform_call": "calls local 0x120168 with r1=model_id, r2=original selector and selected base in r0",
            "return": "local result in r0; exact C++ return type UNKNOWN",
        },
        "general_branch": {
            "guard": "byte [r0] != 0x40",
            "preparation": "builds several local objects through helper calls",
            "dispatch": "if object pointer is non-null, loads vtable slot +8 and invokes it with r0/object, r1/r2 local values",
            "null_path": "returns -1 when the prepared object pointer is null",
            "helper_and_virtual_semantics": "UNKNOWN",
        },
        "runtime_verified": False,
        "callable": False,
    }


def _observe_transform(rows: dict[int, Any]) -> dict[str, Any]:
    """Validate the local selector math called by the special branch."""
    _require(rows, 0x120168, "mov", operands="r3, r0")
    _require(rows, 0x12016A, "bic", operands="r0, r2, #0xfe0")
    _require(rows, 0x12016E, "bic", operands="r0, r0, #0x1f")
    _require(rows, 0x120176, "cbnz", target=0x12017E)
    _require(rows, 0x120178, "lsls", operands="r1, r1, #0xc")
    _require(rows, 0x12017A, "adds", operands="r2, r2, r1")
    _require(rows, 0x12017C, "adds", operands="r2, r2, r3")
    _require(rows, 0x12017E, "mov", operands="r0, r2")
    _require(rows, 0x120180, "pop")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "inputs": {
            "r0": "selected base copied to r3",
            "r1": "model ID candidate, shifted left by 12 only on aligned-selector path",
            "r2": "original selector candidate",
        },
        "guard": "(r2 & 0xfff) != 0 takes the direct return path",
        "aligned_path": "when (r2 & 0xfff) == 0, returns r2 + (r1 << 12) + r0",
        "return": "word in r0; C++ type and selector domain remain UNKNOWN",
    }


def probe_camera_selector(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Validate the bounded selector-helper branch facts."""
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
        transform_rows = _decode_range(
            fp, elf, TRANSFORM_TARGET["entry"], TRANSFORM_TARGET["size"]
        )
    observation = _observe(rows)
    transform = _observe_transform(transform_rows)
    observation["transform_math"] = transform
    return {
        "status": "LOCAL_PRIMARY_ELF_CAMERA_SELECTOR_EVIDENCE_ONLY",
        "binary_file_sha256": digest,
        "address_space": "ELF_VMA",
        "target": TARGET,
        "transform_target": TRANSFORM_TARGET,
        "observation": observation,
        "runtime_verified": False,
        "callable": False,
    }


def validate_camera_selector(report: dict[str, Any]) -> dict[str, Any]:
    """Reject wrong identity or promotion beyond static evidence."""
    errors: list[str] = []
    if report.get("binary_file_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != "ELF_VMA":
        errors.append("address_space")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    if report.get("observation", {}).get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("observation_status")
    if report.get("observation", {}).get("transform_math", {}).get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("transform_observation_status")
    return {"valid": not errors, "errors": sorted(set(errors))}
