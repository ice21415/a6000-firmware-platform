"""Evidence-gated probe for the primary EventManager::push implementation."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from capstone.arm import ARM_OP_IMM
from elftools.elf.elffile import ELFFile

from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA


TARGET = {
    "name": "EventManager::push",
    "entry": 0x7EF960,
    "size": 0x9C,
    "symbol": "_ZN12EventManager4pushEP5Eventb",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_exec_range(fp: Any, elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > 0x200:
        raise ValueError("EventManager::push read exceeds bounded probe limit")
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
        _read_exec_range(fp, elf, TARGET["entry"], TARGET["size"]), TARGET["entry"]
    ))
    if not rows:
        raise ValueError("EventManager::push did not decode")
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


def _observe(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0x7EF960, "push.w")
    _require(rows, 0x7EF966, "mov", operands="r4, r0")
    _require(rows, 0x7EF96A, "mov", operands="r0, r1")
    _require(rows, 0x7EF96C, "mov", operands="r5, r1")
    _require(rows, 0x7EF96E, "mov", operands="r6, r2")
    _require(rows, 0x7EF970, "bl", target=0x7EF88C)
    _require(rows, 0x7EF974, "cmp", immediate=1)
    _require(rows, 0x7EF978, "bne", target=0x7EF9D2)
    _require(rows, 0x7EF988, "blx", operands="r3")
    _require(rows, 0x7EF990, "bl", target=0x7F0AAC)
    _require(rows, 0x7EF998, "bl", target=0x7F0AA0)
    _require(rows, 0x7EF9A8, "cbnz", target=0x7EF9C4)
    _require(rows, 0x7EF9C4, "mov", operands="r0, r4")
    _require(rows, 0x7EF9C6, "bl", target=0x7EF902)
    _require(rows, 0x7EF9CA, "cbz", target=0x7EF9EA)
    _require(rows, 0x7EF9CE, "blx", operands="r3")
    _require(rows, 0x7EF9D2, "cbnz", target=0x7EF9EA)
    _require(rows, 0x7EF9D6, "bl", target=0x7EF8F4)
    _require(rows, 0x7EF9E0, "bl", target=0x7F0AAC)
    _require(rows, 0x7EF9E6, "bl", target=0x7EF902)
    _require(rows, 0x7EF9EA, "movs", immediate=0)
    _require(rows, 0x7EF9F2, "pop.w")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "abi": {
            "r0": "EventManager* receiver candidate",
            "r1": "Event* candidate preserved in r5",
            "r2": "bool candidate preserved in r6; exact truth convention is static only",
            "return": "visible r0=0 on all observed exits",
        },
        "pre_dispatch": "calls local 0x7ef88c with Event* and branches on returned status == 1",
        "success_path": {
            "guard": "status == 1",
            "indirect_dispatch": "loads [this] and invokes function pointer from [this+8] with [this+0] and Event*",
            "helpers": ["0x7f0aac", "0x7f0aa0", "0xbc8574", "0xdcae4", "0x7f1c7c"],
        },
        "non_success_path": {
            "guard": "status == 0 reaches cleanup helper sequence; non-zero status exits",
            "indirect_dispatch": "none observed before cleanup",
            "helpers": ["0x7f0aac", "0x7ef902"],
        },
        "completion": "when incoming r2 is non-zero, invokes function pointer at [this+4] after common cleanup",
        "semantic_limits": "helper meanings, queue/thread behavior, Event ownership and completion result remain UNKNOWN",
        "runtime_verified": False,
        "callable": False,
    }


def probe_event_manager_push(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Validate the bounded EventManager::push implementation."""
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
        value, size = _symbols(elf).get(TARGET["symbol"], (0, 0))
        if (value & ~1) != TARGET["entry"] or size != TARGET["size"]:
            raise ValueError("EventManager::push symbol identity mismatch")
        observation = _observe(_decode(fp, elf))
    return {
        "status": "LOCAL_PRIMARY_ELF_EVENT_MANAGER_PUSH_EVIDENCE_ONLY",
        "binary_file_sha256": digest,
        "address_space": "ELF_VMA",
        "target": TARGET,
        "observation": observation,
        "runtime_verified": False,
        "callable": False,
    }


def validate_event_manager_push(report: dict[str, Any]) -> dict[str, Any]:
    """Reject wrong identity or promotion beyond static evidence."""
    errors: list[str] = []
    if report.get("binary_file_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != "ELF_VMA":
        errors.append("address_space")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    if report.get("target", {}).get("entry") != TARGET["entry"]:
        errors.append("target_entry")
    if report.get("observation", {}).get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("observation_status")
    return {"valid": not errors, "errors": sorted(set(errors))}
