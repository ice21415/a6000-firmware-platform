"""Bounded primary-ELF probe for the EventManager layout initializer candidate."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from capstone.arm import ARM_OP_IMM
from elftools.elf.elffile import ELFFile

from .elf_plt import resolve_plt_binding
from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA


TARGET = {"name": "event_manager_layout_initializer_candidate", "entry": 0x7EF894, "size": 0x4E}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_exec_range(fp: Any, elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > 0x100:
        raise ValueError("EventManager initializer read exceeds bounded probe limit")
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
        raise ValueError("EventManager initializer candidate did not decode")
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


def _observe(rows: dict[int, Any], mutex_init: dict[str, Any], array_alloc: dict[str, Any], word_alloc: dict[str, Any]) -> dict[str, Any]:
    _require(rows, 0x7EF894, "push")
    _require(rows, 0x7EF896, "mov", operands="r6, r2")
    _require(rows, 0x7EF89A, "mov", operands="r4, r0")
    _require(rows, 0x7EF89C, "mov", operands="r5, r1")
    _require(rows, 0x7EF89E, "add.w", operands="r0, r0, #0xc")
    _require(rows, 0x7EF8A2, "movs", operands="r1, #0")
    _require(rows, 0x7EF8A4, "blx", target=0xE2AA0)
    _require(rows, 0x7EF8A8, "ldr", operands="r3, [r6]")
    _require(rows, 0x7EF8AA, "str", operands="r5, [r4, #4]")
    _require(rows, 0x7EF8AE, "ldr", operands="r3, [r3, #0x30]")
    _require(rows, 0x7EF8B0, "blx", operands="r3")
    _require(rows, 0x7EF8B2, "str", operands="r0, [r4, #8]")
    _require(rows, 0x7EF8B4, "movs", operands="r0, #8")
    _require(rows, 0x7EF8B6, "blx", target=0xE0E00)
    _require(rows, 0x7EF8BA, "str", operands="r0, [r4]")
    _require(rows, 0x7EF8BE, "blx", target=0xDC100)
    _require(rows, 0x7EF8C4, "bl", target=0x7F09BE)
    _require(rows, 0x7EF8C8, "ldr", operands="r3, [r4]")
    _require(rows, 0x7EF8CC, "str", operands="r5, [r3]")
    _require(rows, 0x7EF8CE, "blx", target=0xDC100)
    _require(rows, 0x7EF8D4, "bl", target=0x7F09BE)
    _require(rows, 0x7EF8D8, "ldr", operands="r3, [r4]")
    _require(rows, 0x7EF8DA, "mov", operands="r0, r4")
    _require(rows, 0x7EF8DC, "str", operands="r5, [r3, #4]")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "identity": "layout-compatible initializer candidate for EventManager::push; no constructor symbol proof",
        "inputs": {
            "r0": "initializer receiver candidate",
            "r1": "callback/function pointer candidate stored at receiver +4",
            "r2": "provider/context object candidate with vtable slot +0x30",
        },
        "layout": {
            "+0x00": "pointer to an 8-byte state allocation from _Znaj",
            "+0x04": "incoming r1 callback candidate",
            "+0x08": "return value of provider vtable slot +0x30",
            "+0x0c": "pthread_mutex_init(receiver +0x0c, 0) call",
            "state_+0": "8-byte allocation from _Znwj initialized by local 0x7f09be",
            "state_+4": "second 8-byte allocation from _Znwj initialized by local 0x7f09be",
        },
        "bindings": {"mutex_init": mutex_init, "state_array_alloc": array_alloc, "state_word_alloc": word_alloc},
        "runtime_verified": False,
        "callable": False,
    }


def probe_event_manager_init(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Validate the bounded EventManager layout initializer candidate."""
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
        observation = _observe(
            _decode(fp, elf),
            _binding(fp, elf, 0xE2AA0),
            _binding(fp, elf, 0xE0E00),
            _binding(fp, elf, 0xDC100),
        )
    return {
        "status": "LOCAL_PRIMARY_ELF_EVENT_MANAGER_INIT_EVIDENCE_ONLY",
        "binary_file_sha256": digest,
        "address_space": "ELF_VMA",
        "target": TARGET,
        "observation": observation,
        "runtime_verified": False,
        "callable": False,
    }


def validate_event_manager_init(report: dict[str, Any]) -> dict[str, Any]:
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
    observation = report.get("observation", {})
    if observation.get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("observation_status")
    for key in ("mutex_init", "state_array_alloc", "state_word_alloc"):
        if observation.get("bindings", {}).get(key, {}).get("status") != "VERIFIED_STATIC":
            errors.append(f"binding:{key}")
    return {"valid": not errors, "errors": sorted(set(errors))}
