"""Evidence-gated ParamList mutation and lifetime probe.

This module reads only the authenticated private ``libObj.so`` and validates
bounded Capstone observations for clear, destruction, and the unnamed
assignment-like body.  It emits field-level metadata rather than firmware
bytes or a native wrapper.  The unnamed body is intentionally called a
candidate: its stripped ELF has no source-level assignment symbol.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM
from elftools.elf.elffile import ELFFile

from .elf_plt import resolve_plt_binding
from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA


MAX_REGION_BYTES = 0x400
TARGETS: tuple[dict[str, Any], ...] = (
    {"name": "paramlist_clear_wrapper", "entry": 0x7EDB76, "size": 12,
     "symbol": "_ZN9ParamList5clearEv"},
    # Include the four-byte tail branch at 0x7edb72; the loop itself ends
    # before the public twelve-byte clear wrapper begins at 0x7edb76.
    {"name": "paramlist_clear_impl_candidate", "entry": 0x7EDB40, "size": 0x36},
    {"name": "paramlist_destructor", "entry": 0x7EDD08, "size": 46,
     "symbol": "_ZN9ParamListD1Ev", "symbol_value_thumb_tagged": "0x7edd09"},
    {"name": "paramlist_assignment_like_candidate", "entry": 0x7EDCC6, "size": 66},
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_exec_range(fp: Any, elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > MAX_REGION_BYTES:
        raise ValueError("bounded mutation read exceeds the probe limit")
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


def _decode(fp: Any, elf: ELFFile, entry: int, size: int) -> dict[int, Any]:
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    rows = list(decoder.disasm(_read_exec_range(fp, elf, entry, size), entry))
    if not rows:
        raise ValueError(f"no Thumb instructions at 0x{entry:x}")
    return {int(row.address): row for row in rows}


def _imm_target(ins: Any) -> int | None:
    values = [int(op.imm) for op in ins.operands if op.type == ARM_OP_IMM]
    return values[-1] if values else None


def _require(rows: dict[int, Any], address: int, mnemonic: str, target: int | None = None) -> None:
    ins = rows.get(address)
    if ins is None or ins.mnemonic.lower() != mnemonic:
        raise ValueError(f"unexpected instruction at 0x{address:x}")
    if target is not None and _imm_target(ins) != target:
        raise ValueError(f"unexpected branch target at 0x{address:x}")


def _observe_clear(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0x7EDB48, "ldr")
    _require(rows, 0x7EDB4A, "bl", 0x7EDAB0)
    _require(rows, 0x7EDB5E, "cbz", 0x7EDB66)
    _require(rows, 0x7EDB62, "ldr")
    _require(rows, 0x7EDB64, "blx")
    _require(rows, 0x7EDB68, "cmp")
    _require(rows, 0x7EDB6A, "blt", 0x7EDB54)
    _require(rows, 0x7EDB72, "b.w", 0x7EDB32)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "container_length_helper": "0x7edab0",
        "loop": "iterates indices from zero while index < element_count",
        "null_element_behavior": "skips null element before virtual dispatch",
        "element_cleanup": "loads element vptr and invokes slot +8",
        "container_release_helper": "0x7edb32",
    }


def _observe_destructor(rows: dict[int, Any], fp: Any, elf: ELFFile) -> dict[str, Any]:
    for address, mnemonic in ((0x7EDD08, "ldr"), (0x7EDD12, "subs"),
                              (0x7EDD14, "str"), (0x7EDD16, "cbnz"),
                              (0x7EDD18, "bl"), (0x7EDD28, "blx"),
                              (0x7EDD2E, "blx")):
        _require(rows, address, mnemonic)
    delete_binding = resolve_plt_binding(fp, elf, 0xDD620, thumb_stub=False)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "counter_field": "ParamList +0x04",
        "operation": "decrement shared counter; clear and release storage only when result is zero",
        "clear_target": "0x7edb40",
        "container_delete_callsite": "0x7edd28",
        "counter_delete_callsite": "0x7edd2e",
        "delete_binding": delete_binding,
        "runtime_allocator_interposition": "UNKNOWN",
    }


def _observe_assignment(rows: dict[int, Any]) -> dict[str, Any]:
    checks = ((0x7EDCC6, "cmp"), (0x7EDCD2, "ldr"), (0x7EDCD6, "subs"),
              (0x7EDCD8, "str"), (0x7EDCDA, "cbnz"), (0x7EDCDC, "bl"),
              (0x7EDCF6, "ldr"), (0x7EDCFA, "str"), (0x7EDCFC, "adds"),
              (0x7EDCFE, "str"), (0x7EDD00, "ldr"), (0x7EDD02, "str"))
    for address, mnemonic in checks:
        _require(rows, address, mnemonic)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "identity_guard": "cmp source and destination object pointers; self-assignment branches without mutation",
        "destination_release": "decrements destination shared counter and clears/releases on zero",
        "source_share": "copies source counter pointer and container pointer, then increments shared counter",
        "source_level": "STATIC_INFERRED; stripped body has no independently confirmed C++ assignment symbol",
        "copy_on_write_detach_observed": False,
        "thread_safety": "UNKNOWN",
    }


def probe_paramlist_mutation(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA
) -> dict[str, Any]:
    """Decode bounded ParamList mutation/lifetime witnesses from a private ELF."""
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
        decoded: dict[str, dict[str, Any]] = {}
        for target in TARGETS:
            rows = _decode(fp, elf, int(target["entry"]), int(target["size"]))
            name = target["name"]
            if name == "paramlist_clear_wrapper":
                _require(rows, 0x7EDB7E, "b.w", 0x7EDB40)
                facts = {"status": "PRIMARY_ELF_VERIFIED", "tail_target": "0x7edb40"}
            elif name == "paramlist_clear_impl_candidate":
                facts = _observe_clear(rows)
            elif name == "paramlist_destructor":
                facts = _observe_destructor(rows, fp, elf)
            else:
                facts = _observe_assignment(rows)
            decoded[name] = {
                "entry_vma": hex(int(target["entry"])),
                "size_bytes": int(target["size"]),
                "symbol": target.get("symbol"),
                "symbol_value_thumb_tagged": target.get("symbol_value_thumb_tagged"),
                "facts": facts,
            }
    return {
        "status": "LOCAL_PRIMARY_ELF_MUTATION_EVIDENCE_ONLY",
        "binary_file_sha256": digest,
        "address_space": "ELF_VMA",
        "targets": decoded,
        "borrowed_element_lifetime": "STATIC_INFERRED; element deletion in clear/replacement can invalidate get results",
        "copy_on_write_verified": False,
        "thread_safety_verified": False,
        "runtime_verified": False,
        "callable": False,
    }


def validate_paramlist_mutation(report: dict[str, Any]) -> dict[str, Any]:
    """Validate a report without upgrading static evidence to runtime safety."""
    errors: list[str] = []
    if report.get("binary_file_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != "ELF_VMA":
        errors.append("address_space")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    if report.get("copy_on_write_verified") is not False:
        errors.append("copy_on_write_claim")
    targets = report.get("targets")
    if not isinstance(targets, dict) or not {item["name"] for item in TARGETS}.issubset(targets):
        errors.append("missing_targets")
    else:
        for target in targets.values():
            if target.get("facts", {}).get("status") != "PRIMARY_ELF_VERIFIED":
                errors.append("target_status")
    return {"valid": not errors, "errors": sorted(set(errors)), "target_count": len(targets) if isinstance(targets, dict) else 0}
