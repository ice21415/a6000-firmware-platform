"""Verify reported Thumb-2 Camera branches and byte loads against a PRIVATE ELF.

This module does NOT execute code or infer callable Sony APIs. It reads a
locally supplied 32-bit little-endian ARM ELF, requires exact SHA-256, maps
executable PT_LOAD VMAs, and decodes only unambiguous BL / B.W immediate and
LDRB.W / STRB.W unsigned immediate encodings. All other encodings FAIL CLOSED.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile

MAX_ELF_BYTES = 128 * 1024 * 1024
DIRECT = re.compile(r"(bl|b\.w) #?(0x[0-9a-f]+)\Z", re.I)


def _num(value: Any, description: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"{description}: invalid address or offset")
    try:
        v = int(str(value).strip(), 0)
    except ValueError as exc:
        raise ValueError(f"{description}: invalid address or offset") from exc
    if v < 0:
        raise ValueError(f"{description}: negative address or offset")
    return v


def _thumb_imm_branch(data: bytes, vma: int) -> tuple[str, int] | None:
    """Decode Thumb-2 BL T1 and unconditional B.W T4 immediate encodings."""
    if len(data) != 4 or vma & 1:
        return None
    first = int.from_bytes(data[:2], "little")
    second = int.from_bytes(data[2:], "little")
    if first & 0xF800 != 0xF000:
        return None
    op = second & 0xD000
    if op == 0xD000:
        kind = "bl"
    elif op == 0x9000:
        kind = "b.w"
    else:
        # BLX, conditional B.W or other opcode: do not guess.
        return None
    s = (first >> 10) & 1
    j1, j2 = (second >> 13) & 1, (second >> 11) & 1
    i1, i2 = 1 ^ (j1 ^ s), 1 ^ (j2 ^ s)
    imm = ((s << 24) | (i1 << 23) | (i2 << 22)
           | ((first & 0x3FF) << 12) | ((second & 0x7FF) << 1))
    if imm & (1 << 24):
        imm -= 1 << 25
    return kind, vma + 4 + imm


def _thumb_byte_imm(data: bytes) -> tuple[str, int] | None:
    """Decode ONLY Thumb LDRB.W/STRB.W unsigned imm12; omit base/dataflow."""
    if len(data) != 4:
        return None
    first = int.from_bytes(data[:2], "little")
    second = int.from_bytes(data[2:], "little")
    op = first & 0xFFF0
    if op == 0xF890:
        return "FIELD_READ", second & 0xFFF
    if op == 0xF880:
        return "FIELD_WRITE", second & 0xFFF
    return None


def _exec_vma_bytes(fp: Any, elf: ELFFile, vma: int) -> bytes:
    """Four bytes must be wholly inside ONE unambiguous file-backed RX span."""
    spans: list[tuple[int, int]] = []
    for seg in elf.iter_segments():
        if seg["p_type"] != "PT_LOAD" or int(seg["p_flags"]) & 1 == 0:
            continue
        base = int(seg["p_vaddr"])
        size = int(seg["p_filesz"])
        if base <= vma and vma + 4 <= base + size:
            offset = int(seg["p_offset"]) + (vma - base)
            spans.append((offset, offset + 4))
    if len(spans) != 1:
        raise ValueError(f"ELF executable VMA {hex(vma)} has {len(spans)} unique mappings; require exactly one")
    fp.seek(spans[0][0])
    data = fp.read(4)
    if len(data) != 4:
        raise ValueError(f"ELF executable VMA {hex(vma)} has truncated instruction data")
    return data


def verify_camera_elf(
    elf_path: Path, expected_sha256: str,
    calls: list[dict[str, Any]], fields: list[dict[str, Any]],
) -> dict[str, Any]:
    """Verify PRIVATE file bytes; return no copyrighted binary instructions."""
    path = Path(elf_path).resolve()
    if not path.is_file() or not 0 < path.stat().st_size <= MAX_ELF_BYTES:
        raise ValueError("camera ELF is missing, empty or exceeds the 128 MiB read-only limit")
    digest = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual != expected_sha256.lower():
        raise ValueError("camera ELF SHA-256 differs from research catalog; refusing address verification")
    branch_results: list[dict[str, Any]] = []
    byte_results: list[dict[str, Any]] = []
    with path.open("rb") as fp:
        elf = ELFFile(fp)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_ARM":
            raise ValueError("camera ELF verifier supports only 32-bit little-endian ARM")
        if elf["e_type"] not in {"ET_DYN", "ET_EXEC"}:
            raise ValueError("camera ELF must be a shared library or executable")
        for edge in calls:
            vma = _num(edge["callsite"], "callsite")
            asm = edge["instruction"]
            match = DIRECT.fullmatch(asm)
            if match is None:
                branch_results.append({
                    "callsite": hex(vma), "caller": edge["caller"], "callee": edge["callee"],
                    "result": "UNSUPPORTED_REPORTED_BRANCH",
                })
                continue
            expected_target = _num(asm.split("#")[-1].strip(), "reported target")
            raw = _exec_vma_bytes(fp, elf, vma)
            decoded = _thumb_imm_branch(raw, vma)
            ok = bool(decoded and decoded == (match.group(1).lower(), expected_target))
            branch_results.append({
                "callsite": hex(vma), "caller": edge["caller"], "callee": edge["callee"],
                "result": "MATCH_EXACT_ELF_OPCODE_AND_TARGET" if ok else "ELF_OPCODE_OR_TARGET_MISMATCH",
            })
        for field in fields:
            vma = _num(field["instruction_address"], "field instruction")
            raw_offset = _num(field["instruction_immediate_offset"], "raw byte immediate")
            raw = _exec_vma_bytes(fp, elf, vma)
            decoded = _thumb_byte_imm(raw)
            expect_op = "FIELD_READ" if field["kind"] == "FIELD_READ" else "FIELD_WRITE"
            ok = bool(decoded and decoded == (expect_op, raw_offset))
            byte_results.append({
                "instruction_address": hex(vma), "owner": field["owner"],
                "raw_displacement": hex(raw_offset),
                "inferred_model_root_offset": field["object_field_offset"],
                "result": "MATCH_EXACT_ELF_BYTE_OPCODE_AND_IMMEDIATE" if ok
                          else "ELF_BYTE_OPCODE_OR_IMMEDIATE_MISMATCH",
                "object_root_proven_by_opcode_alone": False,
            })
    passes = sum(x["result"] == "MATCH_EXACT_ELF_OPCODE_AND_TARGET" for x in branch_results)
    byte_passes = sum(x["result"] == "MATCH_EXACT_ELF_BYTE_OPCODE_AND_IMMEDIATE" for x in byte_results)
    complete = passes == len(branch_results) and byte_passes == len(byte_results)
    return {
        "status": "ELF_INSTRUCTION_CHECKS_PASS" if complete else "ELF_INSTRUCTION_CHECKS_INCOMPLETE",
        "input_sha256": actual,
        "format": "ELF32_LE_ARM_EXECUTABLE_PT_LOAD",
        "checked_direct_branches": len(branch_results),
        "matching_direct_branches": passes,
        "checked_byte_fields": len(byte_results),
        "matching_byte_fields": byte_passes,
        "branch_checks": branch_results,
        "field_checks": byte_results,
        "all_checked_instruction_sites_match": complete,
        "validated_scope": "Exact opcode/branch target or byte displacement only; caller function bodies and inferred object-root offset NOT established",
        "abi_verified": False,
        "runtime_callable": False,
    }
