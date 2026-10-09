"""Read-only, bounded Thumb instruction research on a user's PRIVATE ELF.

This works on exact-sha ELF32 LE ARM binaries; it never executes or patches
firmware and never publishes instruction bytes or auto-promotes an SDK ABI.
Capstone is a *decoder*, not proof that a region is a complete function.
"""
from __future__ import annotations

import hashlib
import re
import struct
from collections import deque
from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile

EXPECTED_LIBOBJ_SHA = "8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a"
MAX_ELF_BYTES = 128 * 1024 * 1024
MAX_REGION_BYTES = 8192
DEFAULT_REGION_BYTES = 1536
MAX_INSTRUCTIONS = 2048
MAX_LITERALS = 100
MAX_EVENT_HITS = 128
HEX_SHA = re.compile(r"[a-f0-9]{64}\Z")

TARGETS = (
    ("selector_transform_unknown", 0x12D780),
    ("application_submit_tail_candidate", 0x125084),
)


def _read_vma(fp: Any, elf: ELFFile, address: int, size: int, *, executable: bool) -> bytes:
    if size <= 0 or size > 16:
        raise ValueError("invalid bounded instruction/literal read")
    ranges = []
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD":
            continue
        flags = int(segment["p_flags"])
        if executable and not (flags & 1):
            continue
        base, count = int(segment["p_vaddr"]), int(segment["p_filesz"])
        if base <= address and address + size <= base + count:
            ranges.append(int(segment["p_offset"]) + address - base)
    if len(ranges) != 1:
        raise ValueError(f"ELF VMA {hex(address)} not uniquely file-backed by a "
                         + ("code" if executable else "load") + " segment")
    fp.seek(ranges[0])
    data = fp.read(size)
    if len(data) != size:
        raise ValueError("truncated ELF program-header content")
    return data


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _scan_word(fp: Any, elf: ELFFile, needle: int) -> list[dict[str, Any]]:
    """Find candidate encoded constants, NOT decoded references or consumers."""
    pattern = struct.pack("<I", needle)
    hits = []
    seen = set()
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD":
            continue
        base, size = int(segment["p_vaddr"]), int(segment["p_filesz"])
        if size > MAX_ELF_BYTES:
            raise ValueError("unbounded file-backed ELF load segment")
        fp.seek(int(segment["p_offset"]))
        data = fp.read(size)
        for i in range(0, len(data) - 3):
            if data[i:i + 4] != pattern:
                continue
            vma = base + i
            if vma in seen:
                continue
            seen.add(vma)
            if len(hits) == MAX_EVENT_HITS:
                return hits
            hits.append({"vma": hex(vma), "segment_is_executable": bool(int(segment["p_flags"]) & 1),
                         "classification": "RAW_WORD_OCCURRENCE_NOT_XREF_OR_CONSUMER"})
    return sorted(hits, key=lambda x: int(x["vma"], 16))


def _trace_thumb(fp: Any, elf: ELFFile, start: int, max_region: int) -> dict[str, Any]:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET
    from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC
    if start <= 0 or start & 1:
        raise ValueError("Thumb function entry must be a positive even ELF VMA")
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    end = start + max_region
    queue = deque([start])
    queued = {start}
    instructions: dict[int, dict[str, Any]] = {}
    observed_calls: list[dict[str, Any]] = []
    observed_branches: list[dict[str, Any]] = []
    observed_literals: list[dict[str, Any]] = []
    reasons: set[str] = set()
    while queue:
        block = queue.popleft()
        address = block
        while start <= address < end:
            if address in instructions:
                break
            if len(instructions) >= MAX_INSTRUCTIONS:
                reasons.add("MAX_INSTRUCTIONS")
                queue.clear()
                break
            try:
                raw = _read_vma(fp, elf, address, 4, executable=True)
            except ValueError:
                reasons.add("NON_EXECUTABLE_OR_AMBIGUOUS_VMA")
                break
            decoded = list(decoder.disasm(raw, address, count=1))
            if not decoded or decoded[0].size not in (2, 4):
                reasons.add("UNDECODED_INSTRUCTION")
                break
            ins = decoded[0]
            mnemonic = ins.mnemonic.lower()
            row = {"vma": hex(address), "mnemonic": ins.mnemonic,
                   "operands": ins.op_str, "size": ins.size}
            instructions[address] = row
            for operand in ins.operands:
                if operand.type == ARM_OP_MEM and operand.mem.base == ARM_REG_PC and len(observed_literals) < MAX_LITERALS:
                    literal_vma = ((address + 4) & ~3) + operand.mem.disp
                    entry: dict[str, Any] = {"load_site": hex(address), "literal_vma": hex(literal_vma)}
                    try:
                        value = _read_vma(fp, elf, literal_vma, 4, executable=False)
                        entry["u32_le"] = hex(struct.unpack("<I", value)[0])
                    except ValueError:
                        entry["u32_le"] = None
                    observed_literals.append(entry)
            immediate = [int(op.imm) for op in ins.operands if op.type == ARM_OP_IMM]
            target = immediate[-1] if immediate else None
            is_call = ins.group(CS_GRP_CALL)
            is_jump = ins.group(CS_GRP_JUMP)
            is_return = ins.group(CS_GRP_RET) or mnemonic in ("pop", "pop.w") and "pc" in ins.op_str
            is_jump = is_jump or mnemonic in ("tbb", "tbh", "bx", "cbz", "cbnz")
            if is_call:
                observed_calls.append({"callsite": hex(address), "mnemonic": ins.mnemonic,
                                       "target_vma": hex(target) if target is not None else None,
                                       "kind": "REPORTED_DIRECT_TARGET" if target is not None else "INDIRECT_UNRESOLVED"})
                address += ins.size
                continue
            if is_return:
                break
            if is_jump:
                if target is not None:
                    observed_branches.append({"site": hex(address), "target_vma": hex(target),
                                              "mnemonic": ins.mnemonic})
                    normalized = target & ~1
                    if start <= normalized < end and normalized not in queued and normalized not in instructions:
                        queued.add(normalized)
                        queue.append(normalized)
                    elif not start <= normalized < end:
                        reasons.add("OUT_OF_BOUNDED_REGION_BRANCH")
                else:
                    observed_branches.append({"site": hex(address), "target_vma": None,
                                              "mnemonic": ins.mnemonic})
                    reasons.add("INDIRECT_BRANCH_UNRESOLVED")
                unconditional = mnemonic in ("b", "b.w", "bx", "tbh", "tbb")
                if not unconditional and address + ins.size < end:
                    next_address = address + ins.size
                    if next_address not in queued and next_address not in instructions:
                        queued.add(next_address)
                        queue.append(next_address)
                break
            address += ins.size
        if address >= end:
            reasons.add("BOUNDED_REGION_LIMIT")
    return {
        "entry_vma": hex(start), "region_limit_bytes": max_region,
        "decoded_instruction_count": len(instructions),
        "instruction_observations": [instructions[k] for k in sorted(instructions)],
        "direct_or_indirect_calls": observed_calls, "branch_observations": observed_branches,
        "literal_load_candidates": observed_literals,
        "incompleteness_reasons": sorted(reasons),
        "whole_function_cfg_verified": False,
        "dataflow_to_modelcamera_selector_verified": False,
    }


def trace_private_selector_elf(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA,
    entries: tuple[tuple[str, int], ...] = TARGETS,
    max_region_bytes: int = DEFAULT_REGION_BYTES,
    event_word: int = 0x11004003,
) -> dict[str, Any]:
    """Confirm ELF identity; perform constrained nonexecuting disassembly."""
    path = Path(elf_path).resolve()
    if not path.is_file() or not 0 < path.stat().st_size <= MAX_ELF_BYTES:
        raise ValueError("private ELF file is missing, empty, or exceeds the 128 MiB limit")
    if not HEX_SHA.fullmatch(expected_sha256):
        raise ValueError("exact expected ELF digest must be a lowercase SHA-256")
    if not 16 <= max_region_bytes <= MAX_REGION_BYTES or max_region_bytes & 1:
        raise ValueError("per-function region must be even and within 16..8192 bytes")
    if not isinstance(event_word, int) or isinstance(event_word, bool) or not 0 <= event_word < (1 << 32):
        raise ValueError("event search word must be a uint32")
    if len(entries) > 8 or not entries:
        raise ValueError("between 1 and 8 investigation entries required")
    for role, address in entries:
        if not isinstance(role, str) or not role or isinstance(address, bool) or not isinstance(address, int):
            raise ValueError("invalid investigation function entry")
    actual = _sha256(path)
    if actual != expected_sha256:
        raise ValueError("private ELF full-file SHA-256 mismatch: refusing disassembly")
    with path.open("rb") as fp:
        elf = ELFFile(fp)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_ARM":
            raise ValueError("requires ELF32 little-endian ARM")
        if elf["e_type"] not in ("ET_EXEC", "ET_DYN"):
            raise ValueError("requires executable or shared library")
        traced = []
        for role, entry in entries:
            # A target entry must map to one executable file-backed segment.
            # Ambiguous executable mappings are invalid, not partial successes.
            if not isinstance(entry, int) or isinstance(entry, bool) or entry <= 0 or entry & 1:
                raise ValueError("Thumb function entry must be a positive even ELF VMA")
            _read_vma(fp, elf, entry, 4, executable=True)
            report = _trace_thumb(fp, elf, entry, max_region_bytes)
            report["research_role_hint"] = role
            traced.append(report)
        matches = _scan_word(fp, elf, event_word)
    return {
        "status": "PRIVATE_ELF_BOUNDED_OPCODE_TRACE_ONLY",
        "input_sha256": actual, "format": "ELF32_LE_ARM",
        "function_regions": traced,
        "literal_event_word": hex(event_word),
        "unclassified_event_word_occurrences": matches,
        "event_consumer_identified": False,
        "selector_helper_semantics_verified": False,
        "abi_verified": False,
        "device_executed": False,
        "note": "Decoder instruction rows and raw-word occurrences are investigation aids, not complete control flow, semantic interpretation, event consumers, or safe callable SDK APIs.",
    }
