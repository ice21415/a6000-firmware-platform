"""Evidence-gated EventManager callback pointer provenance probe."""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from elftools.elf.elffile import ELFFile

EXPECTED_SHA256 = "8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a"
CALLBACK_SLOT = 0x1031894
CALLBACK_ENTRY = 0x7EEB24


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_vma(stream: Any, elf: ELFFile, vma: int, size: int) -> bytes:
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD":
            continue
        base, length = int(segment["p_vaddr"]), int(segment["p_filesz"])
        if base <= vma and vma + size <= base + length:
            stream.seek(int(segment["p_offset"]) + vma - base)
            data = stream.read(size)
            if len(data) == size:
                return data
    raise ValueError(f"VMA 0x{vma:x} is not file-backed")


def _has_relative_relocation(elf: ELFFile, vma: int) -> bool:
    for section in elf.iter_sections():
        if not hasattr(section, "iter_relocations"):
            continue
        for relocation in section.iter_relocations():
            if int(relocation["r_offset"]) == vma and int(relocation["r_info_type"]) == 23:
                return True
    return False


def probe_event_manager_callback(path: Path, *, expected_sha256: str = EXPECTED_SHA256) -> dict[str, Any]:
    actual = _sha256(path)
    if actual != expected_sha256:
        raise ValueError("ELF SHA-256 does not match the pinned input")
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if not _has_relative_relocation(elf, CALLBACK_SLOT):
            raise ValueError("callback slot lacks R_ARM_RELATIVE relocation")
        slot_offset = None
        for segment in elf.iter_segments():
            if (segment["p_type"] == "PT_LOAD" and
                    int(segment["p_vaddr"]) <= CALLBACK_SLOT <
                    int(segment["p_vaddr"]) + int(segment["p_filesz"])):
                slot_offset = int(segment["p_offset"]) + CALLBACK_SLOT - int(segment["p_vaddr"])
                break
        if slot_offset is None:
            raise ValueError("callback slot is not file-backed")
        stream.seek(slot_offset)
        stored = struct.unpack("<I", stream.read(4))[0]
        callback_bytes = _read_vma(stream, elf, CALLBACK_ENTRY, 0x40)
    instructions = [
        {"instruction_vma": hex(row.address), "mnemonic": row.mnemonic,
         "operands": row.op_str}
        for row in Cs(CS_ARCH_ARM, CS_MODE_THUMB).disasm(callback_bytes, CALLBACK_ENTRY)
    ]
    return {
        "status": "PRIMARY_ELF_RELOCATION_STATIC",
        "elf_sha256": actual,
        "address_space": "ELF_VMA",
        "slot_vma": hex(CALLBACK_SLOT),
        "stored_thumb_value": hex(stored),
        "callback_entry_vma": hex(stored & ~1),
        "relocation": "R_ARM_RELATIVE",
        "consumer_callsite": "0x7ef9ce",
        "field": "EventManager +0x04",
        "verification": "STATIC_INFERRED",
        "instructions": instructions,
        "semantic_identity": "error/termination callback candidate; not a ModelCamera consumer",
        "unresolved_conditions": ["owner provider initialization and callback activation condition",
                                   "runtime object identity and callback semantics"],
        "runtime_verified": False,
    }


def validate_event_manager_callback(result: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if result.get("address_space") != "ELF_VMA":
        errors.append("address_space")
    if result.get("verification") != "STATIC_INFERRED":
        errors.append("verification_promotion")
    if result.get("callback_entry_vma") != hex(CALLBACK_ENTRY):
        errors.append("callback_target")
    if result.get("runtime_verified") is not False:
        errors.append("runtime_promotion")
    return errors


__all__ = ["probe_event_manager_callback", "validate_event_manager_callback", "CALLBACK_SLOT", "CALLBACK_ENTRY"]
