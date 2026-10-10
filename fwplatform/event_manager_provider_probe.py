"""Static evidence for the EventManager provider getter and BSS indirection."""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from elftools.elf.elffile import ELFFile

EXPECTED_SHA256 = "8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a"
GETTER_ENTRY = 0x7EF1E4
TABLE_BASE = 0x102CBD0
FUNCTION_POINTER_TABLE_SLOT = 0x1032238
FUNCTION_POINTER_CELL = 0x10A8930


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _segment(elf: ELFFile, vma: int, size: int = 1) -> Any | None:
    for segment in elf.iter_segments():
        if (segment["p_type"] == "PT_LOAD" and int(segment["p_vaddr"]) <= vma
                and vma + size <= int(segment["p_vaddr"]) + int(segment["p_filesz"])):
            return segment
    return None


def _read(stream: Any, elf: ELFFile, vma: int, size: int) -> bytes:
    segment = _segment(elf, vma, size)
    if segment is None:
        raise ValueError(f"VMA 0x{vma:x} is not file-backed")
    stream.seek(int(segment["p_offset"]) + vma - int(segment["p_vaddr"]))
    data = stream.read(size)
    if len(data) != size:
        raise ValueError("truncated file-backed range")
    return data


def _relocations(elf: ELFFile, vma: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for section in elf.iter_sections():
        if not hasattr(section, "iter_relocations"):
            continue
        symtab = elf.get_section(section["sh_link"]) if section["sh_link"] else None
        for relocation in section.iter_relocations():
            if int(relocation["r_offset"]) == vma:
                index = int(relocation["r_info_sym"])
                symbol = symtab.get_symbol(index) if symtab is not None else None
                rows.append({"section": section.name, "type": int(relocation["r_info_type"]),
                             "symbol_index": index, "symbol": symbol.name if symbol else ""})
    return rows


def probe_event_manager_provider(path: Path, *, expected_sha256: str = EXPECTED_SHA256) -> dict[str, Any]:
    actual = _sha256(path)
    if actual != expected_sha256:
        raise ValueError("ELF SHA-256 does not match pinned input")
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_ARM":
            raise ValueError("probe accepts only ELF32 little-endian ARM")
        decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        rows = list(decoder.disasm(_read(stream, elf, GETTER_ENTRY, 0x60), GETTER_ENTRY))
        by_vma = {int(row.address): row for row in rows}
        required = {0x7EF234: ("ldr", "r3, [pc, #0x14]"),
                    0x7EF23A: ("ldr", "r3, [r4, r3]"),
                    0x7EF23C: ("blx", "r3")}
        for vma, (mnemonic, operands) in required.items():
            row = by_vma.get(vma)
            if row is None or row.mnemonic != mnemonic or row.op_str != operands:
                raise ValueError(f"provider getter instruction mismatch at 0x{vma:x}")
        table_value = struct.unpack("<I", _read(stream, elf, 0x7EF24C, 4))[0]
        initial_pointer = struct.unpack("<I", _read(stream, elf, FUNCTION_POINTER_TABLE_SLOT, 4))[0]
        # This scan intentionally only reports absolute pointer literals in
        # executable file data; PC-relative/indirect writers remain unresolved.
        literal_hits: list[str] = []
        needle = struct.pack("<I", FUNCTION_POINTER_CELL)
        for segment in elf.iter_segments():
            if segment["p_type"] == "PT_LOAD" and (int(segment["p_flags"]) & 1):
                stream.seek(int(segment["p_offset"]))
                data = stream.read(int(segment["p_filesz"]))
                start = 0
                while True:
                    found = data.find(needle, start)
                    if found < 0:
                        break
                    literal_hits.append(hex(int(segment["p_vaddr"]) + found))
                    start = found + 1
        init_array = elf.get_section_by_name(".init_array")
        return {
            "status": "PRIMARY_ELF_PROVIDER_GETTER_EVIDENCE",
            "elf_sha256": actual, "address_space": "ELF_VMA",
            "getter_entry_vma": hex(GETTER_ENTRY),
            "getter_instructions": [
                {"instruction_vma": hex(vma), "mnemonic": by_vma[vma].mnemonic,
                 "operands": by_vma[vma].op_str, "verification": "PRIMARY_ELF_VERIFIED"}
                for vma in sorted(required)
            ],
            "table_base_vma": hex(TABLE_BASE),
            "table_offset_literal_vma": "0x7ef24c",
            "table_offset": hex(table_value),
            "function_pointer_table_slot": hex(FUNCTION_POINTER_TABLE_SLOT),
            "function_pointer_table_relocations": _relocations(elf, FUNCTION_POINTER_TABLE_SLOT),
            "function_pointer_cell": hex(FUNCTION_POINTER_CELL),
            "initial_cell_value": hex(initial_pointer),
            "writer_search": {
                "method": "executable PT_LOAD absolute pointer literal scan",
                "direct_literal_writers": literal_hits,
                "status": "NO_LOCAL_WRITER_FOUND_WITHIN_LITERAL_SCAN" if not literal_hits else "CANDIDATE",
                "coverage_limit": "PC-relative, register-derived and external writers require separate dataflow analysis",
            },
            "init_array": {"vma": hex(int(init_array["sh_addr"])) if init_array else None,
                           "size": int(init_array["sh_size"]) if init_array else 0},
            "provider_vtable_slot": "+0x30",
            "runtime_provider_instance": "UNKNOWN",
            "main_dispatch_target": "UNKNOWN",
            "runtime_verified": False,
        }


def validate_event_manager_provider(result: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if result.get("status") != "PRIMARY_ELF_PROVIDER_GETTER_EVIDENCE": errors.append("status")
    if result.get("elf_sha256") != EXPECTED_SHA256: errors.append("binary_identity")
    if result.get("address_space") != "ELF_VMA": errors.append("address_space")
    if result.get("getter_entry_vma") != hex(GETTER_ENTRY): errors.append("getter_entry")
    required = {"0x7ef234": ("ldr", "r3, [pc, #0x14]"),
                "0x7ef23a": ("ldr", "r3, [r4, r3]"),
                "0x7ef23c": ("blx", "r3")}
    rows = {row.get("instruction_vma"): row for row in result.get("getter_instructions", []) if isinstance(row, dict)}
    for vma, (mnemonic, operands) in required.items():
        row = rows.get(vma)
        if not row or row.get("mnemonic") != mnemonic or row.get("operands") != operands or row.get("verification") != "PRIMARY_ELF_VERIFIED":
            errors.append(f"instruction_{vma}")
    if result.get("function_pointer_table_slot") != hex(FUNCTION_POINTER_TABLE_SLOT): errors.append("table_slot")
    if result.get("function_pointer_cell") != hex(FUNCTION_POINTER_CELL): errors.append("function_cell")
    relocations = result.get("function_pointer_table_relocations")
    if not isinstance(relocations, list) or not any(
        isinstance(row, dict) and row.get("section") == ".rel.dyn" and row.get("type") == 23
        and row.get("symbol_index") == 0 for row in relocations
    ):
        errors.append("table_relocation")
    writer_search = result.get("writer_search")
    if not isinstance(writer_search, dict) or writer_search.get("status") not in {
        "NO_LOCAL_WRITER_FOUND_WITHIN_LITERAL_SCAN", "CANDIDATE"
    }:
        errors.append("writer_search")
    if result.get("provider_vtable_slot") != "+0x30": errors.append("vtable_slot")
    if result.get("runtime_verified") is not False: errors.append("runtime_promotion")
    return errors


__all__ = ["probe_event_manager_provider", "validate_event_manager_provider", "GETTER_ENTRY", "FUNCTION_POINTER_TABLE_SLOT", "FUNCTION_POINTER_CELL"]
