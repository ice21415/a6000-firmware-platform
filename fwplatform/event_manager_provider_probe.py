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


def _memory_ranges(elf: ELFFile) -> dict[str, int]:
    for segment in elf.iter_segments():
        if segment["p_type"] == "PT_LOAD" and int(segment["p_vaddr"]) <= FUNCTION_POINTER_CELL < int(segment["p_vaddr"]) + int(segment["p_memsz"]):
            return {"segment_vma": int(segment["p_vaddr"]), "file_end": int(segment["p_vaddr"]) + int(segment["p_filesz"]), "memory_end": int(segment["p_vaddr"]) + int(segment["p_memsz"])}
    return {}


def _bounded_store_scan(stream: Any, elf: ELFFile, target: int) -> dict[str, Any]:
    """Conservative Thumb store scan; never promotes candidates to writers.

    It only records a store when the target address is explicitly present in
    the bounded decoded window. Register-derived aliases without a proven
    constant are intentionally reported as unresolved.
    """
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    references: list[dict[str, Any]] = []
    instruction_count = 0
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD" or not (int(segment["p_flags"]) & 1):
            continue
        stream.seek(int(segment["p_offset"]))
        data = stream.read(int(segment["p_filesz"]))
        instructions = list(decoder.disasm(data, int(segment["p_vaddr"])))
        instruction_count += len(instructions)
        for index, insn in enumerate(instructions):
            if not insn.mnemonic.startswith(("str", "stm")):
                continue
            window = instructions[max(0, index - 8): index + 1]
            text = " ".join(f"{row.mnemonic} {row.op_str}" for row in window)
            if hex(target) in text:
                references.append({"instruction_vma": hex(insn.address), "mnemonic": insn.mnemonic, "operands": insn.op_str, "classification": "POSSIBLE_WRITE"})
    return {"mode": "THUMB", "instruction_count": instruction_count, "candidates": references, "coverage": "explicit-target-only; register-derived aliases unresolved"}


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


def inventory_init_array(path: Path, *, expected_sha256: str = EXPECTED_SHA256) -> dict[str, Any]:
    """Inventory init-array entries without treating them as provider writers.

    Entries are only address records. A constructor-to-BSS relation requires a
    separate bounded disassembly/dataflow pass and is intentionally left
    unresolved here.
    """
    path = Path(path)
    actual = _sha256(path)
    if actual != expected_sha256:
        raise ValueError("ELF SHA-256 does not match pinned input")
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        section = elf.get_section_by_name(".init_array")
        if section is None or int(section["sh_size"]) % 4:
            raise ValueError("invalid or missing .init_array")
        stream.seek(int(section["sh_offset"]))
        raw = stream.read(int(section["sh_size"]))
        entries: list[dict[str, Any]] = []
        symbol_by_value: dict[int, str] = {}
        for symtab in (elf.get_section_by_name(".symtab"), elf.get_section_by_name(".dynsym")):
            if symtab is None:
                continue
            for sym in symtab.iter_symbols():
                value = int(sym["st_value"])
                if value and int(sym["st_size"]):
                    symbol_by_value.setdefault(value, sym.name)
        relocation_by_offset: dict[int, list[dict[str, Any]]] = {}
        for relocation_section in elf.iter_sections():
            if not hasattr(relocation_section, "iter_relocations"):
                continue
            symtab = elf.get_section(relocation_section["sh_link"]) if relocation_section["sh_link"] else None
            for relocation in relocation_section.iter_relocations():
                offset_value = int(relocation["r_offset"])
                idx = int(relocation["r_info_sym"])
                symbol_obj = symtab.get_symbol(idx) if symtab is not None else None
                relocation_by_offset.setdefault(offset_value, []).append({"section": relocation_section.name, "type": int(relocation["r_info_type"]), "symbol_index": idx, "symbol": symbol_obj.name if symbol_obj else ""})
        store_count = 0
        direct_target_stores: list[str] = []
        for offset in range(0, len(raw), 4):
            slot = int(section["sh_addr"]) + offset
            target = struct.unpack_from("<I", raw, offset)[0]
            entry = target & ~1
            mode = "THUMB" if target & 1 else "ARM"
            symbol = symbol_by_value.get(entry)
            # Bounded first-level body inspection. It is deliberately not a
            # complete CFG: only file-backed entry bytes up to 100 bytes are
            # decoded, and no store is promoted without destination dataflow.
            try:
                body = _read(stream, elf, entry, 100)
                decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB if mode == "THUMB" else CS_MODE_ARM)
                body_rows = list(decoder.disasm(body, entry))
                for row in body_rows:
                    if row.mnemonic.startswith(("str", "stm")):
                        store_count += 1
                        if hex(FUNCTION_POINTER_CELL) in row.op_str:
                            direct_target_stores.append(hex(row.address))
            except ValueError:
                body_rows = []
            entries.append({
                "table_slot_vma": hex(slot),
                "raw_pointer": hex(target),
                "resolved_function_vma": hex(entry),
                "mode": mode,
                "function_boundary_confidence": "SYMBOL_MATCH" if symbol else "ADDRESS_ONLY",
                "symbol": symbol,
                "relocations": relocation_by_offset.get(slot, []),
                "first_level_direct_callees": "UNKNOWN",
                "candidate_bss_writes": [],
                "analysis_coverage": "ENTRY_PLUS_100_BYTES_NO_COMPLETE_CFG",
                "unresolved_conditions": ["constructor body and indirect calls require bounded follow-up analysis"],
            })
        return {
            "status": "PRIMARY_ELF_INIT_ARRAY_INVENTORY",
            "elf_sha256": actual,
            "address_space": "ELF_VMA",
            "table_vma": hex(int(section["sh_addr"])),
            "size": int(section["sh_size"]),
            "entry_count": len(entries),
            "entries": entries,
            "bss_target": hex(FUNCTION_POINTER_CELL),
            "confirmed_constructor_writers": [],
            "bounded_store_destinations_examined": store_count,
            "direct_target_store_candidates": direct_target_stores,
        }


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
        ranges = _memory_ranges(elf)
        store_scan = _bounded_store_scan(stream, elf, FUNCTION_POINTER_CELL)
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
            # Backward-compatible name retained; this is the table slot's
            # initial relocated pointer, not the runtime contents of BSS.
            "initial_cell_value": hex(initial_pointer),
            "table_slot_initial_value": hex(initial_pointer),
            "indirection_level": 2,
            "bss_cell": {
                "vma": hex(FUNCTION_POINTER_CELL),
                "file_backed": bool(ranges and FUNCTION_POINTER_CELL < ranges["file_end"]),
                "pt_load_memory_end": hex(ranges["memory_end"]) if ranges else None,
                "runtime_value": "UNKNOWN",
            },
            "writer_search": {
                "method": "executable PT_LOAD absolute pointer reference scan",
                "literal_references": literal_hits,
                "direct_literal_writers": literal_hits,
                "store_dataflow_candidates": store_scan["candidates"],
                "store_dataflow_scan": store_scan,
                "status": "NO_LOCAL_WRITER_FOUND_WITHIN_LITERAL_SCAN" if not literal_hits else "CANDIDATE",
                "coverage_limit": "Store dataflow, PC-relative/register-derived aliases and external DSO writers require separate analysis",
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
    if result.get("indirection_level") != 2: errors.append("indirection_level")
    bss = result.get("bss_cell")
    if not isinstance(bss, dict) or bss.get("vma") != hex(FUNCTION_POINTER_CELL) or bss.get("file_backed") is not False:
        errors.append("bss_mapping")
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
    if isinstance(writer_search, dict) and "literal_references" not in writer_search:
        errors.append("literal_references")
    scan = writer_search.get("store_dataflow_scan") if isinstance(writer_search, dict) else None
    if not isinstance(scan, dict) or scan.get("mode") != "THUMB" or not isinstance(scan.get("instruction_count"), int):
        errors.append("store_dataflow_scan")
    if result.get("provider_vtable_slot") != "+0x30": errors.append("vtable_slot")
    if result.get("runtime_verified") is not False: errors.append("runtime_promotion")
    return errors


__all__ = ["probe_event_manager_provider", "validate_event_manager_provider", "inventory_init_array", "GETTER_ENTRY", "FUNCTION_POINTER_TABLE_SLOT", "FUNCTION_POINTER_CELL"]
