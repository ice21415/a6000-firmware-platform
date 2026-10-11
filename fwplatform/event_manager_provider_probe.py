"""Static evidence for the EventManager provider getter and BSS indirection."""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, Cs
from elftools.elf.elffile import ELFFile
from .arm_store_dataflow import recover_provider_writes

EXPECTED_SHA256 = "8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a"
GETTER_ENTRY = 0x7EF1E4
TABLE_BASE = 0x102CBD0
FUNCTION_POINTER_TABLE_SLOT = 0x1031C38
FUNCTION_POINTER_CELL = 0x10A8930


def _memory_ranges(elf: ELFFile) -> dict[str, int]:
    for segment in elf.iter_segments():
        if segment["p_type"] == "PT_LOAD" and int(segment["p_vaddr"]) <= FUNCTION_POINTER_CELL < int(segment["p_vaddr"]) + int(segment["p_memsz"]):
            return {"segment_vma": int(segment["p_vaddr"]), "file_end": int(segment["p_vaddr"]) + int(segment["p_filesz"]), "memory_end": int(segment["p_vaddr"]) + int(segment["p_memsz"])}
    return {}



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
    """Recompute provider binding from pinned primary ELF, never JSON claims."""
    path = Path(path)
    actual = _sha256(path)
    if actual != expected_sha256:
        raise ValueError("ELF SHA-256 does not match pinned input")
    writer_cfg = recover_provider_writes(path, expected_sha256, additional_entries=[0x106da9, 0x106c6d, 0x7ef1e5])
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_ARM":
            raise ValueError("expected ELF32 little-endian ARM")
        decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        instructions = {row.address: row for row in decoder.disasm(_read(stream, elf, GETTER_ENTRY, 0x5c), GETTER_ENTRY)}
        required = {0x7ef1f4: ("ldr", "r4, [pc, #0x48]"), 0x7ef1f6: ("add", "r4, pc"), 0x7ef234: ("ldr", "r3, [pc, #0x14]"), 0x7ef23a: ("ldr", "r3, [r4, r3]"), 0x7ef23c: ("blx", "r3")}
        for address, expected in required.items():
            row = instructions.get(address)
            if row is None or (row.mnemonic, row.op_str) != expected:
                raise ValueError(f"instruction mismatch at {address:#x}")
        word = lambda address: struct.unpack("<I", _read(stream, elf, address, 4))[0]
        base = (0x7ef1f6 + 4 + word(0x7ef240)) & 0xffffffff
        offset = word(0x7ef24c)
        slot = (base + offset) & 0xffffffff
        relocations = _relocations(elf, slot)
        if len(relocations) != 1 or relocations[0]["type"] != 21 or relocations[0]["symbol"] != "getConfig":
            raise ValueError("getConfig dynamic binding not uniquely verified")
        checks = [(0x106c6c, 12, {0x106c72: ("ldr", "r0, [r0]")}),
                  (0x106c7c, 32, {0x106c96: ("adds", "r3, #8"), 0x106c98: ("str", "r3, [r4]")}),
                  (0x106da8, 24, {0x106db4: ("bl", "#0x106c7c"), 0x106dbc: ("str", "r4, [r3]")}),
                  (0x106900, 14, {0x10690a: ("ldr", "r0, [r3, r2]")})]
        for entry, size, expected_rows in checks:
            decoded = {i.address: i for i in decoder.disasm(_read(stream, elf, entry, size), entry)}
            for address, expected in expected_rows.items():
                row = decoded.get(address)
                if row is None or (row.mnemonic, row.op_str) != expected:
                    raise ValueError(f"provider chain instruction mismatch {address:#x}")
        singleton = (0x106c74 + word(0x106c78)) & 0xffffffff
        constructor_slot = (0x106c8e + word(0x106d40) + word(0x106d44)) & 0xffffffff
        vptr = word(constructor_slot) + 8
        if singleton != 0x10a8a9c or vptr != 0xfe9b70 or word(vptr + 0x30) != 0x106901:
            raise ValueError("singleton/vptr provenance mismatch")
        callback_slot = (0x106904 + 4 + word(0x106910) + word(0x106914)) & 0xffffffff
        callback_pointer = word(callback_slot)
        callback_relocations = _relocations(elf, callback_slot)
        if callback_slot != 0x1030f6c or callback_pointer != 0x11130d or not any(r["type"] == 23 for r in callback_relocations):
            raise ValueError("configuration callback relocation mismatch")
        return {"schema_version": 2, "status": "PRIMARY_ELF_PROVIDER_GETTER_EVIDENCE", "elf_sha256": actual,
                "address_space": "ELF_VMA", "getter_entry_vma": hex(GETTER_ENTRY),
                "getter_instructions": [{"instruction_vma": hex(a), "mnemonic": instructions[a].mnemonic, "operands": instructions[a].op_str, "verification": "PRIMARY_ELF_VERIFIED"} for a in required],
                "table_base_vma": hex(base), "table_offset": hex(offset), "function_pointer_table_slot": hex(slot),
                "function_pointer_table_relocations": relocations, "import_symbol": "getConfig", "indirection_level": 1,
                "superseded_bss_hypothesis": {"cell": "0x10a8930", "status": "DISPROVEN_AS_GETTER_DEPENDENCY", "reason": "incorrect slot arithmetic and nonexistent extra dereference"},
                "writer_cfg_analysis": writer_cfg,
                "configuration_callback": {"provider_vtable": "0xfe9b70", "slot_vma": "0xfe9ba0", "slot_target": "0x106900", "callback_slot": hex(callback_slot), "stored_thumb_pointer": hex(callback_pointer), "callback_entry": hex(callback_pointer & ~1), "relocations": callback_relocations, "selection": "conditional on AppConfig.so branch and successful initialization"},
                "provider_vtable_slot": "+0x30", "main_dispatch_target": "CONDITIONAL_CANDIDATE_0x11130c", "runtime_verified": False}


def validate_event_manager_provider(result: dict[str, Any]) -> list[str]:
    """Validate report structure only; primary verification requires re-reading ELF."""
    errors = []
    for key, expected in {"schema_version": 2, "elf_sha256": EXPECTED_SHA256, "address_space": "ELF_VMA", "function_pointer_table_slot": "0x1031c38", "indirection_level": 1, "import_symbol": "getConfig", "runtime_verified": False}.items():
        if result.get(key) != expected:
            errors.append(key)
    relocations = result.get("function_pointer_table_relocations", [])
    if not any(r.get("type") == 21 and r.get("symbol") == "getConfig" for r in relocations):
        errors.append("table_relocation")
    return errors


__all__ = ["probe_event_manager_provider", "validate_event_manager_provider", "inventory_init_array", "GETTER_ENTRY", "FUNCTION_POINTER_TABLE_SLOT", "FUNCTION_POINTER_CELL"]
