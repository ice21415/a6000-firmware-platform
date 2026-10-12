"""Static evidence for the EventManager provider getter and BSS indirection."""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, Cs
from elftools.elf.elffile import ELFFile
from .arm_store_dataflow import analyze_function
from .elf_plt import resolve_plt_binding

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
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_ARM":
            raise ValueError("expected ELF32 little-endian ARM")
        decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        instructions = {row.address: row for row in decoder.disasm(_read(stream, elf, GETTER_ENTRY, 0x5c), GETTER_ENTRY)}
        required = {0x7ef1f4: ("ldr", "r4, [pc, #0x48]"), 0x7ef1f6: ("add", "r4, pc"),
                    0x7ef214: ("movs", "r2, #0x14"), 0x7ef216: ("blx", "#0xdfbb8"),
                    0x7ef21a: ("cbnz", "r0, #0x7ef222"), 0x7ef21c: ("blx", "#0xe0354"),
                    0x7ef222: ("bl", "#0x45f320"), 0x7ef22e: ("blx", "#0xdfbb8"),
                    0x7ef232: ("cbnz", "r0, #0x7ef238"),
                    0x7ef234: ("ldr", "r3, [pc, #0x14]"), 0x7ef23a: ("ldr", "r3, [r4, r3]"), 0x7ef23c: ("blx", "r3")}
        for address, expected in required.items():
            row = instructions.get(address)
            if row is None or (row.mnemonic, row.op_str) != expected:
                raise ValueError(f"instruction mismatch at {address:#x}")
        word = lambda address: struct.unpack("<I", _read(stream, elf, address, 4))[0]
        name_address = (0x7ef216 + word(0x7ef244)) & 0xffffffff
        second_name_address = (0x7ef230 + word(0x7ef248)) & 0xffffffff
        if name_address != second_name_address or _read(stream, elf, name_address, 13) != b"AppConfig.so\0":
            raise ValueError("provider selection name provenance mismatch")
        name_binding = resolve_plt_binding(stream, elf, 0xdfbb8, thumb_stub=False)
        if name_binding.get("candidates", [{}])[0].get("symbol") != "strncmp":
            raise ValueError("provider comparison symbol mismatch")
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
                "superseded_bss_hypothesis": {"cell": "0x10a8930", "status": "SUPERSEDED_DISPROVEN", "reason": "incorrect slot arithmetic and nonexistent extra dereference"},
                "configuration_callback": {"provider_vtable": "0xfe9b70", "slot_vma": "0xfe9ba0", "slot_target": "0x106900", "callback_slot": hex(callback_slot), "stored_thumb_pointer": hex(callback_pointer), "callback_entry": hex(callback_pointer & ~1), "relocations": callback_relocations, "selection": "conditional on AppConfig.so branch and successful initialization"},
                "selection_predicate": {"comparison": "strncmp(AppConfig.so, incoming name, 20) == 0", "name_literal_vma": hex(name_address), "comparison_callsites": ["0x7ef216", "0x7ef22e"], "branch_callsites": ["0x7ef21a", "0x7ef232"], "alternative_initializer": "0x45f320", "alternative_getter_slot": "0x1030bcc", "incoming_name_runtime_value": "UNKNOWN"},
                "provider_vtable_slot": "+0x30", "main_dispatch_target": "CONDITIONAL_CANDIDATE_0x11130c", "runtime_verified": False}


def callback_event_eligibility(event_id: int, enabled: bool | None) -> str:
    """Offline descriptor-arm guard only; optional hook remains independent."""
    if enabled is False or event_id != 0x11013008:
        return "DESCRIPTOR_ARM_SKIPPED"
    return "DESCRIPTOR_ARM_CANDIDATE" if enabled else "ENABLE_STATE_UNKNOWN"


def probe_callback_behavior(path: Path, *, expected_sha256: str = EXPECTED_SHA256) -> dict[str, Any]:
    """Reproduce callback CFG and guards; keep full instruction exports private."""
    path = Path(path)
    digest = _sha256(path)
    if digest != expected_sha256:
        raise ValueError("ELF SHA-256 mismatch")
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_ARM":
            raise ValueError("requires ELF32 little-endian ARM")
        word = lambda address: struct.unpack("<I", _read(stream, elf, address, 4))[0]
        section = elf.get_section_by_name(".ARM.exidx")
        if section is None:
            raise ValueError("missing EHABI boundary evidence")
        raw = section.data()
        entries = []
        for offset in range(0, len(raw), 8):
            slot = int(section["sh_addr"]) + offset
            displacement = struct.unpack_from("<I", raw, offset)[0] & 0x7fffffff
            if displacement & 0x40000000:
                displacement -= 0x80000000
            entries.append(((slot + displacement) & 0xffffffff, slot))
        ordered = sorted(entries)
        index = next((i for i, (entry, _) in enumerate(ordered) if entry == 0x11130c), None)
        if index is None or index + 1 >= len(ordered) or ordered[index + 1][0] != 0x11141c:
            raise ValueError("callback EHABI interval mismatch")
        decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        rows = {i.address: i for i in decoder.disasm(_read(stream, elf, 0x11130c, 0xf4), 0x11130c)}
        facts = {
            0x11131a: ("mov", "r6, r0"), 0x11131c: ("mov", "r5, r1"),
            0x111320: ("ldr", "r3, [r3]"), 0x111322: ("cbz", "r3, #0x111326"),
            0x111324: ("blx", "r3"), 0x11132e: ("beq", "#0x1113f6"),
            0x111330: ("mov", "r0, r5"), 0x111332: ("bl", "#0x10fa04"),
            0x111350: ("bl", "#0x11124c"), 0x111360: ("bl", "#0x10fa04"),
            0x111390: ("movs", "r2, #0x18"), 0x11139a: ("movs", "r1, #0x1b"),
            0x11137a: ("bne", "#0x1113d0"), 0x11139e: ("blx", "#0xdd194"),
            0x1113b8: ("movs", "r1, #0"),
            0x1113bc: ("blx", "#0xde708"), 0x1113f4: ("bne", "#0x111356"),
            0x1113fc: ("pop.w", "{r4, r5, r6, r7, r8, sb, pc}"),
        }
        for address, expected in facts.items():
            row = rows.get(address)
            if row is None or (row.mnemonic, row.op_str) != expected:
                raise ValueError(f"callback evidence mismatch {address:#x}")
        helper = {i.address: i for i in decoder.disasm(_read(stream, elf, 0x10fa04, 0x2a), 0x10fa04)}
        for address, expected in {0x10fa10: ("cmp", "r0, r3"), 0x10fa12: ("bne", "#0x10fa28"),
                                  0x10fa16: ("movs", "r1, #0x17"), 0x10fa18: ("movs", "r2, #6"),
                                  0x10fa1a: ("blx", "#0xe0190")}.items():
            if address not in helper or (helper[address].mnemonic, helper[address].op_str) != expected:
                raise ValueError("descriptor guard instruction mismatch")
        if word(0x10fa30) != 0x11013008:
            raise ValueError("descriptor Event ID mismatch")
        base = (0x11131c + word(0x111408)) & 0xffffffff
        hook_slot = base + word(0x11140c)
        flag_slot = base + word(0x111410)
        hook_cell, flag_cell = word(hook_slot), word(flag_slot)
        if (hook_cell, flag_cell) != (0x10a8c6c, 0x10355bc):
            raise ValueError("hook/enable pointer provenance mismatch")
        def memory(address: int, size: int) -> bytes | None:
            segment = _segment(elf, address, size)
            if segment is None or int(segment["p_flags"]) & 2:
                return None
            return _read(stream, elf, address, size)
        cfg = analyze_function(memory, 0x11130c, [(0x11130c, 0x111400)], mode="THUMB", max_instructions=256)
        reachable = cfg["reachable_instruction_vmas"]
        leaders = {0x11130c} | {edge["target"] for edge in cfg["cfg_edges"] if edge["kind"] != "FALLTHROUGH"}
        blocks: list[dict[str, Any]] = []
        for address in reachable:
            if not blocks or address in leaders:
                blocks.append({"entry_vma": hex(address), "instruction_vmas": [], "successors": []})
            blocks[-1]["instruction_vmas"].append(hex(address))
        for block in blocks:
            last = int(block["instruction_vmas"][-1], 16)
            block["successors"] = [hex(edge["target"]) for edge in cfg["cfg_edges"] if edge["source"] == last]
        cfg["basic_blocks"] = blocks
        bindings = {hex(target): resolve_plt_binding(stream, elf, target, thumb_stub=False)
                    for target in (0xdbafc, 0xe0190, 0xdc100, 0xdd194, 0xde708, 0xdcae4)}
        if any(value["status"] != "VERIFIED_STATIC" for value in bindings.values()):
            raise ValueError("callback imported call binding unresolved")
        bridge_checks = {
            0x7ef98e: ("ldr", "r0, [r3, #4]"), 0x7ef990: ("bl", "#0x7f0aac"),
            0x7ef926: ("ldr", "r0, [r3, #4]"), 0x7ef928: ("ldr", "r5, [r3]"),
            0x7ef92a: ("bl", "#0x7f099c"), 0x7ef92e: ("mov", "r1, r0"),
            0x7ef930: ("mov", "r0, r5"), 0x7ef932: ("bl", "#0x7f0aac"),
            0x7ef94c: ("ldr", "r0, [r3]"), 0x7ef94e: ("bl", "#0x7f099c"),
            0x7eefd6: ("ldr", "r0, [r4, #0x10]"), 0x7eefda: ("bl", "#0x7ef940"),
            0x7eefde: ("mov", "r1, r0"), 0x7eefe0: ("mov", "r0, r4"),
            0x7eefe2: ("bl", "#0x7eed0c"), 0x7ef038: ("ldr", "r0, [r4, #0x10]"),
            0x7ef03a: ("bl", "#0x7ef910"), 0x7eedf0: ("bl", "#0x7ed49c"),
        }
        for address, expected in bridge_checks.items():
            row = next(decoder.disasm(_read(stream, elf, address, 4), address, count=1), None)
            if row is None or (row.mnemonic, row.op_str) != expected:
                raise ValueError(f"queue bridge instruction mismatch {address:#x}")
        bridge_calls = [
            ("queue.push.append", 0x7ef960, 0x7ef990, 0x7f0aac),
            ("queue.transfer.pop", 0x7ef910, 0x7ef92a, 0x7f099c),
            ("queue.transfer.append", 0x7ef910, 0x7ef932, 0x7f0aac),
            ("queue.loop.pop", 0x7eeee8, 0x7eefda, 0x7ef940),
            ("queue.loop.router", 0x7eeee8, 0x7eefe2, 0x7eed0c),
            ("queue.loop.transfer", 0x7eeee8, 0x7ef03a, 0x7ef910),
        ]
        return {
            "schema_version": 1, "binary_sha256": digest, "address_space": "ELF_VMA",
            "entry": "0x11130c", "ehabi_slot": hex(ordered[index][1]),
            "ehabi_next_entry": "0x11141c", "code_end_exclusive": "0x111400",
            "literal_pool": ["0x111400", "0x11141c"], "cfg": cfg,
            "abi": {"r0": "list/sentinel context retained in r6", "r1": "Event pointer retained in r5", "return": "UNKNOWN; no stable status assignment", "local_frame_bytes": 20},
            "descriptor_guard": {"event_id": "0x11013008", "parameter_key": 23, "discriminator": 6, "getter": "0x10fa04", "compare": "0x10fa10", "request_event": "0x11004003", "request_descriptor_arm": "SKIPPED_UNLESS_EVENT_TRANSFORMED"},
            "optional_hook": {"callsite": "0x111324", "got_slot": hex(hook_slot), "cell": hex(hook_cell), "target": "UNKNOWN", "precondition": "non-null cell contents"},
            "enable_gate": {"got_slot": hex(flag_slot), "cell": hex(flag_cell), "runtime_value": "UNKNOWN", "branch": "0x11132e"},
            "behavior": "conditional descriptor matching; may add key 0x1b to incoming Event and clear peer Event destination",
            "behavior_verification": "STATIC_INFERRED", "bindings": bindings,
            "router": {"entry": "0x7eed0c", "consumer_callsite": "0x7eedf0", "direct_callback_call": any(call["target"] == 0x7eed0c for call in cfg["calls"]), "optional_hook_connection": "UNKNOWN"},
            "queue_bridge_calls": [{"id": ident, "source_vma": hex(source), "callsite_vma": hex(site), "target_vma": hex(target), "verification": "PRIMARY_ELF_VERIFIED"} for ident, source, site, target in bridge_calls],
            "queue_bridge_conditions": ["same owner EventManager at owner +0x10", "Event class byte +9 selects queue arm", "transfer loop guards and scheduling", "Router destination bit 2 selects generic consumer"],
            "runtime_verified": False, "safe_to_invoke": False,
        }


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


__all__ = ["probe_callback_behavior", "callback_event_eligibility", "probe_event_manager_provider", "validate_event_manager_provider", "inventory_init_array", "GETTER_ENTRY", "FUNCTION_POINTER_TABLE_SLOT", "FUNCTION_POINTER_CELL"]
