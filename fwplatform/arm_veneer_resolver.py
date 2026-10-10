"""Evidence-gated ARM32 veneer to GOT/relocation resolver.

This resolver only reads an ELF file.  It evaluates the ARM PC pipeline used
by the three-instruction veneers emitted by the toolchain and requires a
matching dynamic relocation before reporting an imported symbol.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM, CS_MODE_ARM, Cs
from elftools.elf.elffile import ELFFile

R_ARM_GLOB_DAT = 21
R_ARM_JUMP_SLOT = 22
R_ARM_RELATIVE = 23


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _segment_for(elf: ELFFile, vma: int, size: int = 1) -> Any | None:
    for segment in elf.iter_segments():
        if (segment["p_type"] == "PT_LOAD" and int(segment["p_vaddr"]) <= vma
                and vma + size <= int(segment["p_vaddr"]) + int(segment["p_filesz"])):
            return segment
    return None


def _imm(text: str) -> int | None:
    match = re.search(r"#(0x[0-9a-fA-F]+|[0-9]+)", text)
    return int(match.group(1), 0) if match else None


def _decode(code: bytes, entry: int) -> tuple[list[dict[str, str]], int] | tuple[None, str]:
    decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    rows = list(decoder.disasm(code, entry))
    if len(rows) < 3:
        return None, "incomplete ARM veneer"
    rows = rows[:3]
    if (rows[0].mnemonic != "add" or rows[1].mnemonic != "add"
            or rows[2].mnemonic != "ldr" or not rows[2].op_str.startswith("pc, [ip")):
        return None, "unsupported ARM veneer instruction sequence"
    first, second, third = rows
    first_imm, second_imm, third_imm = _imm(first.op_str), _imm(second.op_str), _imm(third.op_str)
    if first_imm is None or second_imm is None or third_imm is None:
        return None, "missing immediate operand"
    if "ip, pc" not in first.op_str or "ip, ip" not in second.op_str:
        return None, "unexpected ARM register operands"
    # ARM state PC reads as instruction address + 8, unlike Thumb literals.
    computed = first.address + 8 + first_imm + second_imm + third_imm
    instructions = [{"instruction_vma": hex(row.address), "mnemonic": row.mnemonic,
                     "operands": row.op_str} for row in rows]
    return instructions, computed


def resolve_arm_veneer(path: Path, entry: int, *, expected_sha256: str,
                       expected_symbol: str | None = None) -> dict[str, Any]:
    actual = _sha256(path)
    if actual != expected_sha256:
        raise ValueError("ELF SHA-256 does not match pinned input")
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 32 or elf["e_machine"] != "EM_ARM" or elf.little_endian is not True:
            raise ValueError("resolver accepts only ELF32 little-endian ARM")
        segment = _segment_for(elf, entry, 12)
        if segment is None:
            raise ValueError("veneer is outside a file-backed PT_LOAD")
        stream.seek(int(segment["p_offset"]) + entry - int(segment["p_vaddr"]))
        code = stream.read(12)
        decoded, computed = _decode(code, entry)
        if decoded is None:
            raise ValueError(computed)
        got_segment = _segment_for(elf, computed, 4)
        if got_segment is None:
            raise ValueError("computed GOT address is outside file-backed PT_LOAD")
        stream.seek(int(got_segment["p_offset"]) + computed - int(got_segment["p_vaddr"]))
        got_value = int.from_bytes(stream.read(4), "little")
        matches: list[dict[str, Any]] = []
        for section in elf.iter_sections():
            if not hasattr(section, "iter_relocations"):
                continue
            symtab = elf.get_section(section["sh_link"]) if section["sh_link"] else None
            for relocation in section.iter_relocations():
                if int(relocation["r_offset"]) != computed:
                    continue
                index = int(relocation["r_info_sym"])
                symbol = symtab.get_symbol(index) if symtab is not None else None
                matches.append({
                    "section": section.name,
                    "type": int(relocation["r_info_type"]),
                    "symbol_index": index,
                    "symbol": symbol.name if symbol is not None else "",
                })
        result: dict[str, Any] = {
            "veneer_entry_vma": hex(entry), "address_space": "ELF_VMA",
            "instruction_mode": "ARM", "instructions": decoded,
            "computed_got_vma": hex(computed), "got_value": hex(got_value),
            "relocations": matches, "elf_sha256": actual,
            "binding_status": "UNKNOWN", "evidence_level": "STATIC_INFERRED",
            "unresolved_conditions": [],
        }
        if len(matches) != 1:
            result["unresolved_conditions"].append("missing or ambiguous dynamic relocation")
        else:
            rel = matches[0]
            result["relocation_type"] = rel["type"]
            result["dynamic_symbol_index"] = rel["symbol_index"]
            result["dynamic_symbol"] = rel["symbol"]
            if rel["type"] in (R_ARM_JUMP_SLOT, R_ARM_GLOB_DAT) and rel["symbol"]:
                result["binding_status"] = "PRIMARY_ELF_VERIFIED"
                result["evidence_level"] = "PRIMARY_ELF_VERIFIED"
            else:
                result["unresolved_conditions"].append("relocation is not an imported function binding")
            if expected_symbol is not None and rel["symbol"] != expected_symbol:
                result["binding_status"] = "UNKNOWN"
                result["evidence_level"] = "STATIC_INFERRED"
                result["unresolved_conditions"].append("unexpected dynamic symbol")
        return result


__all__ = ["resolve_arm_veneer", "R_ARM_GLOB_DAT", "R_ARM_JUMP_SLOT", "R_ARM_RELATIVE"]
