"""Resolve bounded ARM/Thumb interworking PLT slots from instruction evidence."""
from __future__ import annotations

from typing import Any

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM
from elftools.elf.sections import SymbolTableSection

from .private_thumb_research import _read_vma


def arm_plt_slot(raw: bytes, vma: int, *, thumb_stub: bool) -> int | None:
    """Return a GOT slot only for the explicitly recognized three-instruction stub."""
    offset = 0
    if thumb_stub:
        prefix = list(Cs(CS_ARCH_ARM, CS_MODE_THUMB).disasm(raw[:2], vma))
        if len(prefix) != 1 or prefix[0].mnemonic != "bx" or prefix[0].op_str != "pc":
            return None
        offset = 4
    decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    decoder.detail = True
    instructions = list(decoder.disasm(raw[offset:offset + 12], vma + offset))
    if len(instructions) != 3:
        return None
    first, second, load = instructions
    if first.mnemonic != "add" or second.mnemonic != "add" or load.mnemonic != "ldr":
        return None
    if first.op_str.split(",")[:2] != ["ip", " pc"] or second.op_str.split(",")[:2] != ["ip", " ip"]:
        return None
    if first.operands[2].type != ARM_OP_IMM or second.operands[2].type != ARM_OP_IMM:
        return None
    if load.reg_name(load.operands[0].reg) != "pc" or load.operands[1].type != ARM_OP_MEM:
        return None
    mem = load.operands[1].mem
    if load.reg_name(mem.base) != "ip" or mem.index:
        return None
    def immediate(ins: Any) -> int:
        value = ins.operands[2].imm & 0xffffffff
        if len(ins.operands) == 4:
            rotation = ins.operands[3].imm & 31
            value = ((value >> rotation) | (value << ((32 - rotation) & 31))) & 0xffffffff
        return value
    return (first.address + 8 + immediate(first) + immediate(second) + mem.disp) & 0xffffffff


def resolve_plt_binding(fp: Any, elf: Any, vma: int, *, thumb_stub: bool) -> dict[str, Any]:
    """No basename matching or assumed runtime loader binding."""
    raw = _read_vma(fp, elf, vma, 16, executable=True)
    slot = arm_plt_slot(raw, vma, thumb_stub=thumb_stub)
    result: dict[str, Any] = {"entry_vma": hex(vma), "address_space": "ELF_VMA",
                              "got_slot": hex(slot) if slot is not None else None,
                              "status": "UNKNOWN", "runtime_binding": "UNKNOWN"}
    if slot is None:
        return result
    matches = []
    for section in elf.iter_sections():
        if not hasattr(section, "iter_relocations"):
            continue
        symbols = elf.get_section(section["sh_link"])
        if not isinstance(symbols, SymbolTableSection):
            continue
        for relocation in section.iter_relocations():
            if relocation["r_offset"] == slot and relocation["r_info_sym"]:
                symbol = symbols.get_symbol(relocation["r_info_sym"])
                matches.append({"symbol": symbol.name, "symbol_value": hex(symbol["st_value"]),
                                "relocation_type": relocation["r_info_type"], "section": section.name})
    result["candidates"] = matches
    if len(matches) == 1:
        result["status"] = "VERIFIED_STATIC"
    return result
