from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

LOG = logging.getLogger(__name__)


def analyze_elf(path: Path) -> dict[str, Any]:
    """Extract conservative ELF facts; no symbol name is treated as semantics."""
    from elftools.elf.elffile import ELFFile

    result: dict[str, Any] = {"functions": [], "symbols": [], "imports": [], "exports": [], "relocations": [], "arch": None}
    with path.open("rb") as handle:
        elf = ELFFile(handle)
        result["arch"] = {"class": elf.elfclass, "little_endian": elf.little_endian,
                           "machine": str(elf["e_machine"]), "entry": hex(int(elf["e_entry"]))}
        for section in elf.iter_sections():
            if not section.name.startswith(".symtab") and not section.name.startswith(".dynsym"):
                continue
            for symbol in section.iter_symbols():
                name = symbol.name or ""
                address = int(symbol["st_value"])
                entry = {"name": name, "address": hex(address), "size": int(symbol["st_size"]),
                         "type": str(symbol["st_info"]["type"]), "bind": str(symbol["st_info"]["bind"]),
                         "section": str(symbol["st_shndx"])}
                result["symbols"].append(entry)
                if entry["type"] == "STT_FUNC" and address and entry["section"] != "SHN_UNDEF":
                    result["functions"].append(entry)
                if entry["section"] == "SHN_UNDEF":
                    result["imports"].append(entry)
                elif entry["bind"] in {"STB_GLOBAL", "STB_WEAK"}:
                    result["exports"].append(entry)
        for section in elf.iter_sections():
            if not hasattr(section, "iter_relocations"):
                continue
            for relocation in section.iter_relocations():
                result["relocations"].append({"offset": hex(int(relocation["r_offset"])),
                    "type": int(relocation["r_info_type"]), "symbol_index": int(relocation["r_info_sym"])})
    return result

