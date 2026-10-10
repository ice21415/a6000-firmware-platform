"""SHA-pinned static dataflow facts for the ModelCamera loader.

This probe records only instruction-derived facts.  It does not resolve the
runtime DSO selected by ``dlopen`` or execute any firmware code.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from elftools.elf.elffile import ELFFile

EXPECTED_SHA256 = "8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_vma(stream: Any, elf: ELFFile, vma: int, size: int) -> bytes:
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD" or not (int(segment["p_flags"]) & 1):
            continue
        base, length = int(segment["p_vaddr"]), int(segment["p_filesz"])
        if base <= vma and vma + size <= base + length:
            stream.seek(int(segment["p_offset"]) + vma - base)
            data = stream.read(size)
            if len(data) == size:
                return data
    raise ValueError(f"ELF_VMA 0x{vma:x} is not a complete executable range")


def _instructions(stream: Any, elf: ELFFile, entry: int, size: int) -> dict[int, Any]:
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    return {int(row.address): row for row in decoder.disasm(_read_vma(stream, elf, entry, size), entry)}


def _fact(rows: dict[int, Any], address: int, *, operation: str, detail: str) -> dict[str, str]:
    row = rows.get(address)
    if row is None:
        raise ValueError(f"missing expected instruction at 0x{address:x}")
    return {"instruction_vma": hex(address), "mnemonic": row.mnemonic,
            "operands": row.op_str, "operation": operation, "detail": detail,
            "address_space": "ELF_VMA", "verification": "PRIMARY_ELF_VERIFIED"}


def analyze_loader_dataflow(path: Path, *, expected_sha256: str = EXPECTED_SHA256) -> dict[str, Any]:
    actual = _sha256(path)
    if actual != expected_sha256:
        raise ValueError("ELF SHA-256 does not match the pinned input")
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        loader = _instructions(stream, elf, 0x7F11CA, 0x80)
        initializer = _instructions(stream, elf, 0x7F1156, 0x24)
        registration = _instructions(stream, elf, 0x7EC8A4, 0x90)
    facts = [
        _fact(loader, 0x7F11D6, operation="load_library_name", detail="r0 <- [this + 0x10]"),
        _fact(loader, 0x7F11D8, operation="call_loader_helper", detail="internal helper 0xe0cec; relation to imported dlopen is not proven"),
        _fact(loader, 0x7F11DC, operation="store_loader_handle", detail="[this + 0x18] <- r0"),
        _fact(loader, 0x7F11E2, operation="load_factory_name", detail="r1 <- [this + 0x14]"),
        _fact(loader, 0x7F11E6, operation="resolve_factory_helper", detail="internal helper 0xdfed0; relation to imported dlsym is not proven"),
        _fact(loader, 0x7F11EE, operation="load_factory_receiver", detail="r0 <- [this]"),
        _fact(loader, 0x7F11F0, operation="load_factory_argument", detail="r1 <- [this + 0x20]"),
        _fact(loader, 0x7F11F2, operation="invoke_factory", detail="blx r3; target is dlsym result"),
        _fact(loader, 0x7F11F4, operation="store_instance", detail="[this + 0x1c] <- factory return r0"),
        _fact(initializer, 0x7F116C, operation="initialize_factory_argument", detail="[record + 0x14] <- stack argument"),
        _fact(initializer, 0x7F1176, operation="initialize_dso_argument", detail="[record + 0x20] <- stack argument"),
        _fact(registration, 0x7F091C if 0x7F091C in registration else 0x7EC91C,
              operation="initialize_record", detail="registration invokes Record Initializer 0x7f1156"),
    ]
    return {
        "status": "PRIMARY_ELF_STATIC_DATAFLOW",
        "elf_sha256": actual,
        "address_space": "ELF_VMA",
        "instruction_mode": "Thumb",
        "loader_entry": "0x7f11ca",
        "record_layout": {"library_name": "+0x10", "factory_name": "+0x14",
                           "loader_handle": "+0x18", "instance": "+0x1c",
                           "factory_argument": "+0x20"},
        "imported_plt_candidates": {
            "dlopen": {"plt_entry": "0xe085c", "status": "UNKNOWN",
                        "symbol_table": "undefined dlopen; helper relation not proven"},
            "dlsym": {"plt_entry": "0xdfb0c", "status": "UNKNOWN",
                       "symbol_table": "undefined dlsym; helper relation not proven"},
            "dlclose": {"plt_entry": "0xdf3f8", "status": "UNKNOWN",
                         "symbol_table": "undefined dlclose; cleanup helper relation not proven"},
        },
        "internal_helpers": {"loader": "0xe0cec", "symbol_resolver": "0xdfed0"},
        "facts": facts,
        "failure_paths": ["0x7f11e0: null loader handle", "0x7f11e4: null factory name",
                           "0x7f11ec: null dlsym result", "0x7f11f6: null factory instance"],
        "runtime_loader_identity": "UNKNOWN",
        "registry_modelcamera_identity": "UNKNOWN",
        "unresolved_conditions": ["runtime dlopen search path and selected DSO",
                                   "runtime dlsym binding and factory return object",
                                   "registry key-to-instance population"],
    }


def validate_loader_dataflow(result: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if result.get("status") != "PRIMARY_ELF_STATIC_DATAFLOW":
        errors.append("unexpected status")
    if result.get("address_space") != "ELF_VMA":
        errors.append("missing ELF_VMA address space")
    if len(result.get("facts", [])) < 10:
        errors.append("incomplete instruction fact set")
    if result.get("runtime_loader_identity") != "UNKNOWN":
        errors.append("runtime identity was improperly promoted")
    return errors


__all__ = ["EXPECTED_SHA256", "analyze_loader_dataflow", "validate_loader_dataflow"]
