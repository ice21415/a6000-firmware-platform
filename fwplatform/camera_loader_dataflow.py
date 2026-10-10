"""SHA-pinned static dataflow facts for the ModelCamera loader.

This probe records only instruction-derived facts.  It does not resolve the
runtime DSO selected by ``dlopen`` or execute any firmware code.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, Cs
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


def _arm_veneer(stream: Any, elf: ELFFile, entry: int) -> dict[str, Any]:
    """Describe a fixed ARM interworking veneer without resolving its GOT target."""
    decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    rows = list(decoder.disasm(_read_vma(stream, elf, entry, 12), entry))
    text = [{"instruction_vma": hex(row.address), "mnemonic": row.mnemonic,
             "operands": row.op_str} for row in rows]
    veneer = (len(rows) == 3 and rows[0].mnemonic == "add"
              and rows[1].mnemonic == "add" and rows[2].mnemonic == "ldr"
              and rows[2].op_str.startswith("pc, [ip"))
    return {"entry_vma": hex(entry), "address_space": "ELF_VMA",
            "instruction_mode": "ARM", "is_plt_style_veneer": veneer,
            "instructions": text, "target_resolution": "UNKNOWN"}


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
        loader = _instructions(stream, elf, 0x7F11CA, 0x90)
        initializer = _instructions(stream, elf, 0x7F1156, 0x24)
        registration = _instructions(stream, elf, 0x7EC8A4, 0x90)
        loader_helper = _arm_veneer(stream, elf, 0xE0CEC)
        resolver_helper = _arm_veneer(stream, elf, 0xDFED0)
    facts = [
        _fact(loader, 0x7F11D2, operation="set_loader_flags", detail="r1 <- 0x101 (dlopen mode candidate)"),
        _fact(loader, 0x7F11D6, operation="load_library_name", detail="r0 <- [this + 0x10]"),
        _fact(loader, 0x7F11D8, operation="call_loader_helper", detail="internal helper 0xe0cec; relation to imported dlopen is not proven"),
        _fact(loader, 0x7F11DC, operation="store_loader_handle", detail="[this + 0x18] <- r0"),
        _fact(loader, 0x7F11E2, operation="load_factory_name", detail="r1 <- [this + 0x14]"),
        _fact(loader, 0x7F11E6, operation="resolve_factory_helper", detail="internal helper 0xdfed0; relation to imported dlsym is not proven"),
        _fact(loader, 0x7F11EE, operation="load_factory_receiver", detail="r0 <- [this]"),
        _fact(loader, 0x7F11F0, operation="load_factory_argument", detail="r1 <- [this + 0x20]"),
        _fact(loader, 0x7F11F2, operation="invoke_factory", detail="blx r3; target is dlsym result"),
        _fact(loader, 0x7F11F4, operation="store_instance", detail="[this + 0x1c] <- factory return r0"),
        _fact(loader, 0x7F120E, operation="load_instance_virtual_slot", detail="r3 <- [[this + 0x1c] + 0] + 0x28"),
        _fact(loader, 0x7F1210, operation="invoke_instance_initializer", detail="blx r3; receiver is [this + 0x1c]"),
        _fact(loader, 0x7F1230, operation="release_instance", detail="failure/cleanup helper receives [this + 0x1c]"),
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
        "internal_helpers": {"loader": loader_helper, "symbol_resolver": resolver_helper},
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
    facts = result.get("facts")
    if not isinstance(facts, list) or len(facts) < 10:
        errors.append("incomplete instruction fact set")
        facts = []
    # A count alone is not evidence: reject empty/fabricated fact dictionaries
    # and verify the instruction-level shape that the probe emits.
    expected = {
        "0x7f11d6": ("ldr", "r0", "[r0, #0x10]"),
        "0x7f11dc": ("str", "r0", "[r4, #0x18]"),
        "0x7f11e2": ("ldr", "r1", "[r4, #0x14]"),
        "0x7f11ee": ("ldr", "r0", "[r4]"),
        "0x7f11f0": ("ldr", "r1", "[r4, #0x20]"),
        "0x7f11f4": ("str", "r0", "[r4, #0x1c]"),
    }
    seen: set[str] = set()
    for fact in facts:
        if not isinstance(fact, dict) or not fact:
            errors.append("empty or non-object instruction fact")
            continue
        address = fact.get("instruction_vma")
        if not isinstance(address, str) or address.lower() not in expected and address not in {
            "0x7f11d2", "0x7f11d8", "0x7f11e6", "0x7f11f2", "0x7f116c", "0x7f1176",
            "0x7ec91c", "0x7f120e", "0x7f1210", "0x7f1230"
        }:
            errors.append("unexpected instruction VMA")
            continue
        seen.add(address.lower())
        if fact.get("address_space") != "ELF_VMA" or fact.get("verification") != "PRIMARY_ELF_VERIFIED":
            errors.append(f"unverified fact {address}")
        if address.lower() in expected:
            mnemonic, reg, operand = expected[address.lower()]
            if fact.get("mnemonic") != mnemonic or reg not in str(fact.get("operands", "")) or operand not in str(fact.get("operands", "")):
                errors.append(f"instruction operand mismatch {address}")
    for address in expected:
        if address not in seen:
            errors.append(f"missing instruction fact {address}")
    helpers = result.get("internal_helpers")
    if helpers is not None:
        if not isinstance(helpers, dict):
            errors.append("invalid helper evidence")
        else:
            for name, entry in (("loader", "0xe0cec"), ("symbol_resolver", "0xdfed0")):
                item = helpers.get(name)
                if not isinstance(item, dict) or item.get("entry_vma") != entry:
                    errors.append(f"missing {name} helper evidence")
                elif item.get("address_space") != "ELF_VMA" or item.get("instruction_mode") != "ARM":
                    errors.append(f"invalid {name} helper address space")
    if result.get("runtime_loader_identity") != "UNKNOWN":
        errors.append("runtime identity was improperly promoted")
    return errors


__all__ = ["EXPECTED_SHA256", "analyze_loader_dataflow", "validate_loader_dataflow"]
