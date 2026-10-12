"""Bounded primary-ELF probe for the non-polymorphic Event core object.

This probe follows the Event constructor, copy constructor, destructor,
ParamList setter and parameter forwarding methods.  It emits object-layout
and ownership observations only; it never executes firmware or publishes
machine-code bytes.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from capstone.arm import ARM_OP_IMM
from elftools.elf.elffile import ELFFile

from .elf_plt import resolve_plt_binding
from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA


TARGETS: tuple[dict[str, Any], ...] = (
    {"name": "event_constructor", "entry": 0x7F17F8, "size": 0x34,
     "symbol": "_ZN5EventC1Emhh", "symbol_value_thumb_tagged": "0x7f17f9"},
    {"name": "event_copy_constructor", "entry": 0x7F182C, "size": 0x20,
     "symbol": "_ZN5EventC1ERKS_", "symbol_value_thumb_tagged": "0x7f182d"},
    {"name": "event_destructor", "entry": 0x7F184C, "size": 0x2A,
     "symbol": "_ZN5EventD1Ev", "symbol_value_thumb_tagged": "0x7f184d"},
    {"name": "event_set_param_list", "entry": 0x7F1876, "size": 0x22,
     "symbol": "_ZN5Event12setParamListEP9ParamList", "symbol_value_thumb_tagged": "0x7f1877"},
    {"name": "event_add_parameter", "entry": 0xF0F84, "size": 0x0E,
     "symbol": "_ZN5Event12addParameterEmP9ParamBase", "symbol_value_thumb_tagged": "0xf0f85"},
    {"name": "event_get_parameter", "entry": 0x10D098, "size": 0x0E,
     "symbol": "_ZN5Event12getParameterEmm", "symbol_value_thumb_tagged": "0x10d099"},
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_exec(fp: Any, elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > 0x100:
        raise ValueError("Event core read exceeds bounded limit")
    offsets: list[int] = []
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD" or not (int(segment["p_flags"]) & 1):
            continue
        base = int(segment["p_vaddr"])
        count = int(segment["p_filesz"])
        if base <= start and start + size <= base + count:
            offsets.append(int(segment["p_offset"]) + start - base)
    if len(offsets) != 1:
        raise ValueError(f"ELF_VMA 0x{start:x} is not uniquely executable")
    fp.seek(offsets[0])
    data = fp.read(size)
    if len(data) != size:
        raise ValueError("truncated executable range")
    return data


def _decode(fp: Any, elf: ELFFile, entry: int, size: int) -> dict[int, Any]:
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    rows = list(decoder.disasm(_read_exec(fp, elf, entry, size), entry))
    if not rows:
        raise ValueError(f"no Thumb instructions at 0x{entry:x}")
    return {int(row.address): row for row in rows}


def _immediates(ins: Any) -> list[int]:
    return [int(op.imm) for op in ins.operands if op.type == ARM_OP_IMM]


def _require(
    rows: dict[int, Any], address: int, mnemonic: str, *, target: int | None = None,
    operands: str | None = None,
) -> Any:
    ins = rows.get(address)
    if ins is None or ins.mnemonic.lower() != mnemonic.lower():
        raise ValueError(f"unexpected {mnemonic} at 0x{address:x}")
    if target is not None and target not in _immediates(ins):
        raise ValueError(f"unexpected target at 0x{address:x}")
    if operands is not None and ins.op_str.lower() != operands.lower():
        raise ValueError(f"unexpected operands at 0x{address:x}")
    return ins


def _binding(fp: Any, elf: ELFFile, entry: int) -> dict[str, Any]:
    result = resolve_plt_binding(fp, elf, entry, thumb_stub=False)
    if result.get("status") != "VERIFIED_STATIC":
        raise ValueError(f"PLT binding at 0x{entry:x} is not unique")
    return result


def _symbol_records(elf: ELFFile) -> dict[str, dict[str, Any]]:
    wanted = {str(target["symbol"]): target for target in TARGETS}
    result: dict[str, dict[str, Any]] = {}
    for section_name in (".dynsym", ".symtab"):
        section = elf.get_section_by_name(section_name)
        if section is None:
            continue
        for symbol in section.iter_symbols():
            spec = wanted.get(symbol.name)
            if spec is None:
                continue
            value = int(symbol["st_value"])
            if (value & ~1) != int(spec["entry"]) or int(symbol["st_size"]) != int(spec["size"]):
                continue
            result[symbol.name] = {
                "name": symbol.name,
                "value": hex(value),
                "size": int(symbol["st_size"]),
                "table": section_name,
            }
    missing = wanted.keys() - result.keys()
    if missing:
        raise ValueError(f"Event symbol identity missing: {sorted(missing)}")
    return result


def _observe_constructor(rows: dict[int, Any], bindings: dict[str, Any]) -> dict[str, Any]:
    _require(rows, 0x7F17F8, "push")
    _require(rows, 0x7F17FC, "strb", operands="r2, [r0, #8]")
    _require(rows, 0x7F1800, "strb", operands="r3, [r0, #9]")
    _require(rows, 0x7F1802, "str", operands="r1, [r0, #4]")
    _require(rows, 0x7F1804, "movs", operands="r0, #8")
    _require(rows, 0x7F1806, "blx", target=0xDC100)
    _require(rows, 0x7F180C, "blx", target=0xDF894)
    _require(rows, 0x7F1810, "str", operands="r5, [r4, #0xc]")
    _require(rows, 0x7F1812, "movs", operands="r0, #4")
    _require(rows, 0x7F1814, "blx", target=0xDC100)
    _require(rows, 0x7F1818, "movs", operands="r3, #1")
    _require(rows, 0x7F181A, "str", operands="r3, [r0]")
    _require(rows, 0x7F181C, "str", operands="r0, [r4]")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "inputs": {
            "r0": "Event receiver",
            "r1": "unsigned long event ID candidate",
            "r2": "unsigned char flag byte at +0x08",
            "r3": "unsigned char flag byte at +0x09",
        },
        "layout": {
            "+0x00": "pointer to 4-byte shared counter allocation initialized to 1",
            "+0x04": "event ID word copied from r1",
            "+0x08": "byte copied from r2",
            "+0x09": "byte copied from r3",
            "+0x0c": "owned ParamList* candidate allocated as 8 bytes and constructed through PLT 0xdf894",
        },
        "bindings": bindings,
    }


def _observe_copy(rows: dict[int, Any]) -> dict[str, Any]:
    checks = (
        (0x7F182C, "ldrb"), (0x7F1832, "strb"), (0x7F1834, "ldrb"),
        (0x7F1838, "ldr"), (0x7F183A, "str"), (0x7F183C, "ldr"),
        (0x7F183E, "str"), (0x7F1840, "ldr"), (0x7F1842, "ldr"),
        (0x7F1844, "str"), (0x7F1846, "adds"), (0x7F1848, "str"),
    )
    for address, mnemonic in checks:
        _require(rows, address, mnemonic)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "inputs": {"r0": "destination Event", "r1": "source Event"},
        "operations": "copies +4/+8/+9/+0c, shares source +0 counter pointer and increments the pointed word",
        "counter_field": "+0x00",
        "param_list_copy": "+0x0c pointer copied without an observed clone",
    }


def _observe_destructor(rows: dict[int, Any], bindings: dict[str, Any]) -> dict[str, Any]:
    for address, mnemonic in (
        (0x7F184C, "ldr"), (0x7F1852, "ldr"), (0x7F1856, "subs"),
        (0x7F1858, "str"), (0x7F185A, "cbnz"), (0x7F185C, "ldr"),
        (0x7F185E, "cbz"), (0x7F1862, "blx"), (0x7F1868, "blx"),
        (0x7F186E, "blx"),
    ):
        _require(rows, address, mnemonic)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "counter_field": "+0x00",
        "operation": "decrement shared counter; only zero path destroys/deletes ParamList +0x0c and counter allocation",
        "bindings": bindings,
        "lifetime": "last-owner cleanup is statically observed; external aliases and concurrent safety remain UNKNOWN",
    }


def _observe_set(rows: dict[int, Any], bindings: dict[str, Any]) -> dict[str, Any]:
    for address, mnemonic in (
        (0x7F1876, "push"), (0x7F187C, "mov"), (0x7F187E, "cbz"),
        (0x7F1880, "ldr"), (0x7F1882, "cmp"), (0x7F1884, "beq"),
        (0x7F1886, "cbz"), (0x7F188A, "blx"), (0x7F1890, "blx"),
        (0x7F1894, "str"),
    ):
        _require(rows, address, mnemonic)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "inputs": {"r0": "Event receiver", "r1": "replacement ParamList* candidate"},
        "null_input": "null r1 returns without replacing the existing +0x0c pointer",
        "same_pointer": "same pointer avoids destruction and delete",
        "replacement": "different non-null old pointer is destructed/deleted before storing new pointer",
        "bindings": bindings,
        "ownership": "STATIC_INFERRED raw-pointer replacement/ownership transfer; shared Event copies and external aliases remain UNKNOWN",
    }


def _observe_forwarder(rows: dict[int, Any], *, get: bool, binding: dict[str, Any]) -> dict[str, Any]:
    entry = 0x10D098 if get else 0xF0F84
    tail = 0xE2890 if get else 0xDFDBC
    _require(rows, entry, "push")
    _require(rows, entry + 2, "add")
    _require(rows, entry + 4, "ldr")
    _require(rows, entry + 6, "pop.w")
    _require(rows, entry + 10, "b.w", target=tail)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "receiver_load": "Event +0x0c used as ParamList receiver",
        "forwarding": "tail branch through ARM/Thumb interworking veneer",
        "target_binding": binding,
        "return": "delegated ParamList operation; complete C++ return/error semantics remain UNKNOWN",
    }


def probe_event_core(elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA) -> dict[str, Any]:
    """Read and validate Event core methods from the private SHA-pinned ELF."""
    path = Path(elf_path).resolve()
    if not path.is_file():
        raise ValueError("private ELF is missing")
    if not HEX_SHA.fullmatch(expected_sha256):
        raise ValueError("expected_sha256 must be a lowercase full SHA-256 digest")
    digest = _sha256(path)
    if digest != expected_sha256:
        raise ValueError("full-file ELF SHA-256 mismatch; refusing to decode")
    with path.open("rb") as fp:
        elf = ELFFile(fp)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_ARM":
            raise ValueError("probe accepts only ELF32 little-endian ARM")
        symbols = _symbol_records(elf)
        constructor_bindings = {
            "allocator": _binding(fp, elf, 0xDC100),
            "paramlist_constructor": _binding(fp, elf, 0xDF894),
        }
        destructor_bindings = {
            "paramlist_destructor": _binding(fp, elf, 0xE0080),
            "operator_delete": _binding(fp, elf, 0xDD620),
        }
        set_bindings = {
            "paramlist_destructor": _binding(fp, elf, 0xE0080),
            "operator_delete": _binding(fp, elf, 0xDD620),
        }
        add_binding = _binding(fp, elf, 0xDFDC0)
        get_binding = _binding(fp, elf, 0xE2894)
        observations = {
            "constructor": _observe_constructor(
                _decode(fp, elf, 0x7F17F8, 0x34), constructor_bindings,
            ),
            "copy_constructor": _observe_copy(_decode(fp, elf, 0x7F182C, 0x20)),
            "destructor": _observe_destructor(
                _decode(fp, elf, 0x7F184C, 0x2A), destructor_bindings,
            ),
            "set_param_list": _observe_set(
                _decode(fp, elf, 0x7F1876, 0x22), set_bindings,
            ),
            "add_parameter": _observe_forwarder(
                _decode(fp, elf, 0xF0F84, 0x0E), get=False, binding=add_binding,
            ),
            "get_parameter": _observe_forwarder(
                _decode(fp, elf, 0x10D098, 0x0E), get=True, binding=get_binding,
            ),
        }
    return {
        "status": "LOCAL_PRIMARY_ELF_EVENT_CORE_EVIDENCE_ONLY",
        "binary_file_sha256": digest,
        "address_space": "ELF_VMA",
        "symbols": symbols,
        "observations": observations,
        "runtime_verified": False,
        "callable": False,
    }


def validate_event_core(report: dict[str, Any]) -> dict[str, Any]:
    """Validate static identity and reject runtime/callable promotion."""
    errors: list[str] = []
    if report.get("binary_file_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != "ELF_VMA":
        errors.append("address_space")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    observations = report.get("observations", {})
    for name in ("constructor", "copy_constructor", "destructor", "set_param_list", "add_parameter", "get_parameter"):
        if observations.get(name, {}).get("status") != "PRIMARY_ELF_VERIFIED":
            errors.append(f"observation:{name}")
    for name in TARGETS:
        symbol = name["symbol"]
        if report.get("symbols", {}).get(symbol, {}).get("size") != name["size"]:
            errors.append(f"symbol:{symbol}")
    for observation_name, binding_names in {
        "constructor": ("allocator", "paramlist_constructor"),
        "destructor": ("paramlist_destructor", "operator_delete"),
        "set_param_list": ("paramlist_destructor", "operator_delete"),
    }.items():
        for binding_name in binding_names:
            if observations.get(observation_name, {}).get("bindings", {}).get(binding_name, {}).get("status") != "VERIFIED_STATIC":
                errors.append(f"binding:{observation_name}:{binding_name}")
    for observation_name in ("add_parameter", "get_parameter"):
        if observations.get(observation_name, {}).get("target_binding", {}).get("status") != "VERIFIED_STATIC":
            errors.append(f"binding:{observation_name}:target")
    return {"valid": not errors, "errors": sorted(set(errors))}
