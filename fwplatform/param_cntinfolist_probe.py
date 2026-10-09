"""Evidence-gated PrmCntInfoList method and lifetime probe.

Only bounded instructions from the SHA-pinned private libObj.so are read.
The result describes two embedded collection regions and their observed
accessors; it is not a live wrapper and does not assign unproven collection
or allocator types.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from capstone.arm import ARM_OP_IMM
from elftools.elf.elffile import ELFFile

from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA


TARGETS: tuple[dict[str, Any], ...] = (
    {"name": "type_initializer", "entry": 0x11D42C, "size": 22},
    {"name": "get_parameter", "entry": 0x11D44C, "size": 14,
     "symbol": "_ZN14PrmCntInfoList3GETEPK9ParamListm"},
    {"name": "get_length", "entry": 0x11D45A, "size": 14,
     "symbol": "_ZN14PrmCntInfoList9getLengthEv"},
    {"name": "set_item", "entry": 0x11D4AC, "size": 16,
     "symbol": "_ZN14PrmCntInfoList7setItemEjj"},
    {"name": "set_group", "entry": 0x11D4BC, "size": 16,
     "symbol": "_ZN14PrmCntInfoList8setGroupEjj"},
    {"name": "get_item", "entry": 0x11D4CC, "size": 14,
     "symbol": "_ZN14PrmCntInfoList7getItemEj"},
    {"name": "get_group", "entry": 0x11D4DA, "size": 14,
     "symbol": "_ZN14PrmCntInfoList8getGroupEj"},
    {"name": "append_helper", "entry": 0x11D8E6, "size": 40},
    {"name": "add", "entry": 0x11D90E, "size": 40,
     "symbol": "_ZN14PrmCntInfoList3addEjj"},
    {"name": "default_constructor", "entry": 0x11D680, "size": 84,
     "symbol": "_ZN14PrmCntInfoListC1Ev"},
    {"name": "argument_constructor", "entry": 0x11D938, "size": 120,
     "symbol": "_ZN14PrmCntInfoListC1Ejj"},
    {"name": "destructor", "entry": 0x11D54C, "size": 68,
     "symbol": "_ZN14PrmCntInfoListD1Ev"},
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_exec_range(fp: Any, elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > 0x300:
        raise ValueError("PrmCntInfoList read exceeds bounded probe limit")
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
    rows = list(decoder.disasm(_read_exec_range(fp, elf, entry, size), entry))
    if not rows:
        raise ValueError(f"no Thumb instructions at 0x{entry:x}")
    return {int(row.address): row for row in rows}


def _symbols(elf: ELFFile) -> dict[str, tuple[int, int]]:
    result: dict[str, tuple[int, int]] = {}
    for section_name in (".dynsym", ".symtab"):
        section = elf.get_section_by_name(section_name)
        if section is None:
            continue
        for symbol in section.iter_symbols():
            if symbol.name and symbol.name not in result:
                result[symbol.name] = (int(symbol["st_value"]), int(symbol["st_size"]))
    return result


def _immediates(ins: Any) -> list[int]:
    return [int(op.imm) for op in ins.operands if op.type == ARM_OP_IMM]


def _require(
    rows: dict[int, Any], address: int, mnemonic: str,
    *, target: int | None = None, operands: str | None = None,
) -> Any:
    ins = rows.get(address)
    if ins is None or ins.mnemonic.lower() != mnemonic.lower():
        raise ValueError(f"unexpected {mnemonic} instruction at 0x{address:x}")
    if target is not None and target not in _immediates(ins):
        raise ValueError(f"unexpected target at 0x{address:x}")
    if operands is not None and ins.op_str.lower() != operands.lower():
        raise ValueError(f"unexpected operands at 0x{address:x}")
    return ins


def _observe_initializer(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0x11D430, "add", operands="r3, pc")
    _require(rows, 0x11D436, "ldr")
    _require(rows, 0x11D438, "adds", operands="r3, #8")
    _require(rows, 0x11D43A, "str", operands="r3, [r0]")
    _require(rows, 0x11D43C, "movs", operands="r3, #9")
    _require(rows, 0x11D43E, "str", operands="r3, [r0, #4]")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "vptr": "stores a relocated vtable address point at object +0",
        "discriminator": 9,
        "source_level_identity": "type initializer candidate; RTTI identifies PrmCntInfoList separately",
    }


def _observe_get_parameter(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0x11D44E, "movs", operands="r2, #9")
    _require(rows, 0x11D456, "b.w", target=0xE2890)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "receiver": "ParamList-shaped receiver in r0",
        "key": "forwarded r1",
        "discriminator": 9,
        "return": "tail-return of PLT lookup target 0xe2890; source return type UNKNOWN",
    }


def _observe_get_length(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0x11D45C, "adds", operands="r0, #0xc")
    _require(rows, 0x11D464, "b.w", target=0xE77A2)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "receiver": "PrmCntInfoList* in r0",
        "collection": "first embedded collection at +0x0c",
        "return": "delegated to local collection helper 0xe77a2",
        "return_type": "UNKNOWN",
    }


def _observe_setter(rows: dict[int, Any], offset: int, helper: int) -> dict[str, Any]:
    first = min(rows)
    _require(rows, first, "push")
    _require(rows, first + 2, "adds", operands=f"r0, #0x{offset:x}")
    _require(rows, first + 8, "bl", target=helper)
    store = first + 12
    _require(rows, store, "str", operands="r4, [r0]")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "receiver": "PrmCntInfoList* in r0",
        "index": "unsigned int in r1 from the Ej symbol",
        "value": "unsigned int in r2 from the Ejj symbol",
        "collection_offset": hex(offset),
        "effect": "indexes the selected collection then stores one word",
        "bounds_check": "not observed in this wrapper; helper/container behavior UNKNOWN",
    }


def _observe_getter(rows: dict[int, Any], offset: int, helper: int) -> dict[str, Any]:
    first = min(rows)
    _require(rows, first + 2, "adds", operands=f"r0, #0x{offset:x}")
    _require(rows, first + 6, "bl", target=helper)
    _require(rows, first + 10, "ldr", operands="r0, [r0]")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "receiver": "PrmCntInfoList* in r0",
        "index": "unsigned int in r1 from the Ej symbol",
        "collection_offset": hex(offset),
        "return": "word loaded from selected collection element",
        "bounds_check": "not observed in this wrapper; invalid-index behavior UNKNOWN",
    }


def _observe_append(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0x11D8EA, "ldr", operands="r5, [r0, #0x20]")
    _require(rows, 0x11D8EE, "ldr", operands="r3, [r0, #0x18]")
    _require(rows, 0x11D8F4, "cmp", operands="r3, r5")
    _require(rows, 0x11D8F6, "beq", target=0x11D906)
    _require(rows, 0x11D8FA, "bl", target=0xECD7A)
    _require(rows, 0x11D902, "str", operands="r3, [r4, #0x18]")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "storage": "collection-like object in r0; end word +0x18 and capacity-derived word +0x20",
        "value": "pointer to one input word in r1",
        "capacity_path": "non-full path stores through 0xecd7a and advances end by 4",
        "growth_path": "full path branches to local growth code at 0x11d8b0",
    }


def _observe_add(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0x11D916, "add.w", operands="r0, r0, #0xc")
    _require(rows, 0x11D920, "bl", target=0x11D8E6)
    _require(rows, 0x11D924, "add.w", operands="r0, r4, #0x34")
    _require(rows, 0x11D92A, "bl", target=0x11D8E6)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "receiver": "PrmCntInfoList* in r0",
        "arguments": "r1/r2 are unsigned int candidates from _ZN14PrmCntInfoList3addEjj",
        "effect": "appends r1 to collection +0x0c and r2 to collection +0x34",
        "return_type": "UNKNOWN",
    }


def _observe_constructor(rows: dict[int, Any], argumented: bool) -> dict[str, Any]:
    first = min(rows)
    init = 0x11D688 if not argumented else 0x11D948
    _require(rows, init, "bl", target=0x11D42C)
    if argumented:
        _require(rows, 0x11D978, "bl", target=0x11D8E6)
        _require(rows, 0x11D980, "bl", target=0x11D8E6)
    else:
        _require(rows, 0x11D69C, "bl", target=0x11D670)
        _require(rows, 0x11D6A6, "bl", target=0x11D670)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "discriminator": 9,
        "collections": "+0x0c and +0x34 are initialized through local collection paths",
        "arguments": "r1/r2 are stored and appended" if argumented else "default empty collection paths",
        "key": "not initialized by observed constructor body",
    }


def _observe_destructor(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0x11D562, "str")
    _require(rows, 0x11D568, "bl", target=0x11D52A)
    _require(rows, 0x11D56E, "bl", target=0x11D52A)
    _require(rows, 0x11D574, "bl", target=0xE7A5E)
    _require(rows, 0x11D57A, "bl", target=0xE7A5E)
    _require(rows, 0x11D580, "bl", target=0xE4734)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "effect": "cleans both embedded collection regions then calls local ParamBase destruction path 0xe4734",
        "collection_cleanup": "0x11d52a and 0xe7a5e",
        "allocator_and_exception_behavior": "UNKNOWN",
    }


def probe_param_cntinfolist(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Validate bounded PrmCntInfoList method/lifetime witnesses."""
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
        symbols = _symbols(elf)
        observations: dict[str, Any] = {}
        for target in TARGETS:
            name = target["name"]
            rows = _decode(fp, elf, int(target["entry"]), int(target["size"]))
            symbol_name = target.get("symbol")
            if symbol_name:
                value, size = symbols.get(symbol_name, (0, 0))
                if (value & ~1) != int(target["entry"]) or size != int(target["size"]):
                    raise ValueError(f"symbol identity mismatch for {symbol_name}")
            if name == "type_initializer":
                facts = _observe_initializer(rows)
            elif name == "get_parameter":
                facts = _observe_get_parameter(rows)
            elif name == "get_length":
                facts = _observe_get_length(rows)
            elif name == "set_item":
                facts = _observe_setter(rows, 0x34, 0x11D49E)
            elif name == "set_group":
                facts = _observe_setter(rows, 0x0C, 0x11D49E)
            elif name == "get_item":
                facts = _observe_getter(rows, 0x34, 0x11D49E)
            elif name == "get_group":
                facts = _observe_getter(rows, 0x0C, 0x11D49E)
            elif name == "append_helper":
                facts = _observe_append(rows)
            elif name == "add":
                facts = _observe_add(rows)
            elif name == "default_constructor":
                facts = _observe_constructor(rows, False)
            elif name == "argument_constructor":
                facts = _observe_constructor(rows, True)
            else:
                facts = _observe_destructor(rows)
            observations[name] = {
                "entry_vma": hex(int(target["entry"])),
                "size_bytes": int(target["size"]),
                "symbol": symbol_name,
                "facts": facts,
            }
    return {
        "status": "LOCAL_PRIMARY_ELF_CNTINFOLIST_EVIDENCE_ONLY",
        "binary_file_sha256": digest,
        "address_space": "ELF_VMA",
        "type": "PrmCntInfoList",
        "discriminator": 9,
        "payload_layout": {
            "object_size_bytes": 92,
            "collection_regions": ["+0x0c", "+0x34"],
            "element_type": "UNKNOWN; method arguments are unsigned int candidates",
        },
        "observations": observations,
        "runtime_verified": False,
        "callable": False,
    }


def validate_param_cntinfolist(report: dict[str, Any]) -> dict[str, Any]:
    """Fail closed if metadata is missing or promoted beyond static evidence."""
    errors: list[str] = []
    if report.get("binary_file_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != "ELF_VMA":
        errors.append("address_space")
    if report.get("type") != "PrmCntInfoList" or report.get("discriminator") != 9:
        errors.append("type_identity")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    observations = report.get("observations")
    expected = {item["name"] for item in TARGETS}
    if not isinstance(observations, dict) or not expected.issubset(observations):
        errors.append("missing_observations")
    else:
        for item in observations.values():
            if item.get("facts", {}).get("status") != "PRIMARY_ELF_VERIFIED":
                errors.append("observation_status")
    return {
        "valid": not errors,
        "errors": sorted(set(errors)),
        "observation_count": len(observations) if isinstance(observations, dict) else 0,
    }
