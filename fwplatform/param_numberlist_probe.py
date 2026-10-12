"""Evidence-gated PrmNumberList method and lifetime probe.

This probe reads only the authenticated private libObj.so and validates small,
known Thumb regions.  It emits metadata about the observed uint32-vector
operations; it does not expose firmware bytes or create a callable wrapper.
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
    {"name": "get_list", "entry": 0xECCF4, "size": 8,
     "symbol": "_ZN13PrmNumberList7getListEv"},
    {"name": "get_number", "entry": 0xECD26, "size": 14,
     "symbol": "_ZN13PrmNumberList9getNumberEj"},
    {"name": "get_length", "entry": 0xECD42, "size": 14,
     "symbol": "_ZN13PrmNumberList9getLengthEv"},
    {"name": "add_number", "entry": 0xED1A2, "size": 30,
     "symbol": "_ZN13PrmNumberList9addNumberEj"},
    {"name": "vector_add_helper", "entry": 0xED174, "size": 46},
    {"name": "numberlist_ctor", "entry": 0xECDB8, "size": 52,
     "symbol": "_ZN13PrmNumberListC1Ev"},
    {"name": "numberlist_copy_ctor", "entry": 0xED35C, "size": 72,
     "symbol": "_ZN13PrmNumberListC1ESt6vectorIjSaIjEE"},
    {"name": "numberlist_destructor", "entry": 0xECE64, "size": 52,
     "symbol": "_ZN13PrmNumberListD1Ev"},
    {"name": "numberlist_deleting_destructor", "entry": 0xECE98, "size": 20},
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_exec_range(fp: Any, elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > 0x200:
        raise ValueError("PrmNumberList read exceeds bounded probe limit")
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


def _observe_get_list(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0xECCF6, "adds", operands="r0, #0xc")
    _require(rows, 0xECCFA, "pop")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "receiver": "PrmNumberList* in r0",
        "return": "receiver + 0x0c, the embedded vector-like storage address",
        "payload": "VectorUint32Words begin/end/capacity at +0x0c/+0x10/+0x14",
    }


def _observe_get_number(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0xECD28, "adds", operands="r0, #0xc")
    _require(rows, 0xECD2C, "bl", target=0xECD0A)
    _require(rows, 0xECD30, "ldr", operands="r0, [r0]")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "receiver": "PrmNumberList* in r0",
        "index": "unsigned int in r1 from _ZN13PrmNumberList9getNumberEj",
        "return": "uint32 word loaded from begin + index * 4",
        "bounds_check": "NONE in the observed local helper; invalid index behavior UNKNOWN",
    }


def _observe_get_length(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0xECD44, "adds", operands="r0, #0xc")
    _require(rows, 0xECD4C, "b.w", target=0xECD34)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "receiver": "PrmNumberList* in r0",
        "return": "(end - begin) arithmetic-shifted right by 2",
        "declared_return_type": "UNKNOWN; source return type is not encoded in the symbol",
    }


def _observe_add_number(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0xED1AC, "adds", operands="r0, #0xc")
    _require(rows, 0xED1B4, "bl", target=0xED174)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "receiver": "PrmNumberList* in r0",
        "value": "unsigned int in r1 from _ZN13PrmNumberList9addNumberEj",
        "storage": "embedded vector-like storage at receiver +0x0c",
        "append_helper": "local vector append helper 0xed174",
        "return": "UNKNOWN; local symbol does not encode return type",
    }


def _observe_vector_add(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0xED174, "push")
    _require(rows, 0xED17C, "ldr", operands="r1, [r0, #4]")
    _require(rows, 0xED180, "cmp", operands="r1, r3")
    _require(rows, 0xED182, "beq", target=0xED192)
    _require(rows, 0xED186, "bl", target=0xECD7A)
    _require(rows, 0xED18C, "adds", operands="r3, #4")
    _require(rows, 0xED18E, "str", operands="r3, [r4, #4]")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "capacity_path": "when end != capacity, store value and advance end by 4",
        "reallocation_path": "when end == capacity, branches to local growth/rebuild path at 0xed192",
        "value_store_helper": "0xecd7a",
    }


def _observe_ctor(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0xECDBA, "movs", operands="r1, #0xa")
    _require(rows, 0xECDC2, "blx", target=0xE11A4)
    _require(rows, 0xECDD0, "str")
    _require(rows, 0xECDD6, "bl", target=0xECDA8)
    _require(rows, 0xECDDC, "bl", target=0xECD5E)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "discriminator": 10,
        "base_or_initializer_call": "local call target 0xe11a4 receives r0=this and r1=10; source identity UNKNOWN",
        "vptr": "stores a relocated vtable address point at receiver +0",
        "vector_initialization": "initializes vector-like words at receiver +0x0c through 0xecda8 and 0xecd5e",
        "key": "not initialized by this constructor; ParamList::add key setter remains the observed initializer",
    }


def _observe_copy_ctor(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0xED362, "movs", operands="r1, #0xa")
    _require(rows, 0xED368, "blx", target=0xE11A4)
    _require(rows, 0xED37C, "bl", target=0xECDA8)
    _require(rows, 0xED384, "bl", target=0xED29A)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "discriminator": 10,
        "source": "constructor receives a vector-like source reference in r1; exact C++ reference/value ABI remains UNKNOWN",
        "copy": "initializes destination storage and forwards to local vector copy path 0xed29a",
        "key": "no ParamList key copy observed in this constructor body",
    }


def _observe_destructor(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0xECE76, "str")
    _require(rows, 0xECE7C, "bl", target=0xECD5E)
    _require(rows, 0xECE82, "bl", target=0xECE54)
    _require(rows, 0xECE88, "bl", target=0xE4734)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "operation": "restores NumberList vptr, destroys vector-like storage, then invokes ParamBase destructor path",
        "vector_destroy": "0xecd5e local helper",
        "base_destroy": "local call target 0xe4734; source-level base symbol identity UNKNOWN",
        "ownership": "allocator pairing and exception behavior UNKNOWN",
    }


def _observe_deleting_destructor(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0xECE9E, "blx", target=0xE2A10)
    _require(rows, 0xECEA4, "blx", target=0xDD620)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "nondeleting_path": "local call target 0xe2a10",
        "operator_delete_plt": "0xdd620; exact runtime allocator binding remains UNKNOWN",
        "return": "receiver-shaped r0 observed after delete call; callable destructor ABI not asserted",
    }


def probe_param_numberlist(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Validate bounded PrmNumberList method/lifetime witnesses."""
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
            if name == "get_list":
                facts = _observe_get_list(rows)
            elif name == "get_number":
                facts = _observe_get_number(rows)
            elif name == "get_length":
                facts = _observe_get_length(rows)
            elif name == "add_number":
                facts = _observe_add_number(rows)
            elif name == "vector_add_helper":
                facts = _observe_vector_add(rows)
            elif name == "numberlist_ctor":
                facts = _observe_ctor(rows)
            elif name == "numberlist_copy_ctor":
                facts = _observe_copy_ctor(rows)
            elif name == "numberlist_destructor":
                facts = _observe_destructor(rows)
            else:
                facts = _observe_deleting_destructor(rows)
            observations[name] = {
                "entry_vma": hex(int(target["entry"])),
                "size_bytes": int(target["size"]),
                "symbol": symbol_name,
                "facts": facts,
            }
    return {
        "status": "LOCAL_PRIMARY_ELF_NUMBERLIST_EVIDENCE_ONLY",
        "binary_file_sha256": digest,
        "address_space": "ELF_VMA",
        "type": "PrmNumberList",
        "discriminator": 10,
        "payload_layout": {
            "offset": "0x0c",
            "words": ["begin_address", "end_address", "capacity_address"],
            "element_width": 4,
            "element_type": "uint32_t candidate from _ZN13PrmNumberList9addNumberEj and word loads",
        },
        "observations": observations,
        "runtime_verified": False,
        "callable": False,
    }


def validate_param_numberlist(report: dict[str, Any]) -> dict[str, Any]:
    """Fail closed if metadata is missing or promoted beyond static evidence."""
    errors: list[str] = []
    if report.get("binary_file_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != "ELF_VMA":
        errors.append("address_space")
    if report.get("type") != "PrmNumberList" or report.get("discriminator") != 10:
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
