"""Bounded primary-ELF probe for the request-model Event factory.

The factory is a useful bridge between the model request frontends and the
Event envelope, but it is not a callable SDK function.  This probe emits
only structured observations from the authenticated private ELF; it never
publishes instruction bytes or executes firmware.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from capstone.arm import ARM_OP_IMM
from elftools.elf.elffile import ELFFile

from .elf_plt import resolve_plt_binding
from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA


TARGET = {
    "name": "create_request_model_execute_event",
    "entry": 0x7F0B0C,
    "symbol_value_thumb_tagged": "0x7f0b0d",
    "symbol": "_ZN22AbstractUtilityManager30createRequestModelExecuteEventEimP9ParamList",
    "size": 108,
}
EVENT_ID_LITERAL = {"address": 0x7F0B74, "value": 0x11004003}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_vma(fp: Any, elf: ELFFile, start: int, size: int, *, executable: bool = False) -> bytes:
    if size <= 0 or size > 0x200:
        raise ValueError("request-event probe read exceeds bounded limit")
    offsets: list[int] = []
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD":
            continue
        if executable and not (int(segment["p_flags"]) & 1):
            continue
        base = int(segment["p_vaddr"])
        count = int(segment["p_filesz"])
        if base <= start and start + size <= base + count:
            offsets.append(int(segment["p_offset"]) + start - base)
    if len(offsets) != 1:
        raise ValueError(f"ELF_VMA 0x{start:x} is not uniquely file-backed")
    fp.seek(offsets[0])
    data = fp.read(size)
    if len(data) != size:
        raise ValueError("truncated ELF range")
    return data


def _decode(fp: Any, elf: ELFFile) -> dict[int, Any]:
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    rows = list(decoder.disasm(
        _read_vma(fp, elf, TARGET["entry"], TARGET["size"], executable=True),
        TARGET["entry"],
    ))
    if not rows:
        raise ValueError("request-event factory did not decode")
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
        raise ValueError(f"unexpected call target at 0x{address:x}")
    if operands is not None and ins.op_str.lower() != operands.lower():
        raise ValueError(f"unexpected operands at 0x{address:x}")
    return ins


def _binding(fp: Any, elf: ELFFile, entry: int) -> dict[str, Any]:
    result = resolve_plt_binding(fp, elf, entry, thumb_stub=False)
    if result.get("status") != "VERIFIED_STATIC":
        raise ValueError(f"PLT binding at 0x{entry:x} is not unique")
    return result


def _symbol_record(elf: ELFFile) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    for section_name in (".dynsym", ".symtab"):
        section = elf.get_section_by_name(section_name)
        if section is None:
            continue
        for symbol in section.iter_symbols():
            if symbol.name == TARGET["symbol"]:
                matches.append({
                    "table": section_name,
                    "value": int(symbol["st_value"]),
                    "size": int(symbol["st_size"]),
                })
    if not matches:
        raise ValueError("request-event factory symbol is missing")
    exact = [item for item in matches if (item["value"] & ~1) == TARGET["entry"] and item["size"] == TARGET["size"]]
    if not exact:
        raise ValueError("request-event factory symbol identity/size mismatch")
    return {"name": TARGET["symbol"], "value": hex(exact[0]["value"]), "size": exact[0]["size"]}


def _observe(
    fp: Any,
    elf: ELFFile,
    rows: dict[int, Any],
    bindings: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    _require(rows, 0x7F0B0C, "push.w")
    _require(rows, 0x7F0B10, "movs", operands="r0, #0x10")
    _require(rows, 0x7F0B14, "mov", operands="r6, r1")
    _require(rows, 0x7F0B16, "mov", operands="r8, r2")
    _require(rows, 0x7F0B18, "mov", operands="r5, r3")
    _require(rows, 0x7F0B1A, "blx", target=0xDC100)
    _require(rows, 0x7F0B1E, "ldr", operands="r1, [pc, #0x54]")
    _require(rows, 0x7F0B20, "movs", operands="r2, #2")
    _require(rows, 0x7F0B22, "movs", operands="r3, #0")
    _require(rows, 0x7F0B26, "blx", target=0xDB66C)
    _require(rows, 0x7F0B2A, "cbz", target=0x7F0B34)
    _require(rows, 0x7F0B30, "blx", target=0xDE3A4)
    _require(rows, 0x7F0B3E, "bl", target=0xF0FB0)
    _require(rows, 0x7F0B44, "movs", operands="r1, #7")
    _require(rows, 0x7F0B48, "blx", target=0xDD194)
    _require(rows, 0x7F0B56, "bl", target=0xF0FB0)
    _require(rows, 0x7F0B5C, "movs", operands="r1, #8")
    _require(rows, 0x7F0B60, "blx", target=0xDD194)
    _require(rows, 0x7F0B66, "pop.w")
    _require(rows, 0x7F0B6C, "blx", target=0xDD620)
    _require(rows, 0x7F0B70, "blx", target=0xDD4F8)
    literal = struct.unpack("<I", _read_vma(fp, elf, EVENT_ID_LITERAL["address"], 4))[0]
    if literal != EVENT_ID_LITERAL["value"]:
        raise ValueError("request-event literal does not match expected event identity")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "identity": "AbstractUtilityManager::createRequestModelExecuteEvent symbol-bound factory",
        "inputs": {
            "r0": "AbstractUtilityManager receiver/context candidate",
            "r1": "explicit int model identifier, preserved in r6 and passed to PrmNumber constructor",
            "r2": "explicit unsigned long selector, preserved in r8 and passed to PrmNumber constructor",
            "r3": "ParamList* candidate; null skips Event::setParamList",
        },
        "event": {
            "literal_address": hex(EVENT_ID_LITERAL["address"]),
            "id": hex(literal),
            "constructor": "Event::Event(unsigned long,unsigned char,unsigned char) candidate via PLT 0xdb66c",
            "constructor_arguments": {"r1": "0x11004003", "r2": 2, "r3": 0},
            "param_list": "non-null r3 passed to Event::setParamList through PLT 0xde3a4",
        },
        "parameters": [
            {"key": 7, "value": "PrmNumber candidate constructed from original r1/model id"},
            {"key": 8, "value": "PrmNumber candidate constructed from original r2/selector"},
        ],
        "return": "event allocation pointer returned in r0; declared C++ return type remains UNKNOWN",
        "exception_cleanup": "landing-pad-shaped delete through _ZdlPv then __cxa_end_cleanup; exception table and ownership remain UNKNOWN",
        "bindings": bindings,
        "runtime_verified": False,
        "callable": False,
    }


def probe_request_event_factory(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Validate the bounded request-model Event factory in a private ELF."""
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
        symbol = _symbol_record(elf)
        bindings = {
            "allocator": _binding(fp, elf, 0xDC100),
            "event_constructor": _binding(fp, elf, 0xDB66C),
            "set_param_list": _binding(fp, elf, 0xDE3A4),
            "add_parameter": _binding(fp, elf, 0xDD194),
            "operator_delete": _binding(fp, elf, 0xDD620),
            "exception_cleanup": _binding(fp, elf, 0xDD4F8),
        }
        observation = _observe(fp, elf, _decode(fp, elf), bindings)
    return {
        "status": "LOCAL_PRIMARY_ELF_REQUEST_EVENT_EVIDENCE_ONLY",
        "binary_file_sha256": digest,
        "address_space": "ELF_VMA",
        "target": {**TARGET, "entry": TARGET["entry"]},
        "symbol": symbol,
        "observation": observation,
        "runtime_verified": False,
        "callable": False,
    }


def validate_request_event_factory(report: dict[str, Any]) -> dict[str, Any]:
    """Reject identity errors and any promotion beyond static evidence."""
    errors: list[str] = []
    if report.get("binary_file_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != "ELF_VMA":
        errors.append("address_space")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    target = report.get("target", {})
    if target.get("entry") != TARGET["entry"] or target.get("size") != TARGET["size"]:
        errors.append("target_identity")
    if report.get("symbol", {}).get("name") != TARGET["symbol"]:
        errors.append("symbol_identity")
    observation = report.get("observation", {})
    if observation.get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("observation_status")
    if observation.get("event", {}).get("id") != hex(EVENT_ID_LITERAL["value"]):
        errors.append("event_id")
    for key in ("allocator", "event_constructor", "set_param_list", "add_parameter", "operator_delete", "exception_cleanup"):
        if observation.get("bindings", {}).get(key, {}).get("status") != "VERIFIED_STATIC":
            errors.append(f"binding:{key}")
    return {"valid": not errors, "errors": sorted(set(errors))}
