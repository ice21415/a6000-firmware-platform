"""Evidence-gated primary-ELF probe for the PrmObjMsg payload family.

The probe validates only bounded Thumb instruction facts.  It never emits
firmware bytes, executes the object code, or treats the observed
``MWF::ObjMsg*`` word as an owned or callable host pointer.
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


VTABLE_VMA = 0xFEC498
RTTI_VMA = 0xFEC488
VTABLE_ADDRESS_POINT = 0xFEC4A0


TARGETS: tuple[dict[str, Any], ...] = (
    {"name": "objmsg_destructor", "entry": 0x12C700, "size": 0x34},
    {"name": "objmsg_deleting_destructor", "entry": 0x12C740, "size": 0x14},
    {"name": "objmsg_constructor", "entry": 0x12C754, "size": 0x28,
     "symbol": "_ZN9PrmObjMsgC1EPN3MWF6ObjMsgE"},
    {"name": "objmsg_getter", "entry": 0x12C77C, "size": 8,
     "symbol": "_ZNK9PrmObjMsg18getParamTypeObjMsgEv"},
    {"name": "objmsg_clone", "entry": 0x12C784, "size": 0x34},
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_exec_range(fp: Any, elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > 0x100:
        raise ValueError("PrmObjMsg read exceeds bounded probe limit")
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


def _read_data(elf: ELFFile, address: int, size: int) -> bytes:
    for section in elf.iter_sections():
        start = int(section["sh_addr"])
        end = start + int(section["sh_size"])
        if start <= address and address + size <= end:
            data = section.data()
            offset = address - start
            return data[offset : offset + size]
    raise ValueError(f"ELF_VMA 0x{address:x} is not mapped")


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
    rows: dict[int, Any], address: int, mnemonic: str, *, target: int | None = None,
    operands: str | None = None, immediate: int | None = None,
) -> Any:
    ins = rows.get(address)
    if ins is None or ins.mnemonic.lower() != mnemonic.lower():
        raise ValueError(f"unexpected {mnemonic} at 0x{address:x}")
    if target is not None and target not in _immediates(ins):
        raise ValueError(f"unexpected branch target at 0x{address:x}")
    if immediate is not None and immediate not in _immediates(ins):
        raise ValueError(f"unexpected immediate at 0x{address:x}")
    if operands is not None and ins.op_str.lower() != operands.lower():
        raise ValueError(f"unexpected operands at 0x{address:x}")
    return ins


def _binding(fp: Any, elf: ELFFile, entry: int, symbol: str) -> dict[str, Any]:
    result = resolve_plt_binding(fp, elf, entry, thumb_stub=False)
    candidates = result.get("candidates", [])
    if result.get("status") != "VERIFIED_STATIC" or len(candidates) != 1:
        raise ValueError(f"PLT binding at 0x{entry:x} is not unique")
    if candidates[0].get("symbol") != symbol:
        raise ValueError(f"unexpected PLT symbol at 0x{entry:x}")
    return result


def _observe_vtable(elf: ELFFile) -> dict[str, Any]:
    words = struct.unpack("<5I", _read_data(elf, VTABLE_VMA, 20))
    if words[0] != 0 or words[1] != RTTI_VMA:
        raise ValueError("PrmObjMsg vtable header mismatch")
    expected = {
        2: int(TARGETS[4]["entry"]),
        3: int(TARGETS[0]["entry"]),
        4: int(TARGETS[1]["entry"]),
    }
    for index, target in expected.items():
        if (words[index] & ~1) != target:
            raise ValueError(f"PrmObjMsg vtable slot {index} mismatch")
    rtti_words = struct.unpack("<3I", _read_data(elf, RTTI_VMA, 12))
    if rtti_words[0] != 8:
        raise ValueError("PrmObjMsg RTTI kind mismatch")
    try:
        rtti_name = _read_data(elf, rtti_words[1], 64).split(b"\0", 1)[0].decode("ascii")
    except (UnicodeDecodeError, ValueError):
        rtti_name = "UNKNOWN"
    if rtti_name != "9PrmObjMsg":
        raise ValueError("PrmObjMsg RTTI name mismatch")
    base_rtti_relocation: dict[str, Any] | None = None
    for section in elf.iter_sections():
        if not hasattr(section, "iter_relocations"):
            continue
        symbols = elf.get_section(section["sh_link"])
        for relocation in section.iter_relocations():
            if int(relocation["r_offset"]) != RTTI_VMA + 8:
                continue
            symbol = symbols.get_symbol(relocation["r_info_sym"])
            if symbol.name == "_ZTI9ParamBase":
                base_rtti_relocation = {
                    "symbol": symbol.name,
                    "symbol_value": hex(int(symbol["st_value"])),
                    "relocation_type": int(relocation["r_info_type"]),
                }
                break
        if base_rtti_relocation is not None:
            break
    if base_rtti_relocation is None:
        raise ValueError("PrmObjMsg ParamBase RTTI relocation is missing")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "vtable_vma": hex(VTABLE_VMA),
        "vtable_address_point": hex(VTABLE_ADDRESS_POINT),
        "rtti_vma": hex(RTTI_VMA),
        "rtti_name": rtti_name,
        "base_rtti": base_rtti_relocation["symbol_value"],
        "base_rtti_relocation": base_rtti_relocation,
        "offset_to_top": 0,
        "slot_plus_8_clone": hex(words[2] & ~1),
        "slot_plus_12_destructor": hex(words[3] & ~1),
        "slot_plus_16_deleting_destructor": hex(words[4] & ~1),
    }


def _observe(
    name: str, rows: dict[int, Any], bindings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    bindings = bindings or {}
    if name == "objmsg_constructor":
        _require(rows, 0x12C754, "push")
        _require(rows, 0x12C756, "mov", operands="r6, r1")
        _require(rows, 0x12C75A, "movs", immediate=8)
        _require(rows, 0x12C760, "blx", target=0xE11A4)
        _require(rows, 0x12C76C, "str", operands="r6, [r5, #0xc]")
        _require(rows, 0x12C770, "str", operands="r3, [r5]")
        return {
            "status": "PRIMARY_ELF_VERIFIED",
            "receiver": "PrmObjMsg* in r0",
            "input": "MWF::ObjMsg* candidate in r1, copied to receiver +0x0c",
            "discriminator": 8,
            "vptr": "relocated vtable address point stored at +0",
            "param_base_binding": bindings.get("param_base_constructor"),
            "ownership": "UNKNOWN; constructor stores the pointer but does not prove transfer semantics",
        }
    if name == "objmsg_getter":
        _require(rows, 0x12C780, "ldr", operands="r0, [r0, #0xc]")
        _require(rows, 0x12C782, "pop")
        return {
            "status": "PRIMARY_ELF_VERIFIED",
            "receiver": "PrmObjMsg* in r0",
            "return": "word loaded from receiver +0x0c",
            "pointee_type": "MWF::ObjMsg* candidate from constructor symbol; complete ABI UNKNOWN",
        }
    if name == "objmsg_destructor":
        _require(rows, 0x12C70E, "ldr", operands="r4, [r0, #0xc]")
        _require(rows, 0x12C714, "cbz", target=0x12C722)
        _require(rows, 0x12C718, "blx", target=0xDDD94)
        _require(rows, 0x12C71E, "blx", target=0xDD620)
        _require(rows, 0x12C724, "bl", target=0xE4734)
        return {
            "status": "PRIMARY_ELF_VERIFIED",
            "receiver": "PrmObjMsg* in r0",
            "release": "non-null +0x0c is passed to MWF::ObjMsg::~ObjMsg() PLT 0xddd94 and then operator-delete PLT 0xdd620",
            "base_destructor": "local ParamBase path 0xe4734",
            "bindings": {
                "payload_destructor": bindings.get("payload_destructor"),
                "delete_object": bindings.get("delete_object"),
            },
            "ownership": "release sequence observed; pointee allocator/ownership contract UNKNOWN",
        }
    if name == "objmsg_deleting_destructor":
        _require(rows, 0x12C746, "bl", target=0x12C700)
        _require(rows, 0x12C74C, "blx", target=0xDD620)
        return {
            "status": "PRIMARY_ELF_VERIFIED",
            "nondeleting_path": "calls 0x12c700 before operator-delete PLT 0xdd620",
            "binding": bindings.get("delete_object"),
            "runtime_binding": "UNKNOWN",
        }
    if name == "objmsg_clone":
        _require(rows, 0x12C784, "push")
        _require(rows, 0x12C788, "blx", target=0xDDEE4)
        _require(rows, 0x12C78E, "movs", immediate=8)
        _require(rows, 0x12C790, "blx", target=0xDC100)
        _require(rows, 0x12C794, "mov", operands="r1, r5")
        _require(rows, 0x12C796, "mov", operands="r4, r0")
        _require(rows, 0x12C798, "blx", target=0xE0388)
        _require(rows, 0x12C79C, "movs", immediate=0x10)
        _require(rows, 0x12C79E, "blx", target=0xDC100)
        _require(rows, 0x12C7A2, "mov", operands="r1, r4")
        _require(rows, 0x12C7A6, "blx", target=0xE2080)
        _require(rows, 0x12C7B4, "blx", target=0xDD620)
        return {
            "status": "PRIMARY_ELF_VERIFIED",
            "source": "calls PrmObjMsg::getParamTypeObjMsg() through PLT 0xddee4 on the source receiver",
            "payload_copy": "allocates 8 bytes through _Znwj PLT 0xdc100 and calls MWF::ObjMsg copy constructor PLT 0xe0388",
            "allocation": "allocates a separate 16-byte PrmObjMsg candidate through _Znwj PLT 0xdc100",
            "construction": "passes the copied MWF::ObjMsg* candidate to PrmObjMsg constructor PLT 0xe2080",
            "failure_cleanup": "visible operator-delete PLT 0xdd620 path for the temporary payload candidate",
            "bindings": {
                "payload_getter": bindings.get("payload_getter"),
                "new_payload": bindings.get("new_object"),
                "payload_copy_constructor": bindings.get("payload_copy_constructor"),
                "new_object": bindings.get("new_object"),
                "prm_objmsg_constructor": bindings.get("prm_objmsg_constructor"),
                "delete_object": bindings.get("delete_object"),
            },
            "return": "new PrmObjMsg-like pointer candidate; exact C++ clone ABI UNKNOWN",
        }
    raise ValueError(f"unsupported target {name}")


def probe_param_objmsg(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Validate bounded PrmObjMsg construction and lifetime witnesses."""
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
        bindings = {
            "param_base_constructor": _binding(fp, elf, 0xE11A4, "_ZN9ParamBaseC2Em"),
            "payload_destructor": _binding(fp, elf, 0xDDD94, "_ZN3MWF6ObjMsgD1Ev"),
            "delete_object": _binding(fp, elf, 0xDD620, "_ZdlPv"),
            "payload_getter": _binding(fp, elf, 0xDDEE4, "_ZNK9PrmObjMsg18getParamTypeObjMsgEv"),
            "new_object": _binding(fp, elf, 0xDC100, "_Znwj"),
            "payload_copy_constructor": _binding(fp, elf, 0xE0388, "_ZN3MWF6ObjMsgC1ERKS0_"),
            "prm_objmsg_constructor": _binding(fp, elf, 0xE2080, "_ZN9PrmObjMsgC1EPN3MWF6ObjMsgE"),
        }
        vtable = _observe_vtable(elf)
        observations: dict[str, Any] = {}
        for target in TARGETS:
            entry = int(target["entry"])
            size = int(target["size"])
            symbol_name = target.get("symbol")
            if symbol_name:
                value, symbol_size = symbols.get(symbol_name, (0, 0))
                if (value & ~1) != entry or symbol_size != size:
                    raise ValueError(f"symbol identity mismatch for {symbol_name}")
            observations[target["name"]] = _observe(
                target["name"], _decode(fp, elf, entry, size), bindings,
            )
    return {
        "status": "LOCAL_PRIMARY_ELF_PRMOBJMSG_EVIDENCE_ONLY",
        "binary_file_sha256": digest,
        "address_space": "ELF_VMA",
        "abi": "ARM AAPCS32, Thumb, little endian",
        "vtable": vtable,
        "bindings": bindings,
        "targets": [dict(target) for target in TARGETS],
        "observations": observations,
        "runtime_verified": False,
        "callable": False,
    }


def validate_param_objmsg(report: dict[str, Any]) -> dict[str, Any]:
    """Reject wrong identity or promotion beyond bounded static evidence."""
    errors: list[str] = []
    if report.get("binary_file_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != "ELF_VMA":
        errors.append("address_space")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    if report.get("vtable", {}).get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("missing:vtable")
    required_bindings = {
        "param_base_constructor": "_ZN9ParamBaseC2Em",
        "payload_destructor": "_ZN3MWF6ObjMsgD1Ev",
        "delete_object": "_ZdlPv",
        "payload_getter": "_ZNK9PrmObjMsg18getParamTypeObjMsgEv",
        "new_object": "_Znwj",
        "payload_copy_constructor": "_ZN3MWF6ObjMsgC1ERKS0_",
        "prm_objmsg_constructor": "_ZN9PrmObjMsgC1EPN3MWF6ObjMsgE",
    }
    binding_rows = report.get("bindings")
    if not isinstance(binding_rows, dict):
        errors.append("missing:bindings")
    else:
        for name, symbol in required_bindings.items():
            row = binding_rows.get(name)
            if not isinstance(row, dict):
                errors.append(f"missing:binding:{name}")
                continue
            if row.get("status") != "VERIFIED_STATIC":
                errors.append(f"binding_status:{name}")
            if row.get("runtime_binding") != "UNKNOWN":
                errors.append(f"binding_runtime:{name}")
            candidates = row.get("candidates")
            if not isinstance(candidates, list) or len(candidates) != 1:
                errors.append(f"binding_candidates:{name}")
            elif candidates[0].get("symbol") != symbol:
                errors.append(f"binding_symbol:{name}")
    observations = report.get("observations", {})
    for name in (target["name"] for target in TARGETS):
        if observations.get(name, {}).get("status") != "PRIMARY_ELF_VERIFIED":
            errors.append(f"missing:{name}")
    return {"valid": not errors, "errors": sorted(set(errors))}
