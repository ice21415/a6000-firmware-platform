"""Evidence-gated primary-ELF probe for the PrmObjMsg payload family.

The probe validates only bounded Thumb instruction facts.  It never emits
firmware bytes, executes the object code, or treats the observed
``MWF::ObjMsg*`` word as an owned or callable host pointer.
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


def _observe(name: str, rows: dict[int, Any]) -> dict[str, Any]:
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
            "release": "non-null +0x0c is passed to helper 0xddd94 and operator-delete PLT 0xdd620",
            "base_destructor": "local ParamBase path 0xe4734",
            "ownership": "release sequence observed; pointee allocator/ownership contract UNKNOWN",
        }
    if name == "objmsg_deleting_destructor":
        _require(rows, 0x12C746, "bl", target=0x12C700)
        _require(rows, 0x12C74C, "blx", target=0xDD620)
        return {
            "status": "PRIMARY_ELF_VERIFIED",
            "nondeleting_path": "calls 0x12c700 before operator-delete PLT 0xdd620",
            "runtime_binding": "UNKNOWN",
        }
    if name == "objmsg_clone":
        _require(rows, 0x12C784, "push")
        _require(rows, 0x12C788, "blx", target=0xDDEE4)
        _require(rows, 0x12C78E, "movs", immediate=8)
        _require(rows, 0x12C790, "blx", target=0xDC100)
        _require(rows, 0x12C79C, "movs", immediate=0x10)
        _require(rows, 0x12C79E, "blx", target=0xDC100)
        _require(rows, 0x12C7B4, "blx", target=0xDD620)
        return {
            "status": "PRIMARY_ELF_VERIFIED",
            "source": "PrmObjMsg receiver and payload pointer are preserved through a bounded clone path",
            "allocation": "allocates a 16-byte destination through helper 0xdc100; exact allocator identity UNKNOWN",
            "copy": "payload copy helper 0xe0388 receives the source pointer candidate",
            "failure_cleanup": "visible operator-delete PLT 0xdd620 path",
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
                target["name"], _decode(fp, elf, entry, size)
            )
    return {
        "status": "LOCAL_PRIMARY_ELF_PRMOBJMSG_EVIDENCE_ONLY",
        "binary_file_sha256": digest,
        "address_space": "ELF_VMA",
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
    observations = report.get("observations", {})
    for name in (target["name"] for target in TARGETS):
        if observations.get(name, {}).get("status") != "PRIMARY_ELF_VERIFIED":
            errors.append(f"missing:{name}")
    return {"valid": not errors, "errors": sorted(set(errors))}
