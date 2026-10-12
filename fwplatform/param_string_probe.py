"""Evidence-gated probe for the PrmString ParamBase family.

The probe records bounded ARM/Thumb facts from the authenticated private ELF.
It deliberately describes the payload as an owned C-string buffer candidate;
encoding, allocator ABI, exception behavior and runtime safety remain unknown.
No firmware bytes are returned or executed.
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


PROFILE: dict[str, Any] = {
    "name": "PrmString",
    "discriminator": 2,
    "allocation_size": 0x10,
    "vtable_vma": 0xFE9638,
    "rtti_vma": 0xFE9650,
    "constructor": (0xFF9C8, 0x3E),
    "destructor": (0xFF954, 0x2C),
    "deleting_destructor": (0xFF980, 0x14),
    "clone": (0xFFA18, 0x18),
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_exec_range(fp: Any, elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > 0x100:
        raise ValueError("PrmString read exceeds bounded probe limit")
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


def _immediates(instruction: Any) -> list[int]:
    return [int(operand.imm) for operand in instruction.operands if operand.type == ARM_OP_IMM]


def _require(
    rows: dict[int, Any], address: int, mnemonic: str, *, target: int | None = None,
    immediate: int | None = None, operands: str | None = None,
) -> Any:
    instruction = rows.get(address)
    if instruction is None or instruction.mnemonic.lower() != mnemonic.lower():
        raise ValueError(f"unexpected {mnemonic} at 0x{address:x}")
    if target is not None and target not in _immediates(instruction):
        raise ValueError(f"unexpected target at 0x{address:x}")
    if immediate is not None and immediate not in _immediates(instruction):
        raise ValueError(f"unexpected immediate at 0x{address:x}")
    if operands is not None and instruction.op_str.lower() != operands.lower():
        raise ValueError(f"unexpected operands at 0x{address:x}")
    return instruction


def _binding(fp: Any, elf: ELFFile, entry: int, symbol: str) -> dict[str, Any]:
    result = resolve_plt_binding(fp, elf, entry, thumb_stub=False)
    candidates = result.get("candidates", [])
    if result.get("status") != "VERIFIED_STATIC" or len(candidates) != 1:
        raise ValueError(f"PLT binding at 0x{entry:x} is not unique")
    if candidates[0].get("symbol") != symbol:
        raise ValueError(f"unexpected PLT symbol at 0x{entry:x}")
    return result


def _observe_vtable(elf: ELFFile) -> dict[str, Any]:
    words = struct.unpack("<5I", _read_data(elf, int(PROFILE["vtable_vma"]), 20))
    if words[0] != 0 or words[1] != int(PROFILE["rtti_vma"]):
        raise ValueError("PrmString vtable header mismatch")
    expected = {
        2: int(PROFILE["clone"][0]),
        3: int(PROFILE["destructor"][0]),
        4: int(PROFILE["deleting_destructor"][0]),
    }
    for index, target in expected.items():
        if (words[index] & ~1) != target:
            raise ValueError(f"PrmString vtable slot {index} mismatch")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "vtable_vma": hex(int(PROFILE["vtable_vma"])),
        "rtti_vma": hex(int(PROFILE["rtti_vma"])),
        "offset_to_top": 0,
        "slot_plus_8_clone": hex(words[2] & ~1),
        "slot_plus_12_destructor": hex(words[3] & ~1),
        "slot_plus_16_deleting_destructor": hex(words[4] & ~1),
    }


def _observe_constructor(rows: dict[int, Any], bindings: dict[str, Any]) -> dict[str, Any]:
    entry = int(PROFILE["constructor"][0])
    _require(rows, entry, "push")
    _require(rows, entry + 0x02, "mov", operands="r5, r1")
    _require(rows, entry + 0x06, "movs", immediate=2)
    _require(rows, entry + 0x0C, "blx", target=0xE11A4)
    _require(rows, entry + 0x1A, "str", operands="r3, [r4]")
    _require(rows, entry + 0x1C, "blx", target=0xDD7B8)
    _require(rows, entry + 0x20, "adds", operands="r0, #1")
    _require(rows, entry + 0x22, "blx", target=0xE0E00)
    _require(rows, entry + 0x28, "str", operands="r0, [r4, #0xc]")
    _require(rows, entry + 0x2C, "blx", target=0xDD7B8)
    _require(rows, entry + 0x30, "mov", operands="r1, r5")
    _require(rows, entry + 0x32, "adds", operands="r2, r0, #1")
    _require(rows, entry + 0x34, "mov", operands="r0, r6")
    _require(rows, entry + 0x36, "blx", target=0xDCE00)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "receiver": "PrmString* candidate in r0",
        "input": "NUL-terminated byte-string pointer candidate in r1; strlen is called without a local null guard",
        "discriminator": 2,
        "vptr": "relocated vtable address point stored at +0",
        "payload": "allocates strlen(input)+1 bytes, stores the destination at +0x0c, then strncpy(destination,input,strlen(input)+1)",
        "allocation_size_argument": "length plus one passed to new[]",
        "bindings": {
            "param_base_constructor": bindings["param_base_constructor"],
            "strlen": bindings["strlen"],
            "new_array": bindings["new_array"],
            "strncpy": bindings["strncpy"],
        },
        "encoding": "UNKNOWN",
        "allocation_failure": "no local failure branch observed; C++ allocator/runtime behavior UNKNOWN",
    }


def _observe_destructor(rows: dict[int, Any], bindings: dict[str, Any]) -> dict[str, Any]:
    entry = int(PROFILE["destructor"][0])
    _require(rows, entry + 0x10, "str", operands="r3, [r0]")
    _require(rows, entry + 0x12, "ldr", operands="r0, [r0, #0xc]")
    _require(rows, entry + 0x14, "cbz", target=0xFF96E)
    _require(rows, entry + 0x16, "blx", target=0xDF098)
    _require(rows, entry + 0x1C, "bl", target=0xE4734)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "receiver": "PrmString* candidate in r0",
        "payload_guard": "loads +0x0c and skips release when it is zero",
        "payload_release": "non-null payload passed to delete[] PLT 0xdf098",
        "base_destructor": "local ParamBase destruction path 0xe4734",
        "encoding_and_aliasing": "UNKNOWN",
        "bindings": {"delete_array": bindings["delete_array"]},
    }


def _observe_deleting_destructor(rows: dict[int, Any], bindings: dict[str, Any]) -> dict[str, Any]:
    entry = int(PROFILE["deleting_destructor"][0])
    _require(rows, entry + 0x06, "bl", target=0xFF954)
    _require(rows, entry + 0x0C, "blx", target=0xDD620)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "operation": "calls non-deleting destructor then operator-delete for the object",
        "binding": bindings["delete_object"],
    }


def _observe_clone(rows: dict[int, Any], bindings: dict[str, Any]) -> dict[str, Any]:
    entry = int(PROFILE["clone"][0])
    _require(rows, entry, "push")
    _require(rows, entry + 0x06, "movs", immediate=0x10)
    _require(rows, entry + 0x08, "blx", target=0xDC100)
    _require(rows, entry + 0x0C, "ldr", operands="r1, [r5, #0xc]")
    _require(rows, entry + 0x10, "bl", target=0xFF9C8)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "allocation": "allocates a 0x10-byte destination through new(unsigned int) PLT 0xdc100",
        "source": "loads source +0x0c and passes the pointer candidate to the constructor",
        "return": "destination-shaped value remains in r0; source-level clone return type UNKNOWN",
        "binding": bindings["new_object"],
    }


def probe_param_string(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Validate bounded PrmString construction and lifetime witnesses."""
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
        bindings = {
            "param_base_constructor": _binding(fp, elf, 0xE11A4, "_ZN9ParamBaseC2Em"),
            "strlen": _binding(fp, elf, 0xDD7B8, "strlen"),
            "new_array": _binding(fp, elf, 0xE0E00, "_Znaj"),
            "strncpy": _binding(fp, elf, 0xDCE00, "strncpy"),
            "delete_array": _binding(fp, elf, 0xDF098, "_ZdaPv"),
            "delete_object": _binding(fp, elf, 0xDD620, "_ZdlPv"),
            "new_object": _binding(fp, elf, 0xDC100, "_Znwj"),
        }
        observations = {
            "vtable": _observe_vtable(elf),
            "constructor": _observe_constructor(
                _decode(fp, elf, *PROFILE["constructor"]), bindings,
            ),
            "destructor": _observe_destructor(
                _decode(fp, elf, *PROFILE["destructor"]), bindings,
            ),
            "deleting_destructor": _observe_deleting_destructor(
                _decode(fp, elf, *PROFILE["deleting_destructor"]), bindings,
            ),
            "clone": _observe_clone(
                _decode(fp, elf, *PROFILE["clone"]), bindings,
            ),
        }
    return {
        "status": "LOCAL_PRIMARY_ELF_PRMSTRING_EVIDENCE_ONLY",
        "binary_file_sha256": digest,
        "address_space": "ELF_VMA",
        "abi": "ARM AAPCS32, Thumb, little endian",
        "type": "PrmString candidate supported by RTTI/vtable and bounded bodies",
        "discriminator": 2,
        "allocation_size_bytes": 0x10,
        "payload_layout": {"+0x0c": "owned NUL-terminated byte buffer pointer candidate"},
        "bindings": bindings,
        "observations": observations,
        "ownership": "constructor allocates a copy; destructor conditionally delete[]s it; transfer/alias rules UNKNOWN",
        "runtime_verified": False,
        "callable": False,
        "limitations": [
            "String encoding and source-level C++ type qualifiers are UNKNOWN",
            "Null/invalid input behavior is not protected by a local branch before strlen",
            "Allocator, exception, aliasing, synchronization and runtime loader behavior UNKNOWN",
            "No firmware code is executed by this probe",
        ],
    }


def validate_param_string(report: dict[str, Any]) -> dict[str, Any]:
    """Fail closed on identity, observations and unsafe promotion."""
    errors: list[str] = []
    if report.get("binary_file_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != "ELF_VMA":
        errors.append("address_space")
    if report.get("discriminator") != 2:
        errors.append("discriminator")
    if report.get("allocation_size_bytes") != 0x10:
        errors.append("allocation_size")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    observations = report.get("observations")
    if not isinstance(observations, dict):
        errors.append("missing_observations")
    else:
        for name in ("vtable", "constructor", "destructor", "deleting_destructor", "clone"):
            if observations.get(name, {}).get("status") != "PRIMARY_ELF_VERIFIED":
                errors.append(f"missing:{name}")
    return {"valid": not errors, "errors": sorted(set(errors))}
