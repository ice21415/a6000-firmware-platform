"""Evidence-gated probe for the inline two-word ParamBase families.

The authenticated A6000 ELF contains two stripped classes with the same
machine-level shape: ``PrmPoint`` (discriminator 3) and ``PrmDimension``
(discriminator 4).  This reusable profile verifies their constructors,
destructors, deleting wrappers and clone paths.  It does not assign semantic
names such as coordinates or pixels to either word.
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


FAMILY_PROFILES: tuple[dict[str, Any], ...] = (
    {
        "name": "PrmPoint",
        "discriminator": 3,
        "allocation_size": 0x14,
        "vtable_vma": 0xFE9610,
        "rtti_vma": 0xFE9628,
        "constructor": (0xFFA3C, 0x2A),
        "destructor": (0xFF904, 0x1A),
        "deleting_destructor": (0xFF940, 0x14),
        "clone": (0xFFA70, 0x1C),
        "deleting_call": {"kind": "bl", "target": 0xFF904},
    },
    {
        "name": "PrmDimension",
        "discriminator": 4,
        "allocation_size": 0x14,
        "vtable_vma": 0xFE6E48,
        "rtti_vma": 0xFE6E60,
        "constructor": (0xE5128, 0x2A),
        "destructor": (0xE4774, 0x1A),
        "deleting_destructor": (0xE4868, 0x14),
        "clone": (0xE515C, 0x1A),
        "deleting_call": {"kind": "blx", "target": 0xDFB30,
                           "symbol": "_ZN12PrmDimensionD1Ev"},
    },
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_exec_range(fp: Any, elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > 0x100:
        raise ValueError("Param pair read exceeds bounded probe limit")
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


def _observe_vtable(elf: ELFFile, profile: dict[str, Any]) -> dict[str, Any]:
    vtable = int(profile["vtable_vma"])
    words = struct.unpack("<5I", _read_data(elf, vtable, 20))
    clone_entry = int(profile["clone"][0])
    deleting_entry = int(profile["deleting_destructor"][0])
    if words[0] != 0:
        raise ValueError(f"unexpected vtable offset-to-top for {profile['name']}")
    if words[1] != int(profile["rtti_vma"]):
        raise ValueError(f"unexpected RTTI pointer for {profile['name']}")
    if (words[2] & ~1) != clone_entry:
        raise ValueError(f"unexpected clone/slot +8 target for {profile['name']}")
    if (words[4] & ~1) != deleting_entry:
        raise ValueError(f"unexpected deleting slot target for {profile['name']}")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "vtable_vma": hex(vtable),
        "rtti_vma": hex(int(profile["rtti_vma"])),
        "offset_to_top": 0,
        "slot_plus_8_target": hex(words[2] & ~1),
        "slot_plus_16_target": hex(words[4] & ~1),
        "slot_plus_12": "relocation/file word not used as a type claim",
    }


def _immediates(instruction: Any) -> list[int]:
    return [int(operand.imm) for operand in instruction.operands if operand.type == ARM_OP_IMM]


def _require(
    rows: dict[int, Any], address: int, mnemonic: str, *,
    target: int | None = None, immediate: int | None = None,
    operands: str | None = None,
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


def _observe_constructor(
    rows: dict[int, Any], profile: dict[str, Any], param_base_binding: dict[str, Any],
) -> dict[str, Any]:
    entry, _size = profile["constructor"]
    discriminator = int(profile["discriminator"])
    _require(rows, entry, "push.w")
    _require(rows, entry + 0x08, "movs", immediate=discriminator)
    _require(rows, entry + 0x10, "blx", target=0xE11A4)
    _require(rows, entry + 0x1C, "str", operands="r6, [r4, #0xc]")
    _require(rows, entry + 0x20, "str.w", operands="r8, [r4, #0x10]")
    _require(rows, entry + 0x24, "str", operands="r3, [r4]")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "inputs": {
            "r0": f"{profile['name']} receiver candidate",
            "r1": "first 32-bit payload word candidate",
            "r2": "second 32-bit payload word candidate",
        },
        "discriminator": discriminator,
        "payload": "stores r1 at object +0x0c and r2 at object +0x10",
        "vptr": "stores relocated vtable address point (+8) at object +0",
        "key": "object +0x08 is not written by this constructor",
        "param_base_binding": param_base_binding,
        "field_semantics": "UNKNOWN; no coordinate/unit meaning inferred from these stores",
    }


def _observe_destructor(rows: dict[int, Any], profile: dict[str, Any]) -> dict[str, Any]:
    entry, _size = profile["destructor"]
    _require(rows, entry + 0x10, "str", operands="r3, [r0]")
    _require(rows, entry + 0x12, "bl", target=0xE4734)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "operation": "restores the family vptr and calls local ParamBase destruction path 0xe4734",
        "payload_release": "no separate payload release is observed; words are inline candidates",
        "ownership": "inline storage observed; external alias and synchronization UNKNOWN",
    }


def _observe_deleting_destructor(
    rows: dict[int, Any], profile: dict[str, Any], delete_binding: dict[str, Any],
    named_destructor_binding: dict[str, Any] | None,
) -> dict[str, Any]:
    entry, _size = profile["deleting_destructor"]
    destructor_entry = int(profile["destructor"][0])
    deleting_call = profile["deleting_call"]
    _require(
        rows, entry + 0x06, str(deleting_call["kind"]),
        target=int(deleting_call["target"]),
    )
    _require(rows, entry + 0x0C, "blx", target=0xDD620)
    result = {
        "status": "PRIMARY_ELF_VERIFIED",
        "operation": "calls the non-deleting destructor path then operator-delete",
        "delete_binding": delete_binding,
    }
    if named_destructor_binding is not None:
        result["named_destructor_binding"] = named_destructor_binding
    else:
        result["direct_destructor_target"] = hex(destructor_entry)
    return result


def _observe_clone(
    rows: dict[int, Any], profile: dict[str, Any], allocator_binding: dict[str, Any],
) -> dict[str, Any]:
    entry, _size = profile["clone"]
    constructor_entry = int(profile["constructor"][0])
    _require(rows, entry, "push")
    _require(rows, entry + 0x06, "movs", immediate=int(profile["allocation_size"]))
    _require(rows, entry + 0x08, "blx", target=0xDC100)
    _require(rows, entry + 0x0C, "ldr", operands="r1, [r5, #0xc]")
    _require(rows, entry + 0x0E, "ldr", operands="r2, [r5, #0x10]")
    _require(rows, entry + 0x12, "bl", target=constructor_entry)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "allocation": f"allocates {profile['allocation_size']}-byte destination through 0xdc100",
        "source": "loads source object +0x0c/+0x10 and passes both words to the constructor",
        "return": "destination-shaped value remains in r0; source-level clone return type UNKNOWN",
        "allocator_binding": allocator_binding,
    }


def probe_param_pair(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Decode the Point/Dimension inline-word family profiles."""
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
            "allocator": _binding(fp, elf, 0xDC100, "_Znwj"),
            "delete": _binding(fp, elf, 0xDD620, "_ZdlPv"),
        }
        dimension_destructor_binding = _binding(
            fp, elf, 0xDFB30, "_ZN12PrmDimensionD1Ev",
        )
        bindings["dimension_destructor"] = dimension_destructor_binding
        types: dict[str, Any] = {}
        for profile in FAMILY_PROFILES:
            name = str(profile["name"])
            ctor_entry, ctor_size = profile["constructor"]
            dtor_entry, dtor_size = profile["destructor"]
            deleting_entry, deleting_size = profile["deleting_destructor"]
            clone_entry, clone_size = profile["clone"]
            types[name] = {
                "verification": "PRIMARY_ELF_VERIFIED",
                "vtable_vma": hex(int(profile["vtable_vma"])),
                "discriminator": int(profile["discriminator"]),
                "allocation_size_bytes": int(profile["allocation_size"]),
                "vtable": _observe_vtable(elf, profile),
                "constructor": _observe_constructor(
                    _decode(fp, elf, ctor_entry, ctor_size), profile,
                    bindings["param_base_constructor"],
                ),
                "destructor": _observe_destructor(
                    _decode(fp, elf, dtor_entry, dtor_size), profile,
                ),
                "deleting_destructor": _observe_deleting_destructor(
                    _decode(fp, elf, deleting_entry, deleting_size), profile,
                    bindings["delete"],
                    dimension_destructor_binding if name == "PrmDimension" else None,
                ),
                "clone": _observe_clone(
                    _decode(fp, elf, clone_entry, clone_size), profile,
                    bindings["allocator"],
                ),
                "payload_layout": {
                    "+0x0c": "first inline 32-bit word candidate",
                    "+0x10": "second inline 32-bit word candidate",
                    "semantic_names": "UNKNOWN",
                },
                "runtime_verified": False,
                "callable": False,
            }
    return {
        "status": "LOCAL_PRIMARY_ELF_PARAM_PAIR_EVIDENCE_ONLY",
        "binary_file_sha256": digest,
        "address_space": "ELF_VMA",
        "abi": "ARM AAPCS32, Thumb, little endian",
        "types": types,
        "bindings": bindings,
        "limitations": [
            "No source-level constructor symbols are exported for these profiles",
            "Inline words have no proven coordinate, dimension or hardware units",
            "Runtime loader binding, aliasing, exceptions and synchronization UNKNOWN",
            "No firmware code is executed by this probe",
        ],
        "runtime_verified": False,
        "callable": False,
    }


def validate_param_pair(report: dict[str, Any]) -> dict[str, Any]:
    """Fail closed on identity, family coverage or runtime promotion."""
    errors: list[str] = []
    if report.get("binary_file_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != "ELF_VMA":
        errors.append("address_space")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    types = report.get("types")
    if not isinstance(types, dict):
        errors.append("missing_types")
    else:
        for profile in FAMILY_PROFILES:
            name = str(profile["name"])
            item = types.get(name)
            if not isinstance(item, dict):
                errors.append(f"missing:{name}")
                continue
            if item.get("verification") != "PRIMARY_ELF_VERIFIED":
                errors.append(f"verification:{name}")
            if item.get("discriminator") != int(profile["discriminator"]):
                errors.append(f"discriminator:{name}")
            if item.get("vtable", {}).get("status") != "PRIMARY_ELF_VERIFIED":
                errors.append(f"vtable:{name}")
            for phase in ("constructor", "destructor", "deleting_destructor", "clone"):
                if item.get(phase, {}).get("status") != "PRIMARY_ELF_VERIFIED":
                    errors.append(f"observation:{name}:{phase}")
            if item.get("runtime_verified") is not False or item.get("callable") is not False:
                errors.append(f"unsafe:{name}")
    return {"valid": not errors, "errors": sorted(set(errors))}
