"""Evidence-gated primary-ELF probe for the ``PrmSet`` family.

The probe records the machine-level shape of the embedded payload used by
``PrmSet``.  It deliberately does not name the payload as ``std::set`` or
claim a source-level return type: the bounded code shows self-linked sentinel
words and copy/destruction helpers, but the complete container ABI is not
available from these regions alone.

Only metadata is emitted.  The private ELF is SHA-pinned, no firmware code is
executed, and no instruction bytes are returned by this module.
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
    {"name": "prmset_get_set", "entry": 0x7EFAE8, "size": 8,
     "symbol": "_ZN6PrmSet6getSetEv"},
    {"name": "prmset_get", "entry": 0x7EFAF0, "size": 14,
     "symbol": "_ZN6PrmSet3GETEPK9ParamListm"},
    {"name": "prmset_constructor", "entry": 0x7EFB00, "size": 0x24},
    {"name": "prmset_payload_helper", "entry": 0x7EFB6C, "size": 0x30},
    {"name": "prmset_destructor", "entry": 0x7EFB2C, "size": 0x20},
    {"name": "prmset_deleting_destructor", "entry": 0x7EFB58, "size": 0x14},
    {"name": "prmset_clone", "entry": 0x7EFBB4, "size": 0x1C},
    {"name": "payload_default_init", "entry": 0xFFD22, "size": 0x0E},
    {"name": "payload_init", "entry": 0xFFCF6, "size": 0x30},
    {"name": "payload_sentinel_init", "entry": 0xFFCE4, "size": 0x14},
    {"name": "payload_copy_wrapper", "entry": 0x63E8A6, "size": 0x0E},
    {"name": "payload_destroy_wrapper", "entry": 0xFFE0C, "size": 0x0E},
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_exec_range(fp: Any, elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > 0x200:
        raise ValueError("PrmSet read exceeds bounded probe limit")
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


def _immediates(instruction: Any) -> list[int]:
    return [int(operand.imm) for operand in instruction.operands if operand.type == ARM_OP_IMM]


def _require(
    rows: dict[int, Any], address: int, mnemonic: str, *,
    target: int | None = None, operands: str | None = None,
    immediate: int | None = None,
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
    if result.get("status") != "VERIFIED_STATIC":
        raise ValueError(f"PLT binding at 0x{entry:x} is not unique")
    candidates = result.get("candidates", [])
    if len(candidates) != 1 or candidates[0].get("symbol") != symbol:
        raise ValueError(f"unexpected PLT symbol at 0x{entry:x}")
    return result


def _observe_get_set(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0x7EFAE8, "push")
    _require(rows, 0x7EFAEA, "adds", operands="r0, #0xc")
    _require(rows, 0x7EFAEE, "pop")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "receiver": "PrmSet* candidate in r0",
        "machine_return": "address r0 + 0x0c; no load or allocation in the body",
        "source_return_type": "UNKNOWN; mangled symbol does not encode it",
        "payload_alias": "borrowed address into the receiver's embedded payload",
    }


def _observe_get(rows: dict[int, Any], binding: dict[str, Any]) -> dict[str, Any]:
    _require(rows, 0x7EFAF2, "movs", immediate=7)
    _require(rows, 0x7EFAFA, "b.w", target=0xE2890)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "inputs": {"r0": "const ParamList* candidate", "r1": "unsigned long key candidate"},
        "lookup_discriminator": 7,
        "forwarding": "tail branch through the ParamList::get interworking veneer",
        "target_binding": binding,
        "return": "delegated lookup result; source return and ownership UNKNOWN",
    }


def _observe_constructor(rows: dict[int, Any], bindings: dict[str, Any]) -> dict[str, Any]:
    _require(rows, 0x7EFB00, "push")
    _require(rows, 0x7EFB02, "movs", immediate=7)
    _require(rows, 0x7EFB0A, "blx", target=0xE11A4)
    _require(rows, 0x7EFB16, "adds", immediate=8)
    _require(rows, 0x7EFB18, "str")
    _require(rows, 0x7EFB1C, "bl", target=0xFFD22)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "receiver": "PrmSet* candidate in r0",
        "discriminator": 7,
        "allocation_size_bytes": 0x24,
        "vptr": "relocated vtable address point (+8) stored at object +0",
        "payload": "default initialization is called with object +0x0c",
        "key": "object +0x08 is not written in this bounded constructor",
        "bindings": bindings,
    }


def _observe_payload_sentinel(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0xFFCE4, "movs", immediate=0)
    _require(rows, 0xFFCE6, "str", operands="r3, [r0, #4]")
    _require(rows, 0xFFCEC, "str", operands="r3, [r0, #8]")
    _require(rows, 0xFFCEE, "adds", operands="r3, r0, #4")
    _require(rows, 0xFFCF0, "str", operands="r3, [r0, #0xc]")
    _require(rows, 0xFFCF2, "str", operands="r3, [r0, #0x10]")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "relative_layout": {
            "+0x04": "zero",
            "+0x08": "zero",
            "+0x0c": "pointer to payload +0x04",
            "+0x10": "pointer to payload +0x04",
        },
        "payload_plus_0x00": "not written by this helper; UNKNOWN",
    }


def _observe_payload_init(rows: dict[int, Any], memset_binding: dict[str, Any]) -> dict[str, Any]:
    _require(rows, 0xFFCF6, "push")
    _require(rows, 0xFFCFC, "movs", immediate=0)
    _require(rows, 0xFFCFE, "movs", immediate=0x10)
    _require(rows, 0xFFD00, "adds", operands="r0, #4")
    _require(rows, 0xFFD02, "blx", target=0xDE37C)
    _require(rows, 0xFFD0A, "str", operands="r3, [r4, #0x14]")
    _require(rows, 0xFFD0C, "bl", target=0xFFCE4)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "operation": "zero 16 bytes at payload +0x04, clear payload +0x14, then install sentinel links",
        "payload_plus_0x00": "not written by this bounded path; UNKNOWN",
        "memset_binding": memset_binding,
    }


def _observe_payload_default_init(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0xFFD22, "push")
    _require(rows, 0xFFD28, "bl", target=0xFFD14)
    _require(rows, 0xFFD2C, "mov", operands="r0, r4")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "operation": "delegates default payload initialization to 0xffd14",
        "return": "destination payload pointer remains in r0 on the observed path",
    }


def _observe_payload_helper(rows: dict[int, Any], bindings: dict[str, Any]) -> dict[str, Any]:
    _require(rows, 0x7EFB72, "movs", immediate=7)
    _require(rows, 0x7EFB78, "blx", target=0xE11A4)
    _require(rows, 0x7EFB86, "str")
    _require(rows, 0x7EFB8C, "bl", target=0xFFD22)
    _require(rows, 0x7EFB94, "bl", target=0x63E8A6)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "inputs": {"r0": "destination PrmSet-like object", "r1": "source payload pointer candidate"},
        "operation": "initialize destination base/payload, then copy source payload through 0x63e8a6",
        "payload_source": "source r1 is preserved in the local helper and passed to payload copy",
        "bindings": bindings,
    }


def _observe_copy_wrapper(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0x63E8A6, "push")
    _require(rows, 0x63E8AC, "bl", target=0x63E83A)
    _require(rows, 0x63E8B0, "mov", operands="r0, r4")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "operation": "payload copy wrapper calls local 0x63e83a and returns its destination",
        "self_copy_guard": "implemented in the bounded callee 0x63e83a; complete container semantics UNKNOWN",
    }


def _observe_clone(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0x7EFBB4, "push")
    _require(rows, 0x7EFBBA, "movs", immediate=0x24)
    _require(rows, 0x7EFBBC, "blx", target=0xDC100)
    _require(rows, 0x7EFBC0, "add.w")
    _require(rows, 0x7EFBC6, "bl", target=0x7EFB6C)
    _require(rows, 0x7EFBCA, "mov", operands="r0, r4")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "allocation": "0x24-byte destination allocation through 0xdc100",
        "source_payload": "source receiver +0x0c passed to the helper",
        "return": "destination pointer remains in r0 on the success path; source-level clone return UNKNOWN",
    }


def _observe_destructor(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0x7EFB3C, "str")
    _require(rows, 0x7EFB40, "bl", target=0xFFE0C)
    _require(rows, 0x7EFB46, "bl", target=0xE4734)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "operation": "restore PrmSet vptr, release payload through 0xffe0c, then call local ParamBase destructor path 0xe4734",
        "payload_release": "non-null guard is not observed in this short wrapper; helper behavior UNKNOWN",
    }


def _observe_deleting_destructor(rows: dict[int, Any], delete_binding: dict[str, Any]) -> dict[str, Any]:
    _require(rows, 0x7EFB5E, "bl", target=0x7EFB2C)
    _require(rows, 0x7EFB64, "blx", target=0xDD620)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "operation": "call non-deleting destructor then operator-delete",
        "delete_binding": delete_binding,
    }


def _observe_payload_destroy(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0xFFE0C, "push")
    _require(rows, 0xFFE12, "bl", target=0xFFDF6)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "operation": "delegates embedded payload release to 0xffdf6",
        "container_semantics": "UNKNOWN",
    }


def probe_param_set(elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA) -> dict[str, Any]:
    """Read bounded PrmSet methods from the authenticated private ELF."""
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
        for target in TARGETS:
            symbol_name = target.get("symbol")
            if not symbol_name:
                continue
            value, size = symbols.get(symbol_name, (0, 0))
            if (value & ~1) != int(target["entry"]) or size != int(target["size"]):
                raise ValueError(f"symbol identity mismatch for {symbol_name}")
        bindings = {
            "param_base_constructor": _binding(fp, elf, 0xE11A4, "_ZN9ParamBaseC2Em"),
            "memset": _binding(fp, elf, 0xDE37C, "memset"),
            "allocator": _binding(fp, elf, 0xDC100, "_Znwj"),
            "delete": _binding(fp, elf, 0xDD620, "_ZdlPv"),
            "paramlist_get": _binding(fp, elf, 0xE2894, "_ZNK9ParamList3getEmm"),
        }
        observations = {
            "prmset_get_set": _observe_get_set(_decode(fp, elf, 0x7EFAE8, 8)),
            "prmset_get": _observe_get(_decode(fp, elf, 0x7EFAF0, 14), bindings["paramlist_get"]),
            "prmset_constructor": _observe_constructor(
                _decode(fp, elf, 0x7EFB00, 0x24),
                {"param_base_constructor": bindings["param_base_constructor"]},
            ),
            "prmset_payload_helper": _observe_payload_helper(
                _decode(fp, elf, 0x7EFB6C, 0x30),
                {"param_base_constructor": bindings["param_base_constructor"]},
            ),
            "prmset_destructor": _observe_destructor(_decode(fp, elf, 0x7EFB2C, 0x20)),
            "prmset_deleting_destructor": _observe_deleting_destructor(
                _decode(fp, elf, 0x7EFB58, 0x14), bindings["delete"],
            ),
            "prmset_clone": _observe_clone(_decode(fp, elf, 0x7EFBB4, 0x1C)),
            "payload_default_init": _observe_payload_default_init(
                _decode(fp, elf, 0xFFD22, 0x0E),
            ),
            "payload_init": _observe_payload_init(_decode(fp, elf, 0xFFCF6, 0x30), bindings["memset"]),
            "payload_sentinel_init": _observe_payload_sentinel(_decode(fp, elf, 0xFFCE4, 0x14)),
            "payload_copy_wrapper": _observe_copy_wrapper(_decode(fp, elf, 0x63E8A6, 0x0E)),
            "payload_destroy_wrapper": _observe_payload_destroy(_decode(fp, elf, 0xFFE0C, 0x0E)),
        }
    return {
        "status": "LOCAL_PRIMARY_ELF_PRMSET_EVIDENCE_ONLY",
        "binary_file_sha256": digest,
        "address_space": "ELF_VMA",
        "type": "PrmSet",
        "discriminator": 7,
        "allocation_size_bytes": 0x24,
        "payload_layout": {
            "object_base": "+0x0c",
            "size_bytes": 0x18,
            "fields": {
                "+0x00": "not written by the bounded default initializer; UNKNOWN",
                "+0x04": "zeroed payload field",
                "+0x08": "zeroed payload field",
                "+0x0c": "self-linked sentinel pointer to payload +0x04",
                "+0x10": "self-linked sentinel pointer to payload +0x04",
                "+0x14": "zeroed payload field",
            },
            "container_identity": "ordered-container-like payload candidate; source type UNKNOWN",
        },
        "bindings": bindings,
        "observations": observations,
        "ownership": {
            "constructor": "embedded payload initialized in a newly allocated 0x24-byte object",
            "get_set": "returns a borrowed pointer into the object; no retain operation observed",
            "clone": "allocates a separate object and copies payload through 0x63e8a6",
            "destructor": "releases embedded payload then calls ParamBase destruction path",
            "status": "STATIC_INFERRED; container allocator, aliases, exceptions and synchronization UNKNOWN",
        },
        "runtime_verified": False,
        "callable": False,
    }


def validate_param_set(report: dict[str, Any]) -> dict[str, Any]:
    """Validate evidence identity and reject runtime/callable promotion."""
    errors: list[str] = []
    if report.get("binary_file_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != "ELF_VMA":
        errors.append("address_space")
    if report.get("type") != "PrmSet" or report.get("discriminator") != 7:
        errors.append("type_identity")
    if report.get("allocation_size_bytes") != 0x24:
        errors.append("allocation_size")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    expected = {target["name"] for target in TARGETS}
    observations = report.get("observations")
    if not isinstance(observations, dict) or not expected.issubset(observations):
        errors.append("missing_observations")
    else:
        for name in expected:
            if observations[name].get("status") != "PRIMARY_ELF_VERIFIED":
                errors.append(f"observation:{name}")
    return {"valid": not errors, "errors": sorted(set(errors))}
