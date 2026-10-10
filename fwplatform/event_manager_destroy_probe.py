"""Bounded primary-ELF probe for an EventManager cleanup candidate.

The local body at ``0x7efa1e`` clears a field, locks the same receiver mutex
used by the indexed EventManager methods, releases two linked-state roots,
deallocates the state array, unlocks, and destroys the mutex.  There is no
exported destructor symbol or RTTI proof for this body, so the source-level
destructor identity remains ``STATIC_INFERRED`` rather than verified.

The probe also checks the direct owner witness at ``0x7ef432``: a bounded
unnamed caller loads ``owner + 0x10``, calls this cleanup candidate, and passes
the same pointer to ``_ZdlPv``.  The owner type remains unknown.

Only sanitized metadata is returned.  The private ELF is never executed and
no firmware bytes are emitted.
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


TARGET = {
    "name": "event_manager_cleanup_candidate",
    "entry": 0x7EFA1E,
    "size": 0x4C,
    "symbol": None,
}
OWNER_TARGET = {
    "name": "event_manager_cleanup_owner_candidate",
    "entry": 0x7EF3D8,
    "size": 0x6E,
    "symbol": None,
}
ADDRESS_SPACE = "ELF_VMA"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_exec_range(fp: Any, elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > 0x100:
        raise ValueError("EventManager cleanup read exceeds bounded probe limit")
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


def _decode_at(fp: Any, elf: ELFFile, entry: int, size: int, label: str) -> dict[int, Any]:
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    rows = list(decoder.disasm(
        _read_exec_range(fp, elf, entry, size), entry
    ))
    if not rows:
        raise ValueError(f"{label} did not decode")
    return {int(row.address): row for row in rows}


def _decode(fp: Any, elf: ELFFile) -> dict[int, Any]:
    return _decode_at(
        fp, elf, TARGET["entry"], TARGET["size"], "EventManager cleanup candidate"
    )


def _immediates(instruction: Any) -> list[int]:
    return [int(operand.imm) for operand in instruction.operands if operand.type == ARM_OP_IMM]


def _require(
    rows: dict[int, Any], address: int, mnemonic: str, *,
    operands: str | None = None, target: int | None = None,
) -> Any:
    instruction = rows.get(address)
    if instruction is None or instruction.mnemonic.lower() != mnemonic.lower():
        raise ValueError(f"unexpected {mnemonic} at 0x{address:x}")
    if operands is not None and instruction.op_str.lower() != operands.lower():
        raise ValueError(f"unexpected operands at 0x{address:x}")
    if target is not None and target not in _immediates(instruction):
        raise ValueError(f"unexpected branch target at 0x{address:x}")
    return instruction


def _binding(fp: Any, elf: ELFFile, entry: int) -> dict[str, Any]:
    result = resolve_plt_binding(fp, elf, entry, thumb_stub=False)
    if result.get("status") != "VERIFIED_STATIC":
        raise ValueError(f"PLT binding at 0x{entry:x} is not unique")
    return result


def _observe(rows: dict[int, Any], bindings: dict[str, dict[str, Any]]) -> dict[str, Any]:
    checks = (
        (0x7EFA1E, "push"),
        (0x7EFA20, "mov"),
        (0x7EFA24, "add"),
        (0x7EFA26, "str"),
        (0x7EFA28, "bl"),
        (0x7EFA2C, "ldr"),
        (0x7EFA2E, "ldr"),
        (0x7EFA30, "cbz"),
        (0x7EFA34, "bl"),
        (0x7EFA38, "mov"),
        (0x7EFA3A, "blx"),
        (0x7EFA3E, "ldr"),
        (0x7EFA40, "ldr"),
        (0x7EFA42, "cbz"),
        (0x7EFA46, "bl"),
        (0x7EFA4A, "mov"),
        (0x7EFA4C, "blx"),
        (0x7EFA50, "ldr"),
        (0x7EFA52, "cbz"),
        (0x7EFA54, "blx"),
        (0x7EFA58, "mov"),
        (0x7EFA5A, "bl"),
        (0x7EFA5E, "add.w"),
        (0x7EFA62, "blx"),
        (0x7EFA66, "mov"),
        (0x7EFA68, "pop"),
    )
    for address, mnemonic in checks:
        _require(rows, address, mnemonic)
    _require(rows, 0x7EFA20, "mov", operands="r4, r0")
    _require(rows, 0x7EFA22, "movs", operands="r3, #0")
    _require(rows, 0x7EFA26, "str", operands="r3, [r0, #8]")
    _require(rows, 0x7EFA28, "bl", target=0x7EF8F4)
    _require(rows, 0x7EFA2E, "ldr", operands="r5, [r3]")
    _require(rows, 0x7EFA30, "cbz", target=0x7EFA3E)
    _require(rows, 0x7EFA34, "bl", target=0x7F09D2)
    _require(rows, 0x7EFA38, "mov", operands="r0, r5")
    _require(rows, 0x7EFA3A, "blx", target=0xDD620)
    _require(rows, 0x7EFA40, "ldr", operands="r5, [r3, #4]")
    _require(rows, 0x7EFA42, "cbz", target=0x7EFA50)
    _require(rows, 0x7EFA46, "bl", target=0x7F09D2)
    _require(rows, 0x7EFA4C, "blx", target=0xDD620)
    _require(rows, 0x7EFA52, "cbz", target=0x7EFA58)
    _require(rows, 0x7EFA54, "blx", target=0xDF098)
    _require(rows, 0x7EFA5A, "bl", target=0x7EF902)
    _require(rows, 0x7EFA5E, "add.w", operands="r0, r4, #0xc")
    _require(rows, 0x7EFA62, "blx", target=0xE1610)
    _require(rows, 0x7EFA66, "mov", operands="r0, r4")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "semantic_level": "STATIC_INFERRED",
        "source_level_identity": "UNKNOWN; no EventManager destructor symbol or RTTI/vtable proof for this body",
        "destructor_role": "STATIC_INFERRED; cleanup body shares the receiver fields and mutex wrappers used by EventManager methods",
        "abi": {
            "r0": "receiver pointer candidate",
            "r1_r3": "no semantic use observed in the bounded body",
            "return": "receiver pointer remains in r0 after mutex destruction; source return type UNKNOWN",
        },
        "layout": {
            "+0x00": "state array pointer candidate; two root words at [state] and [state + 4] are released",
            "+0x04": "callback/function pointer field in the related EventManager layout; not read by this body",
            "+0x08": "cleared to zero at entry",
            "+0x0c": "pthread mutex object passed through lock/unlock wrappers and destroy binding",
        },
        "release_sequence": {
            "root_0": "null-guarded; local 0x7f09d2 walks/releases linked state, then _ZdlPv",
            "root_1": "null-guarded; local 0x7f09d2 walks/releases linked state, then _ZdlPv",
            "state_array": "null-guarded; released through _ZdaPv after both roots",
            "mutex": "unlocks through 0x7ef902, then calls pthread_mutex_destroy on receiver +0x0c",
        },
        "bindings": bindings,
        "safety": {
            "null_roots": "local cbz guards are present for both roots and the state array",
            "null_receiver": "UNKNOWN; first store and lock wrapper require a valid receiver",
            "double_destroy": "UNKNOWN",
            "concurrency": "UNKNOWN; observed lock/unlock does not prove destruction synchronization",
            "exception_cleanup": "UNKNOWN; no complete EHABI/throw path is asserted for this body",
        },
        "runtime_verified": False,
        "callable": False,
    }


def _observe_owner(rows: dict[int, Any], delete_binding: dict[str, Any]) -> dict[str, Any]:
    """Verify the direct owner-field cleanup and delete sequence."""
    _require(rows, 0x7EF3D8, "push")
    _require(rows, 0x7EF3DA, "mov", operands="r4, r0")
    _require(rows, 0x7EF42C, "ldr", operands="r5, [r4, #0x10]")
    _require(rows, 0x7EF42E, "cbz", target=0x7EF43C)
    _require(rows, 0x7EF430, "mov", operands="r0, r5")
    _require(rows, 0x7EF432, "bl", target=TARGET["entry"])
    _require(rows, 0x7EF436, "mov", operands="r0, r5")
    _require(rows, 0x7EF438, "blx", target=0xDD620)
    _require(rows, 0x7EF43C, "mov", operands="r0, r4")
    _require(rows, 0x7EF43E, "bl", target=0x7EF3A8)
    _require(rows, 0x7EF442, "mov", operands="r0, r4")
    _require(rows, 0x7EF444, "pop")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "semantic_level": "STATIC_INFERRED",
        "owner_function_entry": "0x7ef3d8",
        "owner_function_identity": "UNKNOWN; no unique ELF symbol or RTTI/vtable identity",
        "cleanup_callsite": "0x7ef432",
        "field_offset": "+0x10",
        "sequence": (
            "load [owner + 0x10], null-check, call cleanup candidate, then pass the "
            "same pointer to _ZdlPv"
        ),
        "base_cleanup_callsite": "0x7ef43e -> 0x7ef3a8",
        "delete_binding": delete_binding,
        "ownership_interpretation": (
            "STATIC_INFERRED; direct cleanup-then-delete pattern supports a "
            "heap-owned subobject candidate, but source type and complete owner "
            "lifetime are UNKNOWN"
        ),
    }


def probe_event_manager_destroy(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Validate the bounded cleanup candidate from the private primary ELF."""
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
            "operator_delete": _binding(fp, elf, 0xDD620),
            "operator_delete_array": _binding(fp, elf, 0xDF098),
            "pthread_mutex_destroy": _binding(fp, elf, 0xE1610),
        }
        observation = _observe(_decode(fp, elf), bindings)
        owner = _observe_owner(
            _decode_at(
                fp, elf, OWNER_TARGET["entry"], OWNER_TARGET["size"],
                "EventManager cleanup owner candidate",
            ),
            bindings["operator_delete"],
        )
    return {
        "schema_version": 1,
        "status": "LOCAL_PRIMARY_ELF_EVENT_MANAGER_DESTROY_CANDIDATE",
        "firmware_version": "3.21",
        "binary_file_sha256": digest,
        "address_space": ADDRESS_SPACE,
        "target": TARGET,
        "owner_target": OWNER_TARGET,
        "observation": observation,
        "owner_observation": owner,
        "runtime_verified": False,
        "callable": False,
    }


def validate_event_manager_destroy(report: dict[str, Any]) -> dict[str, Any]:
    """Reject identity or status promotion beyond bounded static evidence."""
    errors: list[str] = []
    if report.get("schema_version") != 1:
        errors.append("schema_version")
    if report.get("binary_file_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != ADDRESS_SPACE:
        errors.append("address_space")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    target = report.get("target", {})
    if target.get("entry") != TARGET["entry"] or target.get("size") != TARGET["size"]:
        errors.append("target_identity")
    owner_target = report.get("owner_target", {})
    if owner_target.get("entry") != OWNER_TARGET["entry"] or owner_target.get("size") != OWNER_TARGET["size"]:
        errors.append("owner_target_identity")
    observation = report.get("observation", {})
    if observation.get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("observation_status")
    if observation.get("semantic_level") != "STATIC_INFERRED":
        errors.append("semantic_level")
    if observation.get("destructor_role") != "STATIC_INFERRED; cleanup body shares the receiver fields and mutex wrappers used by EventManager methods":
        errors.append("destructor_role")
    expected = {
        "operator_delete": "_ZdlPv",
        "operator_delete_array": "_ZdaPv",
        "pthread_mutex_destroy": "pthread_mutex_destroy",
    }
    bindings = observation.get("bindings", {})
    for key, symbol in expected.items():
        binding = bindings.get(key, {})
        candidates = binding.get("candidates", [])
        if binding.get("status") != "VERIFIED_STATIC" or len(candidates) != 1 or candidates[0].get("symbol") != symbol:
            errors.append(f"binding:{key}")
    owner = report.get("owner_observation", {})
    if owner.get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("owner_observation_status")
    if owner.get("semantic_level") != "STATIC_INFERRED":
        errors.append("owner_semantic_level")
    if owner.get("owner_function_entry") != "0x7ef3d8":
        errors.append("owner_function_entry")
    if owner.get("cleanup_callsite") != "0x7ef432":
        errors.append("owner_cleanup_callsite")
    if owner.get("field_offset") != "+0x10":
        errors.append("owner_field_offset")
    owner_binding = owner.get("delete_binding", {})
    owner_candidates = owner_binding.get("candidates", [])
    if (
        owner_binding.get("status") != "VERIFIED_STATIC"
        or len(owner_candidates) != 1
        or owner_candidates[0].get("symbol") != "_ZdlPv"
    ):
        errors.append("owner_delete_binding")
    return {"valid": not errors, "errors": sorted(set(errors))}
