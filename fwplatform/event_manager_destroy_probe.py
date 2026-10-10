"""Bounded primary-ELF probe for an EventManager cleanup candidate.

The local body at ``0x7efa1e`` clears a field, locks the same receiver mutex
used by the indexed EventManager methods, releases two linked-state roots,
deallocates the state array, unlocks, and destroys the mutex.  There is no
exported destructor symbol or RTTI proof for this body, so the source-level
destructor identity remains ``STATIC_INFERRED`` rather than verified.

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


def _decode(fp: Any, elf: ELFFile) -> dict[int, Any]:
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    rows = list(decoder.disasm(
        _read_exec_range(fp, elf, TARGET["entry"], TARGET["size"]), TARGET["entry"]
    ))
    if not rows:
        raise ValueError("EventManager cleanup candidate did not decode")
    return {int(row.address): row for row in rows}


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
    return {
        "schema_version": 1,
        "status": "LOCAL_PRIMARY_ELF_EVENT_MANAGER_DESTROY_CANDIDATE",
        "firmware_version": "3.21",
        "binary_file_sha256": digest,
        "address_space": ADDRESS_SPACE,
        "target": TARGET,
        "observation": observation,
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
    return {"valid": not errors, "errors": sorted(set(errors))}
