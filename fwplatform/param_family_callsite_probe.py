"""Bounded Capstone checks for representative ParamBase constructor callsites.

This module records only normalized instruction facts: the direct constructor
branch target, the last visible assignment to AAPCS32 argument registers in a
small linear window, and optional post-construction dispatch arguments.  It is
not a substitute for interprocedural data-flow analysis; values that come from
another register, memory or a call remain explicitly unresolved.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterable

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG
from elftools.elf.elffile import ELFFile

from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA, MAX_ELF_BYTES


ALLOCATOR_VMA = 0xDC100


# These are evidence locators selected from the private constructor-xref export.
# The analysis engine itself accepts arbitrary profiles and does not special
# case a family name or infer a semantic key from a numeric value.
PARAMBASE_CALLSITE_PROFILES: tuple[dict[str, Any], ...] = (
    {
        "family": "PrmBool", "constructor_vma": 0xE50E8,
        "callsite_vma": 0xFDDD2, "allocation_size": 0x10,
        "post_dispatch_vma": 0xFDDDC, "post_dispatch_target": 0xDD194,
    },
    {
        "family": "PrmNumber", "constructor_vma": 0xF0FB0,
        "callsite_vma": 0x111B96, "allocation_size": 0x10,
    },
    {
        "family": "PrmString", "constructor_vma": 0xFF9C8,
        "callsite_vma": 0x10288C, "allocation_size": 0x10,
    },
    {
        "family": "PrmPoint", "constructor_vma": 0xFFA3C,
        "callsite_vma": 0x113E8E, "allocation_size": 0x14,
    },
    {
        "family": "PrmStruct", "constructor_vma": 0xE7260,
        "callsite_vma": 0xE73D6, "allocation_size": 0x14,
        "post_dispatch_vma": 0xE73E0, "post_dispatch_target": 0xDFDC0,
    },
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_exec(elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > 0x100:
        raise ValueError("callsite window exceeds bounded limit")
    matches: list[tuple[int, int]] = []
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD" or not (int(segment["p_flags"]) & 1):
            continue
        base = int(segment["p_vaddr"])
        filesz = int(segment["p_filesz"])
        if base <= start and start + size <= base + filesz:
            matches.append((int(segment["p_offset"]) + start - base, size))
    if len(matches) != 1:
        raise ValueError(f"ELF_VMA 0x{start:x} is not uniquely executable")
    offset, count = matches[0]
    stream = elf.stream
    stream.seek(offset)
    data = stream.read(count)
    if len(data) != count:
        raise ValueError("truncated executable window")
    return data


def _decode(elf: ELFFile, start: int, size: int) -> list[Any]:
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    rows = list(decoder.disasm(_read_exec(elf, start, size), start))
    if not rows:
        raise ValueError(f"no Thumb instructions at 0x{start:x}")
    return rows


def _branch_target(instruction: Any) -> int | None:
    for operand in instruction.operands:
        if operand.type == ARM_OP_IMM:
            return int(operand.imm) & ~1
    return None


def _register_name(instruction: Any, operand_index: int) -> str | None:
    if operand_index >= len(instruction.operands):
        return None
    operand = instruction.operands[operand_index]
    if operand.type != ARM_OP_REG:
        return None
    return instruction.reg_name(operand.reg).lower()


def _operand_source(instruction: Any) -> dict[str, Any]:
    if len(instruction.operands) < 2:
        return {"kind": "UNKNOWN"}
    source = instruction.operands[1]
    if source.type == ARM_OP_IMM:
        return {"kind": "IMMEDIATE", "value": int(source.imm)}
    if source.type == ARM_OP_REG:
        return {"kind": "REGISTER", "register": instruction.reg_name(source.reg).lower()}
    if source.type == ARM_OP_MEM:
        base = instruction.reg_name(source.mem.base).lower() if source.mem.base else "NONE"
        index = instruction.reg_name(source.mem.index).lower() if source.mem.index else "NONE"
        return {
            "kind": "MEMORY",
            "base": base,
            "index": index,
            "displacement": int(source.mem.disp),
        }
    return {"kind": "UNKNOWN"}


def _writes_register(instruction: Any, register: str) -> bool:
    destination = _register_name(instruction, 0)
    if destination != register:
        return False
    mnemonic = instruction.mnemonic.lower()
    return mnemonic not in {
        "str", "strb", "strh", "strd", "stm", "stmia", "stmdb",
        "cmp", "cmn", "tst", "teq", "cbz", "cbnz", "b", "bl", "blx",
        "bx", "push",
    }


def _assignment(instruction: Any) -> dict[str, Any]:
    destination = _register_name(instruction, 0)
    return {
        "instruction_vma": hex(int(instruction.address)),
        "mnemonic": instruction.mnemonic.lower(),
        "operands": instruction.op_str,
        "destination": destination or "UNKNOWN",
        "source": _operand_source(instruction),
    }


def _last_assignments(rows: Iterable[Any], registers: Iterable[str]) -> dict[str, dict[str, Any]]:
    wanted = set(registers)
    result: dict[str, dict[str, Any]] = {
        register: {"status": "UNKNOWN", "reason": "no visible definition in bounded window"}
        for register in wanted
    }
    for instruction in rows:
        if instruction.mnemonic.lower() in {"bl", "blx"}:
            target = _branch_target(instruction)
            for register in wanted:
                result[register] = {
                    "status": "UNKNOWN",
                    "reason": "interprocedural call may clobber register",
                    "call_target_vma": hex(target) if target is not None else None,
                }
            continue
        for register in wanted:
            if _writes_register(instruction, register):
                result[register] = {
                    "status": "STATIC_INFERRED",
                    "assignment": _assignment(instruction),
                }
    return result


def _allocation_witness(rows: list[Any], callsite: int, expected_size: int) -> dict[str, Any]:
    before = [row for row in rows if int(row.address) < callsite]
    for index in range(len(before) - 1, -1, -1):
        instruction = before[index]
        if instruction.mnemonic.lower() not in {"bl", "blx"}:
            continue
        if _branch_target(instruction) != ALLOCATOR_VMA:
            continue
        prior = before[index - 1] if index else None
        if prior is None or _register_name(prior, 0) != "r0":
            continue
        source = _operand_source(prior)
        if source.get("kind") != "IMMEDIATE":
            continue
        return {
            "status": "PRIMARY_ELF_VERIFIED" if source["value"] == expected_size else "UNEXPECTED",
            "allocator_vma": hex(ALLOCATOR_VMA),
            "size_assignment": _assignment(prior),
            "allocation_size": source["value"],
        }
    return {"status": "UNKNOWN", "reason": "no bounded allocator witness"}


def _direct_call_witness(rows: list[Any], callsite: int, target: int) -> dict[str, Any]:
    instruction = next((row for row in rows if int(row.address) == callsite), None)
    if instruction is None:
        raise ValueError(f"callsite 0x{callsite:x} is not decoded")
    actual = _branch_target(instruction)
    return {
        "callsite_vma": hex(callsite),
        "mnemonic": instruction.mnemonic.lower(),
        "target_vma": hex(actual) if actual is not None else None,
        "expected_target_vma": hex(target),
        "status": "PRIMARY_ELF_VERIFIED"
        if instruction.mnemonic.lower() in {"bl", "blx"} and actual == (target & ~1)
        else "UNVERIFIED",
    }


def _post_dispatch(
    rows: list[Any], callsite: int, dispatch_vma: int, dispatch_target: int,
) -> dict[str, Any]:
    instruction = next((row for row in rows if int(row.address) == dispatch_vma), None)
    if instruction is None:
        return {"status": "UNKNOWN", "reason": "post-dispatch site not decoded"}
    before = [row for row in rows if callsite < int(row.address) < dispatch_vma]
    return {
        "status": "PRIMARY_ELF_VERIFIED"
        if instruction.mnemonic.lower() in {"bl", "blx"}
        and _branch_target(instruction) == (dispatch_target & ~1)
        else "UNVERIFIED",
        "dispatch_vma": hex(dispatch_vma),
        "target_vma": hex(_branch_target(instruction))
        if _branch_target(instruction) is not None else None,
        "arguments": _last_assignments(before, ("r0", "r1", "r2", "r3")),
    }


def probe_param_family_callsites(
    elf_path: Path,
    *,
    expected_sha256: str = EXPECTED_LIBOBJ_SHA,
    profiles: Iterable[Mapping[str, Any]] = PARAMBASE_CALLSITE_PROFILES,
) -> dict[str, Any]:
    """Verify direct constructor branches and bounded argument provenance."""
    path = Path(elf_path).resolve()
    if not path.is_file() or path.stat().st_size > MAX_ELF_BYTES:
        raise ValueError("private ELF missing or exceeds analysis limit")
    if not HEX_SHA.fullmatch(expected_sha256):
        raise ValueError("expected_sha256 must be a lowercase SHA-256 digest")
    digest = _sha256(path)
    if digest != expected_sha256:
        raise ValueError("full-file ELF SHA-256 mismatch; refusing analysis")
    observations: list[dict[str, Any]] = []
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_ARM":
            raise ValueError("expected ELF32 little-endian ARM")
        for profile in profiles:
            family = str(profile["family"])
            callsite = int(profile["callsite_vma"])
            target = int(profile["constructor_vma"])
            rows = _decode(elf, callsite - 0x30, 0x70)
            before = [row for row in rows if int(row.address) < callsite]
            after = [row for row in rows if int(row.address) >= callsite]
            observation: dict[str, Any] = {
                "family": family,
                "constructor_vma": hex(target),
                "address_space": "ELF_VMA",
                "constructor_call": _direct_call_witness(rows, callsite, target),
                "arguments": _last_assignments(before, ("r0", "r1", "r2", "r3")),
                "allocation": _allocation_witness(rows, callsite, int(profile["allocation_size"])),
                "provenance_scope": "bounded_linear_pre_call_window; branch joins and interprocedural values remain UNKNOWN",
            }
            if "post_dispatch_vma" in profile and "post_dispatch_target" in profile:
                observation["post_dispatch"] = _post_dispatch(
                    after, callsite, int(profile["post_dispatch_vma"]),
                    int(profile["post_dispatch_target"]),
                )
            observations.append(observation)
    return {
        "schema_version": 1,
        "firmware_version": "3.21",
        "binary_sha256": digest,
        "address_space": "ELF_VMA",
        "observations": observations,
        "raw_instruction_bytes_published": False,
        "runtime_verified": False,
        "callable": False,
        "limitations": [
            "Only direct constructor callsites in bounded Thumb windows are checked",
            "Linear last-definition summaries do not resolve branches, loops or interprocedural calls",
            "Register values loaded from memory or another register remain source candidates, not types",
            "Post-dispatch relations do not prove event delivery or key ownership",
            "No runtime execution, C++ exception, allocator, locking or thread-safety claim",
        ],
    }


def validate_param_family_callsites(report: Mapping[str, Any]) -> dict[str, Any]:
    """Reject identity, target or runtime/callable tampering."""
    errors: list[str] = []
    if report.get("binary_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != "ELF_VMA":
        errors.append("address_space")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    for index, item in enumerate(report.get("observations", [])):
        call = item.get("constructor_call", {})
        if call.get("status") != "PRIMARY_ELF_VERIFIED":
            errors.append(f"constructor_call:{index}")
        if item.get("address_space") != "ELF_VMA":
            errors.append(f"observation_address_space:{index}")
    return {"valid": not errors, "errors": errors, "observation_count": len(report.get("observations", []))}
