"""Evidence-gated analysis of the ParamBase factory callers.

The probe reads only the authenticated private ``libObj.so`` and emits
metadata about register preparation, null guards, and the post-success
``ParamList::add`` call.  It does not emit instruction bytes, decompiler
text, or a callable wrapper.  Register provenance is intentionally scoped to
the straight-line instructions immediately preceding each known factory
callsite; it is not a replacement for a complete Ghidra data-flow proof.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterable

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG
from elftools.elf.elffile import ELFFile

from .elf_plt import resolve_plt_binding
from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA


FACTORY_ENTRY = 0x42ACD4
ADD_PLT_ENTRY = 0xDFDC0
ADD_LOCAL_ENTRY = 0x7EE0E6
MAX_READ_BYTES = 0x1000

# These entries are imported from the private Ghidra reference export.  The
# public profile contains identities and addresses only; it does not contain
# Sony bytes or an inferred source-level function name.
FACTORY_CALLERS: tuple[dict[str, int], ...] = (
    {"caller_entry": 0x4CF7A8, "factory_callsite": 0x4CF9BE},
    {"caller_entry": 0x60EC50, "factory_callsite": 0x60ECE0},
    {"caller_entry": 0x66D41C, "factory_callsite": 0x66D574},
    {"caller_entry": 0x682A64, "factory_callsite": 0x682A88},
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_exec_range(fp: Any, elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > MAX_READ_BYTES:
        raise ValueError("bounded executable read exceeds the probe limit")
    matches: list[int] = []
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD" or not (int(segment["p_flags"]) & 1):
            continue
        base = int(segment["p_vaddr"])
        count = int(segment["p_filesz"])
        if base <= start and start + size <= base + count:
            matches.append(int(segment["p_offset"]) + start - base)
    if len(matches) != 1:
        raise ValueError(f"ELF_VMA 0x{start:x} is not uniquely executable")
    fp.seek(matches[0])
    data = fp.read(size)
    if len(data) != size:
        raise ValueError("truncated executable range")
    return data


def _reg_name(ins: Any, operand: Any) -> str:
    return ins.reg_name(operand.reg) if operand.type == ARM_OP_REG else "UNKNOWN"


def _writes_register(ins: Any, register: str) -> bool:
    _, writes = ins.regs_access()
    return register in {ins.reg_name(reg) for reg in writes}


def _source_summary(ins: Any, register: str) -> dict[str, Any]:
    """Describe one immediately preceding register definition.

    The returned status is deliberately STATIC_INFERRED for data-flow
    provenance.  The instruction site itself is PRIMARY_ELF_VERIFIED after
    the authenticated bytes and Capstone decode have been checked.
    """
    result: dict[str, Any] = {
        "register": register,
        "instruction_vma": hex(ins.address),
        "instruction_evidence": "PRIMARY_ELF_VERIFIED",
        "provenance_status": "STATIC_INFERRED",
        "source_kind": "UNKNOWN_WRITE",
    }
    if not ins.operands:
        return result
    mnemonic = ins.mnemonic.lower()
    destination = ins.operands[0]
    if destination.type != ARM_OP_REG or _reg_name(ins, destination) != register:
        return result
    if mnemonic.startswith("mov") and len(ins.operands) >= 2:
        source = ins.operands[1]
        if source.type == ARM_OP_REG:
            result.update(source_kind="REGISTER_COPY", source_register=_reg_name(ins, source))
        elif source.type == ARM_OP_IMM:
            result.update(source_kind="IMMEDIATE", value=hex(int(source.imm) & 0xFFFFFFFF))
        return result
    if mnemonic.startswith("add") and len(ins.operands) >= 3:
        left = ins.operands[1]
        right = ins.operands[2]
        if left.type == ARM_OP_REG and right.type == ARM_OP_IMM:
            result.update(
                source_kind="REGISTER_PLUS_IMMEDIATE",
                base_register=_reg_name(ins, left),
                immediate=hex(int(right.imm) & 0xFFFFFFFF),
            )
        elif left.type == ARM_OP_REG and right.type == ARM_OP_REG:
            result.update(
                source_kind="REGISTER_PLUS_REGISTER",
                base_register=_reg_name(ins, left),
                index_register=_reg_name(ins, right),
            )
        return result
    if mnemonic.startswith("ldr") and len(ins.operands) >= 2:
        memory = ins.operands[1]
        if memory.type == ARM_OP_MEM:
            base = ins.reg_name(memory.mem.base) if memory.mem.base else "NONE"
            index = ins.reg_name(memory.mem.index) if memory.mem.index else None
            result.update(
                source_kind="DYNAMIC_MEMORY_LOAD",
                base_register=base,
                index_register=index,
                displacement=int(memory.mem.disp),
                value_is_static=False,
            )
        return result
    return result


def _nearest_definitions(instructions: list[Any], callsite: int) -> dict[str, dict[str, Any]]:
    before = [ins for ins in instructions if ins.address < callsite]
    definitions: dict[str, dict[str, Any]] = {}
    for register in ("r0", "r1", "r2"):
        for ins in reversed(before):
            if _writes_register(ins, register):
                definitions[register] = _source_summary(ins, register)
                break
        if register not in definitions:
            definitions[register] = {
                "register": register,
                "instruction_vma": None,
                "instruction_evidence": "UNRESOLVED",
                "provenance_status": "UNKNOWN",
                "source_kind": "UNKNOWN_WRITE",
            }
    return definitions


def _null_guard(instructions: list[Any], callsite: int) -> dict[str, Any]:
    after = [ins for ins in instructions if callsite < ins.address <= callsite + 0x30]
    for ins in after:
        mnemonic = ins.mnemonic.lower()
        regs = [ins.reg_name(op.reg) for op in ins.operands if op.type == ARM_OP_REG]
        if mnemonic in {"cbz", "cbnz"} and regs and regs[0] == "r0":
            return {
                "status": "PRIMARY_ELF_VERIFIED",
                "kind": "DIRECT_RESULT_NULL_BRANCH",
                "instruction_vma": hex(ins.address),
                "branch": mnemonic.upper(),
            }
        if mnemonic == "cmp" and regs and regs[0] == "r0":
            return {
                "status": "PRIMARY_ELF_VERIFIED",
                "kind": "DIRECT_RESULT_NULL_COMPARE",
                "instruction_vma": hex(ins.address),
                "branch": "FOLLOWING_CONDITIONAL_BRANCH_UNRESOLVED",
            }
    return {"status": "UNKNOWN", "kind": "NO_LOCAL_RESULT_GUARD"}


def _post_success_add(instructions: list[Any], callsite: int, fp: Any, elf: ELFFile) -> dict[str, Any]:
    for ins in instructions:
        if not callsite < ins.address <= callsite + 0x120:
            continue
        if ins.mnemonic.lower() not in {"bl", "blx"}:
            continue
        targets = [int(op.imm) for op in ins.operands if op.type == ARM_OP_IMM]
        if not targets or targets[-1] != ADD_PLT_ENTRY:
            continue
        binding = resolve_plt_binding(fp, elf, ADD_PLT_ENTRY, thumb_stub=False)
        return {
            "callsite": hex(ins.address),
            "target_vma": hex(ADD_PLT_ENTRY),
            "relation": "CALLS_PLT",
            "binding": binding,
            "path_status": "STATIC_INFERRED; bounded window locates the call after the result guard, but this probe is not a full CFG proof",
            "status": "VERIFIED_STATIC" if binding.get("status") == "VERIFIED_STATIC" else "UNKNOWN",
        }
    return {"status": "UNKNOWN", "relation": "NO_CONFIRMED_PARAMLIST_ADD_IN_LOCAL_WINDOW", "path_status": "UNKNOWN"}


def _decode_window(fp: Any, elf: ELFFile, start: int, end: int) -> list[Any]:
    raw = _read_exec_range(fp, elf, start, end - start)
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    return list(decoder.disasm(raw, start))


def probe_param_factory_callers(
    elf_path: Path,
    *,
    expected_sha256: str = EXPECTED_LIBOBJ_SHA,
    callers: Iterable[dict[str, int]] = FACTORY_CALLERS,
) -> dict[str, Any]:
    """Run the bounded private-ELF caller probe and return safe metadata."""
    path = Path(elf_path).resolve()
    if not path.is_file():
        raise ValueError("private ELF is missing")
    if not isinstance(expected_sha256, str) or not HEX_SHA.fullmatch(expected_sha256):
        raise ValueError("expected_sha256 must be a lowercase full SHA-256 digest")
    digest = _sha256(path)
    if digest != expected_sha256:
        raise ValueError("full-file ELF SHA-256 mismatch; refusing to decode")
    profiles = tuple(dict(item) for item in callers)
    if not profiles or len(profiles) > 8:
        raise ValueError("caller profile must contain one to eight entries")
    results: list[dict[str, Any]] = []
    with path.open("rb") as fp:
        elf = ELFFile(fp)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_ARM":
            raise ValueError("probe accepts only ELF32 little-endian ARM")
        for profile in profiles:
            caller = int(profile["caller_entry"])
            callsite = int(profile["factory_callsite"])
            instructions = _decode_window(fp, elf, caller, callsite + 0x120)
            matching = [
                ins for ins in instructions
                if ins.address == callsite
                and any(op.type == ARM_OP_IMM and int(op.imm) == FACTORY_ENTRY for op in ins.operands)
            ]
            if len(matching) != 1:
                raise ValueError(f"factory callsite 0x{callsite:x} did not decode uniquely")
            results.append({
                "caller_entry": hex(caller),
                "factory_callsite": hex(callsite),
                "factory_target": hex(FACTORY_ENTRY),
                "factory_target_status": "PRIMARY_ELF_VERIFIED",
                "argument_provenance": _nearest_definitions(instructions, callsite),
                "provenance_scope": "straight_line_nearest_definition; dominance and full CFG are not claimed",
                "result_guard": _null_guard(instructions, callsite),
                "post_success_add": _post_success_add(instructions, callsite, fp, elf),
            })
    return {
        "status": "LOCAL_PRIMARY_ELF_CALLER_EVIDENCE_ONLY",
        "binary_file_sha256": digest,
        "address_space": "ELF_VMA",
        "factory_entry": hex(FACTORY_ENTRY),
        "add_plt_entry": hex(ADD_PLT_ENTRY),
        "add_local_entry": hex(ADD_LOCAL_ENTRY),
        "callers": results,
        "dynamic_table_values_recovered": False,
        "ownership_verified": False,
        "runtime_verified": False,
        "callable": False,
    }


def validate_param_factory_probe(report: dict[str, Any]) -> dict[str, Any]:
    """Fail-closed validation used by synthetic tests and CI."""
    errors: list[str] = []
    if report.get("binary_file_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != "ELF_VMA":
        errors.append("address_space")
    if report.get("factory_entry") != hex(FACTORY_ENTRY):
        errors.append("factory_entry")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    if report.get("dynamic_table_values_recovered") is not False:
        errors.append("dynamic_values_must_remain_unknown")
    callers = report.get("callers")
    if not isinstance(callers, list) or not callers:
        errors.append("missing_callers")
    else:
        for item in callers:
            if item.get("factory_target_status") != "PRIMARY_ELF_VERIFIED":
                errors.append("factory_target_status")
            for register in ("r0", "r1", "r2"):
                source = item.get("argument_provenance", {}).get(register, {})
                if source.get("provenance_status") not in {"STATIC_INFERRED", "UNKNOWN"}:
                    errors.append(f"{register}_provenance")
            guard = item.get("result_guard", {})
            if guard.get("status") not in {"PRIMARY_ELF_VERIFIED", "UNKNOWN"}:
                errors.append("result_guard")
            add = item.get("post_success_add", {})
            if add.get("status") == "VERIFIED_STATIC":
                candidates = add.get("binding", {}).get("candidates", [])
                if len(candidates) != 1 or candidates[0].get("symbol") != "_ZN9ParamList3addEmP9ParamBase":
                    errors.append("add_binding")
    return {"valid": not errors, "errors": sorted(set(errors)), "caller_count": len(callers) if isinstance(callers, list) else 0}
