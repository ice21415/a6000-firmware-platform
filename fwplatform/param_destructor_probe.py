"""Evidence-gated ParamBase destructor and deleting-wrapper audit.

This module reads only the authenticated private A6000 3.21 ``libObj.so``.
It records direct receiver-field accesses, direct call targets and the
observed nondeleting/deleting wrapper relationship for the ten known
ParamBase-derived families.  A payload helper is deliberately reported as a
candidate call; the helper's implementation, ownership contract and runtime
allocator behavior are outside this bounded pass.

The output is normalized metadata.  It never emits firmware bytes, executes
the ELF or exposes a callable firmware wrapper.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any, Iterable

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, CS_OP_IMM, CS_OP_MEM, CS_OP_REG, Cs
from capstone.arm import ARM_REG_PC
from elftools.elf.elffile import ELFFile

from .param_family_probe import PARAM_FAMILY_TARGETS, _read_bytes, _symbols, _target_symbol
from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA, MAX_ELF_BYTES


ADDRESS_SPACE = "ELF_VMA"
MAX_BODY_BYTES = 0x80
KEY_OFFSET = 0x08
DELETE_VMA = 0xDD620
PARAMBASE_D1_VMA = 0xE4734
OBJMSG_D1_VMA = 0xDDD94

# These bounds end at the first observed return in the authenticated primary
# ELF.  They are analysis limits, not claims about source-level function size.
DESTRUCTOR_EXTENTS: dict[str, tuple[int, int]] = {
    "PrmBool": (0x1A, 0x14),
    "PrmNumber": (0x1A, 0x14),
    "PrmString": (0x24, 0x14),
    "PrmPoint": (0x1A, 0x14),
    "PrmDimension": (0x1A, 0x14),
    "PrmStruct": (0x22, 0x14),
    "PrmSet": (0x22, 0x14),
    "PrmNumberList": (0x2C, 0x14),
    "PrmCntInfoList": (0x3C, 0x14),
    "PrmObjMsg": (0x2C, 0x14),
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _section_is_executable(elf: ELFFile, address: int, size: int):
    for section in elf.iter_sections():
        start = int(section["sh_addr"])
        end = start + int(section["sh_size"])
        if start <= address and address + size <= end:
            if not (int(section["sh_flags"]) & 0x4):
                raise ValueError(f"ELF_VMA 0x{address:x} is not executable")
            return section
    raise ValueError(f"ELF_VMA 0x{address:x} is not mapped for {size} bytes")


def _decode_body(elf: ELFFile, entry: int, extent: int) -> tuple[list[Any], str]:
    if extent <= 0 or extent > MAX_BODY_BYTES:
        raise ValueError("destructor body exceeds bounded probe limit")
    _section_is_executable(elf, entry, extent)
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    rows: list[Any] = []
    for instruction in decoder.disasm(_read_bytes(elf, entry, extent), entry):
        rows.append(instruction)
        mnemonic = instruction.mnemonic.lower()
        if (mnemonic == "bx" and "lr" in instruction.op_str.lower()) or (
            mnemonic.startswith("pop") and "pc" in instruction.op_str.lower()
        ):
            return rows, "RETURN_OBSERVED"
    return rows, "RETURN_NOT_OBSERVED_WITHIN_BOUND"


def _reg_name(instruction: Any, register: int) -> str:
    return instruction.reg_name(register).lower()


def _offset_expression(expression: str | None, displacement: int) -> int | None:
    if expression == "receiver":
        return displacement
    match = re.fullmatch(r"receiver\+0x([0-9a-f]+)", expression or "")
    if match:
        return int(match.group(1), 16) + displacement
    return None


def _receiver_expression(offset: int) -> str:
    return "receiver" if offset == 0 else f"receiver+0x{offset:x}"


def _add_expression(expression: str | None, amount: int) -> str | None:
    if expression is None:
        return None
    match = re.fullmatch(r"receiver(?:\+0x([0-9a-f]+))?", expression)
    if not match:
        return None
    base = int(match.group(1), 16) if match.group(1) else 0
    return _receiver_expression(base + amount)


def _writeback_step(instruction: Any) -> int | None:
    if not instruction.writeback:
        return None
    for operand in instruction.operands:
        if operand.type == CS_OP_IMM:
            value = int(operand.imm)
            if value > 0:
                return value
    return None


def _call_role(
    target: int | None,
    family: dict[str, Any],
    symbols: dict[str, tuple[int, int]],
    binding_symbol: str | None,
) -> tuple[str, str | None]:
    if target is None:
        return "INDIRECT_TARGET_UNKNOWN", None
    normalized = target & ~1
    family_symbol = family.get("destructor_symbol")
    if family_symbol is None:
        family_symbol = f"_ZN{len(str(family['name']))}{family['name']}D1Ev"
    if binding_symbol == family_symbol or normalized == int(family["destructor_entry"]):
        return "FAMILY_NONDELETING_DESTRUCTOR", binding_symbol or _target_symbol(symbols, normalized)
    if binding_symbol == "_ZdlPv":
        return "OPERATOR_DELETE_PLT", binding_symbol
    if binding_symbol == "_ZdaPv":
        return "ARRAY_DELETE_PLT", binding_symbol
    if normalized == PARAMBASE_D1_VMA:
        return "PARAMBASE_NONDELETING_DESTRUCTOR", _target_symbol(symbols, normalized)
    if normalized == DELETE_VMA:
        return "OPERATOR_DELETE_PLT", "_ZdlPv"
    if normalized == OBJMSG_D1_VMA:
        return "PAYLOAD_OBJMSG_NONDELETING_DESTRUCTOR", "_ZN3MWF6ObjMsgD1Ev"
    return "UNKNOWN_DIRECT_TARGET", binding_symbol or _target_symbol(symbols, normalized)


def _plt_binding(stream: Any, elf: ELFFile, target: int | None) -> dict[str, Any] | None:
    if target is None:
        return None
    from .elf_plt import resolve_plt_binding

    try:
        result = resolve_plt_binding(stream, elf, target & ~1, thumb_stub=False)
    except (OSError, ValueError, KeyError, IndexError):
        return None
    if result.get("status") != "VERIFIED_STATIC":
        return None
    return {
        "got_slot": result.get("got_slot"),
        "status": result.get("status"),
        "runtime_binding": result.get("runtime_binding", "UNKNOWN"),
        "candidates": [
            {
                "symbol": item.get("symbol"),
                "relocation_type": item.get("relocation_type"),
                "section": item.get("section"),
            }
            for item in result.get("candidates", [])
        ],
    }


def _direct_observations(
    stream: Any,
    elf: ELFFile,
    rows: Iterable[Any],
    family: dict[str, Any],
    symbols: dict[str, tuple[int, int]],
) -> dict[str, Any]:
    registers: dict[str, str | None] = {"r0": "receiver"}
    accesses: list[dict[str, Any]] = []
    calls: list[dict[str, Any]] = []

    for instruction in rows:
        mnemonic = instruction.mnemonic.lower()
        operands = instruction.operands

        if mnemonic in {"bl", "blx"}:
            target = next(
                (int(operand.imm) & ~1 for operand in operands if operand.type == CS_OP_IMM),
                None,
            )
            binding = _plt_binding(stream, elf, target)
            binding_symbol = None
            if binding and len(binding["candidates"]) == 1:
                binding_symbol = binding["candidates"][0].get("symbol")
            role, symbol = _call_role(target, family, symbols, binding_symbol)
            calls.append({
                "instruction_vma": hex(int(instruction.address)),
                "target_vma": hex(target) if target is not None else None,
                "target_symbol": symbol,
                "role": role,
                "r0_argument_expression": registers.get("r0"),
                "plt_binding": binding,
                "direct": target is not None,
                "status": "PRIMARY_ELF_VERIFIED",
            })
            # AAPCS caller-saved registers cannot be carried across an opaque
            # call.  Callee-saved receiver aliases remain available.
            for register in ("r0", "r1", "r2", "r3"):
                registers.pop(register, None)
            continue

        # First record memory operations.  A load from the receiver also
        # creates a deliberately opaque expression for later call-argument
        # provenance; it is not promoted to a source-level pointer type.
        for operand in operands:
            if operand.type != CS_OP_MEM:
                continue
            base = _reg_name(instruction, operand.mem.base) if operand.mem.base != ARM_REG_PC else "pc"
            expression = registers.get(base)
            offset = _offset_expression(expression, int(operand.mem.disp))
            is_store = mnemonic.startswith("str") or mnemonic.startswith("stm")
            if offset is not None:
                accesses.append({
                    "instruction_vma": hex(int(instruction.address)),
                    "kind": "STORE" if is_store else "LOAD",
                    "offset": offset,
                    "base_register": base,
                    "mnemonic": mnemonic,
                    "operands": instruction.op_str,
                })
                if not is_store and operands and operands[0].type == CS_OP_REG:
                    registers[_reg_name(instruction, operands[0].reg)] = f"load({_receiver_expression(offset)})"
            elif not is_store and operands and operands[0].type == CS_OP_REG:
                registers[_reg_name(instruction, operands[0].reg)] = None

            step = _writeback_step(instruction)
            if step is not None and expression is not None:
                updated = _add_expression(expression, step)
                accesses.append({
                    "instruction_vma": hex(int(instruction.address)),
                    "kind": "POST_INDEX_STEP",
                    "offset": _offset_expression(updated, 0),
                    "base_register": base,
                    "step_bytes": step,
                    "mnemonic": mnemonic,
                    "operands": instruction.op_str,
                })
                registers[base] = updated

        # Register copies and simple receiver-relative address formation are
        # enough to capture the bounded ARM/Thumb destructor patterns without
        # pretending to be an interprocedural data-flow engine.
        if operands and operands[0].type == CS_OP_REG:
            destination = _reg_name(instruction, operands[0].reg)
            if mnemonic in {"mov", "mov.w", "movs"} and len(operands) > 1:
                source = operands[1]
                if source.type == CS_OP_REG:
                    registers[destination] = registers.get(_reg_name(instruction, source.reg))
                else:
                    registers[destination] = None
            elif mnemonic.startswith("add") and len(operands) >= 3:
                source = operands[1]
                amount = operands[2]
                if source.type == CS_OP_REG and amount.type == CS_OP_IMM:
                    registers[destination] = _add_expression(
                        registers.get(_reg_name(instruction, source.reg)), int(amount.imm)
                    )
                else:
                    registers[destination] = None
            elif mnemonic in {
                "cbz", "cbnz", "cmp", "cmn", "tst", "teq", "str", "strb",
                "strh", "str.w", "push", "pop", "stm", "stmia", "stmdb",
            }:
                pass
            elif not any(operand.type == CS_OP_MEM for operand in operands):
                registers[destination] = None

    key_accesses = [item for item in accesses if item.get("offset") == KEY_OFFSET]
    payload_accesses = [
        item for item in accesses
        if item.get("offset") in {0x0C, 0x10, 0x14, 0x18, 0x20, 0x34}
    ]
    payload_calls = [
        item for item in calls
        if item["role"] not in {
            "PARAMBASE_NONDELETING_DESTRUCTOR",
            "FAMILY_NONDELETING_DESTRUCTOR",
            "OPERATOR_DELETE_PLT",
        }
        and item.get("r0_argument_expression") not in {None, "receiver"}
    ]
    return {
        "accesses": accesses,
        "key_accesses": key_accesses,
        "payload_accesses": payload_accesses,
        "key_directly_accessed": bool(key_accesses),
        "calls": calls,
        "payload_cleanup_call_candidates": payload_calls,
        "base_destructor_call_observed": any(
            item["role"] == "PARAMBASE_NONDELETING_DESTRUCTOR" for item in calls
        ),
    }


def _family_row(stream: Any, elf: ELFFile, symbols: dict[str, tuple[int, int]], spec: dict[str, Any]) -> dict[str, Any]:
    name = str(spec["name"])
    d1_extent, d0_extent = DESTRUCTOR_EXTENTS[name]
    d1_entry = int(spec["destructor_entry"])
    d0_entry = int(spec["deleting_destructor_entry"])
    d1_rows, d1_end = _decode_body(elf, d1_entry, d1_extent)
    d0_rows, d0_end = _decode_body(elf, d0_entry, d0_extent)
    d1 = _direct_observations(stream, elf, d1_rows, spec, symbols)
    d0 = _direct_observations(stream, elf, d0_rows, spec, symbols)
    return {
        "name": name,
        "discriminator": int(spec["discriminator"]),
        "nondeleting_destructor": {
            "entry_vma": hex(d1_entry),
            "bounded_extent_bytes": d1_extent,
            "termination": d1_end,
            "direct_observations": d1,
        },
        "deleting_destructor": {
            "entry_vma": hex(d0_entry),
            "bounded_extent_bytes": d0_extent,
            "termination": d0_end,
            "direct_observations": d0,
        },
        "evidence_level": "PRIMARY_ELF_VERIFIED",
        "semantic_scope": (
            "direct receiver-field accesses and direct call targets only; "
            "helper semantics, allocator ownership, exception behavior, "
            "locking and runtime validity remain UNKNOWN"
        ),
    }


def probe_param_destructors(
    elf_path: Path,
    *,
    expected_sha256: str = EXPECTED_LIBOBJ_SHA,
    targets: Iterable[dict[str, Any]] = PARAM_FAMILY_TARGETS,
) -> dict[str, Any]:
    """Audit D1/D0 destructor paths for all profiled ParamBase families."""
    path = Path(elf_path).resolve()
    if not path.is_file() or path.stat().st_size > MAX_ELF_BYTES:
        raise ValueError("private ELF missing or exceeds analysis limit")
    if not HEX_SHA.fullmatch(expected_sha256):
        raise ValueError("expected_sha256 must be a lowercase full SHA-256 digest")
    digest = _sha256(path)
    if digest != expected_sha256:
        raise ValueError("full-file ELF SHA-256 mismatch; refusing analysis")
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_ARM":
            raise ValueError("expected ELF32 little-endian ARM")
        symbols = _symbols(elf)
        families = [_family_row(stream, elf, symbols, dict(spec)) for spec in targets]
    return {
        "schema_version": 1,
        "status": "LOCAL_PRIMARY_ELF_PARAMBASE_DESTRUCTOR_AUDIT",
        "firmware_version": "3.21",
        "binary_sha256": digest,
        "address_space": ADDRESS_SPACE,
        "abi": "ARM AAPCS32, Thumb, little endian",
        "families": families,
        "aggregate": {
            "family_count": len(families),
            "nondeleting_with_base_destructor_call": sum(
                item["nondeleting_destructor"]["direct_observations"]["base_destructor_call_observed"]
                for item in families
            ),
            "deleting_with_family_d1_and_operator_delete": sum(
                any(call["role"] == "FAMILY_NONDELETING_DESTRUCTOR" for call in item["deleting_destructor"]["direct_observations"]["calls"])
                and any(call["role"] == "OPERATOR_DELETE_PLT" for call in item["deleting_destructor"]["direct_observations"]["calls"])
                for item in families
            ),
            "families_with_payload_cleanup_call_candidate": sum(
                bool(item["nondeleting_destructor"]["direct_observations"]["payload_cleanup_call_candidates"])
                for item in families
            ),
            "nondeleting_with_direct_key_access": sum(
                item["nondeleting_destructor"]["direct_observations"]["key_directly_accessed"]
                for item in families
            ),
            "deleting_with_direct_key_access": sum(
                item["deleting_destructor"]["direct_observations"]["key_directly_accessed"]
                for item in families
            ),
        },
        "lifetime_boundary": {
            "d1_role": "nondeleting destructor candidate; direct base call is observed",
            "d0_role": "deleting-wrapper candidate; family D1 followed by _ZdlPv is observed",
            "verification": "PRIMARY_ELF_VERIFIED",
            "ownership_semantics": "STATIC_INFERRED at most; allocation provenance and external ownership remain UNKNOWN",
        },
        "runtime_verified": False,
        "callable": False,
        "limitations": [
            "Body bounds are bounded first-return extents, not complete source-level function boundaries",
            "Payload cleanup call candidates do not prove helper semantics or ownership transfer",
            "No exception/EHABI edge, allocator pairing, null policy or double-destroy policy is inferred",
            "No locking, atomicity, concurrency or runtime loader behavior is observed by this static pass",
            "No firmware code is executed and no camera is accessed",
        ],
    }


def validate_param_destructors(report: dict[str, Any]) -> dict[str, Any]:
    """Fail closed on identity, D1/D0 call relations and unsafe promotion."""
    errors: list[str] = []
    if report.get("schema_version") != 1:
        errors.append("schema_version")
    if report.get("status") != "LOCAL_PRIMARY_ELF_PARAMBASE_DESTRUCTOR_AUDIT":
        errors.append("status")
    if report.get("binary_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != ADDRESS_SPACE:
        errors.append("address_space")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    families = report.get("families")
    if not isinstance(families, list) or len(families) != len(PARAM_FAMILY_TARGETS):
        errors.append("family_count")
        families = []
    expected_names = {spec["name"] for spec in PARAM_FAMILY_TARGETS}
    if {item.get("name") for item in families} != expected_names:
        errors.append("family_identity")
    for item in families:
        name = item.get("name")
        if item.get("evidence_level") != "PRIMARY_ELF_VERIFIED":
            errors.append(f"evidence_level:{name}")
        d1 = item.get("nondeleting_destructor", {})
        d0 = item.get("deleting_destructor", {})
        if d1.get("termination") != "RETURN_OBSERVED":
            errors.append(f"d1_scope:{name}")
        if d0.get("termination") != "RETURN_OBSERVED":
            errors.append(f"d0_scope:{name}")
        d1_obs = d1.get("direct_observations", {})
        d0_obs = d0.get("direct_observations", {})
        if d1_obs.get("key_directly_accessed"):
            errors.append(f"d1_key_access:{name}")
        if d0_obs.get("key_directly_accessed"):
            errors.append(f"d0_key_access:{name}")
        d1_calls = d1_obs.get("calls", [])
        d0_calls = d0_obs.get("calls", [])
        if not any(call.get("role") == "PARAMBASE_NONDELETING_DESTRUCTOR" for call in d1_calls):
            errors.append(f"d1_base_call:{name}")
        if not any(call.get("role") == "FAMILY_NONDELETING_DESTRUCTOR" for call in d0_calls):
            errors.append(f"d0_family_call:{name}")
        if not any(call.get("role") == "OPERATOR_DELETE_PLT" for call in d0_calls):
            errors.append(f"d0_delete_call:{name}")
    ghidra = report.get("ghidra_crosscheck")
    if not isinstance(ghidra, dict):
        errors.append("missing_ghidra_crosscheck")
    else:
        if ghidra.get("status") != "VERIFIED_STATIC_METADATA_CROSSCHECK":
            errors.append("ghidra_status")
        if ghidra.get("tool") != "Ghidra" or ghidra.get("version") != "12.1.3":
            errors.append("ghidra_identity")
        if ghidra.get("profile") != "param-destructor-field-audit":
            errors.append("ghidra_profile")
        if ghidra.get("binary_sha256") != EXPECTED_LIBOBJ_SHA or ghidra.get("program_sha256") != EXPECTED_LIBOBJ_SHA:
            errors.append("ghidra_binary_identity")
        if ghidra.get("language") != "ARM:LE:32:v8" or ghidra.get("compiler_spec") != "default":
            errors.append("ghidra_abi_identity")
        if ghidra.get("image_base") != "0x10000" or ghidra.get("address_space") != "ram":
            errors.append("ghidra_address_identity")
        execution = ghidra.get("execution", {})
        if execution.get("exit_code") != 0 or execution.get("completion_marker") is not True:
            errors.append("ghidra_execution")
        if execution.get("auto_analysis_completed") is not False:
            errors.append("ghidra_auto_analysis_scope")
        if ghidra.get("raw_export_private") is not True or ghidra.get("semantic_names_verified") is not False:
            errors.append("ghidra_publication_scope")
        if ghidra.get("target_count") != 20:
            errors.append("ghidra_target_count")
        if not all(isinstance(ghidra.get(key), int) and ghidra[key] > 0 for key in ("instruction_count", "basic_block_count", "cfg_edge_count")):
            errors.append("ghidra_nonempty_counts")
        records = ghidra.get("target_records")
        if not isinstance(records, list) or len(records) != 20:
            errors.append("ghidra_target_records")
    aggregate = report.get("aggregate", {})
    if aggregate.get("family_count") != len(PARAM_FAMILY_TARGETS):
        errors.append("aggregate_family_count")
    return {"valid": not errors, "errors": sorted(set(errors))}
