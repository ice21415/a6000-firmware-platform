"""Evidence-gated ParamBase constructor/clone field-access audit.

The existing family probes record RTTI, vtables and selected payload facts.
This module adds a reusable, bounded check over the same SHA-pinned primary
ELF: it records direct receiver-field accesses in each constructor and clone
body, including whether the ParamList key at ``+0x08`` is touched.  It does
not follow arbitrary helper calls, infer a source-level C++ declaration, or
claim that a cloned object preserves its key through an opaque helper.

Only normalized metadata is returned.  No firmware bytes are emitted and the
ELF is never executed.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterable

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, CS_OP_IMM, CS_OP_MEM, CS_OP_REG, Cs
from capstone.arm import ARM_REG_PC
from elftools.elf.elffile import ELFFile

from .param_family_probe import PARAM_FAMILY_TARGETS
from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA, MAX_ELF_BYTES


ADDRESS_SPACE = "ELF_VMA"
MAX_BODY_BYTES = 0x100
KEY_OFFSET = 0x08
PAYLOAD_OFFSETS = frozenset({0x0C, 0x10, 0x14, 0x18, 0x20, 0x34})


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def _read_exec(stream: Any, elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > MAX_BODY_BYTES:
        raise ValueError("lifecycle body exceeds bounded probe limit")
    matches: list[int] = []
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD" or not (int(segment["p_flags"]) & 1):
            continue
        base = int(segment["p_vaddr"])
        filesz = int(segment["p_filesz"])
        if base <= start and start + size <= base + filesz:
            matches.append(int(segment["p_offset"]) + start - base)
    if len(matches) != 1:
        raise ValueError(f"ELF_VMA 0x{start:x} is not uniquely executable")
    stream.seek(matches[0])
    data = stream.read(size)
    if len(data) != size:
        raise ValueError("truncated executable lifecycle body")
    return data


def _target_entry(spec: dict[str, Any], symbols: dict[str, tuple[int, int]], key: str) -> int:
    direct = spec.get(key)
    if direct is not None:
        return int(direct)
    symbol_name = spec.get(f"{key.replace('_vma', '')}_symbol")
    if symbol_name:
        row = symbols.get(str(symbol_name))
        if row is not None:
            return row[0] & ~1
    # The family profile uses constructor_symbol for constructor entries that
    # are exported but do not have a constructor_vma field.
    if key == "constructor_vma" and spec.get("constructor_symbol"):
        row = symbols.get(str(spec["constructor_symbol"]))
        if row is not None:
            return row[0] & ~1
    raise ValueError(f"missing {key} identity for {spec.get('name')}")


def _symbol_size(spec: dict[str, Any], symbols: dict[str, tuple[int, int]], entry: int, role: str) -> int | None:
    name_key = f"{role}_symbol"
    name = spec.get(name_key)
    if name and name in symbols and symbols[name][1]:
        return symbols[name][1]
    for symbol_name, (value, size) in symbols.items():
        if size and (value & ~1) == entry and role in {"constructor", "clone"}:
            return size
    return None


def _is_return(instruction: Any) -> bool:
    mnemonic = instruction.mnemonic.lower()
    return (mnemonic == "bx" and "lr" in instruction.op_str.lower()) or (
        mnemonic.startswith("pop") and "pc" in instruction.op_str.lower()
    )


def _decode_body(stream: Any, elf: ELFFile, entry: int, size_hint: int | None) -> tuple[list[Any], str]:
    # Profiled ``constructor_end`` values are often the address immediately
    # before a 32-bit ``pop.w {...,pc}``.  Add a small bounded margin so the
    # return instruction is included; discovery still stops at the first
    # return and never interprets the following literal pool as body code.
    size = min((size_hint + 0x10) if size_hint else MAX_BODY_BYTES, MAX_BODY_BYTES)
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    rows: list[Any] = []
    for instruction in decoder.disasm(_read_exec(stream, elf, entry, size), entry):
        rows.append(instruction)
        if _is_return(instruction):
            return rows, "RETURN_OBSERVED"
    return rows, "RETURN_NOT_OBSERVED_WITHIN_BOUND"


def _reg_name(instruction: Any, register: int) -> str:
    return instruction.reg_name(register).lower()


def _field_accesses(rows: Iterable[Any]) -> dict[str, Any]:
    """Summarize direct receiver aliases and field-offset memory operations.

    This is intentionally a shallow alias pass.  A register overwritten by a
    call is forgotten; helper-internal accesses and arbitrary pointer values
    are not attributed to the receiver.
    """
    aliases = {"r0"}
    accesses: list[dict[str, Any]] = []
    for instruction in rows:
        mnemonic = instruction.mnemonic.lower()
        operands = instruction.operands
        if mnemonic in {"bl", "blx", "bx"}:
            # r0-r3 are caller-saved under AAPCS; preserve only the receiver
            # aliases that are kept in callee-saved registers by explicit
            # copies.  A call does not erase r4-r11 aliases.
            aliases = {reg for reg in aliases if reg not in {"r0", "r1", "r2", "r3"}}
        if operands and operands[0].type == CS_OP_REG:
            destination = _reg_name(instruction, operands[0].reg)
            if mnemonic in {"mov", "mov.w", "movs"} and len(operands) > 1 and operands[1].type == CS_OP_REG:
                source = _reg_name(instruction, operands[1].reg)
                if source in aliases:
                    aliases.add(destination)
                elif destination in aliases:
                    aliases.discard(destination)
            elif destination in aliases and mnemonic not in {"cmp", "tst", "cmn", "teq"}:
                aliases.discard(destination)
        if mnemonic.startswith("add") and len(operands) >= 3:
            destination = _reg_name(instruction, operands[0].reg) if operands[0].type == CS_OP_REG else "UNKNOWN"
            source = _reg_name(instruction, operands[1].reg) if operands[1].type == CS_OP_REG else "UNKNOWN"
            if source in aliases and operands[2].type == CS_OP_IMM:
                displacement = int(operands[2].imm)
                accesses.append({
                    "instruction_vma": hex(int(instruction.address)),
                    "kind": "ADDRESS_OF_FIELD",
                    "offset": displacement,
                    "base_register": source,
                    "result_register": destination,
                    "mnemonic": mnemonic,
                })
        for operand in operands:
            if operand.type != CS_OP_MEM:
                continue
            base = _reg_name(instruction, operand.mem.base) if operand.mem.base != ARM_REG_PC else "pc"
            if base not in aliases:
                continue
            displacement = int(operand.mem.disp)
            if displacement not in {0, KEY_OFFSET} and displacement not in PAYLOAD_OFFSETS:
                continue
            is_store = mnemonic.startswith("str") or mnemonic.startswith("stm")
            accesses.append({
                "instruction_vma": hex(int(instruction.address)),
                "kind": "STORE" if is_store else "LOAD",
                "offset": displacement,
                "base_register": base,
                "mnemonic": mnemonic,
                "operands": instruction.op_str,
            })
    key = [item for item in accesses if item["offset"] == KEY_OFFSET]
    payload = [item for item in accesses if item["offset"] in PAYLOAD_OFFSETS and item["offset"] != KEY_OFFSET]
    return {
        "accesses": accesses,
        "key_accesses": key,
        "payload_accesses": payload,
        "key_directly_accessed": bool(key),
        "payload_directly_accessed": bool(payload),
    }


def _base_constructor_calls(rows: Iterable[Any]) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    for instruction in rows:
        if instruction.mnemonic.lower() not in {"bl", "blx"}:
            continue
        target = next((int(op.imm) & ~1 for op in instruction.operands if op.type == CS_OP_IMM), None)
        if target in {0xE11A4, 0xE50B4}:
            calls.append({
                "instruction_vma": hex(int(instruction.address)),
                "target_vma": hex(target),
                "target_role": "ParamBaseC2 PLT" if target == 0xE11A4 else "ParamBaseC2 local body",
                "status": "PRIMARY_ELF_VERIFIED",
            })
    return calls


def _family_row(stream: Any, elf: ELFFile, symbols: dict[str, tuple[int, int]], spec: dict[str, Any]) -> dict[str, Any]:
    constructor = _target_entry(spec, symbols, "constructor_vma")
    clone = int(spec["clone_entry"])
    constructor_size = _symbol_size(spec, symbols, constructor, "constructor")
    if constructor_size is None and spec.get("constructor_end") is not None:
        constructor_size = int(spec["constructor_end"]) - constructor
    clone_size = _symbol_size(spec, symbols, clone, "clone")
    constructor_rows, constructor_end = _decode_body(stream, elf, constructor, constructor_size)
    clone_rows, clone_end = _decode_body(stream, elf, clone, clone_size)
    constructor_fields = _field_accesses(constructor_rows)
    clone_fields = _field_accesses(clone_rows)
    return {
        "name": spec["name"],
        "discriminator": int(spec["discriminator"]),
        "constructor": {
            "entry_vma": hex(constructor),
            "bounded_extent_bytes": int(constructor_rows[-1].address + constructor_rows[-1].size - constructor),
            "termination": constructor_end,
            "base_constructor_calls": _base_constructor_calls(constructor_rows),
            "direct_field_access": constructor_fields,
            "key_initialization": "NOT_OBSERVED_IN_DIRECT_CONSTRUCTOR_BODY" if not constructor_fields["key_directly_accessed"] else "DIRECT_ACCESS_OBSERVED",
        },
        "clone": {
            "entry_vma": hex(clone),
            "bounded_extent_bytes": int(clone_rows[-1].address + clone_rows[-1].size - clone),
            "termination": clone_end,
            "direct_field_access": clone_fields,
            "key_copy": "NOT_OBSERVED_IN_DIRECT_CLONE_BODY" if not clone_fields["key_directly_accessed"] else "DIRECT_ACCESS_OBSERVED",
            "payload_source": "DIRECT_RECEIVER_PAYLOAD_ACCESS_OBSERVED" if clone_fields["payload_directly_accessed"] else "NO_DIRECT_RECEIVER_PAYLOAD_ACCESS_OBSERVED",
        },
        "evidence_level": "PRIMARY_ELF_VERIFIED",
        "semantic_scope": "direct receiver-field accesses only; helper-internal accesses, source-level types, ownership and runtime behavior remain UNKNOWN",
    }


def probe_param_lifecycle(
    elf_path: Path,
    *,
    expected_sha256: str = EXPECTED_LIBOBJ_SHA,
    targets: Iterable[dict[str, Any]] = PARAM_FAMILY_TARGETS,
) -> dict[str, Any]:
    """Audit direct key/payload access for every profiled ParamBase family."""
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
        "status": "LOCAL_PRIMARY_ELF_PARAMBASE_LIFECYCLE_AUDIT",
        "firmware_version": "3.21",
        "binary_sha256": digest,
        "address_space": ADDRESS_SPACE,
        "abi": "ARM AAPCS32, Thumb, little endian",
        "families": families,
        "aggregate": {
            "family_count": len(families),
            "constructors_without_direct_key_access": sum(not item["constructor"]["direct_field_access"]["key_directly_accessed"] for item in families),
            "clones_without_direct_key_access": sum(not item["clone"]["direct_field_access"]["key_directly_accessed"] for item in families),
            "clones_with_direct_payload_access": sum(item["clone"]["direct_field_access"]["payload_directly_accessed"] for item in families),
        },
        "key_assignment_boundary": {
            "setter_vma": "0x7eda84",
            "operation": "stores caller-supplied key at ParamBase-derived object +0x08",
            "verification": "PRIMARY_ELF_VERIFIED",
            "scope": "separate ParamList::add path; not a constructor/clone proof",
        },
        "runtime_verified": False,
        "callable": False,
        "limitations": [
            "Direct field accesses are shallow receiver-alias facts; calls are not inlined",
            "No key copy through opaque helper or external container is inferred",
            "Payload offsets do not establish source-level C++ types, ownership or alias safety",
            "Bounded return discovery is not a complete exception/control-flow proof",
            "No firmware code is executed and no camera is accessed",
        ],
    }


def validate_param_lifecycle(report: dict[str, Any]) -> dict[str, Any]:
    """Fail closed on identity, scope and runtime/callable promotion."""
    errors: list[str] = []
    if report.get("schema_version") != 1:
        errors.append("schema_version")
    if report.get("status") != "LOCAL_PRIMARY_ELF_PARAMBASE_LIFECYCLE_AUDIT":
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
        if item.get("evidence_level") != "PRIMARY_ELF_VERIFIED":
            errors.append(f"evidence_level:{item.get('name')}")
        if item.get("constructor", {}).get("direct_field_access", {}).get("key_directly_accessed"):
            errors.append(f"constructor_key_promotion:{item.get('name')}")
        if item.get("clone", {}).get("direct_field_access", {}).get("key_directly_accessed"):
            errors.append(f"clone_key_promotion:{item.get('name')}")
        if item.get("constructor", {}).get("termination") != "RETURN_OBSERVED":
            errors.append(f"constructor_scope:{item.get('name')}")
        if item.get("clone", {}).get("termination") != "RETURN_OBSERVED":
            errors.append(f"clone_scope:{item.get('name')}")
    boundary = report.get("key_assignment_boundary", {})
    if boundary.get("setter_vma") != "0x7eda84" or boundary.get("verification") != "PRIMARY_ELF_VERIFIED":
        errors.append("key_assignment_boundary")
    ghidra = report.get("ghidra_crosscheck")
    if not isinstance(ghidra, dict):
        errors.append("missing_ghidra_crosscheck")
    else:
        if ghidra.get("status") != "VERIFIED_STATIC_METADATA_CROSSCHECK":
            errors.append("ghidra_status")
        if ghidra.get("tool") != "Ghidra" or ghidra.get("version") != "12.1.3":
            errors.append("ghidra_identity")
        if ghidra.get("profile") != "param-lifecycle-field-audit":
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
        elif any(record.get("body_range") is None or record.get("instruction_count", 0) <= 0 for record in records):
            errors.append("ghidra_target_record_scope")
    aggregate = report.get("aggregate", {})
    if aggregate.get("family_count") != len(PARAM_FAMILY_TARGETS):
        errors.append("aggregate_family_count")
    return {"valid": not errors, "errors": sorted(set(errors))}
