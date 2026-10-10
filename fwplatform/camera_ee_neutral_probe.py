"""Bounded primary-ELF evidence probe for the Camera EE-neutral path.

The probe authenticates the private, SHA-pinned A6000 3.21 ``libObj.so``
before decoding two small Thumb regions.  It records instruction facts and
unique file-backed PLT relocations only.  Research aliases such as
``ModelCamera::pvt_ExeEENeutralCmd`` remain descriptive: the ELF does not
provide an independent semantic symbol for those entry points.

This module never executes firmware and never exposes instruction bytes.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from capstone.arm import ARM_OP_IMM
from elftools.elf.elffile import ELFFile

from .elf_plt import resolve_plt_binding
from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA, MAX_ELF_BYTES


ADDRESS_SPACE = "ELF_VMA"
ABI = "ARM AAPCS32, Thumb, little endian"
SENDER_ENTRY = 0x443D14
SENDER_SIZE = 0x80
COMMAND_ENTRY = 0x4B1A20
COMMAND_SIZE = 0x80

_SENDER_BINDINGS = {
    0xDE540: "_ZN3MWF6ObjMsgC1Ejj",
    0xE16B4: "_ZN3MWF17ParamStd_TemplateIjLNS_5Param4TypeE8EEC1Ej",
    0xDE4D8: "_ZN3MWF6ObjMsg19SetCommonRelayParamEjRKNS_5ParamE",
    0xDC198: "_ZN3MWF17ParamStd_TemplateIjLNS_5Param4TypeE8EED1Ev",
    0xDC144: "_ZN3MWF5ObjIf17IssueCommandAsyncEPvPNS_6ObjMsgE",
    0xDDD94: "_ZN3MWF6ObjMsgD1Ev",
    0xDD620: "_ZdlPv",
    0xDC100: "_Znwj",
    0xDE4CC: "_ZN3MWF6ObjMsgC1Ev",
    0xDE37C: "memset",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_exec_range(fp: Any, elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > 0x180:
        raise ValueError("Camera EE-neutral probe exceeds bounded read limit")
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


def _decode_range(fp: Any, elf: ELFFile, entry: int, size: int) -> dict[int, Any]:
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    rows = list(decoder.disasm(_read_exec_range(fp, elf, entry, size), entry))
    if not rows:
        raise ValueError(f"ELF_VMA 0x{entry:x} did not decode as Thumb")
    return {int(row.address): row for row in rows}


def _immediates(ins: Any) -> list[int]:
    return [int(op.imm) for op in ins.operands if op.type == ARM_OP_IMM]


def _require(
    rows: dict[int, Any],
    address: int,
    mnemonic: str,
    *,
    operands: str | None = None,
    target: int | None = None,
    immediate: int | None = None,
) -> Any:
    ins = rows.get(address)
    if ins is None or ins.mnemonic.lower() != mnemonic.lower():
        raise ValueError(f"unexpected {mnemonic} at 0x{address:x}")
    if operands is not None and ins.op_str.lower() != operands.lower():
        raise ValueError(f"unexpected operands at 0x{address:x}")
    if target is not None and target not in _immediates(ins):
        raise ValueError(f"unexpected branch target at 0x{address:x}")
    if immediate is not None and immediate not in _immediates(ins):
        raise ValueError(f"unexpected immediate at 0x{address:x}")
    return ins


def _binding(fp: Any, elf: ELFFile, entry: int, symbol: str) -> dict[str, Any]:
    # These are ARM-state PLT veneers reached by Thumb BLX.  The resolver's
    # thumb_stub=True mode is only for an explicit BX-PC interworking prefix.
    result = resolve_plt_binding(fp, elf, entry, thumb_stub=False)
    candidates = result.get("candidates") or []
    if result.get("status") != "VERIFIED_STATIC" or len(candidates) != 1:
        raise ValueError(f"PLT binding at 0x{entry:x} is not unique")
    if candidates[0].get("symbol") != symbol:
        raise ValueError(
            f"PLT binding at 0x{entry:x} is {candidates[0].get('symbol')!r}, "
            f"expected {symbol!r}"
        )
    return result


def _instruction_fact(row: Any, *, note: str | None = None) -> dict[str, Any]:
    result = {
        "instruction_vma": hex(int(row.address)),
        "mnemonic": row.mnemonic.lower(),
        "operands": row.op_str,
        "status": "PRIMARY_ELF_VERIFIED",
    }
    if note:
        result["note"] = note
    return result


def _observe_sender(fp: Any, elf: ELFFile, rows: dict[int, Any]) -> dict[str, Any]:
    checks = [
        (0x443D14, "push", "{r4, r5, r7, lr}", None, None),
        (0x443D1A, "mov", "r4, r0", None, None),
        (0x443D1C, "mov.w", "r1, #0x3100", None, 0x3100),
        (0x443D20, "add.w", "r0, r7, #8", None, 8),
        (0x443D24, "movw", "r2, #0x7502", None, 0x7502),
        (0x443D28, "blx", None, 0xDE540, None),
        (0x443D2C, "movs", "r0, #8", None, 8),
        (0x443D2E, "bl", None, 0x42067C, None),
        (0x443D34, "mov", "r1, r4", None, None),
        (0x443D36, "mov", "r0, r7", None, None),
        (0x443D38, "blx", None, 0xE16B4, None),
        (0x443D3C, "add.w", "r0, r7, #8", None, 8),
        (0x443D40, "movs", "r1, #1", None, 1),
        (0x443D42, "mov", "r2, r7", None, None),
        (0x443D44, "blx", None, 0xDE4D8, None),
        (0x443D48, "mov", "r0, r7", None, None),
        (0x443D4A, "blx", None, 0xDC198, None),
        (0x443D4E, "mov", "r0, r5", None, None),
        (0x443D50, "add.w", "r1, r7, #8", None, 8),
        (0x443D54, "blx", None, 0xDC144, None),
        (0x443D58, "cbnz", None, 0x443D84, None),
        (0x443D62, "blx", None, 0xDDD94, None),
        (0x443D68, "blx", None, 0xDD620, None),
        (0x443D6E, "blx", None, 0xDC100, None),
        (0x443D74, "blx", None, 0xDE4CC, None),
        (0x443D80, "blx", None, 0xDE37C, None),
        (0x443D88, "blx", None, 0xDDD94, None),
        (0x443D92, "pop", "{r4, r5, r7, pc}", None, None),
    ]
    observations: list[dict[str, Any]] = []
    for address, mnemonic, operands, target, immediate in checks:
        row = _require(
            rows,
            address,
            mnemonic,
            operands=operands,
            target=target,
            immediate=immediate,
        )
        observations.append(_instruction_fact(row))
    bindings = {
        hex(entry): _binding(fp, elf, entry, symbol)
        for entry, symbol in _SENDER_BINDINGS.items()
    }
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "entry_vma": hex(SENDER_ENTRY),
        "bounded_extent_bytes": SENDER_SIZE,
        "address_space": ADDRESS_SPACE,
        "instruction_mode": "Thumb",
        "incoming_r0": "preserved in r4; exact source-level type UNKNOWN",
        "local_message": {
            "address": "r7+8",
            "r7_definition": "sp at function entry plus zero",
            "constructor_call_vma": hex(0xDE540),
            "header_group_r1": hex(0x3100),
            "header_command_r2": hex(0x7502),
            "status": "PRIMARY_ELF_VERIFIED",
        },
        "parameter_setup": {
            "call_vma": hex(0xE16B4),
            "r0": "r7",
            "r1": "incoming r0 preserved in r4",
            "status": "PRIMARY_ELF_VERIFIED",
        },
        "relay_parameter": {
            "call_vma": hex(0xDE4D8),
            "r0": "r7+8",
            "r1": 1,
            "r2": "r7",
            "status": "PRIMARY_ELF_VERIFIED",
        },
        "issue_command_async": {
            "call_vma": hex(0xDC144),
            "symbol_signature_from_relocation": "MWF::ObjIf::IssueCommandAsync(void*, MWF::ObjMsg*)",
            "r0_implicit_this": "result of local call 0x42067c with r0=8; concrete ObjIf type UNKNOWN",
            "r1_explicit_void_pointer": "r7+8; source-level pointee type UNKNOWN",
            "r2_explicit_objmsg_pointer": "UNKNOWN at the callsite because the prior PLT call may clobber caller-save r2",
            "return_register": "r0",
            "branch": "cbnz r0 -> 0x443d84",
            "status": "PRIMARY_ELF_VERIFIED",
            "semantic_return_meaning": "UNKNOWN",
        },
        "cleanup": {
            "success_or_nonzero_path_dtor_vma": hex(0xDDD94),
            "global_previous_object_dtor_vma": hex(0xDDD94),
            "global_previous_object_delete_vma": hex(0xDD620),
            "replacement_allocation_size": 8,
            "replacement_default_ctor_vma": hex(0xDE4CC),
            "zero_fill_call_vma": hex(0xDE37C),
            "status": "PRIMARY_ELF_VERIFIED",
        },
        "bindings": bindings,
        "instructions": observations,
        "semantic_identity": "EE-neutral message sender candidate; exact source-level owner remains STATIC_INFERRED",
        "runtime_verified": False,
        "callable": False,
    }


def _observe_command(rows: dict[int, Any]) -> dict[str, Any]:
    checks = [
        (COMMAND_ENTRY, "push", "{r4, r5, r6, r7, lr}", None, None),
        (COMMAND_ENTRY + 0x02, "mov", "r4, r0", None, None),
        (COMMAND_ENTRY + 0x0C, "add.w", "r5, r4, #0x2700", None, 0x2700),
        (COMMAND_ENTRY + 0x18, "bl", None, 0x4DF3B4, None),
        (COMMAND_ENTRY + 0x1C, "ldr", "r0, [r5]", None, None),
        (COMMAND_ENTRY + 0x1E, "adds", "r0, #1", None, 1),
        (COMMAND_ENTRY + 0x20, "str", "r0, [r5]", None, None),
        (COMMAND_ENTRY + 0x22, "bl", None, SENDER_ENTRY, None),
        (COMMAND_ENTRY + 0x26, "add.w", "r3, r4, #0x2680", None, 0x2680),
        (COMMAND_ENTRY + 0x2A, "movs", "r2, #1", None, 1),
        (COMMAND_ENTRY + 0x2C, "mov", "r0, r4", None, None),
        (COMMAND_ENTRY + 0x2E, "movs", "r1, #0x11", None, 0x11),
        (COMMAND_ENTRY + 0x30, "strb.w", "r2, [r3, #0x7c]", None, None),
        (COMMAND_ENTRY + 0x34, "ldr", "r5, [r5, #4]", None, None),
        (COMMAND_ENTRY + 0x36, "bl", None, 0x131E94, None),
        (COMMAND_ENTRY + 0x3A, "mov", "r6, r0", None, None),
        (COMMAND_ENTRY + 0x3C, "movs", "r1, #0x12", None, 0x12),
        (COMMAND_ENTRY + 0x3E, "mov", "r0, r4", None, None),
        (COMMAND_ENTRY + 0x40, "bl", None, 0x131E94, None),
        (COMMAND_ENTRY + 0x46, "movs", "r1, #0xe", None, 0xE),
        (COMMAND_ENTRY + 0x4A, "movw", "r2, #0x33ba", None, 0x33BA),
        (COMMAND_ENTRY + 0x52, "stm.w", "sp, {r5, r6}", None, None),
        (COMMAND_ENTRY + 0x56, "bl", None, 0x1323B4, None),
        (COMMAND_ENTRY + 0x5A, "add.w", "r4, r4, #0x2700", None, 0x2700),
        (COMMAND_ENTRY + 0x64, "ldr", "r2, [r4]", None, None),
        (COMMAND_ENTRY + 0x66, "bl", None, 0x4DF2C2, None),
        (COMMAND_ENTRY + 0x6A, "mov", "r0, r7", None, None),
        (COMMAND_ENTRY + 0x6C, "bl", None, 0x4DF27C, None),
        (COMMAND_ENTRY + 0x70, "add.w", "r7, r7, #0xc", None, 0xC),
        (COMMAND_ENTRY + 0x74, "mov", "sp, r7", None, None),
        (COMMAND_ENTRY + 0x76, "pop", "{r4, r5, r6, r7, pc}", None, None),
    ]
    observations: list[dict[str, Any]] = []
    for address, mnemonic, operands, target, immediate in checks:
        row = _require(
            rows,
            address,
            mnemonic,
            operands=operands,
            target=target,
            immediate=immediate,
        )
        observations.append(_instruction_fact(row))
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "entry_vma": hex(COMMAND_ENTRY),
        "bounded_extent_bytes": COMMAND_SIZE,
        "address_space": ADDRESS_SPACE,
        "instruction_mode": "Thumb",
        "incoming_r0": "preserved in r4; source-level receiver type UNKNOWN",
        "relay_counter": {
            "field_offset": hex(0x2700),
            "address_expression": "this+0x2700",
            "operation": "load, add 1, store",
            "sender_argument_r0": "updated 32-bit field value",
            "status": "PRIMARY_ELF_VERIFIED",
        },
        "sender_call": {
            "call_vma": hex(0x4B1A42),
            "target_vma": hex(SENDER_ENTRY),
            "status": "PRIMARY_ELF_VERIFIED",
        },
        "pending_byte": {
            "field_offset": hex(0x26FC),
            "derivation": "this+0x2680 followed by [base+0x7c]",
            "width_bits": 8,
            "stored_value": 1,
            "status": "PRIMARY_ELF_VERIFIED",
        },
        "selector_helpers": {
            "helper_vma": hex(0x131E94),
            "calls": [
                {"r1": hex(0x11), "return_saved_to": "r6"},
                {"r1": hex(0x12), "return_saved_to": "stack+8"},
            ],
            "status": "PRIMARY_ELF_VERIFIED",
            "helper_identity": "UNKNOWN",
        },
        "event_or_action_helper": {
            "helper_vma": hex(0x1323B4),
            "r0": "this",
            "r1": hex(0x0E),
            "r2": hex(0x33BA),
            "stack_arguments": "[sp]=field at this+0x2704; [sp+4]=second selector-helper return",
            "status": "PRIMARY_ELF_VERIFIED",
            "semantic_identity": "UNKNOWN",
        },
        "cleanup_helpers": [hex(0x4DF2C2), hex(0x4DF27C)],
        "semantic_identity": "ModelCamera EE-neutral command candidate; source-level alias is STATIC_INFERRED",
        "runtime_verified": False,
        "callable": False,
    }


def probe_camera_ee_neutral(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Decode the bounded EE-neutral sender and command regions."""
    path = Path(elf_path).resolve()
    if not path.is_file() or path.stat().st_size > MAX_ELF_BYTES:
        raise ValueError("private ELF missing or exceeds analysis limit")
    if not HEX_SHA.fullmatch(expected_sha256):
        raise ValueError("expected_sha256 must be a lowercase full SHA-256 digest")
    digest = _sha256(path)
    if digest != expected_sha256:
        raise ValueError("full-file ELF SHA-256 mismatch; refusing analysis")
    with path.open("rb") as fp:
        elf = ELFFile(fp)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_ARM":
            raise ValueError("expected ELF32 little-endian ARM")
        sender_rows = _decode_range(fp, elf, SENDER_ENTRY, SENDER_SIZE)
        command_rows = _decode_range(fp, elf, COMMAND_ENTRY, COMMAND_SIZE)
        sender = _observe_sender(fp, elf, sender_rows)
        command = _observe_command(command_rows)
    return {
        "schema_version": 1,
        "status": "LOCAL_PRIMARY_ELF_CAMERA_EE_NEUTRAL_EVIDENCE_ONLY",
        "firmware_version": "3.21",
        "binary_sha256": digest,
        "address_space": ADDRESS_SPACE,
        "abi": ABI,
        "sender": sender,
        "command": command,
        "relations": [
            {
                "source_vma": hex(COMMAND_ENTRY),
                "target_vma": hex(SENDER_ENTRY),
                "relation": "DIRECT_CALL",
                "callsite_vma": hex(0x4B1A42),
                "status": "PRIMARY_ELF_VERIFIED",
            },
            {
                "source_vma": hex(SENDER_ENTRY),
                "target_symbol": _SENDER_BINDINGS[0xDC144],
                "relation": "PLT_CALL",
                "callsite_vma": hex(0x443D54),
                "status": "VERIFIED_STATIC",
            },
        ],
        "runtime_verified": False,
        "callable": False,
        "limitations": [
            "Source-level identities for 0x4b1a20, 0x443d14 and local helpers are not independently present in the ELF symbol evidence",
            "The IssueCommandAsync return value is observed only as a conditional branch; success/error semantics are UNKNOWN",
            "The transport receiver, relay completion and hardware readiness semantics are UNKNOWN",
            "The 0x131e94 and 0x1323b4 helper identities and complete object layouts remain UNKNOWN",
            "No runtime execution, device access or firmware modification was performed",
        ],
    }


def _check_binding(record: dict[str, Any], expected_symbol: str) -> bool:
    return (
        record.get("status") == "VERIFIED_STATIC"
        and record.get("address_space") == ADDRESS_SPACE
        and record.get("candidates")
        and len(record["candidates"]) == 1
        and record["candidates"][0].get("symbol") == expected_symbol
    )


def validate_camera_ee_neutral(report: dict[str, Any]) -> dict[str, Any]:
    """Validate a sanitized report without promoting it to a callable API."""
    errors: list[str] = []
    if report.get("schema_version") != 1:
        errors.append("schema_version")
    if report.get("status") != "LOCAL_PRIMARY_ELF_CAMERA_EE_NEUTRAL_EVIDENCE_ONLY":
        errors.append("status")
    if report.get("binary_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != ADDRESS_SPACE:
        errors.append("address_space")
    if report.get("abi") != ABI:
        errors.append("abi")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    sender = report.get("sender", {})
    command = report.get("command", {})
    if sender.get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("sender_status")
    if sender.get("entry_vma") != hex(SENDER_ENTRY):
        errors.append("sender_entry")
    if command.get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("command_status")
    if command.get("entry_vma") != hex(COMMAND_ENTRY):
        errors.append("command_entry")
    local_message = sender.get("local_message", {})
    if local_message.get("header_group_r1") != hex(0x3100):
        errors.append("message_group")
    if local_message.get("header_command_r2") != hex(0x7502):
        errors.append("message_command")
    issue = sender.get("issue_command_async", {})
    if issue.get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("issue_status")
    if issue.get("call_vma") != hex(0xDC144):
        errors.append("issue_call")
    pending = command.get("pending_byte", {})
    if pending.get("field_offset") != hex(0x26FC) or pending.get("stored_value") != 1:
        errors.append("pending_field")
    counter = command.get("relay_counter", {})
    if counter.get("field_offset") != hex(0x2700):
        errors.append("relay_field")
    helpers = command.get("selector_helpers", {})
    if [row.get("r1") for row in helpers.get("calls", [])] != [hex(0x11), hex(0x12)]:
        errors.append("selector_values")
    event = command.get("event_or_action_helper", {})
    if event.get("r1") != hex(0x0E) or event.get("r2") != hex(0x33BA):
        errors.append("event_helper_values")
    bindings = sender.get("bindings", {})
    for entry, symbol in _SENDER_BINDINGS.items():
        if not _check_binding(bindings.get(hex(entry), {}), symbol):
            errors.append(f"binding:{hex(entry)}")
    relation = next(
        (row for row in report.get("relations", []) if row.get("relation") == "PLT_CALL"),
        None,
    )
    if (
        not relation
        or relation.get("status") != "VERIFIED_STATIC"
        or relation.get("source_vma") != hex(SENDER_ENTRY)
        or relation.get("callsite_vma") != hex(0x443D54)
        or relation.get("target_symbol") != _SENDER_BINDINGS[0xDC144]
    ):
        errors.append("issue_relation")
    direct_relation = next(
        (row for row in report.get("relations", []) if row.get("relation") == "DIRECT_CALL"),
        None,
    )
    if (
        not direct_relation
        or direct_relation.get("status") != "PRIMARY_ELF_VERIFIED"
        or direct_relation.get("source_vma") != hex(COMMAND_ENTRY)
        or direct_relation.get("target_vma") != hex(SENDER_ENTRY)
        or direct_relation.get("callsite_vma") != hex(0x4B1A42)
    ):
        errors.append("sender_relation")
    ghidra = report.get("ghidra_crosscheck")
    if ghidra is not None:
        if (
            ghidra.get("status") != "VERIFIED_STATIC_METADATA_CROSSCHECK"
            or ghidra.get("tool") != "Ghidra"
            or ghidra.get("version") != "12.1.3"
            or ghidra.get("profile") != "camera-ee-neutral"
            or ghidra.get("exit_code") != 0
            or ghidra.get("completion_marker") != "COMPLETE_TARGET_EXPORT"
            or ghidra.get("auto_analysis_completed") is not False
        ):
            errors.append("ghidra_crosscheck")
        program = ghidra.get("program_identity", {})
        if (
            program.get("binary_sha256") != EXPECTED_LIBOBJ_SHA
            or program.get("language") != "ARM:LE:32:v8"
            or program.get("compiler_spec") != "default"
            or program.get("image_base") != "0x00010000"
            or program.get("address_space") != "ram"
        ):
            errors.append("ghidra_identity")
    return {"valid": not errors, "errors": sorted(set(errors))}
