"""Bounded primary-ELF evidence probe for the Camera EE-neutral path.

The probe authenticates the private, SHA-pinned A6000 3.21 ``libObj.so``
before decoding bounded Thumb regions.  It records instruction facts and
unique file-backed PLT relocations only.  Research aliases such as
``ModelCamera::pvt_ExeEENeutralCmd`` remain descriptive: the ELF does not
provide an independent semantic symbol for those entry points.

This module never executes firmware and never exposes instruction bytes.
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
from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA, MAX_ELF_BYTES


ADDRESS_SPACE = "ELF_VMA"
ABI = "ARM AAPCS32, Thumb, little endian"
SENDER_ENTRY = 0x443D14
SENDER_SIZE = 0x80
COMMAND_ENTRY = 0x4B1A20
COMMAND_SIZE = 0x80
SELECTOR_GETTER_ENTRY = 0x131E94
SELECTOR_GETTER_SIZE = 0x0E
HEADER_BUILDER_ENTRY = 0x131BCC
HEADER_BUILDER_SIZE = 0x34
SET_BLOG_DATA_ENTRY = 0x13228C
SET_BLOG_DATA_SIZE = 0x18
ENVELOPE_BUILDER_ENTRY = 0x1323B4
ENVELOPE_BUILDER_SIZE = 0x50
LOCAL_WORD_GETTER_ENTRY = 0x10CF18
LOCAL_WORD_GETTER_SIZE = 0x08

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


def _read_load_range(
    fp: Any, elf: ELFFile, start: int, size: int, *, executable: bool | None,
) -> bytes:
    if size <= 0 or size > 0x180:
        raise ValueError("Camera EE-neutral probe exceeds bounded read limit")
    offsets: list[int] = []
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD":
            continue
        if executable is not None and bool(int(segment["p_flags"]) & 1) != executable:
            continue
        base = int(segment["p_vaddr"])
        count = int(segment["p_filesz"])
        if base <= start and start + size <= base + count:
            offsets.append(int(segment["p_offset"]) + start - base)
    if len(offsets) != 1:
        raise ValueError(f"ELF_VMA 0x{start:x} is not uniquely mapped in PT_LOAD")
    fp.seek(offsets[0])
    data = fp.read(size)
    if len(data) != size:
        raise ValueError("truncated executable range")
    return data


def _read_exec_range(fp: Any, elf: ELFFile, start: int, size: int) -> bytes:
    return _read_load_range(fp, elf, start, size, executable=True)


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


def _binding(
    fp: Any, elf: ELFFile, entry: int, symbol: str, *, thumb_stub: bool = False,
) -> dict[str, Any]:
    # These are ARM-state PLT veneers reached by Thumb BLX.  The resolver's
    # thumb_stub=True mode is only for an explicit BX-PC interworking prefix.
    result = resolve_plt_binding(fp, elf, entry, thumb_stub=thumb_stub)
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


def _read_vma(fp: Any, elf: ELFFile, start: int, size: int) -> bytes:
    return _read_load_range(fp, elf, start, size, executable=None)


def _observe_literal_label(fp: Any, elf: ELFFile, rows: dict[int, Any]) -> dict[str, Any]:
    """Verify the bounded PC-relative label used by the command callsite."""
    _require(rows, 0x4B1A64, "ldr", operands="r3, [pc, #0x40]")
    _require(rows, 0x4B1A70, "add", operands="r3, pc")
    # Thumb LDR (literal) uses Align(address + 4, 4); ADD (PC) uses
    # address + 4.  Keep both the literal slot and resulting pointer in
    # ELF_VMA rather than conflating them with a Ghidra address.
    literal_slot_vma = ((0x4B1A64 + 4) & ~3) + 0x40
    loaded = _read_vma(fp, elf, literal_slot_vma, 4)
    relative = struct.unpack("<I", loaded)[0]
    label_vma = (relative + 0x4B1A70 + 4) & 0xFFFFFFFF
    label = _read_vma(fp, elf, label_vma, 8)
    if label != b"NeutrOn\x00":
        raise ValueError("unexpected EE-neutral label bytes")
    return {
        "literal_slot_vma": hex(literal_slot_vma),
        "relative_word": hex(relative),
        "label_vma": hex(label_vma),
        "copied_bytes": 8,
        "text_prefix": "NeutrOn",
        "status": "PRIMARY_ELF_VERIFIED",
    }


def _observe_command(
    fp: Any, elf: ELFFile, rows: dict[int, Any],
) -> dict[str, Any]:
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
        (COMMAND_ENTRY + 0x44, "ldr", "r3, [pc, #0x40]", None, None),
        (COMMAND_ENTRY + 0x46, "movs", "r1, #0xe", None, 0xE),
        (COMMAND_ENTRY + 0x4A, "movw", "r2, #0x33ba", None, 0x33BA),
        (COMMAND_ENTRY + 0x50, "add", "r3, pc", None, None),
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
        "pc_relative_label": _observe_literal_label(fp, elf, rows),
        "cleanup_helpers": [hex(0x4DF2C2), hex(0x4DF27C)],
        "semantic_identity": "ModelCamera EE-neutral command candidate; source-level alias is STATIC_INFERRED",
        "runtime_verified": False,
        "callable": False,
    }


def _observe_selector_getter(fp: Any, elf: ELFFile) -> dict[str, Any]:
    rows = _decode_range(fp, elf, SELECTOR_GETTER_ENTRY, SELECTOR_GETTER_SIZE)
    checks = [
        (SELECTOR_GETTER_ENTRY, "push", "{r7, lr}", None, None),
        (SELECTOR_GETTER_ENTRY + 2, "add", "r7, sp, #0", None, None),
        (SELECTOR_GETTER_ENTRY + 4, "ldr", "r0, [r0, #0x20]", None, None),
        (SELECTOR_GETTER_ENTRY + 6, "pop.w", "{r7, lr}", None, None),
        (SELECTOR_GETTER_ENTRY + 10, "b.w", None, 0xDF964, None),
    ]
    facts = []
    for address, mnemonic, operands, target, immediate in checks:
        facts.append(
            _instruction_fact(
                _require(
                    rows, address, mnemonic, operands=operands,
                    target=target, immediate=immediate,
                )
            )
        )
    return {
        "entry_vma": hex(SELECTOR_GETTER_ENTRY),
        "bounded_extent_bytes": SELECTOR_GETTER_SIZE,
        "address_space": ADDRESS_SPACE,
        "instruction_mode": "Thumb",
        "receiver_field_offset": hex(0x20),
        "tail_target_vma": hex(0xDF964),
        "tail_target_symbol": "_ZN12ModelManager11checkStatusEi",
        "tail_target_abi": "r0=[receiver+0x20] as implicit this; r1 is preserved selector; return is propagated",
        "binding": _binding(
            fp, elf, 0xDF964, "_ZN12ModelManager11checkStatusEi",
            thumb_stub=True,
        ),
        "instructions": facts,
        "status": "PRIMARY_ELF_VERIFIED",
        "semantic_identity": "ModelManager::checkStatus forwarding wrapper; source-level owner of the wrapper remains UNKNOWN",
    }


def _observe_local_word_getter(fp: Any, elf: ELFFile) -> dict[str, Any]:
    rows = _decode_range(fp, elf, LOCAL_WORD_GETTER_ENTRY, LOCAL_WORD_GETTER_SIZE)
    checks = [
        (LOCAL_WORD_GETTER_ENTRY, "push", "{r7, lr}", None, None),
        (LOCAL_WORD_GETTER_ENTRY + 2, "add", "r7, sp, #0", None, None),
        (LOCAL_WORD_GETTER_ENTRY + 4, "ldr", "r0, [r0, #0x18]", None, None),
        (LOCAL_WORD_GETTER_ENTRY + 6, "pop", "{r7, pc}", None, None),
    ]
    facts = [
        _instruction_fact(
            _require(rows, address, mnemonic, operands=operands,
                     target=target, immediate=immediate)
        )
        for address, mnemonic, operands, target, immediate in checks
    ]
    return {
        "entry_vma": hex(LOCAL_WORD_GETTER_ENTRY),
        "bounded_extent_bytes": LOCAL_WORD_GETTER_SIZE,
        "address_space": ADDRESS_SPACE,
        "instruction_mode": "Thumb",
        "receiver_field_offset": hex(0x18),
        "return_register": "r0",
        "instructions": facts,
        "status": "PRIMARY_ELF_VERIFIED",
        "semantic_identity": "unnamed local word getter; field meaning UNKNOWN",
    }


def _observe_header_builder(fp: Any, elf: ELFFile) -> dict[str, Any]:
    rows = _decode_range(fp, elf, HEADER_BUILDER_ENTRY, HEADER_BUILDER_SIZE)
    # The key stores are checked separately so the record remains readable;
    # no source-level message type is assigned to this byte layout.
    checks = [
        (0x131BCC, "push", None, None, None),
        (0x131BD2, "movs", None, None, 0),
        (0x131BDA, "strh", "r0, [r4]", None, None),
        (0x131BDC, "strb", "r2, [r4, #2]", None, None),
        (0x131BDE, "strb", "r1, [r4, #3]", None, None),
        (0x131BE0, "strh", "r3, [r4, #4]", None, None),
        (0x131BE2, "strh", "r0, [r4, #6]", None, None),
        (0x131BE4, "cbz", None, 0x131BF0, None),
        (0x131BF6, "blx", None, 0xDE37C, None),
        (0x131BFC, "pop", "{r3, r4, r5, r6, r7, pc}", None, None),
    ]
    facts = [
        _instruction_fact(
            _require(rows, address, mnemonic, operands=operands,
                     target=target, immediate=immediate)
        )
        for address, mnemonic, operands, target, immediate in checks
    ]
    return {
        "entry_vma": hex(HEADER_BUILDER_ENTRY),
        "bounded_extent_bytes": HEADER_BUILDER_SIZE,
        "address_space": ADDRESS_SPACE,
        "instruction_mode": "Thumb",
        "layout": {
            "+0x00": "u16 zero",
            "+0x02": "u8 from r2",
            "+0x03": "u8 from r1",
            "+0x04": "u16 from r3",
            "+0x06": "u16 zero",
            "+0x08": "+0x1c source pointer, 20 bytes; null source is memset zero",
        },
        "null_source": {
            "guard": "cbz fifth stack argument",
            "callee_symbol": "memset",
            "callee_vma": hex(0xDE37C),
            "arguments": "dest=r0+8, fill=0, length=0x14",
        },
        "bindings": {
            hex(0xDE37C): _binding(fp, elf, 0xDE37C, "memset"),
        },
        "instructions": facts,
        "status": "PRIMARY_ELF_VERIFIED",
        "semantic_identity": "20-byte payload envelope header builder; protocol namespace UNKNOWN",
    }


def _observe_set_blog_data(fp: Any, elf: ELFFile) -> dict[str, Any]:
    rows = _decode_range(fp, elf, SET_BLOG_DATA_ENTRY, SET_BLOG_DATA_SIZE)
    checks = [
        (0x13228C, "push", None, None, None),
        (0x132292, "bl", None, 0x10CF18, None),
        (0x132298, "strh", "r0, [r4]", None, None),
        (0x13229A, "movs", None, None, 0x0A),
        (0x1322A0, "b.w", None, 0xDE480, None),
    ]
    facts = [
        _instruction_fact(
            _require(rows, address, mnemonic, operands=operands,
                     target=target, immediate=immediate)
        )
        for address, mnemonic, operands, target, immediate in checks
    ]
    return {
        "entry_vma": hex(SET_BLOG_DATA_ENTRY),
        "bounded_extent_bytes": SET_BLOG_DATA_SIZE,
        "address_space": ADDRESS_SPACE,
        "instruction_mode": "Thumb",
        "local_word_getter_vma": hex(LOCAL_WORD_GETTER_ENTRY),
        "local_word_getter_field": hex(0x18),
        "set_blog_data_vma": hex(0xDE480),
        "set_blog_data_symbol": "setBlogData",
        "set_blog_data_abi": "r0=0x0a; r1=envelope pointer; return is propagated through tail branch",
        "binding": _binding(fp, elf, 0xDE480, "setBlogData", thumb_stub=True),
        "instructions": facts,
        "status": "PRIMARY_ELF_VERIFIED",
        "semantic_identity": "setBlogData forwarding wrapper; blog/event meaning UNKNOWN",
    }


def _observe_envelope_builder(fp: Any, elf: ELFFile) -> dict[str, Any]:
    rows = _decode_range(fp, elf, ENVELOPE_BUILDER_ENTRY, ENVELOPE_BUILDER_SIZE)
    checks = [
        (0x1323B4, "push", None, None, None),
        (0x1323BE, "ldr", "r2, [r7, #0x48]", None, None),
        (0x1323C2, "str", "r2, [r7, #0x1c]", None, None),
        (0x1323C4, "ldr", "r2, [r7, #0x4c]", None, None),
        (0x1323C8, "ldr", "r2, [r7, #0x50]", None, None),
        (0x1323CC, "movs", None, None, 0),
        (0x1323D2, "cbz", None, 0x1323E0, None),
        (0x1323DA, "adds", None, None, 8),
        (0x1323DC, "blx", None, 0xDCE00, None),
        (0x1323EE, "bl", None, HEADER_BUILDER_ENTRY, None),
        (0x1323F6, "bl", None, SET_BLOG_DATA_ENTRY, None),
        (0x1323FA, "movs", None, None, 0),
        (0x132402, "pop", "{r4, r5, r6, r7, pc}", None, None),
    ]
    facts = [
        _instruction_fact(
            _require(rows, address, mnemonic, operands=operands,
                     target=target, immediate=immediate)
        )
        for address, mnemonic, operands, target, immediate in checks
    ]
    return {
        "entry_vma": hex(ENVELOPE_BUILDER_ENTRY),
        "bounded_extent_bytes": ENVELOPE_BUILDER_SIZE,
        "address_space": ADDRESS_SPACE,
        "instruction_mode": "Thumb",
        "input_registers": {
            "r0": "receiver/target candidate",
            "r1": "copied to envelope header byte +0x02 through header builder",
            "r2": "low 16 bits copied to envelope header halfword +0x04",
            "r3": "optional pointer; first 8 bytes copied when non-null",
        },
        "stack_arguments": {
            "r7+0x48": "copied to local +0x1c",
            "r7+0x4c": "copied to local +0x20",
            "r7+0x50": "copied to local +0x24",
        },
        "payload": {
            "source": "local +0x1c",
            "length": 0x14,
            "optional_pointer_copy": "local +0x28, length 8 through strncpy; local +0x28/+0x2c initially zero",
            "protocol_meaning": "UNKNOWN",
        },
        "calls": {
            "header_builder": hex(HEADER_BUILDER_ENTRY),
            "set_blog_data": hex(SET_BLOG_DATA_ENTRY),
            "strncpy_vma": hex(0xDCE00),
        },
        "strncpy_binding": _binding(fp, elf, 0xDCE00, "strncpy"),
        "return": "zero in r0 after setBlogData call",
        "instructions": facts,
        "status": "PRIMARY_ELF_VERIFIED",
        "semantic_identity": "generic 20-byte envelope builder; event/action meaning UNKNOWN",
    }


def _observe_helper_evidence(fp: Any, elf: ELFFile) -> dict[str, Any]:
    return {
        "selector_getter": _observe_selector_getter(fp, elf),
        "local_word_getter": _observe_local_word_getter(fp, elf),
        "header_builder": _observe_header_builder(fp, elf),
        "set_blog_data": _observe_set_blog_data(fp, elf),
        "envelope_builder": _observe_envelope_builder(fp, elf),
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
        command = _observe_command(fp, elf, command_rows)
        helpers = _observe_helper_evidence(fp, elf)
    return {
        "schema_version": 1,
        "status": "LOCAL_PRIMARY_ELF_CAMERA_EE_NEUTRAL_EVIDENCE_ONLY",
        "firmware_version": "3.21",
        "binary_sha256": digest,
        "address_space": ADDRESS_SPACE,
        "abi": ABI,
        "sender": sender,
        "command": command,
        "helper_evidence": helpers,
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
            {
                "source_vma": hex(SELECTOR_GETTER_ENTRY),
                "target_symbol": "_ZN12ModelManager11checkStatusEi",
                "relation": "PLT_CALL",
                "callsite_vma": hex(0x131E9E),
                "status": "VERIFIED_STATIC",
            },
            {
                "source_vma": hex(ENVELOPE_BUILDER_ENTRY),
                "target_vma": hex(HEADER_BUILDER_ENTRY),
                "relation": "DIRECT_CALL",
                "callsite_vma": hex(0x1323EE),
                "status": "PRIMARY_ELF_VERIFIED",
            },
            {
                "source_vma": hex(ENVELOPE_BUILDER_ENTRY),
                "target_vma": hex(SET_BLOG_DATA_ENTRY),
                "relation": "DIRECT_CALL",
                "callsite_vma": hex(0x1323F6),
                "status": "PRIMARY_ELF_VERIFIED",
            },
            {
                "source_vma": hex(SET_BLOG_DATA_ENTRY),
                "target_symbol": "setBlogData",
                "relation": "PLT_CALL",
                "callsite_vma": hex(0x1322A0),
                "status": "VERIFIED_STATIC",
            },
            {
                "source_vma": hex(ENVELOPE_BUILDER_ENTRY),
                "target_symbol": "strncpy",
                "relation": "PLT_CALL",
                "callsite_vma": hex(0x1323DC),
                "status": "VERIFIED_STATIC",
            },
            {
                "source_vma": hex(HEADER_BUILDER_ENTRY),
                "target_symbol": "memset",
                "relation": "PLT_CALL",
                "callsite_vma": hex(0x131BF6),
                "status": "VERIFIED_STATIC",
            },
        ],
        "runtime_verified": False,
        "callable": False,
        "limitations": [
            "Source-level identities for 0x4b1a20, 0x443d14 and local helpers are not independently present in the ELF symbol evidence",
            "The IssueCommandAsync return value is observed only as a conditional branch; success/error semantics are UNKNOWN",
            "The transport receiver, relay completion and hardware readiness semantics are UNKNOWN",
            "The complete ModelManager, setBlogData and envelope object layouts remain UNKNOWN",
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
    label = command.get("pc_relative_label", {})
    if (
        label.get("literal_slot_vma") != hex(0x4B1AA8)
        or label.get("label_vma") != hex(0xCE8D7B)
        or label.get("copied_bytes") != 8
        or label.get("text_prefix") != "NeutrOn"
        or label.get("status") != "PRIMARY_ELF_VERIFIED"
    ):
        errors.append("pc_relative_label")
    helpers = report.get("helper_evidence", {})
    selector = helpers.get("selector_getter", {})
    if (
        selector.get("status") != "PRIMARY_ELF_VERIFIED"
        or selector.get("receiver_field_offset") != hex(0x20)
        or selector.get("tail_target_vma") != hex(0xDF964)
        or not _check_binding(
            selector.get("binding", {}), "_ZN12ModelManager11checkStatusEi"
        )
    ):
        errors.append("selector_helper")
    local_getter = helpers.get("local_word_getter", {})
    if (
        local_getter.get("status") != "PRIMARY_ELF_VERIFIED"
        or local_getter.get("receiver_field_offset") != hex(0x18)
    ):
        errors.append("local_word_getter")
    header = helpers.get("header_builder", {})
    if (
        header.get("status") != "PRIMARY_ELF_VERIFIED"
        or header.get("layout", {}).get("+0x02") != "u8 from r2"
        or header.get("layout", {}).get("+0x03") != "u8 from r1"
        or header.get("layout", {}).get("+0x04") != "u16 from r3"
        or not _check_binding(header.get("bindings", {}).get("0xde37c", {}), "memset")
    ):
        errors.append("header_builder")
    blog = helpers.get("set_blog_data", {})
    if (
        blog.get("status") != "PRIMARY_ELF_VERIFIED"
        or blog.get("set_blog_data_symbol") != "setBlogData"
        or blog.get("set_blog_data_vma") != hex(0xDE480)
        or not _check_binding(blog.get("binding", {}), "setBlogData")
    ):
        errors.append("set_blog_data")
    envelope = helpers.get("envelope_builder", {})
    if (
        envelope.get("status") != "PRIMARY_ELF_VERIFIED"
        or envelope.get("payload", {}).get("length") != 0x14
        or envelope.get("payload", {}).get("optional_pointer_copy")
        != "local +0x28, length 8 through strncpy; local +0x28/+0x2c initially zero"
        or not _check_binding(envelope.get("strncpy_binding", {}), "strncpy")
    ):
        errors.append("envelope_builder")
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
    expected_relations = {
        (hex(SELECTOR_GETTER_ENTRY), "_ZN12ModelManager11checkStatusEi", "PLT_CALL"),
        (hex(ENVELOPE_BUILDER_ENTRY), hex(HEADER_BUILDER_ENTRY), "DIRECT_CALL"),
        (hex(ENVELOPE_BUILDER_ENTRY), hex(SET_BLOG_DATA_ENTRY), "DIRECT_CALL"),
        (hex(SET_BLOG_DATA_ENTRY), "setBlogData", "PLT_CALL"),
        (hex(ENVELOPE_BUILDER_ENTRY), "strncpy", "PLT_CALL"),
        (hex(HEADER_BUILDER_ENTRY), "memset", "PLT_CALL"),
    }
    actual_relations = set()
    for row in report.get("relations", []):
        target = row.get("target_symbol", row.get("target_vma"))
        actual_relations.add((row.get("source_vma"), target, row.get("relation")))
    if not expected_relations.issubset(actual_relations):
        errors.append("helper_relations")
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
        records = ghidra.get("target_records", [])
        aggregate = ghidra.get("aggregate", {})
        if (
            len(records) != 7
            or aggregate != {
                "targets": 7,
                "instructions": 166,
                "basic_blocks": 16,
                "cfg_edges": 39,
            }
            or any(not row.get("body_ranges") for row in records)
        ):
            errors.append("ghidra_target_ranges")
    return {"valid": not errors, "errors": sorted(set(errors))}
