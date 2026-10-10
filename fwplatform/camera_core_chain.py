"""Evidence-gated Camera request/event/action chain probe.

This module joins bounded, SHA-pinned observations that already have primary
ELF support.  It deliberately does not guess the indirect EventManager target
or a ModelCamera event consumer.  The output is a sanitized relation graph:
addresses, identities, evidence locators and verification levels are retained,
while firmware bytes and decompiler text remain private.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from capstone.arm import ARM_OP_IMM
from elftools.elf.elffile import ELFFile

from .camera_request_event_probe import probe_request_event_factory
from .elf_plt import resolve_plt_binding
from .event_manager_push_probe import probe_event_manager_push
from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA


SCHEMA_VERSION = 1
FIRMWARE_VERSION = "3.21"
ADDRESS_SPACE = "ELF_VMA"
ABI = "ARM AAPCS32, Thumb, little endian"


FUNCTIONS: dict[str, dict[str, Any]] = {
    "ViewBase::requestModelExecute": {
        "entry": 0x12106E, "size": 0x3A,
        "symbol": "_ZN8ViewBase19requestModelExecuteEPKcmP9ParamList",
    },
    "viewManagerIf::requestModelExecute": {
        "entry": 0x1250C0, "size": 0x44,
        "symbol": "_ZN13viewManagerIf19requestModelExecuteEPKcmP9ParamList",
    },
    "viewManagerIf::requestModelExecute.submit_helper": {
        "entry": 0x125084, "size": 0x34, "symbol": None,
    },
    "AbstractUtilityManager::createRequestModelExecuteEvent": {
        "entry": 0x7F0B0C, "size": 0x6C,
        "symbol": "_ZN22AbstractUtilityManager30createRequestModelExecuteEventEimP9ParamList",
    },
    "View::requestApplicationExecute": {
        "entry": 0x7F1B0C, "size": 0x2E,
        "symbol": "_ZN4View25requestApplicationExecuteEP5Event",
    },
    "View::pushEvent": {
        "entry": 0x7F1B68, "size": 0x0E,
        "symbol": "_ZN4View9pushEventEP5Event",
    },
    "EventManager::push": {
        "entry": 0x7EF960, "size": 0x9C,
        "symbol": "_ZN12EventManager4pushEP5Eventb",
    },
    # The owner and layout initializer are intentionally kept as candidates:
    # neither has a unique source-level symbol in the available ELF.  Their
    # instruction ranges are nevertheless bounded and independently checked.
    "EventManager::owner_initializer_candidate": {
        "entry": 0x7EF254, "size": 0x120, "symbol": None,
    },
    "EventManager::layout_initializer_candidate": {
        "entry": 0x7EF894, "size": 0x4E, "symbol": None,
    },
    "ModelCamera::ActionGpSetSetting": {
        "entry": 0x4CFB9C, "size": None, "symbol": None,
    },
    "ModelCamera::pvt_ActionSetInit": {
        "entry": 0x4CF7A8, "size": None, "symbol": None,
    },
    "ModelCamera::pvt_ExeEENeutralCmd": {
        "entry": 0x4B1A20, "size": None, "symbol": None,
    },
    "ModelCamera::EE_neutral_sender_candidate": {
        "entry": 0x443D14, "size": None, "symbol": None,
    },
}

EVENT_ID = 0x11004003
MODEL_EVENT_KEYS = (7, 8)
MODEL_ACTION_SELECTOR = 0x0F01
EVENT_MANAGER_DISPATCH_FIELD = 0x08
EVENT_MANAGER_COMPLETION_FIELD = 0x04


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_exec_range(fp: Any, elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > 0x200:
        raise ValueError("Camera chain probe read exceeds bounded limit")
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


def _decode_at(fp: Any, elf: ELFFile, start: int, size: int) -> dict[int, Any]:
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    rows = list(decoder.disasm(_read_exec_range(fp, elf, start, size), start))
    if not rows:
        raise ValueError(f"ELF_VMA 0x{start:x} did not decode as Thumb")
    return {int(row.address): row for row in rows}


def _immediates(instruction: Any) -> list[int]:
    return [int(operand.imm) for operand in instruction.operands if operand.type == ARM_OP_IMM]


def _require(
    rows: dict[int, Any], address: int, mnemonic: str, *,
    operands: str | None = None, target: int | None = None,
    immediate: int | None = None,
) -> Any:
    instruction = rows.get(address)
    if instruction is None or instruction.mnemonic.lower() != mnemonic.lower():
        raise ValueError(f"unexpected {mnemonic} at 0x{address:x}")
    if operands is not None and instruction.op_str.lower() != operands.lower():
        raise ValueError(f"unexpected operands at 0x{address:x}")
    if target is not None and target not in _immediates(instruction):
        raise ValueError(f"unexpected target at 0x{address:x}")
    if immediate is not None and immediate not in _immediates(instruction):
        raise ValueError(f"unexpected immediate at 0x{address:x}")
    return instruction


def _binding(fp: Any, elf: ELFFile, entry: int) -> dict[str, Any]:
    result = resolve_plt_binding(fp, elf, entry, thumb_stub=False)
    if result.get("status") != "VERIFIED_STATIC":
        raise ValueError(f"PLT binding at 0x{entry:x} is not unique")
    return result


def _symbol_matches(elf: ELFFile, name: str, entry: int, size: int) -> bool:
    for section_name in (".dynsym", ".symtab"):
        section = elf.get_section_by_name(section_name)
        if section is None:
            continue
        for symbol in section.iter_symbols():
            if symbol.name == name and (int(symbol["st_value"]) & ~1) == entry:
                if size is None or int(symbol["st_size"]) == size:
                    return True
    return False


def _scan_executable_literal_vmas(fp: Any, elf: ELFFile, value: int) -> list[int]:
    """Locate a 32-bit little-endian literal in executable PT_LOAD ranges.

    This is intentionally a literal inventory only.  A matching word is not
    treated as an event consumer, instruction, or semantic relationship; the
    caller must still prove the surrounding control flow and function owner.
    """
    needle = int(value).to_bytes(4, "little", signed=False)
    locations: list[int] = []
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD" or not (int(segment["p_flags"]) & 1):
            continue
        data = segment.data()
        offset = 0
        while True:
            hit = data.find(needle, offset)
            if hit < 0:
                break
            locations.append(int(segment["p_vaddr"]) + hit)
            offset = hit + 1
    return sorted(set(locations))


def _read_load_word(fp: Any, elf: ELFFile, address: int) -> int:
    """Read one file-backed load word without treating it as executable code."""
    offsets: list[int] = []
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD":
            continue
        base = int(segment["p_vaddr"])
        count = int(segment["p_filesz"])
        if base <= address and address + 4 <= base + count:
            offsets.append(int(segment["p_offset"]) + address - base)
    if len(offsets) != 1:
        raise ValueError(f"ELF_VMA 0x{address:x} is not uniquely load-backed")
    fp.seek(offsets[0])
    data = fp.read(4)
    if len(data) != 4:
        raise ValueError("truncated load word")
    return struct.unpack("<I", data)[0]


def _relocation_type(elf: ELFFile, address: int) -> int | None:
    """Return the unique relocation type for a data word, if present."""
    found: list[int] = []
    for section in elf.iter_sections():
        if section["sh_type"] not in ("SHT_REL", "SHT_RELA"):
            continue
        for relocation in section.iter_relocations():
            if int(relocation["r_offset"]) == address:
                found.append(int(relocation["r_info_type"]))
    values = sorted(set(found))
    if len(values) > 1:
        raise ValueError(f"ambiguous relocation at ELF_VMA 0x{address:x}")
    return values[0] if values else None


def _evidence(
    digest: str, locator: str, *, method: str = "CAPSTONE_PRIMARY_ELF",
    status: str = "PRIMARY_ELF_VERIFIED", confidence: str = "HIGH",
) -> dict[str, Any]:
    return {
        "source_binary_sha256": digest,
        "source_locator": locator,
        "address_space": ADDRESS_SPACE,
        "evidence_method": method,
        "verification_status": status,
        "confidence": confidence,
    }


def _edge(
    edge_id: str, source: str, target: str | None, relation: str,
    source_vma: int, digest: str, *, target_vma: int | None = None,
    callsite_vma: int | None = None, status: str = "PRIMARY_ELF_VERIFIED",
    confidence: str = "HIGH", method: str = "CAPSTONE_PRIMARY_ELF",
    note: str = "",
) -> dict[str, Any]:
    return {
        "id": edge_id,
        "source": source,
        "target": target,
        "target_vma": (hex(target_vma) if target_vma is not None else None),
        "source_vma": hex(source_vma),
        "callsite_vma": (hex(callsite_vma) if callsite_vma is not None else hex(source_vma)),
        "relation": relation,
        "address_space": ADDRESS_SPACE,
        "verification_status": status,
        "confidence": confidence,
        "evidence": _evidence(
            digest, f"ELF_VMA:{hex(callsite_vma if callsite_vma is not None else source_vma)}",
            method=method, status=status, confidence=confidence,
        ),
        "note": note,
    }


def _observe_request_frontends(fp: Any, elf: ELFFile, digest: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    view = _decode_at(fp, elf, 0x12106E, 0x3A)
    _require(view, 0x121076, "ldr.w", operands="sb, [r0, #0x7c]")
    _require(view, 0x12107A, "mov", operands="r0, r1")
    _require(view, 0x12107C, "mov", operands="sl, r2")
    _require(view, 0x121080, "mov", operands="r6, r3")
    _require(view, 0x121082, "blx", target=0xDFFB8)
    _require(view, 0x12108C, "bl", target=0x12D780)
    _require(view, 0x121098, "blx", target=0xDFBDC)
    _require(view, 0x1210A4, "b.w", target=0xDB578)

    interface = _decode_at(fp, elf, 0x1250C0, 0x44)
    _require(interface, 0x1250D8, "blx", target=0xDFFB8)
    _require(interface, 0x1250E2, "bl", target=0x12D780)
    _require(interface, 0x1250EE, "blx", target=0xDFBDC)
    _require(interface, 0x1250F6, "b.w", target=0x125084)

    helper = _decode_at(fp, elf, 0x125084, 0x34)
    _require(helper, 0x12508E, "blx", target=0xDC100)
    _require(helper, 0x1250A4, "blx", target=0xDD194)
    _require(helper, 0x1250B4, "b.w", target=0x7F25E0)

    edges = [
        _edge("request.viewbase.factory", "ViewBase::requestModelExecute", "AbstractUtilityManager::createRequestModelExecuteEvent", "CALLS", 0x12106E, digest, target_vma=0x7F0B0C, callsite_vma=0x121098, method="CAPSTONE_PRIMARY_ELF+PLT_RELOCATION"),
        _edge("request.viewmanager.factory", "viewManagerIf::requestModelExecute", "AbstractUtilityManager::createRequestModelExecuteEvent", "CALLS", 0x1250C0, digest, target_vma=0x7F0B0C, callsite_vma=0x1250EE, method="CAPSTONE_PRIMARY_ELF+PLT_RELOCATION"),
        _edge("request.viewbase.submit", "ViewBase::requestModelExecute", "View::requestApplicationExecute", "TAIL_BRANCH", 0x12106E, digest, target_vma=0x7F1B0C, callsite_vma=0x1210A4, method="CAPSTONE_PRIMARY_ELF+PLT_RELOCATION"),
        _edge("request.viewmanager.submit_helper", "viewManagerIf::requestModelExecute", "viewManagerIf::requestModelExecute.submit_helper", "TAIL_BRANCH", 0x1250C0, digest, target_vma=0x125084, callsite_vma=0x1250F6),
        _edge("request.helper.submit", "viewManagerIf::requestModelExecute.submit_helper", "EventManager::push", "TAIL_BRANCH", 0x125084, digest, target_vma=0x7EF960, callsite_vma=0x1250B4, method="CAPSTONE_PRIMARY_ELF+PLT_RELOCATION", note="The helper loads an opaque receiver from a global indirection before the push thunk."),
    ]
    observation = {
        "status": "PRIMARY_ELF_VERIFIED",
        "viewbase": {
            "entry_vma": hex(0x12106E),
            "r0": "ViewBase* receiver",
            "r1": "model name pointer, converted by IdGenerator::Get",
            "r2": "selector input, transformed by 0x12d780",
            "r3": "ParamList* candidate forwarded as factory r3",
            "factory_registers": {"r0": "[this + 0x7c]", "r1": "model identifier", "r2": "selector transform result", "r3": "original ParamList*"},
            "submit": "factory result is moved to r1 and tail-branched to View::requestApplicationExecute",
        },
        "view_manager_interface": {
            "entry_vma": hex(0x1250C0),
            "r0": "model name pointer",
            "r1": "selector input",
            "r2": "ParamList* candidate",
            "factory_receiver": "loaded through global indirection; source identity UNKNOWN",
            "submit": "tail branch to local helper 0x125084",
        },
        "selector_transform": {"entry_vma": hex(0x12D780), "semantics": "UNKNOWN", "output_register": "r0"},
    }
    return edges, observation


def _observe_submission(fp: Any, elf: ELFFile, digest: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    app = _decode_at(fp, elf, 0x7F1B0C, 0x2E)
    _require(app, 0x7F1B14, "movs", immediate=0x10)
    _require(app, 0x7F1B1C, "ldr", operands="r1, [r5, #0x18]")
    _require(app, 0x7F1B2A, "blx", target=0xDD194)
    _require(app, 0x7F1B2E, "ldr", operands="r0, [r5, #0x24]")
    _require(app, 0x7F1B36, "b.w", target=0x7F25E0)

    push_event = _decode_at(fp, elf, 0x7F1B68, 0x0E)
    _require(push_event, 0x7F1B6C, "ldr", operands="r0, [r0, #0x24]")
    _require(push_event, 0x7F1B72, "b.w", target=0x7F25E0)

    helper = _decode_at(fp, elf, 0x7F25E0, 0x10)
    _require(helper, 0x7F25E2, "movs", immediate=1)
    _require(helper, 0x7F25E6, "ldr", operands="r0, [r0, #0x10]")
    _require(helper, 0x7F25EC, "b.w", target=0xDF270)

    edges = [
        _edge("submit.app.add_parameter", "View::requestApplicationExecute", "Event::addParameter", "ADDS_PARAMETER", 0x7F1B0C, digest, target_vma=0xDD194, callsite_vma=0x7F1B2A, method="CAPSTONE_PRIMARY_ELF+PLT_RELOCATION", note="Key 6 is added by the application submitter; it is distinct from request keys 7 and 8."),
        _edge("submit.app.push_helper", "View::requestApplicationExecute", "View::submit_event_helper", "TAIL_BRANCH", 0x7F1B0C, digest, target_vma=0x7F25E0, callsite_vma=0x7F1B36),
        _edge("submit.push_event.push_helper", "View::pushEvent", "View::submit_event_helper", "TAIL_BRANCH", 0x7F1B68, digest, target_vma=0x7F25E0, callsite_vma=0x7F1B72),
        _edge("submit.helper.event_manager", "View::submit_event_helper", "EventManager::push", "TAIL_BRANCH", 0x7F25E0, digest, target_vma=0x7EF960, callsite_vma=0x7F25EC, method="CAPSTONE_PRIMARY_ELF+PLT_RELOCATION", note="r2 is set to 1; the receiver is loaded from the helper input +0x10."),
    ]
    return edges, {
        "status": "PRIMARY_ELF_VERIFIED",
        "request_application": {"event_parameter_key": 6, "view_field_0x18": "source of the added application parameter", "view_field_0x24": "opaque owner/manager candidate"},
        "submit_helper": {"entry_vma": hex(0x7F25E0), "input_field": "+0x10", "event_manager_push_flag": 1},
        "push_event": {"view_field_0x24": "opaque owner/manager candidate"},
    }


def _observe_action_path(fp: Any, elf: ELFFile, digest: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    dispatch = _decode_at(fp, elf, 0x4CFE8A, 0x16)
    _require(dispatch, 0x4CFE8A, "movw", immediate=MODEL_ACTION_SELECTOR)
    _require(dispatch, 0x4CFE8E, "cmp", operands="r0, r3")
    _require(dispatch, 0x4CFE90, "bne.w", target=0x4D02B8)
    _require(dispatch, 0x4CFE94, "mov", operands="r0, r5")
    _require(dispatch, 0x4CFE96, "mov", operands="r1, r4")
    _require(dispatch, 0x4CFE98, "bl", target=0x4CF7A8)

    action_init = _decode_at(fp, elf, 0x4CF7A8, 0x84)
    _require(action_init, 0x4CF7F0, "bl", target=0x42ABCC)
    _require(action_init, 0x4CF814, "bl", target=0x4B1A20)
    _require(action_init, 0x4CF81A, "bl", target=0x4B096C)

    neutral = _decode_at(fp, elf, 0x4B1A20, 0x60)
    _require(neutral, 0x4B1A42, "bl", target=0x443D14)
    _require(neutral, 0x4B1A50, "strb.w", operands="r2, [r3, #0x7c]")

    edges = [
        _edge("camera.action.selector_0f01", "ModelCamera::ActionGpSetSetting", "ModelCamera::pvt_ActionSetInit", "DISPATCHES_SELECTOR", 0x4CFB9C, digest, target_vma=0x4CF7A8, callsite_vma=0x4CFE98, method="CAPSTONE_PRIMARY_ELF", note="The dispatch arm compares a register against 0x0f01 and passes r4 as r1."),
        _edge("camera.action.init.neutral", "ModelCamera::pvt_ActionSetInit", "ModelCamera::pvt_ExeEENeutralCmd", "CALLS", 0x4CF7A8, digest, target_vma=0x4B1A20, callsite_vma=0x4CF814),
        _edge("camera.action.init.prepchk", "ModelCamera::pvt_ActionSetInit", "ModelCamera::PrepChk", "CALLS", 0x4CF7A8, digest, target_vma=0x4B096C, callsite_vma=0x4CF81A),
        _edge("camera.neutral.sender", "ModelCamera::pvt_ExeEENeutralCmd", "ModelCamera::EE_neutral_sender_candidate", "CALLS", 0x4B1A20, digest, target_vma=0x443D14, callsite_vma=0x4B1A42, note="Sender identity and completion receiver remain unresolved."),
    ]
    return edges, {
        "status": "PRIMARY_ELF_VERIFIED",
        "selector_dispatch": {"selector": hex(MODEL_ACTION_SELECTOR), "payload_register": "r1", "target": hex(0x4CF7A8)},
        "action_init": {"param_query_helper": hex(0x42ABCC), "ee_neutral": hex(0x4B1A20), "prep_check": hex(0x4B096C)},
        "ee_neutral": {"sender": hex(0x443D14), "pending_byte_store": "+0x26fc (via r3 = this + 0x2680, immediate +0x7c)", "receiver": "UNKNOWN"},
    }


def _observe_event_manager_owner(
    fp: Any, elf: ELFFile, digest: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Recover the bounded owner -> EventManager setup path.

    This is deliberately a setup witness, not a callback resolution.  The
    owner candidate allocates and initializes the EventManager layout, then
    obtains an event from a provider vtable slot and calls the statically
    bound ``EventManager::push`` PLT entry.  The actual callback stored in
    ``[this + 8]`` remains an indirect, unresolved target.
    """
    owner = _decode_at(fp, elf, 0x7EF254, 0x120)
    _require(owner, 0x7EF254, "push.w")
    _require(owner, 0x7EF268, "bl", target=0x7EF1E4)
    _require(owner, 0x7EF270, "str", operands="r0, [r4, #0x14]")
    _require(owner, 0x7EF2BA, "blx", target=0xDC100)
    _require(owner, 0x7EF2C0, "ldr", operands="r2, [r4, #0x14]")
    _require(owner, 0x7EF2C8, "mov", operands="r6, r0")
    _require(owner, 0x7EF2CA, "bl", target=0x7EF894)
    _require(owner, 0x7EF2D4, "str", operands="r6, [r4, #0x10]")
    _require(owner, 0x7EF348, "ldr", operands="r5, [r4, #0x10]")
    _require(owner, 0x7EF34C, "ldr", operands="r0, [r4, #0x14]")
    _require(owner, 0x7EF350, "ldr", operands="r3, [r3, #0x2c]")
    _require(owner, 0x7EF352, "blx", operands="r3")
    _require(owner, 0x7EF354, "movs", immediate=1)
    _require(owner, 0x7EF356, "mov", operands="r1, r0")
    _require(owner, 0x7EF358, "mov", operands="r0, r5")
    _require(owner, 0x7EF35A, "blx", target=0xDF274)

    initializer = _decode_at(fp, elf, 0x7EF894, 0x4E)
    _require(initializer, 0x7EF894, "push")
    _require(initializer, 0x7EF8A8, "ldr", operands="r3, [r6]")
    _require(initializer, 0x7EF8AE, "ldr", operands="r3, [r3, #0x30]")
    _require(initializer, 0x7EF8B0, "blx", operands="r3")
    _require(initializer, 0x7EF8B2, "str", operands="r0, [r4, #8]")
    _require(initializer, 0x7EF8AA, "str", operands="r5, [r4, #4]")
    push_binding = _binding(fp, elf, 0xDF274)

    edges = [
        _edge(
            "event_manager.owner.provider",
            "EventManager owner initializer candidate",
            "EventManager owner provider helper candidate",
            "CALLS",
            0x7EF254,
            digest,
            target_vma=0x7EF1E4,
            callsite_vma=0x7EF268,
            note="The owner candidate obtains a provider/context pointer; source-level owner type is UNKNOWN.",
        ),
        _edge(
            "event_manager.owner.init",
            "EventManager owner initializer candidate",
            "EventManager layout initializer candidate",
            "INITIALIZES",
            0x7EF254,
            digest,
            target_vma=0x7EF894,
            callsite_vma=0x7EF2CA,
            note="An allocated 0x24-byte object is passed as r0; initializer identity is bounded but not a confirmed C++ constructor.",
        ),
        _edge(
            "event_manager.owner.push",
            "EventManager owner initializer candidate",
            "EventManager::push",
            "CALLS",
            0x7EF254,
            digest,
            target_vma=0x7EF960,
            callsite_vma=0x7EF35A,
            method="CAPSTONE_PRIMARY_ELF+PLT_RELOCATION",
            note="The call is through PLT entry 0xdf274, uniquely bound to EventManager::push; r2 is the observed literal 1.",
        ),
        _edge(
            "event_manager.init.callback_factory",
            "EventManager layout initializer candidate",
            "ProviderVtableSlot:+0x30",
            "LOADS_INDIRECT_FACTORY",
            0x7EF894,
            digest,
            callsite_vma=0x7EF8B0,
            note="The provider vtable result is stored at EventManager +0x08; this identifies the slot source, not the eventual callback target.",
        ),
        _edge(
            "event_manager.init.dispatch_state_store",
            "EventManager layout initializer candidate",
            "EventManager::push.dispatch_state_+0x08",
            "INITIALIZES_DISPATCH_STATE",
            0x7EF894,
            digest,
            callsite_vma=0x7EF8B2,
            note="The indirect factory result is written to the field later read by EventManager::push at 0x7ef988.",
        ),
    ]
    return edges, {
        "status": "PRIMARY_ELF_VERIFIED",
        "semantic_level": "STATIC_INFERRED",
        "entry_vma": hex(0x7EF254),
        "function_identity": "UNKNOWN; no unique ELF symbol or source-level owner type",
        "owner_fields": {
            "+0x10": "allocated EventManager-like layout pointer retained in r6",
            "+0x14": "provider/context pointer passed to the layout initializer",
        },
        "provider": {
            "helper_entry": hex(0x7EF1E4),
            "event_vtable_slot": "+0x2c",
            "result_register": "r0",
            "identity": "UNKNOWN; indirect provider vtable target",
        },
        "initializer": {
            "entry_vma": hex(0x7EF894),
            "allocated_size": "0x24",
            "callsite_vma": hex(0x7EF2CA),
            "dispatch_factory_vtable_slot": "+0x30",
            "dispatch_state_field": "+0x08",
            "completion_field": "+0x04",
            "push_binding": push_binding,
        },
        "push": {
            "callsite_vma": hex(0x7EF35A),
            "target_vma": hex(0x7EF960),
            "flag_r2": 1,
            "event_source": "provider vtable slot +0x2c result",
        },
        "limits": [
            "EventManager::push dispatch target remains an indirect function pointer.",
            "Provider vtable slots +0x2c and +0x30 have no unique target identity in this bounded pass.",
            "Owner and initializer are candidates, not confirmed C++ class constructors.",
        ],
        "runtime_verified": False,
        "callable": False,
    }


def _observe_provider_callback_candidate(
    fp: Any, elf: ELFFile, digest: str,
) -> dict[str, Any]:
    """Record a bounded provider/vtable candidate without selecting it.

    The owner helper has two statically visible provider branches.  One local
    branch lazily constructs an ``AppConfigAC``-RTTI object.  Its vtable
    ``+0x30`` method returns a code address from a relocated data word, but
    the owner input is not proven to select this branch.  This observation is
    deliberately kept separate from the EventManager callback edge: it is a
    candidate source and cannot establish a ModelCamera consumer.
    """
    constructor = _decode_at(fp, elf, 0x45F2FC, 0x24)
    _require(constructor, 0x45F300, "ldr", operands="r4, [pc, #0x14]")
    _require(constructor, 0x45F304, "bl", target=0x106C0C)
    _require(constructor, 0x45F30E, "ldr", operands="r3, [r4, r3]")
    _require(constructor, 0x45F310, "adds", immediate=8)
    _require(constructor, 0x45F312, "str", operands="r3, [r5]")

    constructor_got = 0x10345D8
    vtable_base = _read_load_word(fp, elf, constructor_got)
    if vtable_base != 0x1007520 or _relocation_type(elf, constructor_got) != 23:
        raise ValueError("AppConfigAC candidate vtable relocation mismatch")
    vtable_address_point = vtable_base + 8
    slot_address = vtable_address_point + 0x30
    slot_target_tagged = _read_load_word(fp, elf, slot_address)
    if slot_target_tagged != 0x45EE65 or _relocation_type(elf, slot_address) != 23:
        raise ValueError("provider candidate +0x30 slot mismatch")

    slot_method = _decode_at(fp, elf, 0x45EE64, 0x10)
    _require(slot_method, 0x45EE64, "ldr", operands="r3, [pc, #0xc]")
    _require(slot_method, 0x45EE66, "ldr", operands="r2, [pc, #0x10]")
    _require(slot_method, 0x45EE68, "add", operands="r3, pc")
    _require(slot_method, 0x45EE6E, "ldr", operands="r0, [r3, r2]")

    callback_got = 0x10312CC
    callback_tagged = _read_load_word(fp, elf, callback_got)
    if callback_tagged != 0x45EE5D or _relocation_type(elf, callback_got) != 23:
        raise ValueError("provider candidate callback relocation mismatch")
    callback = _decode_at(fp, elf, 0x45EE5C, 6)
    _require(callback, 0x45EE5C, "push")
    _require(callback, 0x45EE5E, "add", operands="r7, sp, #0")
    _require(callback, 0x45EE60, "pop", operands="{r7, pc}")

    # The local branch target is obtained from the name helper's relative
    # relocation.  The other branch is the external getConfig import; the
    # owner input that selects either branch is not present in this bounded
    # evidence set.
    helper_got_local = 0x1030BCC
    local_accessor_tagged = _read_load_word(fp, elf, helper_got_local)
    if local_accessor_tagged != 0x45F2ED or _relocation_type(elf, helper_got_local) != 23:
        raise ValueError("provider helper local branch mismatch")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "semantic_level": "STATIC_INFERRED",
        "scope": "candidate vtable and provider branch only; not an EventManager callback proof",
        "constructor_candidate": {
            "entry_vma": hex(0x45F2FC),
            "vtable_got_slot": hex(constructor_got),
            "vtable_vma": hex(vtable_base),
            "vtable_address_point": hex(vtable_address_point),
            "vptr_write": "r3 + 8 stored at [r5]",
            "rtti_identity": "11AppConfigAC",
        },
        "provider_slot": {
            "slot_offset": "+0x30",
            "slot_vma": hex(slot_address),
            "target_vma": hex(slot_target_tagged & ~1),
            "target_thumb_tag": hex(slot_target_tagged),
            "target_relocation_type": 23,
        },
        "returned_callback_candidate": {
            "method_vma": hex(0x45EE64),
            "relocated_word_slot": hex(callback_got),
            "returned_target_vma": hex(callback_tagged & ~1),
            "returned_target_thumb_tag": hex(callback_tagged),
            "leaf_shape": "push/add/pop only; no event consumer call observed",
        },
        "provider_selection": {
            "local_accessor_vma": hex(0x45F2EC),
            "local_accessor_relocation_target": hex(local_accessor_tagged & ~1),
            "external_alternative": "getConfig via the other name-helper branch",
            "selected_branch": "UNKNOWN",
        },
        "event_manager_link": "UNKNOWN; owner +0x14 is not proven to reference this candidate object",
        "model_camera_consumer": "UNKNOWN; candidate leaf does not establish event delivery",
        "evidence": _evidence(
            digest,
            "ELF_VMA:0x45f2fc,0x1007558,0x45ee64,0x10312cc",
            method="CAPSTONE_PRIMARY_ELF+R_ARM_RELATIVE",
            status="PRIMARY_ELF_VERIFIED",
            confidence="MEDIUM",
        ),
        "runtime_verified": False,
        "callable": False,
    }


def _observe_request_consumer(fp: Any, elf: ELFFile, digest: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Verify the computed event-ID branch and parameter-to-model handoff.

    This proves the generic request consumer, not the dynamic identity of
    the model selected from its registry.  Split normal code from literal
    pools and keep the final vtable target unresolved.
    """
    dispatch = _decode_at(fp, elf, 0x7ED49C, 0xBA)
    _require(dispatch, 0x7ED4AA, "blx", target=0xDBAFC)
    _require(dispatch, 0x7ED4AE, "mov", operands="r6, r0")
    _require(dispatch, 0x7ED4EA, "ldr", operands="r3, [pc, #0x264]")
    base_id = _read_load_word(fp, elf, 0x7ED750)
    if base_id != 0x11004005 or base_id - 3 + 1 != EVENT_ID:
        raise ValueError("computed request event ID mismatch")
    _require(dispatch, 0x7ED4F4, "subs", operands="r3, #3")
    _require(dispatch, 0x7ED4FC, "adds", operands="r3, #1")
    _require(dispatch, 0x7ED4FE, "cmp", operands="r6, r3")
    _require(dispatch, 0x7ED500, "bne", target=0x7ED552)
    _require(dispatch, 0x7ED502, "b", target=0x7ED5C8)
    branch = _decode_at(fp, elf, 0x7ED5C8, 0xA2)
    for address, key in ((0x7ED5D2, 7), (0x7ED5E8, 8)):
        _require(branch, address, "movs", operands=f"r1, #{key}")
    _require(branch, 0x7ED5D4, "bl", target=0x7EA918)
    _require(branch, 0x7ED5EA, "bl", target=0x7EA918)
    _require(branch, 0x7ED5DA, "bl", target=0xE5B18)
    _require(branch, 0x7ED5F2, "bl", target=0xE5B18)
    _require(branch, 0x7ED5FC, "bl", target=0x7EB8FA)
    _require(branch, 0x7ED624, "mov", operands="r1, sb")
    _require(branch, 0x7ED62A, "blx", target=0xDB66C)
    _require(branch, 0x7ED630, "blx", target=0xDBD20)
    _require(branch, 0x7ED640, "bl", target=0x7EDA9C)
    _require(branch, 0x7ED648, "blx", target=0xDE3A4)
    _require(branch, 0x7ED64C, "mov", operands="r0, r8")
    _require(branch, 0x7ED64E, "mov", operands="r1, r6")
    _require(branch, 0x7ED650, "bl", target=0x7F124A)
    reader = _decode_at(fp, elf, 0x7EA918, 0x10)
    _require(reader, 0x7EA91A, "movs", immediate=1)
    _require(reader, 0x7EA91E, "ldr", operands="r0, [r0, #0xc]")
    _require(reader, 0x7EA924, "b.w", target=0xE2890)
    if _binding(fp, elf, 0xE2894)["candidates"][0]["symbol"] != "_ZNK9ParamList3getEmm":
        raise ValueError("consumer ParamList query binding mismatch")
    forward = _decode_at(fp, elf, 0x7F124A, 0x16)
    _require(forward, 0x7F124A, "ldr", operands="r0, [r0, #0x1c]")
    _require(forward, 0x7F1252, "bl", target=0x7EFCCA)
    execute = _decode_at(fp, elf, 0x7EFCCA, 0x1A)
    _require(execute, 0x7EFCD0, "str", operands="r1, [r0, #0x14]")
    _require(execute, 0x7EFCDE, "ldr", operands="r3, [r3, #0x18]")
    _require(execute, 0x7EFCE0, "blx", operands="r3")
    loop = _decode_at(fp, elf, 0x7EEDDA, 0x1A)
    _require(loop, 0x7EEDDA, "and", operands="r3, r6, #2")
    _require(loop, 0x7EEDF0, "bl", target=0x7ED49C)
    bindings = {name: _binding(fp, elf, address) for name, address in (
        ("get_id", 0xDBAFC), ("event_constructor", 0xDB66C),
        ("get_paramlist", 0xDBD20), ("set_paramlist", 0xDE3A4))}
    edges = [
        _edge("consumer.loop.model_dispatch", "application event router candidate", "request consumer candidate", "CALLS", 0x7EED0C, digest, target_vma=0x7ED49C, callsite_vma=0x7EEDF0, note="Conditional on Event destination bit 2; owner +4 supplies receiver."),
        _edge("consumer.event_id", "request consumer candidate", "EventID:0x11004003", "HANDLES_EVENT", 0x7ED49C, digest, callsite_vma=0x7ED4FE, note="Literal 0x11004005 at 0x7ed750 minus 3 plus 1; equal branch reaches 0x7ed5c8."),
        _edge("consumer.key7", "request consumer candidate", "EventParameterKey:7", "READS_PARAMETER", 0x7ED49C, digest, target_vma=0x7EA918, callsite_vma=0x7ED5D4),
        _edge("consumer.key8", "request consumer candidate", "EventParameterKey:8", "READS_PARAMETER", 0x7ED49C, digest, target_vma=0x7EA918, callsite_vma=0x7ED5EA),
        _edge("consumer.model_lookup", "request consumer candidate", "model registry lookup candidate", "CALLS", 0x7ED49C, digest, target_vma=0x7EB8FA, callsite_vma=0x7ED5FC, note="r1 contains key 7 payload; dynamic registry entry identity UNKNOWN."),
        _edge("consumer.model_handoff", "request consumer candidate", "model event forwarder candidate", "CALLS", 0x7ED49C, digest, target_vma=0x7F124A, callsite_vma=0x7ED650, note="r0=registry result; r1=new Event whose ID comes from key 8."),
        _edge("consumer.forward.execute", "model event forwarder candidate", "model execution candidate", "CALLS", 0x7F124A, digest, target_vma=0x7EFCCA, callsite_vma=0x7F1252),
    ]
    return edges, {
        "status": "PRIMARY_ELF_VERIFIED", "entry_vma": "0x7ed49c",
        "computed_event_id": {"literal_vma": "0x7ed750", "literal_value": hex(base_id), "subtract": 3, "add": 1, "result": hex(EVENT_ID), "compare_vma": "0x7ed4fe", "branch_target": "0x7ed5c8"},
        "input": {"r0": "router owner +4 receiver candidate", "r1": "Event pointer retained in r5"},
        "parameters": {"7": {"query_callsite": "0x7ed5d4", "word_getter": "0x7ed5da", "destination": "model registry lookup r1", "missing": "0xffffffff"}, "8": {"query_callsite": "0x7ed5ea", "word_getter": "0x7ed5f2", "destination": "new Event constructor r1", "missing": "zero"}},
        "paramlist": "original Event getParamList result copied via 0x7eda9c then passed to Event::setParamList; ownership and concurrent aliases UNKNOWN",
        "final_dispatch": {"entry_vma": "0x7efcca", "event_store": "receiver +0x14 at 0x7efcd0", "vtable_slot": "+0x18", "callsite_vma": "0x7efce0", "target": "UNKNOWN"},
        "model_camera_identity": "UNKNOWN; registry population and +0x18 virtual target are not proven",
        "bindings": bindings, "runtime_verified": False, "callable": False,
    }


def _observe_config_provider(fp: Any, elf: ELFFile, digest: str) -> dict[str, Any]:
    """Verify the second provider branch without assuming runtime selection."""
    caller = _decode_at(fp, elf, 0x7ED984, 0x54)
    _require(caller, 0x7ED990, "mov", operands="r0, r7")
    _require(caller, 0x7ED996, "bl", target=0x7EF254)
    getter = _decode_at(fp, elf, 0x106C6C, 0x0C)
    _require(getter, 0x106C72, "ldr", operands="r0, [r0]")
    init = _decode_at(fp, elf, 0x106DA8, 0x18)
    _require(init, 0x106DB4, "bl", target=0x106C7C)
    _require(init, 0x106DBC, "str", operands="r4, [r3]")
    getter_global = (_read_load_word(fp, elf, 0x106C78) + 0x106C74) & 0xFFFFFFFF
    init_global = (_read_load_word(fp, elf, 0x106DCC) + 0x106DBE) & 0xFFFFFFFF
    if getter_global != 0x10A8A9C or getter_global != init_global:
        raise ValueError("getConfig singleton source mismatch")
    for address, expected in ((0x1030350, 0xFE9B68), (0xFE9BA0, 0x106901), (0x1030F6C, 0x11130D)):
        if _read_load_word(fp, elf, address) != expected or _relocation_type(elf, address) != 23:
            raise ValueError("configured provider relocation mismatch")
    constructor = _decode_at(fp, elf, 0x106C7C, 0x20)
    _require(constructor, 0x106C90, "ldr", operands="r3, [r5, r3]")
    _require(constructor, 0x106C96, "adds", immediate=8)
    _require(constructor, 0x106C98, "str", operands="r3, [r4]")
    slot = _decode_at(fp, elf, 0x106900, 0x0E)
    _require(slot, 0x10690A, "ldr", operands="r0, [r3, r2]")
    # Verify arithmetic that resolves the two GOT sources, including the
    # unaligned architectural PC used by Thumb ADD (not literal-load PC).
    if (_read_load_word(fp, elf, 0x106D40) + 0x106C8E + _read_load_word(fp, elf, 0x106D44)) & 0xFFFFFFFF != 0x1030350:
        raise ValueError("config constructor GOT calculation mismatch")
    if (_read_load_word(fp, elf, 0x106910) + 0x106908 + _read_load_word(fp, elf, 0x106914)) & 0xFFFFFFFF != 0x1030F6C:
        raise ValueError("config callback GOT calculation mismatch")
    return {
        "status": "PRIMARY_ELF_VERIFIED", "owner_callsite": "0x7ed996",
        "owner_entry": "0x7ef254", "owner_storage": "stack receiver in r7",
        "name_source": "0x10df828 (BSS); contents and selected branch UNKNOWN",
        "get_config_entry": "0x106c6c", "initialize_config_entry": "0x106da8",
        "singleton_address": hex(getter_global), "constructor_entry": "0x106c7c",
        "vtable_address_point": "0xfe9b70", "slot_plus_0x30": "0xfe9ba0",
        "slot_method": "0x106900", "callback_got": "0x1030f6c", "callback_candidate": "0x11130c",
        "selection": "UNKNOWN; named BSS input is not statically initialized in this batch",
        "runtime_loader_binding": "UNKNOWN; GLOB_DAT getConfig can be interposed",
        "evidence": _evidence(digest, "ELF_VMA:0x7ed996,0x106c72,0x106dbc,0xfe9ba0,0x1030f6c", method="CAPSTONE_PRIMARY_ELF+R_ARM_RELATIVE"),
        "runtime_verified": False, "callable": False,
    }


def _unresolved(digest: str) -> list[dict[str, Any]]:
    return [
        {
            "id": "event_manager.dispatch_target",
            "source": "EventManager::push",
            "candidate_target": None,
            "relation": "DISPATCHES_EVENT",
            "source_vma": hex(0x7EF988),
            "address_space": ADDRESS_SPACE,
            "status": "UNKNOWN",
            "reason": "The body invokes [this + 0x08] with r0=[state + 0x04], r1=Event*; provider selection is not uniquely proven.",
            "evidence": _evidence(digest, "ELF_VMA:0x7ef988", confidence="MEDIUM"),
        },
        {
            "id": "event_manager.completion_target",
            "source": "EventManager::push",
            "candidate_target": None,
            "relation": "COMPLETES_EVENT",
            "source_vma": hex(0x7EF9CE),
            "address_space": ADDRESS_SPACE,
            "status": "UNKNOWN",
            "reason": "The nonzero incoming flag selects an indirect callback from [this + 0x04]; callback identity and ABI are unresolved.",
            "evidence": _evidence(digest, "ELF_VMA:0x7ef9ce", confidence="MEDIUM"),
        },
        {
            "id": "event.consumer.model_camera",
            "source": "EventID:0x11004003",
            "candidate_target": "ModelCamera event consumer",
            "relation": "CONSUMED_BY",
            "source_vma": hex(0x7F0B74),
            "address_space": ADDRESS_SPACE,
            "status": "UNKNOWN",
            "reason": "Generic consumer 0x7ed49c handles this ID, reads keys 7/8 and forwards a new Event; model registry population and virtual target at 0x7efce0 remain UNKNOWN.",
            "evidence": _evidence(digest, "ELF_VMA:0x7f0b74", confidence="MEDIUM"),
        },
        {
            "id": "event.keys.model_camera",
            "source": "EventID:0x11004003",
            "candidate_target": "ModelCamera selector/action parser",
            "relation": "PARSes_KEYS",
            "source_vma": hex(0x7F0B44),
            "address_space": ADDRESS_SPACE,
            "status": "UNKNOWN",
            "reason": "Generic receiver reads key 7 for model lookup and key 8 for the new Event ID; exact ModelCamera registry entry and normalization to action selector remain UNKNOWN.",
            "evidence": _evidence(digest, "ELF_VMA:0x7f0b44", confidence="MEDIUM"),
        },
        {
            "id": "request.selector_transform.semantic",
            "source": "selector transform 0x12d780",
            "candidate_target": None,
            "relation": "TRANSFORMS_SELECTOR",
            "source_vma": hex(0x12D780),
            "address_space": ADDRESS_SPACE,
            "status": "UNKNOWN",
            "reason": "Both request frontends establish the call and output register, but this pass does not claim the helper's semantic mapping.",
            "evidence": _evidence(digest, "ELF_VMA:0x12d780", confidence="LOW"),
        },
    ]


def probe_camera_core_chain(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Run one bounded, primary-ELF Camera Core chain analysis batch."""
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
        event_id_literal_vmas = _scan_executable_literal_vmas(fp, elf, EVENT_ID)
        for name in ("ViewBase::requestModelExecute", "viewManagerIf::requestModelExecute", "AbstractUtilityManager::createRequestModelExecuteEvent", "View::requestApplicationExecute", "View::pushEvent", "EventManager::push"):
            target = FUNCTIONS[name]
            if not _symbol_matches(elf, str(target["symbol"]), int(target["entry"]), int(target["size"])):
                raise ValueError(f"symbol identity mismatch: {name}")
        bindings = {
            "model_identifier": _binding(fp, elf, 0xDFFB8),
            "request_factory": _binding(fp, elf, 0xDFBDC),
            "application_submit": _binding(fp, elf, 0xDB57C),
            "event_add_parameter": _binding(fp, elf, 0xDD194),
            "event_manager_push": _binding(fp, elf, 0xDF274),
        }
        request_edges, request_observation = _observe_request_frontends(fp, elf, digest)
        submit_edges, submit_observation = _observe_submission(fp, elf, digest)
        action_edges, action_observation = _observe_action_path(fp, elf, digest)
        owner_edges, owner_observation = _observe_event_manager_owner(fp, elf, digest)
        provider_observation = _observe_provider_callback_candidate(fp, elf, digest)
        consumer_edges, consumer_observation = _observe_request_consumer(fp, elf, digest)
        configured_provider = _observe_config_provider(fp, elf, digest)
        factory = probe_request_event_factory(path, expected_sha256=expected_sha256)
        event_manager = probe_event_manager_push(path, expected_sha256=expected_sha256)
    event_edge = _edge("factory.event_id", "AbstractUtilityManager::createRequestModelExecuteEvent", f"EventID:{hex(EVENT_ID)}", "CREATES_EVENT", 0x7F0B0C, digest, callsite_vma=0x7F0B1E, method="CAPSTONE_PRIMARY_ELF", note="The target is an event value, not a code address or VMA.")
    event_edge["target_value"] = hex(EVENT_ID)
    event_edge["literal_vma"] = hex(0x7F0B74)
    key7_edge = _edge("factory.key7", f"EventID:{hex(EVENT_ID)}", "EventParameterKey:7", "CARRIES_PARAMETER", 0x7F0B0C, digest, callsite_vma=0x7F0B48)
    key7_edge["key_literal_vma"] = hex(0x7F0B44)
    key8_edge = _edge("factory.key8", f"EventID:{hex(EVENT_ID)}", "EventParameterKey:8", "CARRIES_PARAMETER", 0x7F0B0C, digest, callsite_vma=0x7F0B60)
    key8_edge["key_literal_vma"] = hex(0x7F0B5C)
    edges = request_edges + submit_edges + action_edges + owner_edges + consumer_edges + [
        event_edge,
        key7_edge,
        key8_edge,
    ]
    # These are intentionally nodes/observations rather than a fabricated
    # consumer edge.  A literal address is not a function target.
    nodes = [
        {"id": "event:0x11004003", "type": "EventID", "label": f"EventID:{hex(EVENT_ID)}", "status": "PRIMARY_ELF_VERIFIED"},
        {"id": "event-key:7", "type": "EventParameterKey", "label": "EventParameterKey:7", "status": "PRIMARY_ELF_VERIFIED"},
        {"id": "event-key:8", "type": "EventParameterKey", "label": "EventParameterKey:8", "status": "PRIMARY_ELF_VERIFIED"},
        {"id": "model-camera", "type": "FunctionCandidate", "label": "ModelCamera event consumer", "status": "UNKNOWN"},
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "LOCAL_PRIMARY_ELF_CAMERA_CORE_CHAIN_EVIDENCE_ONLY",
        "firmware_version": FIRMWARE_VERSION,
        "binary_file_sha256": digest,
        "address_space": ADDRESS_SPACE,
        "abi": ABI,
        "bindings": bindings,
        "observations": {
            "request_frontends": request_observation,
            "request_event_factory": {
                "status": "PRIMARY_ELF_VERIFIED",
                "event_id": hex(EVENT_ID),
                "keys": list(MODEL_EVENT_KEYS),
                "model_key_source": "factory r1/model identifier",
                "selector_key_source": "factory r2/transformed selector",
                "paramlist_r3": "optional ParamList* passed to Event::setParamList when non-null",
            },
            "submission": submit_observation,
            "event_manager": event_manager["observation"],
            "event_manager_owner_setup": owner_observation,
            "event_manager_provider_candidate": provider_observation,
            "request_consumer": consumer_observation,
            "configured_provider_candidate": configured_provider,
            "event_id_literal_scan": {
                "status": "PRIMARY_ELF_VERIFIED",
                "value": hex(EVENT_ID),
                "scope": "all executable PT_LOAD bytes; literal inventory only",
                "literal_vmas": [hex(value) for value in event_id_literal_vmas],
                "consumer_relation": "UNKNOWN; literal presence does not identify a receiver or event dispatch path",
            },
            "camera_action": action_observation,
        },
        "nodes": nodes,
        "edges": edges,
        "unresolved_edges": _unresolved(digest),
        "chain_summary": {
            "request_to_factory": "PRIMARY_ELF_VERIFIED",
            "factory_to_event_submit": "PRIMARY_ELF_VERIFIED",
            "event_manager_owner_init_push": "PRIMARY_ELF_VERIFIED",
            "generic_request_consumer_and_keys_7_8": "PRIMARY_ELF_VERIFIED",
            "event_manager_indirect_dispatch_target": "UNKNOWN",
            "event_consumer_model_camera": "UNKNOWN",
            "event_keys_7_8_to_model_camera": "UNKNOWN",
            "selector_0f01_to_action_set_init": "PRIMARY_ELF_VERIFIED",
            "action_set_init_to_ee_neutral": "PRIMARY_ELF_VERIFIED",
            "ee_neutral_receiver_and_completion": "UNKNOWN",
        },
        "verification": {
            "primary_elf_sha256_verified": True,
            "runtime_verified": False,
            "callable": False,
            "safe_to_invoke": False,
            "raw_firmware_bytes_emitted": False,
        },
    }


def validate_camera_core_chain(report: dict[str, Any], *, expected_sha256: str = EXPECTED_LIBOBJ_SHA) -> dict[str, Any]:
    """Fail closed on identity errors and unsupported semantic promotion."""
    errors: list[str] = []
    if report.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version")
    if report.get("status") != "LOCAL_PRIMARY_ELF_CAMERA_CORE_CHAIN_EVIDENCE_ONLY":
        errors.append("status")
    if report.get("firmware_version") != FIRMWARE_VERSION:
        errors.append("firmware_version")
    if report.get("binary_file_sha256") != expected_sha256:
        errors.append("binary_identity")
    if report.get("address_space") != ADDRESS_SPACE:
        errors.append("address_space")
    verification = report.get("verification", {})
    if verification.get("runtime_verified") is not False or verification.get("callable") is not False or verification.get("safe_to_invoke") is not False:
        errors.append("runtime_or_callable_promotion")
    summary = report.get("chain_summary", {})
    consumer = report.get("observations", {}).get("request_consumer")
    if consumer is not None:
        computed = consumer.get("computed_event_id", {})
        if computed != {"literal_vma": "0x7ed750", "literal_value": "0x11004005", "subtract": 3, "add": 1, "result": "0x11004003", "compare_vma": "0x7ed4fe", "branch_target": "0x7ed5c8"}:
            errors.append("consumer_event_id_derivation")
        if consumer.get("final_dispatch", {}).get("target") != "UNKNOWN":
            errors.append("consumer_virtual_target_promotion")
        if not str(consumer.get("model_camera_identity", "")).startswith("UNKNOWN"):
            errors.append("consumer_model_identity_promotion")
    for key in ("event_manager_indirect_dispatch_target", "event_consumer_model_camera", "event_keys_7_8_to_model_camera", "ee_neutral_receiver_and_completion"):
        if summary.get(key) != "UNKNOWN":
            errors.append(f"unresolved:{key}")
    literal_scan = report.get("observations", {}).get("event_id_literal_scan")
    if literal_scan is not None:
        if literal_scan.get("status") != "PRIMARY_ELF_VERIFIED":
            errors.append("event_literal_scan_status")
        if literal_scan.get("value") != hex(EVENT_ID):
            errors.append("event_literal_scan_value")
        locations = literal_scan.get("literal_vmas")
        if not isinstance(locations, list) or locations != sorted(set(locations)) or not locations:
            errors.append("event_literal_scan_locations")
        relation = str(literal_scan.get("consumer_relation", ""))
        if "UNKNOWN" not in relation or "does not identify" not in relation:
            errors.append("event_literal_scan_semantic_scope")
    edges = report.get("edges")
    if not isinstance(edges, list) or not edges:
        errors.append("edges_missing")
    else:
        required = {
            "request.viewbase.factory", "request.viewbase.submit",
            "submit.helper.event_manager", "factory.event_id", "factory.key7",
            "factory.key8", "camera.action.selector_0f01",
            "event_manager.owner.init", "event_manager.owner.push",
            "event_manager.init.callback_factory",
        }
        present = {str(edge.get("id")) for edge in edges if isinstance(edge, dict)}
        errors.extend(f"edge_missing:{item}" for item in sorted(required - present))
        required_targets = {
            "event_manager.owner.init": ("0x7ef894", "0x7ef2ca"),
            "event_manager.owner.push": ("0x7ef960", "0x7ef35a"),
            "event_manager.init.callback_factory": (None, "0x7ef8b0"),
            "event_manager.init.dispatch_state_store": (None, "0x7ef8b2"),
        }
        if consumer is not None:
            consumer_targets = {
                "consumer.loop.model_dispatch": ("0x7ed49c", "0x7eedf0"),
                "consumer.event_id": (None, "0x7ed4fe"),
                "consumer.key7": ("0x7ea918", "0x7ed5d4"),
                "consumer.key8": ("0x7ea918", "0x7ed5ea"),
                "consumer.model_lookup": ("0x7eb8fa", "0x7ed5fc"),
                "consumer.model_handoff": ("0x7f124a", "0x7ed650"),
                "consumer.forward.execute": ("0x7efcca", "0x7f1252"),
            }
            errors.extend(f"edge_missing:{item}" for item in sorted(consumer_targets.keys() - present))
            required_targets.update(consumer_targets)
        for edge in edges:
            if not isinstance(edge, dict):
                errors.append("edge_not_object")
                continue
            if edge.get("verification_status") == "PRIMARY_ELF_VERIFIED":
                if not edge.get("source") or not edge.get("target") or not edge.get("source_vma") or not edge.get("evidence", {}).get("source_binary_sha256"):
                    errors.append(f"edge_evidence:{edge.get('id')}")
                if edge.get("evidence", {}).get("verification_status") != "PRIMARY_ELF_VERIFIED":
                    errors.append(f"edge_provenance:{edge.get('id')}")
                if edge.get("evidence", {}).get("source_binary_sha256") != expected_sha256 or edge.get("address_space") != ADDRESS_SPACE:
                    errors.append(f"edge_identity:{edge.get('id')}")
                if edge.get("id") in required_targets:
                    target_vma, callsite_vma = required_targets[edge["id"]]
                    if edge.get("target_vma") != target_vma:
                        errors.append(f"edge_target:{edge.get('id')}")
                    if edge.get("callsite_vma") != callsite_vma:
                        errors.append(f"edge_callsite:{edge.get('id')}")
    unresolved = report.get("unresolved_edges")
    if not isinstance(unresolved, list) or len(unresolved) < 4:
        errors.append("unresolved_edges_missing")
    for item in unresolved or []:
        if item.get("status") not in {"UNKNOWN", "CANDIDATE", "INFERRED"}:
            errors.append(f"unresolved_status:{item.get('id')}")
        if item.get("evidence", {}).get("source_binary_sha256") != expected_sha256:
            errors.append(f"unresolved_provenance:{item.get('id')}")
    ghidra = report.get("ghidra_crosscheck")
    if ghidra is not None:
        if ghidra.get("status") != "VERIFIED_STATIC":
            errors.append("ghidra_status")
        if ghidra.get("version") != "12.1.3" or ghidra.get("language") != "ARM:LE:32:v8":
            errors.append("ghidra_environment")
        if ghidra.get("process_exit") != 0 or ghidra.get("completion_marker") != "COMPLETE_TARGET_EXPORT":
            errors.append("ghidra_completion")
        if ghidra.get("auto_analysis_completed") is not False:
            errors.append("ghidra_auto_analysis_promotion")
        if ghidra.get("raw_export_private") is not True or ghidra.get("firmware_bytes_public") is not False:
            errors.append("ghidra_visibility")
    return {"valid": not errors, "errors": sorted(set(errors))}
