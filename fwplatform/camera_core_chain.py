"""Evidence-gated Camera request/event/action chain probe.

This module joins bounded, SHA-pinned observations that already have primary
ELF support.  It deliberately does not guess the indirect EventManager target
or a ModelCamera event consumer.  The output is a sanitized relation graph:
addresses, identities, evidence locators and verification levels are retained,
while firmware bytes and decompiler text remain private.
"""
from __future__ import annotations

import hashlib
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
            "reason": "The body loads [this + 0x00] then invokes a function pointer from [state + 0x08]; no unique callback target is proven by the current bounded evidence.",
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
            "reason": "The factory proves event creation and keys 7/8, but no event-ID compare and receiver function linking this ID to ModelCamera has been found in the bounded primary-ELF pass.",
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
            "reason": "Keys 7 and 8 are inserted by the factory; their receiver-side extraction and selector mapping are not proven.",
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
        factory = probe_request_event_factory(path, expected_sha256=expected_sha256)
        event_manager = probe_event_manager_push(path, expected_sha256=expected_sha256)
    event_edge = _edge("factory.event_id", "AbstractUtilityManager::createRequestModelExecuteEvent", f"EventID:{hex(EVENT_ID)}", "CREATES_EVENT", 0x7F0B0C, digest, callsite_vma=0x7F0B1E, method="CAPSTONE_PRIMARY_ELF", note="The target is an event value, not a code address or VMA.")
    event_edge["target_value"] = hex(EVENT_ID)
    event_edge["literal_vma"] = hex(0x7F0B74)
    key7_edge = _edge("factory.key7", f"EventID:{hex(EVENT_ID)}", "EventParameterKey:7", "CARRIES_PARAMETER", 0x7F0B0C, digest, callsite_vma=0x7F0B48)
    key7_edge["key_literal_vma"] = hex(0x7F0B44)
    key8_edge = _edge("factory.key8", f"EventID:{hex(EVENT_ID)}", "EventParameterKey:8", "CARRIES_PARAMETER", 0x7F0B0C, digest, callsite_vma=0x7F0B60)
    key8_edge["key_literal_vma"] = hex(0x7F0B5C)
    edges = request_edges + submit_edges + action_edges + [
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
            "camera_action": action_observation,
        },
        "nodes": nodes,
        "edges": edges,
        "unresolved_edges": _unresolved(digest),
        "chain_summary": {
            "request_to_factory": "PRIMARY_ELF_VERIFIED",
            "factory_to_event_submit": "PRIMARY_ELF_VERIFIED",
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
    for key in ("event_manager_indirect_dispatch_target", "event_consumer_model_camera", "event_keys_7_8_to_model_camera", "ee_neutral_receiver_and_completion"):
        if summary.get(key) != "UNKNOWN":
            errors.append(f"unresolved:{key}")
    edges = report.get("edges")
    if not isinstance(edges, list) or not edges:
        errors.append("edges_missing")
    else:
        required = {"request.viewbase.factory", "request.viewbase.submit", "submit.helper.event_manager", "factory.event_id", "factory.key7", "factory.key8", "camera.action.selector_0f01"}
        present = {str(edge.get("id")) for edge in edges if isinstance(edge, dict)}
        errors.extend(f"edge_missing:{item}" for item in sorted(required - present))
        for edge in edges:
            if not isinstance(edge, dict):
                errors.append("edge_not_object")
                continue
            if edge.get("verification_status") == "PRIMARY_ELF_VERIFIED":
                if not edge.get("source") or not edge.get("target") or not edge.get("source_vma") or not edge.get("evidence", {}).get("source_binary_sha256"):
                    errors.append(f"edge_evidence:{edge.get('id')}")
                if edge.get("evidence", {}).get("verification_status") != "PRIMARY_ELF_VERIFIED":
                    errors.append(f"edge_provenance:{edge.get('id')}")
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
