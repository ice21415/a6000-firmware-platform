"""Bounded primary-ELF probe for the request-model Event factory.

The factory is a useful bridge between the model request frontends and the
Event envelope, but it is not a callable SDK function.  This probe emits
only structured observations from the authenticated private ELF; it never
publishes instruction bytes or executes firmware.
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
from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA
from .arm_store_dataflow import analyze_function


TARGET = {
    "name": "create_request_model_execute_event",
    "entry": 0x7F0B0C,
    "symbol_value_thumb_tagged": "0x7f0b0d",
    "symbol": "_ZN22AbstractUtilityManager30createRequestModelExecuteEventEimP9ParamList",
    "size": 108,
}
EVENT_ID_LITERAL = {"address": 0x7F0B74, "value": 0x11004003}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_vma(fp: Any, elf: ELFFile, start: int, size: int, *, executable: bool = False) -> bytes:
    if size <= 0 or size > 0x200:
        raise ValueError("request-event probe read exceeds bounded limit")
    offsets: list[int] = []
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD":
            continue
        if executable and not (int(segment["p_flags"]) & 1):
            continue
        base = int(segment["p_vaddr"])
        count = int(segment["p_filesz"])
        if base <= start and start + size <= base + count:
            offsets.append(int(segment["p_offset"]) + start - base)
    if len(offsets) != 1:
        raise ValueError(f"ELF_VMA 0x{start:x} is not uniquely file-backed")
    fp.seek(offsets[0])
    data = fp.read(size)
    if len(data) != size:
        raise ValueError("truncated ELF range")
    return data


def _decode(fp: Any, elf: ELFFile) -> dict[int, Any]:
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    rows = list(decoder.disasm(
        _read_vma(fp, elf, TARGET["entry"], TARGET["size"], executable=True),
        TARGET["entry"],
    ))
    if not rows:
        raise ValueError("request-event factory did not decode")
    return {int(row.address): row for row in rows}


def _immediates(ins: Any) -> list[int]:
    return [int(op.imm) for op in ins.operands if op.type == ARM_OP_IMM]


def _require(
    rows: dict[int, Any], address: int, mnemonic: str, *, target: int | None = None,
    operands: str | None = None,
) -> Any:
    ins = rows.get(address)
    if ins is None or ins.mnemonic.lower() != mnemonic.lower():
        raise ValueError(f"unexpected {mnemonic} at 0x{address:x}")
    if target is not None and target not in _immediates(ins):
        raise ValueError(f"unexpected call target at 0x{address:x}")
    if operands is not None and ins.op_str.lower() != operands.lower():
        raise ValueError(f"unexpected operands at 0x{address:x}")
    return ins


def _binding(fp: Any, elf: ELFFile, entry: int) -> dict[str, Any]:
    result = resolve_plt_binding(fp, elf, entry, thumb_stub=False)
    if result.get("status") != "VERIFIED_STATIC":
        raise ValueError(f"PLT binding at 0x{entry:x} is not unique")
    return result


def _symbol_record(elf: ELFFile) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    for section_name in (".dynsym", ".symtab"):
        section = elf.get_section_by_name(section_name)
        if section is None:
            continue
        for symbol in section.iter_symbols():
            if symbol.name == TARGET["symbol"]:
                matches.append({
                    "table": section_name,
                    "value": int(symbol["st_value"]),
                    "size": int(symbol["st_size"]),
                })
    if not matches:
        raise ValueError("request-event factory symbol is missing")
    exact = [item for item in matches if (item["value"] & ~1) == TARGET["entry"] and item["size"] == TARGET["size"]]
    if not exact:
        raise ValueError("request-event factory symbol identity/size mismatch")
    return {"name": TARGET["symbol"], "value": hex(exact[0]["value"]), "size": exact[0]["size"]}


def _observe(
    fp: Any,
    elf: ELFFile,
    rows: dict[int, Any],
    bindings: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    _require(rows, 0x7F0B0C, "push.w")
    _require(rows, 0x7F0B10, "movs", operands="r0, #0x10")
    _require(rows, 0x7F0B14, "mov", operands="r6, r1")
    _require(rows, 0x7F0B16, "mov", operands="r8, r2")
    _require(rows, 0x7F0B18, "mov", operands="r5, r3")
    _require(rows, 0x7F0B1A, "blx", target=0xDC100)
    _require(rows, 0x7F0B1E, "ldr", operands="r1, [pc, #0x54]")
    _require(rows, 0x7F0B20, "movs", operands="r2, #2")
    _require(rows, 0x7F0B22, "movs", operands="r3, #0")
    _require(rows, 0x7F0B26, "blx", target=0xDB66C)
    _require(rows, 0x7F0B2A, "cbz", target=0x7F0B34)
    _require(rows, 0x7F0B30, "blx", target=0xDE3A4)
    _require(rows, 0x7F0B3E, "bl", target=0xF0FB0)
    _require(rows, 0x7F0B44, "movs", operands="r1, #7")
    _require(rows, 0x7F0B48, "blx", target=0xDD194)
    _require(rows, 0x7F0B56, "bl", target=0xF0FB0)
    _require(rows, 0x7F0B5C, "movs", operands="r1, #8")
    _require(rows, 0x7F0B60, "blx", target=0xDD194)
    _require(rows, 0x7F0B66, "pop.w")
    _require(rows, 0x7F0B6C, "blx", target=0xDD620)
    _require(rows, 0x7F0B70, "blx", target=0xDD4F8)
    literal = struct.unpack("<I", _read_vma(fp, elf, EVENT_ID_LITERAL["address"], 4))[0]
    if literal != EVENT_ID_LITERAL["value"]:
        raise ValueError("request-event literal does not match expected event identity")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "identity": "AbstractUtilityManager::createRequestModelExecuteEvent symbol-bound factory",
        "inputs": {
            "r0": "AbstractUtilityManager receiver/context candidate",
            "r1": "explicit int model identifier, preserved in r6 and passed to PrmNumber constructor",
            "r2": "explicit unsigned long selector, preserved in r8 and passed to PrmNumber constructor",
            "r3": "ParamList* candidate; null skips Event::setParamList",
        },
        "event": {
            "literal_address": hex(EVENT_ID_LITERAL["address"]),
            "id": hex(literal),
            "constructor": "Event::Event(unsigned long,unsigned char,unsigned char) candidate via PLT 0xdb66c",
            "constructor_arguments": {"r1": "0x11004003", "r2": 2, "r3": 0},
            "param_list": "non-null r3 passed to Event::setParamList through PLT 0xde3a4",
        },
        "parameters": [
            {"key": 7, "value": "PrmNumber candidate constructed from original r1/model id"},
            {"key": 8, "value": "PrmNumber candidate constructed from original r2/selector"},
        ],
        "return": "event allocation pointer returned in r0; declared C++ return type remains UNKNOWN",
        "exception_cleanup": "landing-pad-shaped delete through _ZdlPv then __cxa_end_cleanup; exception table and ownership remain UNKNOWN",
        "bindings": bindings,
        "runtime_verified": False,
        "callable": False,
    }


def probe_request_event_factory(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Validate the bounded request-model Event factory in a private ELF."""
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
        symbol = _symbol_record(elf)
        bindings = {
            "allocator": _binding(fp, elf, 0xDC100),
            "event_constructor": _binding(fp, elf, 0xDB66C),
            "set_param_list": _binding(fp, elf, 0xDE3A4),
            "add_parameter": _binding(fp, elf, 0xDD194),
            "operator_delete": _binding(fp, elf, 0xDD620),
            "exception_cleanup": _binding(fp, elf, 0xDD4F8),
        }
        observation = _observe(fp, elf, _decode(fp, elf), bindings)
    return {
        "status": "LOCAL_PRIMARY_ELF_REQUEST_EVENT_EVIDENCE_ONLY",
        "binary_file_sha256": digest,
        "address_space": "ELF_VMA",
        "target": {**TARGET, "entry": TARGET["entry"]},
        "symbol": symbol,
        "observation": observation,
        "runtime_verified": False,
        "callable": False,
    }


def validate_request_event_factory(report: dict[str, Any]) -> dict[str, Any]:
    """Reject identity errors and any promotion beyond static evidence."""
    errors: list[str] = []
    if report.get("binary_file_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != "ELF_VMA":
        errors.append("address_space")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    target = report.get("target", {})
    if target.get("entry") != TARGET["entry"] or target.get("size") != TARGET["size"]:
        errors.append("target_identity")
    if report.get("symbol", {}).get("name") != TARGET["symbol"]:
        errors.append("symbol_identity")
    observation = report.get("observation", {})
    if observation.get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("observation_status")
    if observation.get("event", {}).get("id") != hex(EVENT_ID_LITERAL["value"]):
        errors.append("event_id")
    for key in ("allocator", "event_constructor", "set_param_list", "add_parameter", "operator_delete", "exception_cleanup"):
        if observation.get("bindings", {}).get(key, {}).get("status") != "VERIFIED_STATIC":
            errors.append(f"binding:{key}")
    return {"valid": not errors, "errors": sorted(set(errors))}


def assess_request_event_eligibility(
    event_id: int, queue_class: int | None, destination: int | None, *,
    receiver_enabled: bool | None = None, append_accepts: bool | None = None,
    pointer_preserved: bool | None = None, scheduled: bool | None = None,
) -> dict[str, Any]:
    """Evaluate hypothetical conditions offline; never certify runtime delivery.

    Class and destination are observed bytes, not a guessed Event subtype.
    Boolean conditions are caller-supplied model inputs, not trusted evidence.
    """
    if type(event_id) is not int or not 0 <= event_id <= 0xffffffff:
        raise ValueError("event ID must be an ARM32 word")
    for value in (queue_class, destination):
        if value is not None and (type(value) is not int or not 0 <= value <= 255):
            raise ValueError("Event fields must be bytes or unknown")
    for value in (receiver_enabled, append_accepts, pointer_preserved, scheduled):
        if value is not None and type(value) is not bool:
            raise ValueError("model conditions must be booleans or unknown")
    queue = "UNKNOWN" if queue_class is None else "QUEUE0" if queue_class == 0 else "QUEUE1" if queue_class == 1 else "NO_QUEUE_ON_OBSERVED_BRANCH"
    mask_pass = None if destination is None else bool(destination & 0x02)
    blocked = event_id != EVENT_ID_LITERAL["value"] or queue == "NO_QUEUE_ON_OBSERVED_BRANCH" or mask_pass is False or False in (receiver_enabled, append_accepts, pointer_preserved, scheduled)
    unknowns = [name for name, value in {"queue_class": queue_class, "destination": destination, "receiver_enabled": receiver_enabled, "append_accepts": append_accepts, "pointer_preserved": pointer_preserved, "scheduling": scheduled}.items() if value is None]
    if queue == "QUEUE1":
        unknowns.extend(["pre_enqueue_callback_effect", "queue1_transfer_trigger"])
    return {"queue_selected": queue, "requires_queue1_transfer": queue == "QUEUE1",
            "requires_pre_enqueue_callback": queue == "QUEUE1", "destination_mask": 2,
            "destination_bit_index": 1, "destination_pass": mask_pass,
            "consumer_event_id_pass": event_id == EVENT_ID_LITERAL["value"],
            "status": "INELIGIBLE_UNDER_MODEL_INPUTS" if blocked else "CONDITIONAL_STATIC_ELIGIBILITY",
            "unresolved_conditions": unknowns, "evidence_level": "OFFLINE_MODEL_ONLY",
            "runtime_verified": False, "safe_to_invoke": False}


def probe_request_event_eligibility(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Recover Request header and same-register pointer handoffs from primary ELF."""
    factory = probe_request_event_factory(elf_path, expected_sha256=expected_sha256)
    path = Path(elf_path)
    with path.open("rb") as fp:
        elf = ELFFile(fp)
        decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        decoder.detail = True
        def require(address: int, mnemonic: str, operands: str) -> dict[str, Any]:
            row = next(decoder.disasm(_read_vma(fp, elf, address, 4, executable=True), address, count=1), None)
            if row is None or (row.mnemonic, row.op_str) != (mnemonic, operands):
                raise ValueError(f"eligibility instruction mismatch at {address:#x}")
            owners = [(0x7f17f8, 0x7f182c), (0x10f9f4, 0x10f9fc), (0x7eebf8, 0x7eec00),
                      (0x7ef88c, 0x7ef894), (0x7ef960, 0x7ef9fc), (0x7ef910, 0x7ef940),
                      (0x7ef940, 0x7ef960), (0x7eeee8, 0x7ef1e4), (0x7eed0c, 0x7eeec8),
                      (0x7ed49c, 0x7ed8e0), (0x7eaa14, 0x7eaa24)]
            owner = next((start for start, end in owners if start <= address < end), None)
            if owner is None:
                raise ValueError("instruction outside bounded target bodies")
            return {"function_vma": hex(owner), "instruction_vma": hex(address), "mnemonic": mnemonic, "operands": operands,
                    "binary_sha256": factory["binary_file_sha256"],
                    "address_space": "ELF_VMA", "verification": "PRIMARY_ELF_VERIFIED"}
        checks = {
            0x7f17fc: ("strb", "r2, [r0, #8]"), 0x7f1800: ("strb", "r3, [r0, #9]"),
            0x7f1802: ("str", "r1, [r0, #4]"), 0x10f9f8: ("strb", "r1, [r0, #8]"),
            0x7eebfc: ("ldrb", "r0, [r0, #8]"), 0x7ef890: ("ldrb", "r0, [r0, #9]"),
            0x7ef974: ("cmp", "r0, #1"), 0x7ef978: ("bne", "#0x7ef9d2"),
            0x7ef9d2: ("cbnz", "r0, #0x7ef9ea"), 0x7ef9dc: ("mov", "r1, r5"),
            0x7ef9de: ("ldr", "r0, [r3]"), 0x7ef9e0: ("bl", "#0x7f0aac"),
            0x7ef922: ("cbz", "r0, #0x7ef936"), 0x7ef92a: ("bl", "#0x7f099c"),
            0x7ef92e: ("mov", "r1, r0"), 0x7ef930: ("mov", "r0, r5"),
            0x7ef932: ("bl", "#0x7f0aac"), 0x7ef952: ("mov", "r5, r0"),
            0x7ef95a: ("mov", "r0, r5"), 0x7eefda: ("bl", "#0x7ef940"),
            0x7eefde: ("mov", "r1, r0"), 0x7eefe0: ("mov", "r0, r4"),
            0x7eefe2: ("bl", "#0x7eed0c"), 0x7eed14: ("mov", "r5, r1"),
            0x7eed86: ("mov", "r6, r0"),
            0x7eedda: ("and", "r3, r6, #2"), 0x7eede0: ("cbz", "r3, #0x7eedf4"),
            0x7eedec: ("ldr", "r0, [r4, #4]"), 0x7eedee: ("mov", "r1, r5"),
            0x7eedf0: ("bl", "#0x7ed49c"), 0x7ed4a8: ("mov", "r5, r1"),
            0x7ed4b2: ("bl", "#0x7eaa14"), 0x7ed4b8: ("beq.w", "#0x7ed8d8"),
            0x7eaa14: ("ldr.w", "r0, [r0, #0xa4]"),
            0x7ed4f4: ("subs", "r3, #3"), 0x7ed4fc: ("adds", "r3, #1"),
            0x7ed4fe: ("cmp", "r6, r3"), 0x7ed500: ("bne", "#0x7ed552"),
            0x7ed502: ("b", "#0x7ed5c8"),
            0x7ed5d4: ("bl", "#0x7ea918"), 0x7ed5ea: ("bl", "#0x7ea918"),
            0x7ed5fc: ("bl", "#0x7eb8fa"),
        }
        evidence = [require(address, *expected) for address, expected in checks.items()]
        literal = struct.unpack("<I", _read_vma(fp, elf, 0x7ed750, 4))[0]
        if literal - 3 + 1 != EVENT_ID_LITERAL["value"]:
            raise ValueError("consumer request ID calculation mismatch")
        bindings = {name: _binding(fp, elf, entry) for name, entry in {
            "event_constructor": 0xdb66c, "get_destination": 0xdcecc,
            "get_id": 0xdbafc, "set_destination": 0xde708}.items()}
        required_symbols = {"event_constructor": "_ZN5EventC1Emhh", "get_destination": "_ZN5Event7getDestEv", "get_id": "_ZNK5Event5getIdEv", "set_destination": "_ZN5Event7setDestEh"}
        for name, symbol in required_symbols.items():
            if bindings[name]["candidates"][0]["symbol"] != symbol:
                raise ValueError(f"unexpected binding: {name}")
        def memory(address: int, size: int) -> bytes | None:
            for segment in elf.iter_segments():
                if segment["p_type"] == "PT_LOAD" and int(segment["p_vaddr"]) <= address and address + size <= int(segment["p_vaddr"]) + int(segment["p_filesz"]):
                    if int(segment["p_flags"]) & 2:
                        return None
                    return _read_vma(fp, elf, address, size)
            return None
        factory_cfg = analyze_function(memory, TARGET["entry"], [(TARGET["entry"], TARGET["entry"] + TARGET["size"])])
        constructor_call = next(call for call in factory_cfg["calls"] if call["callsite"] == 0x7f0b26)
        for register, value in {"r1": 0x11004003, "r2": 2, "r3": 0}.items():
            if constructor_call["argument_registers"][register]["values"] != [value]:
                raise ValueError(f"constructor argument dataflow mismatch: {register}")
        transfer_cfg = analyze_function(memory, 0x7ef910, [(0x7ef910, 0x7ef940)])
        # Analyze the forwarding basic block, not an invented function entry.
        forwarding_cfg = analyze_function(memory, 0x7eefd6, [(0x7eefd6, 0x7eefe6)])
        pointer_flows = []
        for cfg, producer, consumer, owner in [(transfer_cfg, 0x7ef92a, 0x7ef932, 0x7ef910),
                                                (forwarding_cfg, 0x7eefda, 0x7eefe2, 0x7eeee8)]:
            call = next(call for call in cfg["calls"] if call["callsite"] == consumer)
            argument = call["argument_registers"]["r1"]
            if not cfg["converged"] or producer not in argument["instruction_origins"]:
                raise ValueError("pop/dequeue return provenance not preserved")
            pointer_flows.append({"function_vma": hex(owner), "producer_callsite": hex(producer),
                                  "consumer_callsite": hex(consumer), "argument_register": "r1",
                                  "value": "UNKNOWN_POINTER_WORD", "provenance": argument,
                                  "analysis_scope": "function" if owner == 0x7ef910 else "forwarding basic block within application loop"})
    return {
        "schema_version": 1, "analyzer_version": "request-event-eligibility-1", "status": "LOCAL_PRIMARY_ELF_REQUEST_ELIGIBILITY",
        "binary_sha256": factory["binary_file_sha256"], "address_space": "ELF_VMA",
        "request_event": {"event_id": "0x11004003", "factory": "0x7f0b0c", "constructor": "0x7f17f8",
                          "allocation_bytes": 16, "id_field": {"offset": 4, "width": 4},
                          "class_field": {"offset": 9, "width": 1, "value": 0, "meaning": "observed queue-selection byte; source-level subtype UNKNOWN"},
                          "destination_field": {"offset": 8, "width": 1, "value": 2}, "parameter_keys": [7, 8]},
        "queue_eligibility": {"queue_selected": "QUEUE0", "predicate": "Event[9] == 0", "append_callsite": "0x7ef9e0",
                              "queue1_transfer_required": False, "main_callback_required": False,
                              "conditions": ["same object and unchanged class byte", "local symbol binding", "append succeeds"]},
        "queue_transfer": {"entry": "0x7ef910", "source_queue": "[manager.state + 4]", "destination_queue": "[manager.state + 0]",
                           "pointer_flow": ["0x7ef92a:r0", "0x7ef92e:r1=r0", "0x7ef932:append argument r1"],
                           "guard": "queue1 count nonzero", "events_per_invocation_max": 1,
                           "ownership": "list node removed; Event pointer retained, no Event release observed",
                           "required_for_default_request": False},
        "application_loop": {"entry": "0x7eeee8", "event_manager_source": "owner +0x10",
                             "pointer_flow": ["0x7eefda:return r0", "0x7eefde:r1=r0", "0x7eefe2:router argument r1"],
                             "guard": "count(0) nonzero on observed drain loop", "scheduling": "UNKNOWN"},
        "router_eligibility": {"entry": "0x7eed0c", "consumer_callsite": "0x7eedf0", "consumer": "0x7ed49c",
                              "destination_predicate": "snapshot_destination & 0x02 != 0", "mask": 2, "bit_index": 1,
                              "request_passes_initial_mask": True, "consumer_receiver_source": "owner +4",
                              "consumer_state_predicate": "receiver word +0xa4 != 0", "request_id_predicate": "Event.id == 0x11004003"},
        "end_to_end": {"status": "CONDITIONAL_STATIC_REQUEST_PATH", "queue1_request_hypothesis": "SUPERSEDED_DISPROVEN_FOR_INITIAL_REQUEST",
                       "unresolved": ["runtime scheduling and owner identity", "callback/helper interposition and later aliases", "append guards/allocation exceptions", "receiver enabled state", "model registry instance and runtime DSO identity"],
                       "event_lifetime": "borrowed through consumer; Router later destructs/deletes Event"},
        "model_assessment": assess_request_event_eligibility(0x11004003, 0, 2),
        "dataflow": {"constructor_arguments": constructor_call["argument_registers"], "factory_reachable_instructions": factory_cfg["instruction_count"],
                     "pointer_flows": pointer_flows, "transfer_reachable_instructions": transfer_cfg["instruction_count"],
                     "forwarding_block_reachable_instructions": forwarding_cfg["instruction_count"]},
        "evidence": evidence, "bindings": bindings, "runtime_verified": False, "safe_to_invoke": False,
    }
