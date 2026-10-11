"""Bounded primary-ELF evidence for the consumer receiver gate and registry gate.

This probe deliberately proves object-relative accesses and branch predicates,
not runtime object identity or field semantics.  Firmware bytes stay private;
the result contains only curated instruction metadata and provenance.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from capstone.arm import ARM_OP_IMM
from elftools.elf.elffile import ELFFile

EXPECTED_SHA256 = "8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a"
ANALYZER_VERSION = "camera-receiver-registry-probe-1"


def classify_receiver_field(value: int) -> str:
    """Model only the observed getter's zero/nonzero normalization."""
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("receiver field must be an unsigned 32-bit integer")
    return "DISABLED" if value == 0 else "NONZERO"


def classify_registry_record(record_field_8: int | None, *, record_present: bool = True) -> str:
    """Apply the observed unsigned range gate without naming its semantics."""
    if not record_present:
        return "NULL_RECORD"
    if record_field_8 is None or not isinstance(record_field_8, int) or isinstance(record_field_8, bool):
        return "UNKNOWN_RECORD_FIELD"
    value = record_field_8 & 0xFFFFFFFF
    return "FORWARD" if 0x10001 <= value <= 0x6FFFF else "REJECT"


def classify_record_state(value: int | None) -> str:
    """Describe the observed state-machine domain without naming its type."""
    if value is None or not isinstance(value, int) or isinstance(value, bool):
        return "UNKNOWN"
    value &= 0xFFFFFFFF
    if value == 0x10000:
        return "INITIAL_SENTINEL"
    if value in {0x20000, 0x30000, 0x40000, 0x50000, 0x60000, 0x70000}:
        return "STATE_DOMAIN"
    return "OUTSIDE_OBSERVED_DOMAIN"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _reader(stream: Any, elf: ELFFile):
    segments = [s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]

    def read(vma: int, size: int) -> bytes:
        matches = [s for s in segments if int(s["p_vaddr"]) <= vma
                   and vma + size <= int(s["p_vaddr"]) + int(s["p_filesz"])]
        if len(matches) != 1:
            raise ValueError(f"VMA 0x{vma:x} is not uniquely file-backed")
        seg = matches[0]
        stream.seek(int(seg["p_offset"]) + vma - int(seg["p_vaddr"]))
        data = stream.read(size)
        if len(data) != size:
            raise ValueError("truncated executable range")
        return data

    return read


def _decode(read, entry: int, size: int) -> dict[int, Any]:
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    rows = list(decoder.disasm(read(entry, size), entry))
    if not rows:
        raise ValueError(f"Thumb decode failed at 0x{entry:x}")
    return {int(row.address): row for row in rows}


def _need(rows: dict[int, Any], address: int, mnemonic: str, operands: str | None = None, target: int | None = None):
    row = rows.get(address)
    if row is None or row.mnemonic.lower() != mnemonic.lower():
        raise ValueError(f"unexpected instruction at 0x{address:x}")
    if operands is not None and row.op_str.lower() != operands.lower():
        raise ValueError(f"unexpected operands at 0x{address:x}")
    if target is not None and target not in [int(op.imm) for op in row.operands if op.type == ARM_OP_IMM]:
        raise ValueError(f"unexpected branch target at 0x{address:x}")
    return row


def probe_receiver_registry(path: Path, *, expected_sha256: str = EXPECTED_SHA256) -> dict[str, Any]:
    """Re-read the pinned ELF and return receiver/registry facts.

    The record ``+8`` range check is reported as a gate only.  It is not
    renamed to a model ID or state until an independent type/initialization
    witness exists.
    """
    path = Path(path).resolve()
    digest = _sha(path)
    if digest != expected_sha256:
        raise ValueError("ELF SHA256 mismatch")
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_ARM":
            raise ValueError("requires ELF32 little-endian ARM")
        read = _reader(stream, elf)

        getter = _decode(read, 0x7EAA14, 0x10)
        _need(getter, 0x7EAA14, "ldr.w", "r0, [r0, #0xa4]")
        _need(getter, 0x7EAA1A, "subs", "r0, #0")
        _need(getter, 0x7EAA1E, "it", "ne")
        _need(getter, 0x7EAA20, "movne", "r0, #1")
        _need(getter, 0x7EAA22, "pop", "{r7, pc}")

        consumer = _decode(read, 0x7ED4A8, 0x18)
        _need(consumer, 0x7ED4A8, "mov", "r5, r1")
        _need(consumer, 0x7ED4B0, "mov", "r0, r4")
        _need(consumer, 0x7ED4B2, "bl", target=0x7EAA14)
        _need(consumer, 0x7ED4B6, "cmp", "r0, #0")
        _need(consumer, 0x7ED4B8, "beq.w", target=0x7ED8D8)

        router = _decode(read, 0x7EEDDC, 0x20)
        _need(router, 0x7EEDEC, "ldr", "r0, [r4, #4]")
        _need(router, 0x7EEDEE, "mov", "r1, r5")
        _need(router, 0x7EEDF0, "bl", target=0x7ED49C)

        setter = _decode(read, 0x7EB118, 0xA0)
        _need(setter, 0x7EB118, "ldr.w", "r3, [r0, #0xa4]")
        _need(setter, 0x7EB11E, "cmp", "r1, r3")
        _need(setter, 0x7EB12A, "str.w", "r1, [r0, #0xa4]")
        _need(setter, 0x7EB12E, "beq", target=0x7EB13C)
        _need(setter, 0x7EB1AE, "pop", "{r4, r5, r7, pc}")

        calls = []
        for site, value in ((0x7EC9B6, 0x40000), (0x7ED038, 0x30000),
                            (0x7ED1D2, 0x70000), (0x7ED250, 0x50000),
                            (0x7ED47C, 0x40000)):
            rows = _decode(read, site - 6, 0x0C)
            _need(rows, site - 4, "mov.w", f"r1, #{hex(value)}")
            _need(rows, site, "bl", target=0x7EB118)
            calls.append({"callsite_vma": hex(site), "receiver_register": "r0",
                          "written_value": hex(value), "verification": "PRIMARY_ELF_VERIFIED"})

        registry = _decode(read, 0x7ED5F8, 0x62)
        _need(registry, 0x7ED5FC, "bl", target=0x7EB8FA)
        _need(registry, 0x7ED600, "mov", "r8, r0")
        _need(registry, 0x7ED602, "cmp", "r0, #0")
        _need(registry, 0x7ED604, "beq", target=0x7ED66A)
        _need(registry, 0x7ED606, "ldr", "r2, [r0, #8]")
        _need(registry, 0x7ED60A, "sub.w", "r2, r2, #0x10001")
        _need(registry, 0x7ED610, "bhi", target=0x7ED66A)
        _need(registry, 0x7ED650, "bl", target=0x7F124A)

        init = _decode(read, 0x7F1156, 0x24)
        _need(init, 0x7F1164, "mov.w", "r2, #0x10000")
        _need(init, 0x7F1168, "str", "r2, [r0, #8]")
        _need(init, 0x7F1174, "str", "r2, [r0, #0x1c]")
        forward = _decode(read, 0x7F124A, 0x18)
        _need(forward, 0x7F124A, "ldr", "r0, [r0, #0x1c]")
        _need(forward, 0x7F1250, "cbz", target=0x7F125A)
        _need(forward, 0x7F1252, "bl", target=0x7EFCCA)
        lookup = _decode(read, 0x7EB8FA, 0x48)
        _need(lookup, 0x7EB904, "add.w", "r4, r0, #0x88")
        _need(lookup, 0x7EB938, "ldr", "r0, [r0, #4]")

        # These are deliberately recorded as negative/conditional evidence.
        # They are stores to a word at offset +8, but the surrounding code
        # proves different base objects from the lookup result.  A matching
        # field offset alone must not promote either store to a registry-record
        # state transition.
        state_a = _decode(read, 0x7EAFF0, 0x40)
        _need(state_a, 0x7EB016, "str", "r3, [r4, #8]")
        state_b = _decode(read, 0x7EC844, 0x40)
        _need(state_b, 0x7EC874, "str", "r1, [r4, #8]")

        # Configuration registration is separately checked from the registry
        # lookup.  It proves the descriptor strings and IdGenerator callsite,
        # but not the runtime value returned by IdGenerator::Get nor record
        # identity after tree insertion.
        registration = _decode(read, 0x402088, 0x24)
        _need(registration, 0x40208E, "add", "r0, pc")
        _need(registration, 0x402090, "blx", target=0xDFFB8)
        _need(registration, 0x40209A, "add", "r3, pc")
        _need(registration, 0x4020A0, "blx", target=0xDF58C)

        factory = _decode(read, 0x4C8C64, 0x30)
        _need(factory, 0x4C8C74, "bl", target=0x4C8AF4)
        _need(factory, 0x4C8C78, "str", "r5, [r4, #0x20]")
        constructor = _decode(read, 0x4C8AF4, 0x30)
        _need(constructor, 0x4C8B10, "str", "r2, [r5]")

        state_machine = _decode(read, 0x7EAC60, 0x50)
        _need(state_machine, 0x7EAC62, "mov", "r4, r1")
        _need(state_machine, 0x7EAC6E, "ldr", "r3, [r4, #8]")
        _need(state_machine, 0x7EAC86, "cmp.w", "r3, #0x10000")
        _need(state_machine, 0x7EACA0, "cmp.w", "r3, #0x50000")
        consumer_model = _decode(read, 0x7ED710, 0x24)
        _need(consumer_model, 0x7ED71E, "bl", target=0x7EB8FA)
        _need(consumer_model, 0x7ED722, "mov", "r1, r0")
        _need(consumer_model, 0x7ED72E, "bl", target=0x7EAC60)

    return {
        "schema_version": 1,
        "analyzer_version": ANALYZER_VERSION,
        "binary_sha256": digest,
        "address_space": "ELF_VMA",
        "receiver_gate": {
            "consumer_vma": "0x7ed49c", "getter_vma": "0x7eaa14",
            "field_offset": "0xa4", "field_width": 4,
            "input_receiver": "consumer r4 from router owner +4",
            "return": "0 if word is zero, otherwise 1",
            "branch": {"callsite": "0x7ed4b2", "zero_target": "0x7ed8d8",
                       "predicate": "RECEIVER_FIELD_A4 == 0"},
            "verification": "PRIMARY_ELF_VERIFIED",
        },
        "router_receiver_provenance": {
            "router_entry": "0x7eed0c",
            "owner_register": "r4",
            "receiver_load_vma": "0x7eedec",
            "receiver_source": "[r4 + 0x4]",
            "event_register_move_vma": "0x7eedee",
            "consumer_callsite": "0x7eedf0",
            "consumer_target": "0x7ed49c",
            "verification": "PRIMARY_ELF_VERIFIED_POINTER_FLOW",
            "runtime_object_identity": "UNKNOWN",
        },
        "receiver_writers": {
            "setter_vma": "0x7eb118", "store_vma": "0x7eb12a",
            "effective_address": "caller r0 + 0xa4",
            "written_value": "caller r1 (word)",
            "same_value_early_return": "0x7eb11e -> 0x7eb1ae",
            "callers": calls,
            "object_identity": "CONDITIONAL; callers are state-machine receivers, not proven router owner",
            "verification": "PRIMARY_ELF_VERIFIED_STATIC_STORE",
        },
        "registry_gate": {
            "lookup_vma": "0x7eb8fa", "lookup_callsite": "0x7ed5fc",
            "record_register": "r8", "null_guard": "0x7ed604 -> 0x7ed66a",
            "field_offset": "0x8", "predicate": "0x10001 <= record[+8] <= 0x6ffff",
            "range_check": {"subtract": "0x10001", "upper_inclusive": "0x6ffff",
                            "literal_vma": "0x7ed768", "literal_value": "0x5fffe"},
            "success_forwarder": {"callsite": "0x7ed650", "target": "0x7f124a",
                                   "record_register": "r0", "event_register": "r1"},
            "verification": "PRIMARY_ELF_VERIFIED",
        },
        "record_provenance": {
            "record_initializer": "0x7f1156", "initial_field_8": "0x10000",
            "initial_instance_field_1c": 0,
            "lookup_tree_receiver_offset": "0x88",
            "lookup_return": "tree node value at +4",
            "model_id_11_record_identity": "UNKNOWN",
            "runtime_dso_identity": "UNKNOWN",
        },
        "state_transition_candidates": [
            {
                "function_vma": "0x7eac60",
                "store_vma": "0x7eb016",
                "base_register": "r4 (record parameter r1)",
                "written_value": "r3 = 0x60000 or 0x50000, path dependent",
                "classification": "CONDITIONAL_RECORD_STATE_WRITE",
                "object_identity": "PRIMARY_ELF_VERIFIED; r4 is the record passed by state-machine caller",
                "verification": "PRIMARY_ELF_VERIFIED_POINTER_DATAFLOW",
                "precondition": "state-machine branch reaches forwarder failure/success state path",
            },
            {
                "function_vma": "0x7ec844",
                "store_vma": "0x7ec874",
                "base_register": "r4",
                "written_value": "r1 = end/capacity-derived value",
                "classification": "CANDIDATE_OFFSET8_STORE",
                "object_identity": "UNKNOWN; r4 is the registry/container receiver candidate, not the returned record",
                "verification": "PRIMARY_ELF_VERIFIED_INSTRUCTION_ONLY",
                "exclusion_reason": "store is in container growth path and lacks record +8 provenance",
            },
            {
                "function_vma": "0x7eac60",
                "store_vma": "0x7eaf4a",
                "base_register": "r4 (record parameter r1)",
                "written_value": "0x40000",
                "classification": "CONDITIONAL_RECORD_STATE_WRITE",
                "object_identity": "PRIMARY_ELF_VERIFIED; r4 is the record passed by state-machine caller",
                "verification": "PRIMARY_ELF_VERIFIED_POINTER_DATAFLOW",
                "precondition": "state branch reaches 0x7eaf32 and its notification path succeeds",
            },
            {
                "function_vma": "0x7eac60",
                "store_vma": "0x7eafce",
                "base_register": "r4 (record parameter r1)",
                "written_value": "0x70000",
                "classification": "CONDITIONAL_RECORD_STATE_WRITE",
                "object_identity": "PRIMARY_ELF_VERIFIED; r4 is the record passed by state-machine caller",
                "verification": "PRIMARY_ELF_VERIFIED_POINTER_DATAFLOW",
                "precondition": "state + event comparison selects 0x7eafd4 path",
            },
        ],
        "record_state_machine": {
            "entry_vma": "0x7eac60",
            "record_argument": "r1 -> r4 at 0x7eac62",
            "state_load_vma": "0x7eac6e",
            "state_field": "+0x8",
            "recognized_values": ["0x10000", "0x20000", "0x30000", "0x40000", "0x50000", "0x60000", "0x70000"],
            "consumer_callsite": "0x7ed72e",
            "lookup_return_to_record_argument": "0x7ed71e -> r0; 0x7ed722 -> r1",
            "verification": "PRIMARY_ELF_VERIFIED_POINTER_FLOW",
            "forwarder_identity": "same record pointer is used on state-machine forwarder calls; runtime model identity remains UNKNOWN",
        },
        "model_registration": {
            "compact_name": "@M00B",
            "compact_name_literal_vma": "0xcbc97e",
            "id_generator_callsite": "0x402090",
            "id_generator_target": "0xdffb8",
            "add_callsite": "0x4020a0",
            "add_target": "0x7f08a0",
            "library": "modelCamera.so",
            "factory_symbol": "ModelCameraToInstance",
            "verification": "PRIMARY_ELF_VERIFIED_STATIC_REGISTRATION",
            "returned_model_id": "STATIC_INFERRED; IdGenerator return value not independently decoded as 11",
            "record_identity_after_insert": "UNKNOWN",
        },
        "modelcamera_factory": {
            "factory_vma": "0x4c8c64",
            "constructor_callsite": "0x4c8c74",
            "constructor_vma": "0x4c8af4",
            "context_store_vma": "0x4c8c78",
            "vptr_store_vma": "0x4c8b10",
            "instance_record_field": "+0x1c",
            "verification": "PRIMARY_ELF_VERIFIED_FACTORY_SHAPE",
            "runtime_dso_identity": "UNKNOWN",
        },
        "runtime_verified": False,
        "safe_to_invoke": False,
        "limitations": [
            "object identity for receiver +0xa4 writers is unresolved",
            "record +8 semantic type is unresolved; this probe does not call it Model ID",
            "runtime registry population and modelCamera.so alias are unresolved",
            "no runtime behavior or callable ABI is claimed",
        ],
    }
