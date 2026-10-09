"""Static Appframework event-loop evidence audit; no claimed Camera consumer.

This only checks saved annotated ARM assembly from an earlier offline
research run. It does not decode the current Sony ELF or execute hardware.
The event factory and the queue loop are distinct endpoints; matching a
binary SHA is NOT proof that a specific event reaches a specific consumer.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

SHA256 = "8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a"
SAVED_REPORT_SHA256 = "f8e31f84d8d7845f91397f7ec1cfd876e23ff7b2da4af98e6581be2fb743bbeb"
MAX_FIXTURE = 128 * 1024
MAX_SAVED_REPORT = 2 * 1024 * 1024
HEADER = re.compile(r"^FUNCTION (\S+) (0x[0-9a-fA-F]+)\s*$")
INST = re.compile(r"^(0x[0-9a-fA-F]+):\s*(.+)$")

# Explicit approved, previously inspected static site fingerprints. These
# deliberately do not contain Sony opcode bytes or complete pseudocode.
EXPECTED = {
    ("application_thread_body", "0x7eeee8"): (
        ("0x7ef0d4", "bl       #0x7eecac"),
        ("0x7ef0da", "cmp      r0, #0"),
        ("0x7ef0dc", "bne      #0x7ef0c0"),
        ("0x7ef180", "bl       #0x7eeec8"),
        ("0x7ef186", "cmp      r0, #0"),
        ("0x7ef188", "beq.w    #0x7eeefa"),
        ("0x7ef0c6", "bl       #0x7f2210"),
        ("0x7ef15a", "bl       #0x7f2210"),
        ("0x7ef16e", "bl       #0x7eecac"),
    ),
    ("app_event_pop", "0x7eec8c"): (
        ("0x7eec92", "ldr      r0, [r0, #0x10]"),
        ("0x7eec98", "b.w      #0xdf82c"),
    ),
    ("app_event_dispatch", "0x7eecac"): (
        ("0x7eecac", "push     {r7, lr}"),
        ("0x7eecb0", "ldr      r0, [r0, #0x18]"),
        ("0x7eecb6", "b.w      #0x7f21e8"),
    ),
    ("app_event_cleanup", "0x7eecbc"): (
        ("0x7eece6", "cmp      r0, #0"),
        ("0x7eecec", "bl       #0x7eecac"),
        ("0x7eecf2", "bne      #0x7eecc8"),
    ),
    ("app_event_queue_receive", "0x7eeec8"): (
        ("0x7eeed0", "bl       #0x7f29ec"),
        ("0x7eeed4", "cbnz     r0, #0x7eeee4"),
        ("0x7eeed8", "bl       #0x7eaa14"),
    ),
    ("application_event_candidate", "0x7f2210"): (
        ("0x7f2212", "mov.w    r1, #-1"),
        ("0x7f221a", "literal 0x830451"),
        ("0x7f221c", "osal_wai_sem_tmo"),
        ("0x7f2222", "bl       #0x7f099c"),
        ("0x7f2228", "literal 0x830451"),
        ("0x7f222a", "osal_sig_sem"),
    ),
}
UNRESOLVED_FLAGS = (
    "event_factory_to_app_queue_verified",
    "event_id_11004003_dispatched_by_these_sites_verified",
    "dispatch_target_0x7f21e8_semantics_verified",
    "handler_or_model_camera_consumer_verified",
    "parameter_keys_7_8_decoded_by_consumer_verified",
    "event_consumer_abi_verified",
    "runtime_callable_verified",
)


def _load_fixture(path: Path) -> dict[str, Any]:
    if not path.is_file() or not 0 < path.stat().st_size <= MAX_FIXTURE:
        raise ValueError("event-loop fixture absent or exceeds 128 KiB")
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict) or obj.get("schema_version") != 1:
        raise ValueError("invalid event-loop schema")
    return obj


def _function_region(text: str, name: str, start: str) -> dict[int, str]:
    """Keep only instruction rows until next FUNCTION or FILE heading."""
    regions: list[list[str]] = []
    active: list[str] | None = None
    for line in text.splitlines():
        if line.startswith("FUNCTION ") or line.startswith("FILE "):
            if active is not None:
                regions.append(active)
            active = None
            heading = HEADER.match(line)
            if heading and heading.group(1) == name and int(heading.group(2), 16) == int(start, 16):
                active = []
            continue
        if active is not None:
            active.append(line)
    if active is not None:
        regions.append(active)
    if len(regions) != 1:
        raise ValueError(f"missing or ambiguous saved app-event function: {name}")
    output: dict[int, str] = {}
    for line in regions[0]:
        match = INST.match(line)
        if match:
            addr = int(match.group(1), 16)
            if addr in output:
                raise ValueError("duplicate instruction address in saved function region")
            output[addr] = match.group(2)
    if len(output) > 1000:
        raise ValueError("unbounded saved event-loop instruction region")
    return output


def audit_application_event_loop(
    fixture: Path, *, saved_disassembly: Path | None = None,
) -> dict[str, Any]:
    obj = _load_fixture(Path(fixture))
    if (obj.get("status") != "APPLICATION_EVENT_LOOP_STATIC_SITES_CONSISTENT_EVENT_ID_CONSUMER_UNRESOLVED"
        or obj.get("firmware_version") != "3.21" or obj.get("factory_envelope_event_id") != "0x11004003"):
        raise ValueError("event-loop report scope or event id mismatch")
    identity = obj.get("binary", {})
    if not isinstance(identity, dict) or identity.get("name") != "libObj.so" or identity.get("sha256") != SHA256:
        raise ValueError("event-loop exact ELF research identity mismatch")
    metadata = obj.get("provenance", {})
    if not isinstance(metadata, dict) or (
        metadata.get("saved_disassembly_basename") != "app-event-functions.txt"
        or metadata.get("original_elf_bytes_checked_in_current_session") is not False
        or metadata.get("live_event_tracing") is not False
    ):
        raise ValueError("misrepresented Appframework event-loop provenance")
    boundary = obj.get("boundary")
    if not isinstance(boundary, dict) or any(boundary.get(key) is not False for key in UNRESOLVED_FLAGS):
        raise ValueError("cannot claim inferred Appframework event-ID consumer or ABI")
    targets = obj.get("next_targets")
    if not isinstance(targets, list) or not {
        "0x7f21e8", "0x7f099c", "0x12d780",
    }.issubset({p.get("elf_vma") for p in targets if isinstance(p, dict)}):
        raise ValueError("event-loop follow-up targets missing")
    entries = obj.get("observed_functions")
    if not isinstance(entries, list) or len(entries) != len(EXPECTED):
        raise ValueError("event-loop saved function regions missing")
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for item in entries:
        if not isinstance(item, dict):
            raise ValueError("event-loop function item must be object")
        key = item.get("name"), item.get("elf_vma")
        if key in by_key or key not in EXPECTED:
            raise ValueError("duplicated or unexpected event-loop function")
        sites = item.get("sites")
        if not isinstance(sites, list):
            raise ValueError("event-loop sites must be a list")
        actual = [(row.get("vma"), row.get("opcode_contains")) for row in sites if isinstance(row, dict)]
        if set(actual) != set(EXPECTED[key]) or len(actual) != len(EXPECTED[key]):
            raise ValueError(f"event-loop expected instruction sites differ: {key[0]}")
        by_key[key] = item
    if len(by_key) != len(EXPECTED):
        raise ValueError("event-loop incomplete approved function regions")
    results: list[dict[str, Any]] = []
    evidence_verified = False
    if saved_disassembly is not None:
        path = Path(saved_disassembly)
        if not path.is_file() or not 0 < path.stat().st_size <= MAX_SAVED_REPORT:
            raise ValueError("saved app-event disassembly missing or exceeds 2 MiB")
        # Do not claim original ELF SHA from a text-only report.
        source = path.read_text(encoding="utf-8")
        for key, sites in EXPECTED.items():
            opcodes = _function_region(source, *key)
            for vma, snippet in sites:
                observed = opcodes.get(int(vma, 16))
                if observed is None or snippet not in observed:
                    raise ValueError(f"saved app-event opcode report mismatch at {vma}")
            results.append({"function": key[0], "entry": key[1],
                            "annotated_instruction_sites_checked": len(sites)})
        evidence_verified = True
    return {
        "status": ("SAVED_APP_EVENT_LOOP_TEXT_MATCH_EVENT_CONSUMER_UNPROVEN" if evidence_verified
                   else "APP_EVENT_LOOP_BOUNDARY_CANDIDATES_ONLY"),
        "firmware_sha256_reported": identity["sha256"],
        "event_id_under_investigation": obj["factory_envelope_event_id"],
        "function_regions_checked": len(results),
        "opcode_text_sites_checked": sum(row["annotated_instruction_sites_checked"] for row in results),
        "per_function": results,
        "saved_report_text_verified": evidence_verified,
        "original_elf_instruction_bytes_verified": False,
        "queue_consumer_of_this_event_id_verified": False,
        "dispatch_or_callback_runtime_verified": False,
        "event_key_7_8_to_camera_action_verified": False,
        "abi_verified": False,
        "outstanding": targets,
    }
