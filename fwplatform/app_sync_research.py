"""Read-only ModelManager event-gate and semaphore-report triangulation.

A saved disassembly can validate +0xa4 nonzero normalization / queue
inversion *locally*. A separate saved secondary JSON report can review
semaphore wrapper and status-setter hypotheses. Neither proves that a
specific 0x11004003 event reaches ModelCamera, nor validates an ABI.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .app_event_loop import _function_region

ELF_SHA256 = "8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a"
MAX_FIXTURE_BYTES = 192 * 1024
MAX_ASM_BYTES = 2 * 1024 * 1024
MAX_REPORT_BYTES = 192 * 1024

PRIMARY_SITES = {
    ("app_event_wait_or_check", "0x7eaa14"): (
        ("0x7eaa14", "ldr.w    r0, [r0, #0xa4]"),
        ("0x7eaa1a", "subs     r0, #0"),
        ("0x7eaa1e", "it       ne"),
        ("0x7eaa20", "movne    r0, #1"),
        ("0x7eaa22", "pop      {r7, pc}"),
        # Adjacent region appears within one *bounded report window*,
        # NOT necessarily inside the same C++ function:
        ("0x7eaa68", "ldr.w    r3, [r0, #0xa4]"),
        ("0x7eaa6e", "cmp.w    r3, #0x50000"),
        ("0x7eaa76", "cmp.w    r3, #0x70000"),
        ("0x7eaa7c", "cmp.w    r3, #0x40000"),
    ),
    ("app_event_queue_receive", "0x7eeec8"): (
        ("0x7eeed0", "bl       #0x7f29ec"),
        ("0x7eeed4", "cbnz     r0, #0x7eeee4"),
        ("0x7eeed8", "bl       #0x7eaa14"),
        ("0x7eeedc", "eor      r0, r0, #1"),
        ("0x7eeee0", "uxtb     r0, r0"),
        ("0x7eeee4", "movs     r0, #0"),
    ),
    ("application_thread_body", "0x7eeee8"): (
        ("0x7ef180", "bl       #0x7eeec8"),
        ("0x7ef186", "cmp      r0, #0"),
        ("0x7ef188", "beq.w    #0x7eeefa"),
    ),
}
EXPECTED_WAIT = {
    "0x7f21e8": ("0x7f0aa0", ("0x7eecb6",)),
    "0x7f2210": ("0x7f099c", ("0x7ef0c6", "0x7ef15a")),
    "0x7f2238": ("0x7f0aac", ("0x10b144",)),
}
EXPECTED_STATES = (
    ("0x7ec9b6", "0x40000"),
    ("0x7ed038", "0x30000"),
    ("0x7ed1d2", "0x70000"),
    ("0x7ed250", "0x50000"),
    ("0x7ed47c", "0x40000"),
)
REQUIRED_FALSE = (
    "event_0x11004003_consumed_by_this_loop",
    "event_keys_7_and_8_extracted_here",
    "model_camera_action_dispatch_link",
    "wait_wrappers_0x7f21e8_0x7f2238_redecoded_from_original_elf",
    "status_field_exact_CPP_type_or_object_owner",
    "camera_ready_semantics",
    "runtime_event_frequency",
    "actual_boot_delay_caused_by_semaphore",
    "sony_abi_or_callable_sdk",
)


def _read_json(path: Path, cap: int) -> dict[str, Any]:
    if not path.is_file() or not 0 < path.stat().st_size <= cap:
        raise ValueError("status-sync research JSON missing or exceeds size bound")
    o = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(o, dict):
        raise ValueError("status-sync source must be JSON object")
    return o


def _exact_sites(rows: Any, expected: tuple[tuple[str, str], ...], label: str) -> None:
    if not isinstance(rows, list) or len(rows) != len(expected):
        raise ValueError(f"{label}: incomplete or excessive address observations")
    actual = [(x.get("vma"), x.get("match")) for x in rows if isinstance(x, dict)]
    if actual != list(expected):
        raise ValueError(f"{label}: saved instruction location/fingerprint list mismatch")


def _verify_fixture(obj: dict[str, Any]) -> None:
    if (obj.get("schema_version") != 1 or obj.get("firmware_version") != "3.21"
        or obj.get("kind") != "app_model_status_gate_and_semaphore_triangulation"
        or obj.get("status") != "SAVED_STATUS_BOOLEAN_PATH_OBSERVED_SEMAPHORE_WRAPPERS_SECONDARY_REPORT"
        or obj.get("elf_name") != "libObj.so" or obj.get("elf_sha256") != ELF_SHA256):
        raise ValueError("status-sync fixture has wrong firmware identity or claim scope")
    provenance = obj.get("source_artifacts")
    if (not isinstance(provenance, dict)
        or provenance.get("instruction_report") != "app-event-functions.txt"
        or provenance.get("status_wait_report") != "app-status-wait-chain.json"
        or provenance.get("source_elf_redecoded_this_session") is not False):
        raise ValueError("status-sync source provenance must not imply original ELF verification")
    status = obj.get("model_manager_status_reader")
    gate = obj.get("queue_gate")
    loop = obj.get("loop_use")
    adjacent = obj.get("adjacent_state_selection_lead")
    if not all(isinstance(x, dict) for x in (status, gate, loop, adjacent)):
        raise ValueError("status-sync event gate segments are missing")
    if (status.get("entry_vma") != "0x7eaa14"
        or status.get("reported_field_offset") != "0xa4"
        or status.get("semantic_scope") != "LOCAL_NONZERO_BOOLEAN_OF_WORD_AT_R0_PLUS_0xA4"
        or gate.get("entry_vma") != "0x7eeec8"
        or loop.get("entry_vma") != "0x7eeee8"
        or loop.get("callsite") != "0x7ef180"
        or loop.get("branch_site") != "0x7ef188"
        or loop.get("zero_result_branch") != "0x7eeefa"
        or adjacent.get("vma") != "0x7eaa68"
        or adjacent.get("semantic_relation_to_status_reader") != "UNRESOLVED"):
        raise ValueError("status-sync source addresses / semantic boundaries mismatch")
    if adjacent.get("reported_state_comparisons") != ["0x50000", "0x70000", "0x40000"]:
        raise ValueError("status-sync adjacent candidate state comparisons mismatch")
    a = PRIMARY_SITES[("app_event_wait_or_check", "0x7eaa14")]
    _exact_sites(status.get("observed_sites"), a[:5], "ModelManager status reader")
    _exact_sites(adjacent.get("observed_sites"), a[5:], "adjacent scanner region")
    _exact_sites(gate.get("observed_sites"), PRIMARY_SITES[("app_event_queue_receive", "0x7eeec8")],
                 "queue inversion")
    _exact_sites(loop.get("observed_sites"), PRIMARY_SITES[("application_thread_body", "0x7eeee8")],
                 "application loop branch")
    truth = gate.get("conditional_model_status_path", {}).get(
        "observed_truth_table_for_only_this_guard_path")
    if truth != [
        {"model_status_plus_a4_zero": True, "status_reader_r0": 0, "queue_gate_r0": 1},
        {"model_status_plus_a4_zero": False, "status_reader_r0": 1, "queue_gate_r0": 0},
    ]:
        raise ValueError("queue inversion truth table mismatches observed ARM instructions")
    if gate.get("conditional_model_status_path", {}).get("if_prior_guard_result_nonzero") != "immediate return 0":
        raise ValueError("queue inversion source guard must keep short circuit")
    wrappers = obj.get("secondary_report_sync_wrappers")
    if not isinstance(wrappers, list) or len(wrappers) != 3:
        raise ValueError("secondary wait-wrapper list incomplete")
    seen: set[str] = set()
    for row in wrappers:
        if not isinstance(row, dict) or row.get("vma") not in EXPECTED_WAIT or row["vma"] in seen:
            raise ValueError("duplicate or foreign secondary wait wrapper")
        seen.add(row["vma"])
        completion, callers = EXPECTED_WAIT[row["vma"]]
        if (row.get("wait_call") != "osal_wai_sem_tmo" or row.get("semaphore") != "0x830451"
            or row.get("timeout") != -1 or row.get("completion_helper") != completion
            or row.get("caller_sites") != list(callers)
            or row.get("primary_opcode_reverified") is not False):
            raise ValueError("secondary wait-wrapper report does not support the claimed topology")
    setter = obj.get("secondary_report_status_setter")
    if not isinstance(setter, dict) or (
        setter.get("vma") != "0x7eb118" or setter.get("field") != "0xa4"
        or setter.get("entry_opcode_reverified") is not False
        or [(x.get("callsite"), x.get("state")) for x in setter.get("callsite_to_reported_new_state", [])
            if isinstance(x, dict)] != list(EXPECTED_STATES)):
        raise ValueError("status setter is a separate secondary research lead, not ABI")
    flags = obj.get("unverified")
    if not isinstance(flags, dict) or any(flags.get(k) is not False for k in REQUIRED_FALSE):
        raise ValueError("status-sync cannot promote unknown event consumer, boot cause or ABI")


def _check_saved_status_chain(report: dict[str, Any]) -> None:
    if (report.get("target") != "libObj.so (Sony ILCE-6000 firmware 3.21)"
        or report.get("purpose") != "Static evidence for the application-thread wait chain observed during the cold-boot gap"):
        raise ValueError("secondary status report target/scope mismatch")
    nodes = report.get("nodes")
    if not isinstance(nodes, list):
        raise ValueError("secondary status report missing nodes")
    by_addr: dict[str, dict[str, Any]] = {}
    for n in nodes:
        if not isinstance(n, dict) or not isinstance(n.get("address"), str):
            raise ValueError("secondary status report invalid node")
        if n["address"] in by_addr:
            raise ValueError("duplicate secondary status node")
        by_addr[n["address"]] = n
    required = {"0x7eeee8", "0x7eeec8", "0x7eec00", "0x7eea44", "0x7f2210",
                "0x7f21e8", "0x7f2238", "0x7eb118"}
    if not required.issubset(by_addr):
        raise ValueError("secondary status report incomplete node graph")
    for addr, (completion, callers) in EXPECTED_WAIT.items():
        n = by_addr[addr]
        if (n.get("wait") != "osal_wai_sem_tmo" or n.get("timeout_argument") != -1
            or n.get("semaphore_literal") != "0x830451"
            or not n.get("completion", "").startswith(completion + " then osal_sig_sem")):
            raise ValueError(f"secondary status wait wrapper mismatch at {addr}")
        if addr != "0x7f2210" and n.get("callers") != list(callers):
            raise ValueError(f"secondary status wrapper caller mismatch at {addr}")
    other = by_addr["0x7eeec8"].get("checks")
    if other != [
        {"address": "0x7f29ec", "field": "+0x28", "role": "guard"},
        {"address": "0x7eaa14", "field": "+0xa4", "role": "ModelManager state nonzero"},
    ]:
        raise ValueError("queue guard and status-reader edge differs from saved report")
    setter = by_addr["0x7eb118"]
    if setter.get("field") != "+0xa4":
        raise ValueError("secondary setter object offset mismatch")
    transitions = report.get("exact_status_setter_callsites")
    if [(x.get("callsite"), x.get("new_state")) for x in transitions if isinstance(x, dict)] != list(EXPECTED_STATES):
        raise ValueError("five secondary status transition observations mismatch")
    if report.get("observed_gap_ms", {}).get("duration") != 11615:
        raise ValueError("secondary report has changed historical duration data")
    if report.get("conclusion") != "The wait mechanism is confirmed, but the producer responsible for the 11.615 s instance is not identified statically.":
        raise ValueError("secondary report must not assert a single cold-boot delay cause")


def audit_app_status_sync(
    fixture: Path, *, saved_disassembly: Path | None = None,
    saved_status_chain: Path | None = None,
) -> dict[str, Any]:
    obj = _read_json(Path(fixture), MAX_FIXTURE_BYTES)
    _verify_fixture(obj)
    source_checks = 0
    if saved_disassembly is not None:
        p = Path(saved_disassembly)
        if not p.is_file() or not 0 < p.stat().st_size <= MAX_ASM_BYTES:
            raise ValueError("saved app event instruction report missing or too large")
        text = p.read_text(encoding="utf-8")
        for (label, entry), sites in PRIMARY_SITES.items():
            rows = _function_region(text, label, entry)
            for vma, expected in sites:
                opcode = rows.get(int(vma, 16))
                if opcode is None or expected not in opcode:
                    raise ValueError(f"saved ARM status-gate opcode mismatch at {vma}")
                source_checks += 1
    secondary = False
    if saved_status_chain is not None:
        report = _read_json(Path(saved_status_chain), MAX_REPORT_BYTES)
        _check_saved_status_chain(report)
        secondary = True
    tier = ("BOTH_SAVED_SOURCES_MATCH_CONSUMER_UNVERIFIED"
            if source_checks and secondary else
            "SAVED_ARM_GATE_TEXT_MATCH_ONLY" if source_checks else
            "SAVED_SECONDARY_SYNC_REPORT_MATCH_ONLY" if secondary else
            "CANDIDATE_FIXTURE_ONLY")
    return {
        "status": tier,
        "firmware_sha256_reported": obj["elf_sha256"],
        "saved_instruction_sites_checked": source_checks,
        "secondary_status_report_consistent": secondary,
        "status_reader_vma": "0x7eaa14",
        "status_field_offset": "0xa4",
        "queue_gate_vma": "0x7eeec8",
        "guard_short_circuit_nonzero_returns_zero": True,
        "on_guard_pass_model_status_nonzero": {
            "model_status_plus_0xa4_zero": "queue_gate_result_1",
            "model_status_plus_0xa4_nonzero": "queue_gate_result_0",
        },
        "app_loop_zero_queue_result_branches_to": "0x7eeefa",
        "secondary_wait_wrappers": [
            {"vma": addr, "semaphore": "0x830451",
             "completion_helper": EXPECTED_WAIT[addr][0],
             "independent_opcode_proven": False}
            for addr in sorted(EXPECTED_WAIT)
        ],
        "reported_status_transition_callsites": len(EXPECTED_STATES),
        "event_0x11004003_consumer_verified": False,
        "event_7_8_payload_to_camera_verified": False,
        "event_dispatch_wait_original_elf_opcode_verified": False,
        "single_boot_delay_cause_proven": False,
        "camera_ready_state_proven": False,
        "abi_verified": False,
        "original_elf_bytes_analyzed_in_this_run": False,
    }
