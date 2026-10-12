"""Audit saved static requestModelExecute event-envelope disassembly (offline only).

The supported source is a previously saved ARM instruction report. It is
NOT an original ELF, executable API implementation, Ghidra session, or device
trace. Identity, symbolic PLT resolution and downstream delivery all require
separate evidence.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

SHA = re.compile(r"[a-f0-9]{64}\Z")
ENTRY = re.compile(r"^ENTRY\s+(0x[0-9a-fA-F]+)\s+(.*)$")
ASM = re.compile(r"^(0x[0-9a-fA-F]+):\s+(.+)$")
MAX_FIXTURE = 192 * 1024
MAX_SAVED_REPORT = 2 * 1024 * 1024

FRONT_SITES = (
    ("0x121076", "ldr.w    sb, [r0, #0x7c]"),
    ("0x12107a", "mov      r0, r1"),
    ("0x12107c", "mov      sl, r2"),
    ("0x12107e", "mov      r5, r1"),
    ("0x121080", "mov      r6, r3"),
    ("0x121082", "blx      #0xdffb8 ; _ZN11IdGenerator3GetEPKc"),
    ("0x121086", "mov      r1, sl"),
    ("0x121088", "mov      r8, r0"),
    ("0x12108a", "mov      r0, r5"),
    ("0x12108c", "bl       #0x12d780"),
    ("0x121090", "mov      r1, r8"),
    ("0x121092", "mov      r3, r6"),
    ("0x121094", "mov      r2, r0"),
    ("0x121096", "mov      r0, sb"),
    ("0x121098", "blx      #0xdfbdc ; _ZN22AbstractUtilityManager30createRequestModelExecuteEventEimP9ParamList"),
    ("0x1210a4", "b.w      #0xdb578 ; _ZN4View25requestApplicationExecuteEP5Event"),
)
ALT_FRONT_SITES = (
    ("0x1250c6", "mov      r4, r2"),
    ("0x1250ce", "mov      r5, r0"),
    ("0x1250d0", "mov      sb, r1"),
    ("0x1250d4", "ldr.w    r8, [r3]"),
    ("0x1250d8", "blx      #0xdffb8 ; _ZN11IdGenerator3GetEPKc"),
    ("0x1250dc", "mov      r1, sb"),
    ("0x1250de", "mov      r6, r0"),
    ("0x1250e0", "mov      r0, r5"),
    ("0x1250e2", "bl       #0x12d780"),
    ("0x1250e6", "mov      r1, r6"),
    ("0x1250e8", "mov      r3, r4"),
    ("0x1250ea", "mov      r2, r0"),
    ("0x1250ec", "mov      r0, r8"),
    ("0x1250ee", "blx      #0xdfbdc ; _ZN22AbstractUtilityManager30createRequestModelExecuteEventEimP9ParamList"),
    ("0x1250f6", "b.w      #0x125084"),
)

FACTORY_SITES = (
    ("0x7f0b14", "mov      r6, r1"),
    ("0x7f0b16", "mov      r8, r2"),
    ("0x7f0b18", "mov      r5, r3"),
    ("0x7f0b1e", "literal 0x11004003"),
    ("0x7f0b20", "movs     r2, #2"),
    ("0x7f0b22", "movs     r3, #0"),
    ("0x7f0b26", "blx      #0xdb66c ; _ZN5EventC1Emhh"),
    ("0x7f0b2a", "cbz      r5, #0x7f0b34"),
    ("0x7f0b2e", "mov      r1, r5"),
    ("0x7f0b30", "blx      #0xde3a4 ; _ZN5Event12setParamListEP9ParamList"),
    ("0x7f0b3a", "mov      r1, r6"),
    ("0x7f0b3e", "bl       #0xf0fb0"),
    ("0x7f0b42", "mov      r2, r5"),
    ("0x7f0b44", "movs     r1, #7"),
    ("0x7f0b48", "blx      #0xdd194 ; _ZN5Event12addParameterEmP9ParamBase"),
    ("0x7f0b52", "mov      r1, r8"),
    ("0x7f0b56", "bl       #0xf0fb0"),
    ("0x7f0b5c", "movs     r1, #8"),
    ("0x7f0b60", "blx      #0xdd194 ; _ZN5Event12addParameterEmP9ParamBase"),
)


def _num(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError("invalid static function VMA")
    try:
        n = int(str(value), 0)
    except ValueError as exc:
        raise ValueError("invalid static function VMA") from exc
    if n <= 0:
        raise ValueError("static function VMA must be positive")
    return n


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file() or not 0 < path.stat().st_size <= MAX_FIXTURE:
        raise ValueError("event envelope fixture missing or exceeds size limit")
    result = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(result, dict) or result.get("schema_version") != 1:
        raise ValueError("invalid event envelope fixture schema")
    return result


def _entry_instructions(text: str, vma: int, marker: str) -> dict[int, str]:
    """Reject duplicate/ambiguous entry labels and duplicate opcode VMAs."""
    chunks: list[list[str]] = []
    current: list[str] | None = None
    for line in text.splitlines():
        m = ENTRY.match(line)
        if m:
            if current is not None:
                chunks.append(current)
            current = [] if int(m.group(1), 16) == vma and marker in m.group(2) else None
            continue
        if current is not None:
            current.append(line)
    if current is not None:
        chunks.append(current)
    if len(chunks) != 1:
        raise ValueError("saved instruction report missing or ambiguous function entry")
    result: dict[int, str] = {}
    for line in chunks[0]:
        m = ASM.match(line)
        if not m:
            continue
        address = int(m.group(1), 16)
        if address in result or address < vma:
            raise ValueError("saved instruction report has duplicated or out-of-entry address")
        result[address] = m.group(2)
    if len(result) > 500:
        raise ValueError("saved instruction report function exceeds review instruction budget")
    return result


def _check_sites(instructions: dict[int, str], sites: tuple[tuple[str, str], ...]) -> None:
    for addr, expected in sites:
        actual = instructions.get(int(addr, 16))
        if actual is None or expected not in actual:
            raise ValueError(f"static opcode report mismatch at {addr}: expected {expected}")


def audit_model_execute_event(
    fixture_path: Path, *, saved_disassembly: Path | None = None,
) -> dict[str, Any]:
    """Validate structured event envelope claims with optional raw *text* report."""
    fixture = _read_json(Path(fixture_path))
    if fixture.get("type") != "model_execute_event_envelope_research" or fixture.get(
            "status") != "STATIC_ENVELOPE_SITES_REPORTED_CONSUMER_UNRESOLVED":
        raise ValueError("event envelope must be a report-only unresolved candidate")
    identity = fixture.get("binary")
    frontend, factory = fixture.get("request_frontend"), fixture.get("factory_implementation_lead")
    alternate = fixture.get("alternative_request_frontend")
    if not isinstance(alternate, dict) or (
        alternate.get("name") != "viewManagerIf::requestModelExecute"
        or alternate.get("entry_vma") != "0x1250c0"
        or alternate.get("this_pointer_or_original_r0_meaning") != "UNKNOWN"
        or alternate.get("same_local_direct_transform_helper_as_ViewBase") is not True
        or alternate.get("same_factory_import_stub_address_as_ViewBase") is not True
        or alternate.get("final_application_dispatch_verified") is not False
    ):
        raise ValueError("alternate frontend requires a source-scoped unknown ABI and no consumer claim")
    alt_expected = (
        ("0x1250d8", "0xdffb8"), ("0x1250e2", "0x12d780"),
        ("0x1250ee", "0xdfbdc"), ("0x1250f6", "0x125084"),
    )
    alt_items = alternate.get("observed_sites")
    if not isinstance(alt_items, list) or len(alt_items) != 4 or [
        (x.get("site"), x.get("target")) for x in alt_items if isinstance(x, dict)
    ] != list(alt_expected):
        raise ValueError("alternate frontend reported callsite targets are inconsistent")
    if not all(isinstance(x, dict) for x in (identity, frontend, factory)):
        raise ValueError("event envelope is missing identity/front-end/factory")
    if not SHA.fullmatch(str(identity.get("sha256") or "")) or identity.get("name") != "libObj.so":
        raise ValueError("event envelope ELF identity mismatch")
    if _num(frontend.get("entry_vma")) != 0x12106e or _num(factory.get("entry_vma")) != 0x7f0b0c:
        raise ValueError("event envelope unexpected function VMAs")
    if frontend.get("name") != "ViewBase::requestModelExecute":
        raise ValueError("invalid event request frontend")
    if factory.get("name") != "AbstractUtilityManager::createRequestModelExecuteEvent":
        raise ValueError("invalid event factory symbol")
    if factory.get("event_id") != "0x11004003":
        raise ValueError("event envelope ID not supported by preserved disassembly")
    if factory.get("dynamic_linked_to_frontend_plt_verified") is not False or frontend.get(
            "application_submit", {}).get("delivers_to_camera_dispatcher_verified") is not False:
        raise ValueError("event import resolution or Camera delivery not verified")
    if any(fixture.get(k) != 0 for k in ("complete_abi_count", "confirmed_runtime_camera_apis")):
        raise ValueError("event envelope cannot claim completed ABI or callable APIs")
    keys = factory.get("parameter_keys")
    if not isinstance(keys, list) or len(keys) != 2:
        raise ValueError("event envelope must have two observed parameter keys")
    if [(k.get("key"), k.get("origin"), k.get("insert_site")) for k in keys if isinstance(k, dict)] != [
            (7, "model_name_id_output", "0x7f0b48"),
            (8, "selector_transform_output", "0x7f0b60")]:
        raise ValueError("event parameter-key layout differs from reported instructions")
    if any(k.get("receiver_identity_verified") is not False for k in keys):
        raise ValueError("event parameter receiver is still unresolved")
    if factory.get("parameter_ownership_verified") is not False or factory.get(
            "return_convention_verified") is not False:
        raise ValueError("event envelope ParamList and return semantics not verified")
    sites = factory.get("sites")
    if not isinstance(sites, list) or len(sites) != 10:
        raise ValueError("event envelope factory observation list is incomplete")
    for row in sites:
        if not isinstance(row, dict) or (row.get("address"), row.get("instruction_contains")) not in FACTORY_SITES:
            raise ValueError("factory opcode observation inconsistent with saved research")
    site_addresses = [row["address"] for row in sites]
    if len(site_addresses) != len(set(site_addresses)):
        raise ValueError("duplicate factory instruction site")
    front_targets = (
        ("model_name_resolve", "0x121082", "0xdffb8"),
        ("selector_transform", "0x12108c", "0x12d780"),
        ("factory_call", "0x121098", "0xdfbdc"),
        ("application_submit", "0x1210a4", "0xdb578"),
    )
    for section, expected_site, expected_target in front_targets:
        obj = frontend.get(section)
        if not isinstance(obj, dict) or obj.get("site") != expected_site or obj.get(
                "reported_plt_target", obj.get("reported_direct_target")) != expected_target:
            raise ValueError(f"event envelope {section} unresolved site mismatch")
    gaps = fixture.get("unresolved_boundaries")
    if not isinstance(gaps, list) or len(gaps) < 4 or not all(isinstance(x, str) and x.strip() for x in gaps):
        raise ValueError("missing model request routing limitations")
    observed: dict[str, Any] = {
        "front_end_opcode_sites_checked": 0,
        "alternate_front_end_opcode_sites_checked": 0,
        "factory_opcode_sites_checked": 0,
        "report_text_verified": False, "original_elf_instruction_bytes_verified": False,
    }
    if saved_disassembly is not None:
        path = Path(saved_disassembly)
        if not path.is_file() or not 0 < path.stat().st_size <= MAX_SAVED_REPORT:
            raise ValueError("saved disassembly report missing or exceeds 2 MiB")
        source = path.read_text(encoding="utf-8")
        front = _entry_instructions(source, 0x12106e, "_ZN8ViewBase19requestModelExecute")
        alt = _entry_instructions(source, 0x1250c0, "_ZN13viewManagerIf19requestModelExecute")
        implementation = _entry_instructions(
            source, 0x7f0b0c, "_ZN22AbstractUtilityManager30createRequestModelExecuteEvent")
        _check_sites(front, FRONT_SITES)
        _check_sites(alt, ALT_FRONT_SITES)
        _check_sites(implementation, FACTORY_SITES)
        observed = {
            "front_end_opcode_sites_checked": len(FRONT_SITES),
            "alternate_front_end_opcode_sites_checked": len(ALT_FRONT_SITES),
            "factory_opcode_sites_checked": len(FACTORY_SITES),
            "report_text_verified": True,
            "original_elf_instruction_bytes_verified": False,
        }
    return {
        "status": "SAVED_STATIC_EVENT_ENVELOPE_TEXT_MATCH" if observed["report_text_verified"]
                  else "EVENT_ENVELOPE_CANDIDATE_ONLY",
        "elf_sha256_reported": identity["sha256"],
        "request_frontend_vma": frontend["entry_vma"],
        "alternative_request_frontend_vma": alternate["entry_vma"],
        "same_reported_helper_and_factory_stub_targets": True,
        "factory_implementation_lead_vma": factory["entry_vma"],
        "event_id": factory["event_id"],
        "event_parameter_keys": [7, 8],
        "optional_paramlist": True,
        "audit": observed,
        "factory_import_dynamic_target_resolved": False,
        "application_event_consumer_resolved": False,
        "modelcamera_dispatch_link_verified": False,
        "selector_transform_semantics_verified": False,
        "ABI_and_runtime_callability_verified": False,
        "remaining_unknowns": gaps,
    }
