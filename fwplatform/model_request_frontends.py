"""Cross-check two reported libObj.so model-request frontends (offline static only).

The saved report shows matching selector transformation and event factory
call roles from two different entrypoints, but NOT the body of 0x12d780,
correct dynamic relocation, event queue consumer or executable SDK ABI.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any
import json
import re

from .event_envelope import _entry_instructions, _check_sites, MAX_SAVED_REPORT

EXPECTED: dict[str, dict[str, Any]] = {
    "VIEWBASE": {
        "symbol": "_ZN8ViewBase19requestModelExecuteEPKcmP9ParamList",
        "entry_vma": "0x12106e",
        "name_site": "0x121082", "helper_site": "0x12108c",
        "factory_site": "0x121098", "submit_site": "0x1210a4",
        "submit_target": "0xdb578",
        "submit_symbol": "_ZN4View25requestApplicationExecuteEP5Event",
        "pointer_origin": "this_plus_0x7c",
        "instructions": (
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
        ),
    },
    "VIEW_MANAGER_INTERFACE": {
        "symbol": "_ZN13viewManagerIf19requestModelExecuteEPKcmP9ParamList",
        "entry_vma": "0x1250c0",
        "name_site": "0x1250d8", "helper_site": "0x1250e2",
        "factory_site": "0x1250ee", "submit_site": "0x1250f6",
        "submit_target": "0x125084", "submit_symbol": None,
        "pointer_origin": "indirection_via_global_at_0x102cbd0",
        "instructions": (
            ("0x1250c0", "literal 0xf07b02"),
            ("0x1250c6", "mov      r4, r2"),
            ("0x1250ce", "mov      r5, r0"),
            ("0x1250d0", "mov      sb, r1"),
            ("0x1250d2", "ldr      r3, [r3, r2]"),
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
        ),
    },
}
ALLOWED_SHA = re.compile(r"[a-f0-9]{64}\Z")
MAX_FIXTURE_BYTES = 200_000
MODEL_ID_SYMBOL = "_ZN11IdGenerator3GetEPKc"
FACTORY_SYMBOL = "_ZN22AbstractUtilityManager30createRequestModelExecuteEventEimP9ParamList"


def _int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"{label}: invalid integer")
    try:
        v = int(str(value), 0)
    except ValueError as exc:
        raise ValueError(f"{label}: invalid integer") from exc
    if v <= 0:
        raise ValueError(f"{label}: expected positive address")
    return v


def _read_fixture(path: Path) -> dict[str, Any]:
    if not path.is_file() or not 0 < path.stat().st_size <= MAX_FIXTURE_BYTES:
        raise ValueError("request frontend fixture missing or too large")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("request frontend fixture has invalid schema")
    return data


def audit_model_request_frontends(
    fixture: Path, *, saved_disassembly: Path | None = None,
    event_envelope: Path | None = None,
) -> dict[str, Any]:
    """Check saved bounded instructions without touching ELF, DB or hardware."""
    data = _read_fixture(Path(fixture))
    if data.get("scope") != "TWO_REQUEST_FRONTENDS_SHARED_SELECTOR_HELPER_AND_FACTORY" or data.get("saved_report_only") is not True:
        raise ValueError("two-frontend static report status is required")
    if data.get("binary_name") != "libObj.so" or not ALLOWED_SHA.fullmatch(str(data.get("binary_sha256") or "")):
        raise ValueError("two-frontend ELF SHA identity is missing")
    if data.get("independent_raw_elf_bytes_checked") is not False:
        raise ValueError("this saved report cannot claim newly checked ELF bytes")
    if data.get("verified_complete_api_contracts") != 0 or data.get("sdk_callable_api_count") != 0:
        raise ValueError("unresolved frontends cannot claim complete ABI or callable API")
    shared = data.get("shared_observation")
    if not isinstance(shared, dict):
        raise ValueError("shared model-event observation is missing")
    if any(shared.get(k) is not False for k in (
        "function_signature_verified", "selector_transform_semantics_verified",
        "factory_plt_to_impl_relocation_verified", "consumer_verified"
    )):
        raise ValueError("unresolved ABI, selector, relocation or event consumer cannot be promoted")
    for k, expected in (("selector_transform_entry_candidate", 0x12D780),
                        ("named_factory_import_target", 0xDFBDC),
                        ("model_identifier_import_target", 0xDFFB8)):
        if _int(shared.get(k), k) != expected:
            raise ValueError(f"{k}: common helper or import call target differs")
    gaps = data.get("blockers")
    if not isinstance(gaps, list) or len(gaps) < 4 or not all(isinstance(x, str) and x for x in gaps):
        raise ValueError("unresolved boundaries missing")
    frontends = data.get("recorded_frontends")
    if not isinstance(frontends, list) or len(frontends) != 2:
        raise ValueError("expected two distinct static frontend candidates")
    observed = set()
    front_report: list[dict[str, Any]] = []
    for entry in frontends:
        if not isinstance(entry, dict) or entry.get("caller_kind") not in EXPECTED:
            raise ValueError("unknown or invalid static frontend candidate")
        kind = entry["caller_kind"]
        if kind in observed:
            raise ValueError("duplicated frontend candidate")
        observed.add(kind)
        expected = EXPECTED[kind]
        if entry.get("symbol") != expected["symbol"] or _int(entry.get("entry_vma"), "frontend.entry_vma") != _int(expected["entry_vma"], "expected entry"):
            raise ValueError(f"{kind}: function symbol / ELF VMA differs")
        for section, site_key, target_key, expected_site, expected_target, name in (
            ("name_identifier_import", "site", "target", expected["name_site"], "0xdffb8", MODEL_ID_SYMBOL),
            ("selector_transform", "site", "target", expected["helper_site"], "0x12d780", None),
            ("envelope_import", "site", "target", expected["factory_site"], "0xdfbdc", FACTORY_SYMBOL),
        ):
            obj = entry.get(section)
            if not isinstance(obj, dict) or _int(obj.get(site_key), f"{section}.site") != _int(expected_site, f"{section}.site") or _int(obj.get(target_key), f"{section}.target") != _int(expected_target, "target"):
                raise ValueError(f"{kind}: mismatched {section} callsite / target")
            if name is not None and obj.get("name") != name:
                raise ValueError(f"{kind}: mismatched {section} symbol")
        helper, event = entry["selector_transform"], entry["envelope_import"]
        if helper.get("semantics") != "UNKNOWN" or helper.get("arguments_observed") != {
            "r0": "name_arg", "r1": "selector_arg"
        } or helper.get("output_register") != "r0":
            raise ValueError(f"{kind}: unknown selector transform input roles not preserved")
        if any(event.get(k) != v for k,v in {
            "r1_origin": "name_identifier_result",
            "r2_origin": "selector_transform_result",
            "r3_origin": "paramlist_arg",
            "receiver_binding": "UNVERIFIED_DYNAMIC_LINK",
        }.items()):
            raise ValueError(f"{kind}: argument register provenance or dynamic binding not supported")
        submit = entry.get("submit")
        if not isinstance(submit, dict) or _int(submit.get("site"), "submit.site") != _int(expected["submit_site"], "submit.site") or _int(submit.get("target"), "submit.target") != _int(expected["submit_target"], "submit.target") or submit.get("form") != "TAIL_BRANCH" or submit.get("symbol") != expected["submit_symbol"]:
            raise ValueError(f"{kind}: submit tail branch differs")
        if not str(submit.get("actual_target_and_delivery", "")).startswith("UNVERIFIED"):
            raise ValueError(f"{kind}: unproven event consumer cannot be promoted")
        if entry.get("target_pointer_origin") != expected["pointer_origin"]:
            raise ValueError(f"{kind}: message manager pointer provenance differs")
        front_report.append({
            "kind": kind,
            "entry_vma": expected["entry_vma"],
            "model_identifier_import_site": expected["name_site"],
            "selector_helper_site": expected["helper_site"],
            "event_factory_import_site": expected["factory_site"],
            "submit_site": expected["submit_site"],
            "submit_target": expected["submit_target"],
            "submit_path_is_resolved": False,
            "saved_text_opcode_sites_checked": 0,
        })
    if observed != set(EXPECTED):
        raise ValueError("two frontend candidates incomplete")
    cross_envelope = "NOT_PROVIDED"
    if event_envelope is not None:
        from .event_envelope import audit_model_execute_event
        envelope = audit_model_execute_event(event_envelope)
        if envelope["elf_sha256_reported"] != data["binary_sha256"] or envelope["request_frontend_vma"] != EXPECTED["VIEWBASE"]["entry_vma"]:
            raise ValueError("frontend report and event envelope have mismatched ELF/function identity")
        if envelope["factory_import_dynamic_target_resolved"] or envelope["application_event_consumer_resolved"]:
            raise ValueError("import/event binding not independently established")
        cross_envelope = "EXACT_ELF_IDENTITY_AND_VIEWBASE_FUNCTION_MATCH"
    if saved_disassembly is not None:
        path = Path(saved_disassembly)
        if not path.is_file() or not 0 < path.stat().st_size <= MAX_SAVED_REPORT:
            raise ValueError("saved disassembly missing or exceeds text report budget")
        text = path.read_text(encoding="utf-8")
        for row in front_report:
            expected = EXPECTED[row["kind"]]
            instructions = _entry_instructions(
                text, _int(expected["entry_vma"], "frontend.entry_vma"), expected["symbol"]
            )
            _check_sites(instructions, expected["instructions"])
            row["saved_text_opcode_sites_checked"] = len(expected["instructions"])
    return {
        "status": ("BOTH_SAVED_FRONTEND_PATHS_RECHECKED"
                   if saved_disassembly is not None else "TWO_FRONTEND_RESEARCH_LEADS_ONLY"),
        "binary_sha256": data["binary_sha256"],
        "shared_selector_transform_entry": "0x12d780",
        "shared_model_identifier_import": "0xdffb8",
        "shared_named_event_factory_import": "0xdfbdc",
        "frontend_count": 2,
        "frontends": front_report,
        "total_saved_text_opcode_sites_checked": sum(x["saved_text_opcode_sites_checked"] for x in front_report),
        "event_envelope_crosscheck": cross_envelope,
        "independent_raw_elf_bytes_checked_now": False,
        "selector_transform_body_recovered": False,
        "event_consumer_resolved": False,
        "runtime_callable": False,
        "verified_complete_abi_contracts": 0,
        "next_evidence": gaps,
    }
