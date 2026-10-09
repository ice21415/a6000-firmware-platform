"""Review the 0x13200a action-payload type *constraints*, not a fabricated ABI.

The preserved Sony 3.21 instruction report contains multiple consumers
of the same opaque action-payload getter. We can prove that the returned
r0 passes into a common wrapper and is subsequently used with ParamList-
related key/error paths. Without the wrapper/getter implementations, the
C++ return type is not yet proven, and this module refuses such claims.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .event_envelope import _entry_instructions

MAX_FIXTURE = 128 * 1024
MAX_TEXT = 2 * 1024 * 1024
ELF_SHA = "8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a"

# Curated *instruction text* fingerprints within distinct previously saved
# full-ish bounded entry reports, not an analysis of the original ELF bytes.
CASES: dict[tuple[str, str], tuple[tuple[str, str], ...]] = {
    ("0x4aea00", "ActionExeTest"): (
        ("0x4aea1c", "mov      r0, r4"),
        ("0x4aea1e", "bl       #0x13200a"),
        ("0x4aea22", "mov      r1, r0"),
        ("0x4aea24", "add.w    r0, r7, #0x10"),
        ("0x4aea28", "bl       #0x42abcc"),
        ("0x4aea34", "_ZN9ParamListC1Ev"),
    ),
    ("0x4bac78", "ActionExeAfRangeLimitDrive"): (
        ("0x4bac92", "mov      r0, r4"),
        ("0x4bac94", "bl       #0x13200a"),
        ("0x4bac98", "mov      r1, r0"),
        ("0x4bac9a", "add.w    r0, r7, #0x20"),
        ("0x4bac9e", "bl       #0x42abcc"),
        ("0x4baca6", "movw     r1, #0x3fe"),
        ("0x4bacb4", "bl       #0x42ac00"),
        ("0x4bacb8", "cbz      r0, #0x4bacc4"),
        ("0x4bacc0", "'Invalid ParamList'"),
        ("0x4bacc8", "movw     r1, #0x3ff"),
        ("0x4bacd2", "bl       #0x42ac00"),
        ("0x4bacde", "'Invalid ParamList'"),
    ),
    ("0x4afc9c", "ActionObjectFocusPosDisplayEvent"): (
        ("0x4afcba", "mov      r0, r4"),
        ("0x4afcbc", "bl       #0x13200a"),
        ("0x4afcc0", "mov      r1, r0"),
        ("0x4afcc2", "mov      r0, r7"),
        ("0x4afcc4", "bl       #0x42abcc"),
        ("0x4afcd8", "bl       #0x42ac00"),
    ),
    ("0x4ae930", "ActionObjectNotifyMfDistance"): (
        ("0x4ae94a", "mov      r0, r4"),
        ("0x4ae94c", "bl       #0x13200a"),
        ("0x4ae950", "mov      r1, r0"),
        ("0x4ae952", "mov.w    r2, #0x3100"),
        ("0x4ae958", "movw     r3, #0x8517"),
        ("0x4ae95c", "bl       #0x44a284"),
    ),
    ("0x4cf7a8", "ModelCamera_pvt_ActionSetInit"): (
        ("0x4cf7ac", "mov      sl, r1"),
        ("0x4cf7ea", "add.w    r0, r7, #0x6a0"),
        ("0x4cf7ee", "mov      r1, sl"),
        ("0x4cf7f0", "bl       #0x42abcc"),
        ("0x4cf814", "bl       #0x4b1a20"),
        ("0x4cf81a", "bl       #0x4b096c"),
    ),
}

ALLOWED_INFERENCES = {
    "0x4aea00": "PAYLOAD_WRAPPED_FOR_PARSING",
    "0x4bac78": "WRAPPED_PAYLOAD_KEY_LOOKUP_WITH_PARAMLIST_ERROR",
    "0x4afc9c": "WRAPPED_PAYLOAD_KEY_LOOKUP",
    "0x4ae930": "PAYLOAD_FORWARDED_TO_MESSAGE_CONSTRUCTOR",
    "0x4cf7a8": "CALLER_SUPPLIED_PAYLOAD_TO_SHARED_WRAPPER",
}
OPAQUE_TYPE = "OPAQUE_ACTION_PAYLOAD_CONSUMED_BY_PARAMLIST_LIKE_WRAPPER"
CANDIDATE_STATUS = "EVENT_PAYLOAD_PARAMLIST_COMPATIBLE_USE_OBSERVED_CXX_TYPE_UNVERIFIED"


def _load(path: Path) -> dict[str, Any]:
    if not path.is_file() or not 0 < path.stat().st_size <= MAX_FIXTURE:
        raise ValueError("action payload ABI fixture missing or exceeds size limit")
    result = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(result, dict):
        raise ValueError("action payload ABI fixture must be an object")
    return result


def _validate_fixture(obj: dict[str, Any]) -> None:
    if obj.get("schema_version") != 1 or obj.get("firmware") != "3.21" or obj.get("status") != CANDIDATE_STATUS:
        raise ValueError("action payload candidate must remain source-scoped")
    identity = obj.get("elf")
    if not isinstance(identity, dict) or (
        identity.get("name") != "libObj.so" or identity.get("sha256") != ELF_SHA
        or identity.get("source") != "previous private offline model-camera-methods.txt"
        or identity.get("redecoded_this_session") is not False
    ):
        raise ValueError("action payload firmware/source identity not supported")
    getter = obj.get("opaque_getter")
    if not isinstance(getter, dict) or (
        getter.get("target_vma") != "0x13200a"
        or getter.get("cpp_return_type") != "UNKNOWN"
        or getter.get("paramlist_pointer_cpp_type_verified") is not False
    ):
        raise ValueError("action-payload getter is not proven to return ParamList*")
    items = obj.get("observations")
    if not isinstance(items, list) or len(items) != len(CASES):
        raise ValueError("action payload case set incomplete")
    seen: set[tuple[str, str]] = set()
    for row in items:
        if not isinstance(row, dict):
            raise ValueError("invalid action payload observation")
        key = row.get("entry"), row.get("context")
        if key in seen or key not in CASES:
            raise ValueError("duplicate or unsupported payload action case")
        seen.add(key)
        if row.get("kind") != ALLOWED_INFERENCES[key[0]]:
            raise ValueError("action payload case inference exceeds available evidence")
        sites = row.get("sites")
        if not isinstance(sites, list) or len(sites) != len(CASES[key]):
            raise ValueError("action payload fingerprint site count incorrect")
        reported = [(site.get("vma"), site.get("snippet"))
                    for site in sites if isinstance(site, dict)]
        if reported != list(CASES[key]):
            raise ValueError(f"action payload annotated addresses differ at {key[0]}")
    if seen != set(CASES):
        raise ValueError("action payload case set not exhaustive")
    if next(row for row in items if row["entry"] == "0x4bac78").get("observed_keys") != [
        "0x3fe", "0x3ff"
    ]:
        raise ValueError("parameter lookup IDs not consistent with source")
    dispatch = obj.get("action_selector_provenance")
    if not isinstance(dispatch, dict) or (
        dispatch.get("dispatcher") != "0x4cfb9c"
        or dispatch.get("selector_value") != "0x0f01"
        or dispatch.get("selected_callsite") != "0x4cfe98"
        or dispatch.get("callee") != "0x4cf7a8"
        or dispatch.get("getter") != "0x13200a"
        or dispatch.get("argument_register_at_callee") != "r1"
        or dispatch.get("event_0x11004003_direct_mapping_verified") is not False
    ):
        raise ValueError("ActionGpSetSetting-to-SetInit event path still unresolved")
    candidate = obj.get("candidate_contract")
    if not isinstance(candidate, dict) or (
        candidate.get("getter_return_category") != OPAQUE_TYPE
        or candidate.get("getter_return_cpp_type") != "UNKNOWN"
        or candidate.get("wrapper_0x42abcc_signature") != "UNKNOWN"
        or candidate.get("lookup_0x42ac00_signature") != "UNKNOWN"
        or candidate.get("callable_sony_camera_api") is not False
    ):
        raise ValueError("action payload may not claim ABI, wrapper signature or callable API")
    if not isinstance(obj.get("missing_evidence"), list) or len(obj["missing_evidence"]) < 4:
        raise ValueError("missing essential ABI validation blockers")


def audit_action_payload_abi(
    fixture: Path, *, saved_libobj: Path | None = None,
) -> dict[str, Any]:
    obj = _load(Path(fixture))
    _validate_fixture(obj)
    results = []
    if saved_libobj is not None:
        path = Path(saved_libobj)
        if not path.is_file() or not 0 < path.stat().st_size <= MAX_TEXT:
            raise ValueError("saved Camera instruction source missing or too large")
        source = path.read_text(encoding="utf-8")
        for (entry, context), sites in CASES.items():
            # All research entries in this report are anonymous C++ local
            # function addresses (ENTRY line), with a display label elsewhere.
            instructions = _entry_instructions(source, int(entry, 16), "")
            for address, snippet in sites:
                opcode = instructions.get(int(address, 16))
                if opcode is None or snippet not in opcode:
                    raise ValueError(f"{context} saved Thumb text mismatch at {address}")
            results.append({
                "entry_vma": entry, "context": context,
                "saved_opcode_text_sites_checked": len(sites),
                "inference": ALLOWED_INFERENCES[entry],
            })
    return {
        "status": ("SAVED_OPAQUE_ACTION_PAYLOAD_REGISTER_USES_MATCHED" if results
                   else "OPAQUE_ACTION_PAYLOAD_CONTRACT_CANDIDATE_ONLY"),
        "elf_sha256_reported": obj["elf"]["sha256"],
        "getter_vma": "0x13200a",
        "getter_return_category": OPAQUE_TYPE,
        "getter_cpp_return_type_verified": False,
        "action_wrapper_vma": "0x42abcc",
        "action_wrapper_cpp_signature_verified": False,
        "key_lookup_helper_vma": "0x42ac00",
        "observed_key_literals": ["0x3fe", "0x3ff"],
        "actionsetinit_param1_received_from_this_getter": True,
        "actionsetinit_param1_type_verified": False,
        "event_0x11004003_consumer_to_camera_proven": False,
        "actions_with_saved_text_checked": len(results),
        "saved_instruction_text_sites_checked": sum(x["saved_opcode_text_sites_checked"] for x in results),
        "per_action": results,
        "original_sony_elf_machine_bytes_revalidated": False,
        "callable_core_camera_apis": 0,
        "remaining_proofs": obj["missing_evidence"],
    }
