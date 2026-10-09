"""Conservative ARM AAPCS32 register contract for Camera parameter lookups.

Evidence is limited to saved instruction *callers*, not the original Sony
ELF function bodies. r0/r1/r2 roles are visible at callsites. r3, C++
type declarations, lifetime, and the full return contract remain unknown.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .event_envelope import _entry_instructions

MAX_FIXTURE_BYTES = 160 * 1024
MAX_REPORT_BYTES = 2 * 1024 * 1024
ELF_SHA = "8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a"
STATUS = "REGISTER_INPUT_OUTPUT_AND_BRANCH_SEMANTICS_INFERRED_CXX_ABI_UNVERIFIED"

# Observed call-site flow: r0 = local wrapper, r1 = numeric lookup
# ID, r2 = caller-provided output pointer. Treat r3 as UNKNOWN even
# when sampled callers manipulate it before the call.
LOOKUP_CASES = {
    "0x4bac78": {
        "label": "ActionExeAfRangeLimitDrive",
        "ids": ["0x3fe", "0x3ff"],
        "zero": "SKIP_INVALID_PARAMLIST_BRANCH",
        "sites": (
            ("0x4bac9e", "bl       #0x42abcc"),
            ("0x4baca2", "add.w    r0, r7, #0x20"),
            ("0x4baca6", "movw     r1, #0x3fe"),
            ("0x4bacaa", "add.w    r2, r7, #0x34"),
            ("0x4bacb4", "bl       #0x42ac00"),
            ("0x4bacb8", "cbz      r0, #0x4bacc4"),
            ("0x4bacc0", "'Invalid ParamList'"),
            ("0x4bacc4", "add.w    r0, r7, #0x20"),
            ("0x4bacc8", "movw     r1, #0x3ff"),
            ("0x4baccc", "add.w    r2, r7, #0x30"),
            ("0x4bacd0", "ldr      r5, [r7, #0x34]"),
            ("0x4bacd2", "bl       #0x42ac00"),
            ("0x4bacd6", "cbz      r0, #0x4bace6"),
            ("0x4bacde", "'Invalid ParamList'"),
            ("0x4bacf2", "ldr      r6, [r7, #0x30]"),
        ),
    },
    "0x4afc9c": {
        "label": "ActionObjectFocusPosDisplayEvent",
        "ids": ["0x1b8", "0x1b9"],
        "zero": "READ_AND_STORE_OUT_SLOT",
        "sites": (
            ("0x4afcc4", "bl       #0x42abcc"),
            ("0x4aff4a", "mov      r0, r7"),
            ("0x4aff4c", "mov.w    r1, #0x1b8"),
            ("0x4aff50", "add.w    r2, r7, #0x14"),
            ("0x4aff54", "bl       #0x42ac00"),
            ("0x4aff58", "cbnz     r0, #0x4aff6a"),
            ("0x4aff5a", "ldr      r3, [r7, #0x14]"),
            ("0x4aff64", "str.w    r3, [r4, #0x200]"),
            ("0x4aff6e", "movw     r1, #0x1b9"),
            ("0x4aff72", "add.w    r2, r7, #0x14"),
            ("0x4aff76", "bl       #0x42ac00"),
            ("0x4aff7a", "cbnz     r0, #0x4aff8a"),
            ("0x4aff7c", "ldr      r3, [r7, #0x14]"),
            ("0x4aff86", "str.w    r3, [r4, #0x204]"),
        ),
    },
}
ALT_SITES = (
    ("0x4cf850", "add.w    r0, r7, #0x6a0"),
    ("0x4cf854", "literal 0x12000005"),
    ("0x4cf856", "add.w    r2, r7, #0x6c8"),
    ("0x4cf85e", "bl       #0x42abdc"),
    ("0x4cf862", "cmp      r0, #0"),
    ("0x4cf864", "bne      #0x4cf8dc"),
    ("0x4cf866", "ldr.w    r3, [r7, #0x6c8]"),
    ("0x4cf86a", "cmp      r3, #1"),
    ("0x4cf86c", "bne      #0x4cf8dc"),
    ("0x4cf874", "'EasyMode ON'"),
)

INPUT_ROLES = {
    "r0": "stack-local payload view/context address",
    "r1": "numeric parameter ID",
    "r2": "address of caller-provided output slot",
    "r3": "UNKNOWN; no stable cross-caller role established",
}
ALT_INPUT_ROLES = {
    "r0": "stack-local payload view pointer",
    "r1": "literal key/value 0x12000005",
    "r2": "output address",
    "r3": "UNKNOWN",
}


def _load(path: Path) -> dict[str, Any]:
    if not path.is_file() or not 0 < path.stat().st_size <= MAX_FIXTURE_BYTES:
        raise ValueError("parameter query research fixture unavailable or too large")
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("parameter query fixture must be a JSON object")
    return obj


def _sites(actual: Any, expected: tuple[tuple[str, str], ...], role: str) -> None:
    if not isinstance(actual, list) or len(actual) != len(expected):
        raise ValueError(f"{role}: missing or excessive annotated instruction sites")
    values = [(row.get("vma"), row.get("snippet")) for row in actual if isinstance(row, dict)]
    if values != list(expected):
        raise ValueError(f"{role}: evidence addresses or instructions differ from inspected source")


def _validate_fixture(obj: dict[str, Any]) -> None:
    if (obj.get("schema_version") != 1
        or obj.get("firmware_version") != "3.21"
        or obj.get("status") != STATUS
        or obj.get("kind") != "action_parameter_lookup_register_convention_research"
        or obj.get("abi_verified") is not False
        or obj.get("device_callability_verified") is not False
        or obj.get("complete_core_camera_apis") != 0):
        raise ValueError("parameter lookup ABI remains only a local register contract")
    elf = obj.get("elf")
    if (not isinstance(elf, dict)
        or elf.get("name") != "libObj.so" or elf.get("sha256") != ELF_SHA
        or elf.get("primary_elf_opcode_redecoded_now") is not False):
        raise ValueError("private Sony ELF source not verified during this session")
    data = obj.get("helper_0x42ac00")
    if not isinstance(data, dict) or (
        data.get("target_vma") != "0x42ac00"
        or data.get("register_roles") != INPUT_ROLES
        or data.get("return_value_observed") != (
            "r0 checked immediately: zero branch skips Invalid ParamList or reads output slot; "
            "other branch treated as error in sampled code")
        or data.get("return_abi_type_verified") is not False
        or data.get("output_slot_cpp_type_verified") is not False
        or data.get("source_cpp_type_verified") is not False
    ):
        raise ValueError("lookup helper prototype exceeds AAPCS32 caller evidence")
    cases = data.get("cases")
    if not isinstance(cases, list) or len(cases) != len(LOOKUP_CASES):
        raise ValueError("lookup helper case list incomplete")
    seen: set[str] = set()
    for case in cases:
        if not isinstance(case, dict) or case.get("entry") not in LOOKUP_CASES:
            raise ValueError("invalid parameter query case")
        key = case["entry"]
        if key in seen:
            raise ValueError("duplicate parameter query case entry")
        seen.add(key)
        expected = LOOKUP_CASES[key]
        if (case.get("label") != expected["label"]
            or case.get("observed_parameter_ids") != expected["ids"]
            or case.get("zero_branch_semantics") != expected["zero"]):
            raise ValueError("parameter lookup case IDs or zero branch mismatch")
        _sites(case.get("observations"), expected["sites"], key)
    other = obj.get("helper_0x42abdc")
    if not isinstance(other, dict) or (
        other.get("target_vma") != "0x42abdc"
        or other.get("caller") != "0x4cf7a8"
        or other.get("comparison_relation_to_0x42ac00") != "UNKNOWN_SEPARATE_NEARBY_HELPER"
        or other.get("register_roles") != ALT_INPUT_ROLES
        or other.get("return_cpp_type_verified") is not False):
        raise ValueError("alternate EasyMode lookup has separate unknown semantics")
    _sites(other.get("observations"), ALT_SITES, "EasyMode alternate helper")
    issues = obj.get("critical_limitations")
    if not isinstance(issues, list) or len(issues) < 5:
        raise ValueError("parameter query still lacks primary function and ABI evidence")


def audit_parameter_lookup_abi(
    fixture: Path, *, saved_libobj: Path | None = None,
) -> dict[str, Any]:
    obj = _load(Path(fixture))
    _validate_fixture(obj)
    verified: list[dict[str, Any]] = []
    alt_checked = 0
    if saved_libobj is not None:
        p = Path(saved_libobj)
        if not p.is_file() or not 0 < p.stat().st_size <= MAX_REPORT_BYTES:
            raise ValueError("saved Camera instruction text missing or exceeds limit")
        src = p.read_text(encoding="utf-8")
        for entry, details in LOOKUP_CASES.items():
            region = _entry_instructions(src, int(entry, 16), "")
            for site, opcode in details["sites"]:
                if opcode not in region.get(int(site, 16), ""):
                    raise ValueError(f"parameter lookup source text mismatch at {site}")
            verified.append({"entry": entry, "case": details["label"],
                             "observed_keys": details["ids"],
                             "saved_opcode_sites_checked": len(details["sites"])})
        region = _entry_instructions(src, 0x4cf7a8, "")
        for site, opcode in ALT_SITES:
            if opcode not in region.get(int(site, 16), ""):
                raise ValueError(f"alternate EasyMode parameter lookup source mismatch at {site}")
            alt_checked += 1
    return {
        "status": ("SAVED_CALLER_OUTPUT_PARAMETER_ABI_TEXT_MATCH" if verified
                   else "PARAMETER_LOOKUP_ABI_CANDIDATE_ONLY"),
        "helper": "0x42ac00",
        "input_register_roles": INPUT_ROLES,
        "sampled_zero_return_behavior": "branch permits reading output/avoids invalid-ParamList error",
        "sampled_output_slot_width_bytes": 4,
        "output_slot_cpp_type_verified": False,
        "fourth_register_parameter_verified": False,
        "helper_0x42abdc_distinct_implementation_proven": False,
        "helper_0x42abdc_cpp_abi_verified": False,
        "primary_elf_bytes_decoded_now": False,
        "action_case_count_checked": len(verified),
        "case_sites_checked": sum(v["saved_opcode_sites_checked"] for v in verified),
        "alternate_easy_mode_sites_checked": alt_checked,
        "verified_callable_camera_core_apis": 0,
        "case_details": verified,
        "next_work": obj["critical_limitations"],
    }
