"""Offline camera reverse-engineering research graph validator.

Only checks internal consistency of previously transcribed static research.
Neither JSON bundle is primary instruction evidence, and a valid audit
NEVER establishes a verified ABI, safe device invocation or Sony SDK API.
"""
from __future__ import annotations

import json
import re
from collections import deque
from pathlib import Path
from typing import Any

HEX_SHA = re.compile(r"[0-9a-fA-F]{64}\Z")
DIRECT_BRANCH = re.compile(r"(blx|bl|b(?:\.w)?)\s+#?(0x[0-9a-fA-F]+)\Z", re.I)
ARTIFACT = re.compile(r"[A-Za-z0-9_.-]+\Z")
FIELD_KINDS = {"FIELD_READ", "FIELD_WRITE", "FIELD_WRITE_CONDITIONAL", "FIELD_WRITE_DEFERRED"}
LIMITS = {"interfaces": 2000, "static_calls": 4000, "field_observations": 4000,
          "normalized_selector_routes": 4000, "unresolved_external": 1000}


def _load(path: Path) -> dict[str, Any]:
    if path.stat().st_size > 8_000_000:
        raise ValueError("research JSON exceeds the 8 MB limit")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ValueError("research JSON requires an object with schema_version=1")
    return payload


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label}: expected non-empty string")
    return value.strip()


def _address(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError(f"{label}: invalid ELF VMA")
    try:
        n = int(str(value).strip(), 0)
    except ValueError as exc:
        raise ValueError(f"{label}: invalid ELF VMA") from exc
    if n <= 0:
        raise ValueError(f"{label}: ELF VMA must be positive")
    return n


def _artifact(value: Any) -> str:
    text = _text(value, "source_artifact")
    if not ARTIFACT.fullmatch(text) or text in {".", ".."}:
        raise ValueError("source_artifact must be a basename, not a private path")
    return text


def _array(data: dict[str, Any], name: str) -> list[Any]:
    items = data.get(name)
    if not isinstance(items, list) or len(items) > LIMITS[name]:
        raise ValueError(f"{name} must be an array of at most {LIMITS[name]} entries")
    return items


def inspect_camera_research(
    catalog: Path, graph: Path, *, focus: str = "",
) -> dict[str, Any]:
    """Check normalized addresses/branches and show a static review subgraph.

    This command is completely pure: it never opens SQLite, ELF, a Ghidra
    session or a device. Provenance names identify private research artifacts,
    not independent evidence bundled in this repository.
    """
    inventory, evidence = _load(catalog), _load(graph)
    if inventory.get("firmware_version") != evidence.get("firmware_version"):
        raise ValueError("catalog and graph firmware versions do not match")
    if inventory.get("verified_static_contract_count") != 0 or inventory.get("verified_runtime_count") != 0:
        raise ValueError("candidate catalog cannot claim completed or runtime SDK contracts")
    if evidence.get("proof_policy") != "RESEARCH_REPORT_ONLY":
        raise ValueError("research graph must declare report-only evidence policy")
    if evidence.get("verified_static_api_count") != 0 or evidence.get("camera_sdk_callable_count") is not None:
        raise ValueError("static research graph cannot assert callable camera APIs")
    sha = _text(evidence.get("binary_sha256"), "graph binary_sha256").lower()
    if not HEX_SHA.fullmatch(sha):
        raise ValueError("invalid graph ELF digest")
    functions: dict[str, dict[str, Any]] = {}
    located: set[tuple[str, int]] = set()
    for entry in _array(inventory, "interfaces"):
        if not isinstance(entry, dict):
            raise ValueError("catalog interfaces must contain objects")
        name = _text(entry.get("name"), "interface.name")
        item_sha = _text(entry.get("binary_sha256"), "interface.binary_sha256").lower()
        address = _address(entry.get("address"), name)
        if not HEX_SHA.fullmatch(item_sha) or item_sha != sha:
            raise ValueError(f"{name}: ELF identity does not match graph")
        if name in functions or (item_sha, address) in located:
            raise ValueError(f"{name}: duplicate name or numeric entry in same ELF")
        if entry.get("domain") != "Camera":
            raise ValueError(f"{name}: this graph is scoped to Camera only")
        if entry.get("verification_status") != "CANDIDATE" or entry.get("runtime_safety") != "DESCRIPTIVE_ONLY":
            raise ValueError(f"{name}: no API can be promoted using a research report")
        if any(entry.get(field) is not None for field in
               ("abi", "calling_convention", "parameter_layout", "return_semantics")):
            raise ValueError(f"{name}: research aliases cannot declare independently verified ABI")
        review = entry.get("review")
        if not isinstance(review, dict) or review.get("runtime_callable_verified") is not False:
            raise ValueError(f"{name}: explicit unknown runtime status required")
        sources = review.get("source_artifact_basenames")
        if not isinstance(sources, list) or not sources:
            raise ValueError(f"{name}: missing private research source names")
        for source in sources:
            _artifact(source)
        located.add((item_sha, address))
        functions[name] = {"name": name, "address": hex(address),
                           "domain": "Camera", "runtime_callable": False,
                           "abi_status": "UNKNOWN", "independent_instruction_proof_bundled": False,
                           "source_artifacts": sources}

    callsite_owners: set[tuple[str, int]] = set()
    calls: list[dict[str, Any]] = []
    for idx, edge in enumerate(_array(evidence, "static_calls")):
        if not isinstance(edge, dict):
            raise ValueError(f"static_calls[{idx}]: not an object")
        caller = _text(edge.get("caller"), "call.caller")
        callee = _text(edge.get("callee"), "call.callee")
        if caller not in functions or callee not in functions:
            raise ValueError(f"static_calls[{idx}]: unknown caller or callee")
        callsite = _address(edge.get("callsite"), "call.callsite")
        if callsite < int(functions[caller]["address"], 0):
            raise ValueError(f"static_calls[{idx}]: callsite precedes reported entry")
        key = (caller, callsite)
        if key in callsite_owners:
            raise ValueError(f"static_calls[{idx}]: ambiguous target for callsite")
        callsite_owners.add(key)
        instruction = _text(edge.get("instruction"), "call.instruction")
        m = DIRECT_BRANCH.fullmatch(instruction)
        if not m:
            raise ValueError(f"static_calls[{idx}]: not a direct branch instruction")
        if int(m.group(2), 16) != int(functions[callee]["address"], 0):
            raise ValueError(f"static_calls[{idx}]: branch target does not match callee ELF VMA")
        kind = "DIRECT_CALL" if m.group(1).lower() in {"bl", "blx"} else "TAIL_BRANCH"
        if edge.get("kind") != kind:
            raise ValueError(f"static_calls[{idx}]: incorrect instruction edge kind")
        calls.append({"caller": caller, "callee": callee, "callsite": hex(callsite),
                      "kind": kind, "source_artifact": _artifact(edge.get("source_artifact")),
                      "proof_level": "REPORTED_STATIC_INSTRUCTION_NOT_PUBLICLY_REVALIDATED",
                      "runtime_executed": False})

    fields: list[dict[str, Any]] = []
    for idx, obj in enumerate(_array(evidence, "field_observations")):
        if not isinstance(obj, dict) or obj.get("owner") not in functions:
            raise ValueError(f"field_observations[{idx}]: unknown function owner")
        if obj.get("kind") not in FIELD_KINDS or obj.get("width_bits") != 8:
            raise ValueError(f"field_observations[{idx}]: invalid operation/byte width")
        if _address(obj.get("instruction_address"), "field.instruction_address") < int(functions[obj["owner"]]["address"], 0):
            raise ValueError(f"field_observations[{idx}]: instruction precedes reported entry")
        offset = _address(obj.get("object_field_offset"), "field.object_field_offset")
        if offset > 0x100000:
            raise ValueError("field offset exceeds allowed model structure range")
        observed = obj.get("observed_value")
        if observed is not None and (isinstance(observed, bool) or observed not in {0, 1}):
            raise ValueError("field value must be 0, 1 or UNKNOWN")
        fields.append({"owner": obj["owner"], "kind": obj["kind"], "offset": hex(offset),
                       "instruction_address": hex(_address(obj["instruction_address"], "field.instruction_address")),
                       "observed_value": observed, "source_artifact": _artifact(obj.get("source_artifact")),
                       "runtime_observed": False})

    selectors: list[dict[str, Any]] = []
    routes: set[tuple[str, int, int]] = set()
    for idx, route in enumerate(_array(evidence, "normalized_selector_routes")):
        if not isinstance(route, dict) or route.get("owner") not in functions:
            raise ValueError(f"normalized_selector_routes[{idx}]: unknown owner")
        state, action = route.get("state"), route.get("action")
        if any(isinstance(x, bool) or not isinstance(x, int) for x in (state, action)):
            raise ValueError("state/action must be integers")
        if not 0 <= state <= 6 or not 0 <= action <= 115:
            raise ValueError("state/action outside recorded ModelCamera lookup range")
        next_state = route.get("next_state")
        if next_state is not None and (isinstance(next_state, bool) or not isinstance(next_state, int)
                                       or not 0 <= next_state <= 6):
            raise ValueError("invalid next-state")
        selector = _address(route.get("selector"), "normalized selector")
        key = (route["owner"], state, selector)
        if key in routes:
            raise ValueError("duplicate normalized selector route")
        routes.add(key)
        if route.get("status") != "STATIC_BOUNDED_EVALUATION":
            raise ValueError("selector routes are not observed live device events")
        selectors.append({"owner": route["owner"], "state": state, "selector": hex(selector),
                          "action": action, "next_state": next_state,
                          "source_artifact": _artifact(route.get("source_artifact")),
                          "raw_message_mapping_proven": False})

    unresolved: list[dict[str, Any]] = []
    for idx, item in enumerate(_array(evidence, "unresolved_external")):
        if not isinstance(item, dict) or item.get("owner") not in functions or item.get("kind") != "INDIRECT_DISPATCH":
            raise ValueError(f"unresolved_external[{idx}]: invalid unresolved boundary")
        unresolved.append({"owner": item["owner"], "callsite": hex(_address(item.get("callsite"), "unresolved.callsite")),
                           "target_symbol_hint": _text(item.get("target_symbol"), "unresolved.target_symbol"),
                           "source_artifact": _artifact(item.get("source_artifact")),
                           "resolved_target": None})

    focus = focus.strip() if isinstance(focus, str) else ""
    if focus and focus not in functions:
        raise ValueError(f"focus function is not in the research catalog: {focus}")
    if focus:
        visible = {focus}
        todo = deque([focus])
        while todo:
            current = todo.popleft()
            for edge in calls:
                if edge["caller"] == current and edge["callee"] not in visible:
                    visible.add(edge["callee"])
                    todo.append(edge["callee"])
    else:
        visible = set(functions)
    return {
        "status": "RESEARCH_GRAPH_INTERNALLY_CONSISTENT",
        "firmware_version": inventory["firmware_version"],
        "binary_sha256": sha,
        "focus": focus or None,
        "catalog_candidate_count": len(functions),
        "reported_direct_branch_count": len(calls),
        "reported_byte_field_observation_count": len(fields),
        "reported_normalized_selector_count": len(selectors),
        "reported_unresolved_indirect_count": len(unresolved),
        "functions": [v for k, v in functions.items() if k in visible],
        "static_calls": [v for v in calls if v["caller"] in visible and v["callee"] in visible],
        "field_observations": [v for v in fields if v["owner"] in visible],
        "normalized_selector_routes": [v for v in selectors if v["owner"] in visible],
        "unresolved_external": [v for v in unresolved if v["owner"] in visible],
        "validation": {
            "addresses_and_reported_branch_targets_consistent": True,
            "independent_instruction_bytes_checked": False,
            "independent_abi_verified": False,
            "live_device_behavior_verified": False,
            "callsite_body_membership_verified": False,
            "complete_sdk_api_denominator": None,
        },
        "callable_camera_apis": None,
        "rule": "A consistent report is not proof of a callable SDK or a verified camera control API.",
    }
