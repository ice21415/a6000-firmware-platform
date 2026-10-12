"""Inspect an exact function ID even when Sony symbols are stripped/generated.

This read-only path is independent of lexical domain hints and can be used
to examine Ghidra/ELF function entries in an existing private research DB.
"""
from __future__ import annotations

from typing import Any

from .core_api import (
    _callsite_relations, _cfg_context, _jni_relations, _lifecycle_relations,
    _osal_relations, MAX_RELATIONS,
)
from .sdk_contracts import _address_value, _proves_function_location
from .db import Database


def inspect_function(db: Database, *, function_id: int, relation_limit: int = 8) -> dict[str, Any]:
    if isinstance(function_id, bool) or not isinstance(function_id, int) or function_id <= 0:
        raise ValueError("function_id must be a positive integer")
    if isinstance(relation_limit, bool) or not isinstance(relation_limit, int) or not 1 <= relation_limit <= MAX_RELATIONS:
        raise ValueError("relation limit must be between 1 and 12")
    rows = db.query("""SELECT f.id,f.name,f.address,f.binary_id,f.module_id,
        f.generated_name,f.prototype,f.source_evidence_id,f.address_space,
        b.path AS binary_path,b.sha256 AS binary_sha256,
        m.name AS module_name,
        e.kind AS entry_evidence_kind,e.status AS entry_evidence_status,
        e.excerpt AS entry_evidence_excerpt,e.source_sha256 AS entry_source_sha256,
        e.metadata_json AS entry_evidence_metadata_json
        FROM function f LEFT JOIN binary b ON b.id=f.binary_id
        LEFT JOIN module m ON m.id=f.module_id
        LEFT JOIN evidence e ON e.id=f.source_evidence_id
        WHERE f.id=?""", (function_id,))
    if not rows:
        raise ValueError(f"function_id {function_id} does not exist")
    row = rows[0]
    sha = str(row["binary_sha256"] or "")
    bid = row["binary_id"]
    address = _address_value(row["address"])
    unique_binary = bool(sha and len(db.query(
        "SELECT id FROM binary WHERE lower(sha256)=?", (sha.lower(),),
    )) == 1)
    entries = (db.query("SELECT address FROM function WHERE binary_id=?", (bid,))
               if bid is not None else [])
    unique_entry = address is not None and sum(
        _address_value(item["address"]) == address for item in entries
    ) == 1
    evidence = {
        "excerpt": row["entry_evidence_excerpt"],
        "metadata_json": row["entry_evidence_metadata_json"],
        "source_sha256": row["entry_source_sha256"],
    }
    location_evidenced = bool(
        unique_binary and unique_entry and
        row["entry_evidence_status"] == "VERIFIED_STATIC" and
        _proves_function_location(evidence, sha, str(row["address"]))
    )
    module_context: list[dict[str, Any]] = []
    if row["module_id"] is not None:
        module_context = [dict(v) for v in db.query(
            """SELECT m.id,m.name,m.status,m.source_evidence_id,
                (SELECT COUNT(*) FROM state_transition t WHERE t.machine_id=m.id)
                    AS transitions
               FROM state_machine m WHERE m.module_id=? ORDER BY m.id LIMIT ?""",
            (row["module_id"], relation_limit + 1),
        )]
    return {
        "status": "STATIC_FUNCTION_RESEARCH_ONLY",
        "read_only": True,
        "hardware_access": False,
        "function": {
            "id": row["id"], "name": row["name"], "entry_address": row["address"],
            "address_space": row["address_space"],
            "generated_name": bool(row["generated_name"]),
            "raw_prototype_unverified": row["prototype"],
            "binary_id": bid, "binary_path": row["binary_path"],
            "binary_sha256": row["binary_sha256"], "module_id": row["module_id"],
            "module_name": row["module_name"], "identity_unique": bool(unique_binary and unique_entry),
            "location_evidence_valid": location_evidenced,
            "location_evidence_id": row["source_evidence_id"] if location_evidenced else None,
            "abi_status": "UNKNOWN", "semantics_status": "UNKNOWN",
            "runtime_callable": False,
        },
        "cfg": _cfg_context(db, function_id),
        "incoming_calls": _callsite_relations(db, function_id, "incoming", relation_limit),
        "outgoing_calls": _callsite_relations(db, function_id, "outgoing", relation_limit),
        "osal_function_roles": _osal_relations(db, function_id, relation_limit),
        "jni_native_bridges": _jni_relations(db, function_id, relation_limit),
        "lifecycle_callbacks": _lifecycle_relations(db, function_id, relation_limit),
        "module_state_machine_context": {
            "scope": "module_id_only_not_function_transition_proof",
            "rows": module_context[:relation_limit],
            "truncated": len(module_context) > relation_limit,
            "function_to_state_link_verified": False,
        },
        "unresolved_edges": _unresolved(db, function_id, relation_limit),
        "required_evidence": [
            "FUNCTION_CONTROL_FLOW_AND_CALLSITE_REVIEW",
            "INDEPENDENT_CALLING_CONVENTION_PARAMETERS_AND_RETURN",
            "STATE_OR_OSAL_CAUSAL_EVIDENCE_WHEN_APPLICABLE",
            "RUNTIME_BEHAVIOR_AND_DEVICE_SAFETY_INDEPENDENT_VALIDATION",
        ],
        "rule": "An exact function entry is not a confirmed Camera/Lens/Sensor API or a safe runtime call.",
    }


def _unresolved(db: Database, function_id: int, limit: int) -> dict[str, Any]:
    rows = [dict(r) for r in db.query(
        """SELECT id,relation,reason,status,source_evidence_id
           FROM unresolved_edge WHERE from_type='function' AND from_id=?
           ORDER BY id LIMIT ?""", (function_id, limit + 1),
    )]
    return {"rows": rows[:limit], "shown": min(limit, len(rows)), "truncated": len(rows) > limit}
