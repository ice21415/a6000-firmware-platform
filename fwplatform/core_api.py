"""Evidence-bound core camera API investigation; never executes firmware code.

The investigation collects explicit database relationships for static research.
Domain names from ELF exports are *search hints*. No cross-table association
is fabricated from a shared address, symbol name, module or message number.
"""
from __future__ import annotations

from typing import Any

from .db import Database
from .sdk_contracts import DOMAINS
from .sdk_discovery import discover_sdk_candidates

MAX_ITEMS = 100
MAX_RELATIONS = 12
CORE_DOMAINS = tuple(domain for domain in DOMAINS if domain != "Other")


def _relations(db: Database, sql: str, function_id: int, cap: int) -> dict[str, Any]:
    """Return bounded explicit rows and an accurate (cap+1) truncation flag."""
    rows = [dict(r) for r in db.query(sql, (function_id, cap + 1))]
    return {
        "rows": rows[:cap],
        "truncated": len(rows) > cap,
        "shown": min(len(rows), cap),
    }


def _callsite_relations(db: Database, function_id: int, direction: str, cap: int) -> dict[str, Any]:
    assert direction in ("incoming", "outgoing")
    on = "cs.callee_id" if direction == "incoming" else "cs.caller_id"
    other = "cs.caller_id" if direction == "incoming" else "cs.callee_id"
    sql = f"""SELECT cs.id AS callsite_id,cs.address AS callsite_address,
        cs.status AS reported_status,cs.source_evidence_id AS evidence_id,
        cs.caller_resolution,cs.address_space,
        f.id AS peer_function_id,f.name AS peer_function_name,
        f.address AS peer_function_address,b.sha256 AS peer_binary_sha256,
        e.kind AS evidence_kind,e.status AS evidence_status
        FROM callsite cs LEFT JOIN function f ON f.id={other}
        LEFT JOIN binary b ON b.id=f.binary_id
        LEFT JOIN evidence e ON e.id=cs.source_evidence_id
        WHERE {on}=? ORDER BY cs.id LIMIT ?"""
    result = _relations(db, sql, function_id, cap)
    for row in result["rows"]:
        row["relationship"] = "direct_function_id" if row["peer_function_id"] is not None else "unresolved_peer"
        row["semantic_proof"] = False
    return result


def _osal_relations(db: Database, function_id: int, cap: int) -> dict[str, Any]:
    """Only explicit function foreign keys count: never message-ID coincidence."""
    sql = """SELECT mf.id AS flow_id,mf.role,mf.status AS reported_status,
        mf.source_evidence_id AS evidence_id,
        q.namespace AS queue_namespace,q.queue_value,
        mi.namespace AS message_namespace,mi.value AS message_value,
        e.kind AS evidence_kind,e.status AS evidence_status
        FROM message_flow mf JOIN osal_message om ON om.id=mf.osal_message_id
        JOIN message_queue q ON q.id=om.queue_id
        LEFT JOIN message_id mi ON mi.id=om.message_id
        LEFT JOIN evidence e ON e.id=mf.source_evidence_id
        WHERE mf.function_id=? ORDER BY mf.id LIMIT ?"""
    result = _relations(db, sql, function_id, cap)
    for row in result["rows"]:
        row["semantic_proof"] = False
    return result


def _jni_relations(db: Database, function_id: int, cap: int) -> dict[str, Any]:
    sql = """SELECT j.id AS bridge_id,j.class_name,j.method_name,j.signature,j.dex_path,
        j.status AS reported_status,j.source_evidence_id AS evidence_id,
        e.kind AS evidence_kind,e.status AS evidence_status
        FROM jni_bridge j LEFT JOIN evidence e ON e.id=j.source_evidence_id
        WHERE j.native_function_id=? ORDER BY j.id LIMIT ?"""
    result = _relations(db, sql, function_id, cap)
    for row in result["rows"]:
        row["method_body_verified"] = False
        row["runtime_registration_verified"] = False
    return result


def _lifecycle_relations(db: Database, function_id: int, cap: int) -> dict[str, Any]:
    sql = """SELECT l.id AS callback_id,l.phase,l.name,l.status AS reported_status,
        l.source_evidence_id AS evidence_id,
        e.kind AS evidence_kind,e.status AS evidence_status
        FROM lifecycle_callback l LEFT JOIN evidence e ON e.id=l.source_evidence_id
        WHERE l.function_id=? ORDER BY l.id LIMIT ?"""
    return _relations(db, sql, function_id, cap)


def _cfg_context(db: Database, function_id: int) -> dict[str, Any]:
    def count(table: str) -> int:
        # Closed allowlist prevents SQL table-name interpolation from input.
        if table not in {"basic_block", "cfg_edge", "function_body_range"}:
            raise ValueError("unsupported CFG table")
        return int(db.connection.execute(
            f"SELECT COUNT(*) FROM {table} WHERE function_id=?", (function_id,),
        ).fetchone()[0])
    return {
        "basic_blocks": count("basic_block"),
        "cfg_edges": count("cfg_edge"),
        "body_ranges": count("function_body_range"),
        "abi_verified_by_cfg": False,
    }


def _state_context(db: Database, domain: str, cap: int) -> dict[str, Any]:
    """State-machine names are only search context, never per-function links."""
    if domain != "Camera":
        return {"scope": "not_queried_for_domain", "machines": []}
    rows = db.query("""SELECT m.id,m.name,m.status,m.source_evidence_id,
        (SELECT COUNT(*) FROM state_transition t WHERE t.machine_id=m.id) AS transitions
        FROM state_machine m WHERE LOWER(m.name) LIKE '%camera%'
        ORDER BY m.id LIMIT ?""", (cap + 1,))
    return {
        "scope": "lexical_machine_name_only",
        "machines": [dict(r) for r in rows[:cap]],
        "truncated": len(rows) > cap,
        "function_to_state_link_verified": False,
        "camera_ready_or_first_shot_verified": False,
    }


def investigate_core_apis(
    db: Database, *, domain: str = "Camera", name: str = "",
    binary_sha256: str = "", include_internal: bool = False,
    include_generated: bool = False, limit: int = 25,
    relation_limit: int = 8,
) -> dict[str, Any]:
    """Produce a read-only core API research queue with scoped source evidence."""
    if domain not in CORE_DOMAINS:
        raise ValueError("core API domain must be Camera, Lens, Sensor, Media, UI, OSAL, Android or Networking")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_ITEMS:
        raise ValueError("core API limit must be between 1 and 100")
    if isinstance(relation_limit, bool) or not isinstance(relation_limit, int) or not 1 <= relation_limit <= MAX_RELATIONS:
        raise ValueError("core API relation limit must be between 1 and 12")
    discovery = discover_sdk_candidates(
        db, name=name, binary_sha256=binary_sha256, domain=domain,
        include_internal=include_internal, include_generated=include_generated,
        limit=limit,
    )
    investigations: list[dict[str, Any]] = []
    for candidate in discovery["candidates"]:
        fid = int(candidate["function_id"])
        incoming = _callsite_relations(db, fid, "incoming", relation_limit)
        outgoing = _callsite_relations(db, fid, "outgoing", relation_limit)
        osal = _osal_relations(db, fid, relation_limit)
        jni = _jni_relations(db, fid, relation_limit)
        lifecycle = _lifecycle_relations(db, fid, relation_limit)
        cfg = _cfg_context(db, fid)
        blockers = ["ABI_AND_ARGUMENT_LAYOUT_NOT_INDEPENDENTLY_CONFIRMED",
                    "DOMAIN_SEMANTICS_NOT_CONFIRMED", "RUNTIME_NOT_VERIFIED"]
        if not candidate["entry_location_evidence_valid"]:
            blockers.insert(0, "MISSING_UNAMBIGUOUS_FUNCTION_ENTRY_PROOF")
        if not cfg["body_ranges"]:
            blockers.append("FUNCTION_BODY_RANGES_MISSING")
        if not incoming["shown"] and not outgoing["shown"]:
            blockers.append("EXPLICIT_CALLSITES_MISSING")
        if domain in {"Camera", "Lens", "Sensor"} and not osal["shown"]:
            blockers.append("OSAL_LINK_NOT_EVIDENCED")
        if domain == "Android" and not jni["shown"]:
            blockers.append("JNI_LINK_NOT_EVIDENCED")
        investigations.append({
            "candidate": candidate,
            "cfg": cfg,
            "incoming_calls": incoming,
            "outgoing_calls": outgoing,
            "osal_function_roles": osal,
            "jni_native_bridges": jni,
            "lifecycle_callbacks": lifecycle,
            "blockers": blockers,
            "domain_semantics_confirmed": False,
            "abi_verified": False,
            "runtime_callable": False,
        })
    return {
        "status": "STATIC_RESEARCH_ONLY",
        "domain": domain,
        "selected_by": "lexical_function_name_hint_not_semantic_proof",
        "read_only": True,
        "hardware_access": False,
        "indexed_candidates": len(investigations),
        "more_candidates_possible": discovery["more_candidates_possible"],
        "state_machine_context": _state_context(db, domain, relation_limit),
        "investigations": investigations,
        "core_api_completion": None,
        "runtime_callable_apis": None,
        "rule": "Direct relational IDs are static observations, not verified firmware behavior; lexical state names are context only.",
    }
