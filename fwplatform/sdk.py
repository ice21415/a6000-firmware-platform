from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import __version__
from .db import Database, utc_now
from .sdk_contracts import audit_sdk_contracts


def _count(db: Database, sql: str, args: list[Any] | None = None) -> int:
    return int(db.connection.execute(sql, args or []).fetchone()[0])


def _row_to_interface(row: Any) -> dict[str, Any]:
    return {"name": row["name"], "domain": row["domain"], "module_id": row["module_id"],
        "binary_id": row["binary_id"], "function_id": row["function_id"], "address": row["address"],
        "abi": row["abi"], "calling_convention": row["calling_convention"],
        "parameter_layout": row["parameter_layout"], "return_semantics": row["return_semantics"],
        "preconditions": row["preconditions"], "thread_context": row["thread_context"],
        "state_requirements": row["state_requirements"], "side_effects": row["side_effects"],
        "event_dependencies": row["event_dependencies"], "firmware_version": row["firmware_version"],
        "evidence_references": row["evidence_references"], "verification_status": row["verification_status"],
        "runtime_safety": row["runtime_safety"], "mock_status": row["mock_status"],
        "source_evidence_id": row["source_evidence_id"], "analyzer_version": row["analyzer_version"]}


def build_sdk_index(db: Database, output: Path, firmware_version: str = "3.21") -> dict[str, Any]:
    """Build descriptive SDK metadata from current evidence-backed rows.

    A function symbol is indexed by default; it becomes an SDK interface only
    when an explicit sdk_interface row exists. Runtime safety is independent
    from static confidence and remains descriptive unless separately verified.
    """
    indexed = _count(db, "SELECT COUNT(*) FROM function")
    cfg = _count(db, "SELECT COUNT(DISTINCT function_id) FROM basic_block WHERE function_id IS NOT NULL")
    semantic = _count(db, "SELECT COUNT(*) FROM sdk_interface WHERE verification_status IN ('VERIFIED_STATIC','VERIFIED_RUNTIME','MOCK_TESTED')")
    runtime = _count(db, "SELECT COUNT(*) FROM sdk_interface WHERE verification_status='VERIFIED_RUNTIME'")
    protocol = _count(db, """SELECT COUNT(*) FROM semantic_edge e JOIN evidence v ON v.id=e.evidence_id
        WHERE e.relation_type IN ('SENDS_MESSAGE','RECEIVES_MESSAGE','JNI_BRIDGE','DEPENDS_ON')
        AND e.status IN ('VERIFIED_STATIC','VERIFIED_RUNTIME') AND v.status IN ('VERIFIED_STATIC','VERIFIED_RUNTIME')""")
    interfaces = [_row_to_interface(row) for row in db.query("SELECT * FROM sdk_interface ORDER BY domain,name")]
    # A database flag is not sufficient evidence that direct camera calls are safe.
    audit = audit_sdk_contracts(db)
    data = {"format": "a6000-unofficial-descriptive-sdk", "version": __version__, "generated_at": utc_now(),
        "firmware": {"model": "Sony ILCE-6000", "version": firmware_version},
        "generated_from": "local evidence database (private snapshot is not shipped)",
        "database_snapshot_included": False,
        "coverage": {"indexed_functions": indexed, "cfg_recovered_functions": cfg,
                      "semantically_understood_functions": semantic, "runtime_verified_interfaces": runtime,
                      "verified_protocol_edges": protocol, "sdk_documented_interfaces": len(interfaces),
                      "callable_validated_interfaces": None,
                      "static_contract_complete": audit["static_contract_complete"],
                      "denominators": {"indexed_functions": "all function rows in current database",
                                       "cfg_recovered_functions": "distinct function_id with basic_block rows",
                                       "semantically_understood_functions": "explicit sdk_interface rows with verified/mock status",
                                       "runtime_verified_interfaces": "explicit sdk_interface rows marked VERIFIED_RUNTIME",
                                       "verified_protocol_edges": "semantic protocol edges whose edge and primary evidence statuses are VERIFIED_*",
                                       "callable_validated_interfaces": "UNKNOWN: no offline database flag authorizes runtime invocation",
                                       "static_contract_complete": "explicit ABI/parameters/evidence and unique binary/function ownership"}},
        "interfaces": interfaces,
        "contract_audit": audit,
        "rule": "Indexed symbols and names are not callable APIs. Offline SDK export is descriptive only; runtime safety cannot be inferred from database status flags, even VERIFIED_RUNTIME."}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return data
