"""Sanitized Phase 3.1 reports generated from SQLite, never from raw firmware."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .db import Database, utc_now
from .semantic_graph import validate_graph_provenance


def _count(db: Database, sql: str, args: list[Any] | None = None) -> int:
    return int(db.connection.execute(sql, args or []).fetchone()[0])


def metrics(db: Database) -> dict[str, Any]:
    observations = _count(db, "SELECT COUNT(*) FROM research_observation")
    synthetic = _count(db, "SELECT COUNT(*) FROM research_observation WHERE source_path LIKE '%test%' OR source_path LIKE '%fixture%'")
    real = observations - synthetic
    return {
        "generated_at": utc_now(),
        "functions_indexed": _count(db, "SELECT COUNT(*) FROM function"),
        "cfg_analyzed_functions": _count(db, "SELECT COUNT(DISTINCT function_id) FROM basic_block WHERE function_id IS NOT NULL"),
        "function_body_ranges": _count(db, "SELECT COUNT(*) FROM function_body_range"),
        "basic_blocks": _count(db, "SELECT COUNT(*) FROM basic_block"),
        "cfg_edges": _count(db, "SELECT COUNT(*) FROM cfg_edge"),
        "callsites": _count(db, "SELECT COUNT(*) FROM callsite"),
        "xrefs": _count(db, "SELECT COUNT(*) FROM cross_reference"),
        "semantic_nodes": _count(db, "SELECT COUNT(*) FROM semantic_node"),
        "semantic_edges": _count(db, "SELECT COUNT(*) FROM semantic_edge"),
        "evidence_verified_edges": _count(db, """SELECT COUNT(*) FROM semantic_edge e JOIN evidence v ON v.id=e.evidence_id
            WHERE e.status LIKE 'VERIFIED_%' AND v.status LIKE 'VERIFIED_%'"""),
        "research_observations": {"total": observations, "real_firmware_static_or_historical": real,
                                   "synthetic_fixture": synthetic, "runtime_verified": 0},
        "osal_observations": _count(db, "SELECT COUNT(*) FROM research_observation WHERE observation_type LIKE 'osal_%'"),
        "osal_messages": _count(db, "SELECT COUNT(*) FROM osal_message"),
        "jni_bridges": _count(db, "SELECT COUNT(*) FROM jni_bridge"),
        "state_machines": _count(db, "SELECT COUNT(*) FROM state_machine"),
        "state_transitions": _count(db, "SELECT COUNT(*) FROM state_transition"),
        "unresolved_relations": _count(db, "SELECT COUNT(*) FROM unresolved_edge"),
        "ghidra_runs": _count(db, "SELECT COUNT(*) FROM analysis_run WHERE analyzer='ghidra_headless'"),
        "ghidra_complete_runs": _count(db, "SELECT COUNT(*) FROM analysis_run WHERE analyzer='ghidra_headless' AND status='COMPLETE'"),
        "sdk_descriptive": _count(db, "SELECT COUNT(*) FROM sdk_interface"),
        "sdk_runtime_verified": _count(db, "SELECT COUNT(*) FROM sdk_interface WHERE verification_status='VERIFIED_RUNTIME'"),
        "provenance": validate_graph_provenance(db),
    }


def _write(path: Path, title: str, body: str) -> None:
    path.write_text(f"# {title}\n\n{body.rstrip()}\n", encoding="utf-8")


def write_phase3_1_reports(db: Database, output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    m = metrics(db)
    j = json.dumps(m, ensure_ascii=False, indent=2, default=str)
    _write(output_dir / "PHASE3_1_AUDIT.md", "Phase 3.1 Audit", "This report is generated from SQLite. It does not claim runtime verification.\n\n```json\n" + j + "\n```")
    _write(output_dir / "REAL_EVIDENCE_INGESTION_REPORT.md", "Real Evidence Ingestion", f"Real firmware static or historical observations: **{m['research_observations']['real_firmware_static_or_historical']}**; synthetic fixture observations: **{m['research_observations']['synthetic_fixture']}**; runtime-verified observations: **{m['research_observations']['runtime_verified']}**.\n\nSource hashes, locators, adapter runs and original statuses are stored in `research_observation` and `evidence`. Static/historical evidence is not runtime verification, and a count is not semantic understanding.")
    _write(output_dir / "OSAL_SYNCANDROID_CHAIN.md", "SyncAndroid OSAL Chain", f"OSAL observations: **{m['osal_observations']}**; materialized messages: **{m['osal_messages']}**. Queue, command, synchronous semantics and producer observations are evidence-bound. Native receiver dispatch remains unresolved where no canonical function identity was found.\n\nRuntime verification: **UNKNOWN**.")
    _write(output_dir / "JNI_NATIVE_TO_JAVA_REPORT.md", "JNI Native to Java", f"JNI bridge rows: **{m['jni_bridges']}**. Registration and `(I)V` method lookup evidence are stored with direction `NATIVE_TO_JAVA`; unresolved native implementation entries remain explicit.\n\nRuntime verification: **UNKNOWN**.")
    _write(output_dir / "CAMERA_STATE_MACHINE_REPORT.md", "ModelCamera State Machine", f"State machines: **{m['state_machines']}**; transitions: **{m['state_transitions']}**. The imported selector evaluation is static evidence; UI ready, camera prepare, camera ready and first-shot-ready are separate and not inferred from these rows.")
    _write(output_dir / "GHIDRA_MULTI_ELF_REPORT.md", "Ghidra Coverage", f"Ghidra runs recorded: **{m['ghidra_runs']}**; complete: **{m['ghidra_complete_runs']}**; CFG edges: **{m['cfg_edges']}**. Batch expansion remains controlled and no full 709-ELF run is implied.")
    _write(output_dir / "SEMANTIC_COVERAGE_REPORT.md", "Semantic Coverage", f"Indexed functions: **{m['functions_indexed']}**; CFG-recovered functions: **{m['cfg_analyzed_functions']}**; semantic edges: **{m['semantic_edges']}**; evidence-status verified edges: **{m['evidence_verified_edges']}**; unresolved relations: **{m['unresolved_relations']}**. Provenance gaps are reported rather than silently promoted.\n\n```json\n" + json.dumps(m['provenance'], ensure_ascii=False, indent=2) + "\n```")
    return {"output_dir": str(output_dir), "metrics": m, "reports": 7}
