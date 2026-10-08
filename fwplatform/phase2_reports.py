from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import __version__
from .db import Database, utc_now
from .report import coverage


def _count(db: Database, table: str, where: str = "", args: list[Any] | None = None) -> int:
    sql = f"SELECT COUNT(*) FROM {table}" + (f" WHERE {where}" if where else "")
    return int(db.connection.execute(sql, args or []).fetchone()[0])


def _tables(db: Database) -> list[tuple[str, int]]:
    return [(str(row[0]), _count(db, str(row[0]))) for row in db.connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]


def _integrity(db: Database) -> dict[str, Any]:
    duplicate_evidence = int(db.connection.execute(
        "SELECT COUNT(*) FROM (SELECT evidence_key FROM evidence GROUP BY evidence_key HAVING COUNT(*)>1)").fetchone()[0])
    null_keys = {table: int(db.connection.execute(f"SELECT COUNT(*) FROM {table} WHERE {column} IS NULL OR {column}='' ").fetchone()[0])
                 for table, column in (("evidence", "evidence_key"), ("evidence", "locator_key"),
                                        ("binary_identity", "identity_key"), ("source_identity", "identity_key"))}
    return {"schema_version": db.connection.execute("PRAGMA user_version").fetchone()[0],
            "quick_check": db.connection.execute("PRAGMA quick_check").fetchone()[0],
            "foreign_key_errors": len(db.connection.execute("PRAGMA foreign_key_check").fetchall()),
            "duplicate_evidence_keys": duplicate_evidence, "null_identity_keys": null_keys,
            "evidence_rows": _count(db, "evidence"), "evidence_archive_rows": _count(db, "evidence_archive"),
            "tables": _tables(db)}


def write_phase2_reports(db: Database, output_dir: Path) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    cov = coverage(db)
    integrity = _integrity(db)
    ghidra_runs = [dict(row) for row in db.query("""SELECT ar.id,ar.binary_id,b.path,ar.analyzer,ar.analyzer_version,ar.status,
        ar.checkpoint,ar.error_text,ar.metadata_json FROM analysis_run ar LEFT JOIN binary b ON b.id=ar.binary_id
        WHERE ar.analyzer='ghidra_headless' ORDER BY ar.id""")]
    cfg = {table: _count(db, table) for table in ("function", "basic_block", "instruction", "callsite", "cross_reference", "unresolved_edge")}
    linkage = {"module_dependency": _count(db, "module_dependency"),
               "resolved_import_xrefs": _count(db, "cross_reference", "kind='resolved_import'"),
               "dynamic_evidence": _count(db, "evidence", "kind='elf_dynamic'")}
    cli_smoke = {
        "callers_open": int(db.connection.execute("SELECT COUNT(*) FROM callsite cs LEFT JOIN function f ON f.id=cs.callee_id WHERE f.name LIKE '%open%'").fetchone()[0]),
        "callsite_0x11250": int(db.connection.execute("SELECT COUNT(*) FROM callsite WHERE address='0x11250'").fetchone()[0]),
        "xrefs_0x11250": int(db.connection.execute("SELECT COUNT(*) FROM cross_reference WHERE from_address='0x11250' OR to_address='0x11250'").fetchone()[0]) + int(db.connection.execute("SELECT COUNT(*) FROM callsite WHERE address='0x11250' OR target='0x11250'").fetchone()[0]),
        "trace_seed_open": int(db.connection.execute("SELECT COUNT(*) FROM function WHERE name LIKE '%open%' OR address LIKE '%open%'").fetchone()[0]),
    }
    gaps = {"lifecycle_total": _count(db, "lifecycle_callback"),
            "lifecycle_with_function": _count(db, "lifecycle_callback", "function_id IS NOT NULL"),
            "unresolved_edges": _count(db, "unresolved_edge"),
            "failed_analysis_runs": _count(db, "analysis_run", "status IN ('FAILED','ERROR')"),
            "candidate_evidence": _count(db, "evidence", "status='CANDIDATE'"),
            "unknown_evidence": _count(db, "evidence", "status='UNKNOWN'")}
    failed_rows = [dict(row) for row in db.query("""SELECT ar.analyzer,b.path,ar.error_text FROM analysis_run ar
        LEFT JOIN binary b ON b.id=ar.binary_id WHERE ar.status IN ('FAILED','ERROR') ORDER BY ar.id""")]
    test_log = output_dir / "phase2-tests.txt"
    test_summary = "UNKNOWN (no saved test output)"
    if test_log.is_file():
        try:
            raw_test = test_log.read_bytes()
            test_text = raw_test.decode("utf-16", errors="replace") if b"\x00" in raw_test[:200] else raw_test.decode("utf-8", errors="replace")
            test_summary = "PASS" if "OK" in test_text and "Ran " in test_text else "FAIL/UNKNOWN"
        except (OSError, UnicodeError):
            pass
    phase2 = {
        "generated_at": utc_now(), "tool_version": __version__, "schema_version": integrity["schema_version"],
        "implemented": {"migration_v3": "fwplatform/migration_v3.py", "migration_v4": "fwplatform/migration_v4.py",
                         "inventory": "fwplatform/inventory.py", "ghidra_export": "ghidra-scripts/AnalyzeBinary.java",
                         "ghidra_wrapper": "tools/run-ghidra-headless.ps1", "ghidra_import": "fwplatform/ghidra_importer.py",
                         "linkage": "fwplatform/linkage.py", "queries": "fwplatform/cli.py"},
        "cfg": cfg, "linkage": linkage, "cli_smoke": cli_smoke, "ghidra_runs": ghidra_runs, "integrity": integrity, "gaps": gaps,
        "coverage": cov}
    (output_dir / "phase2-data.json").write_text(json.dumps(phase2, ensure_ascii=False, indent=2, default=str), encoding="utf-8")

    integrity_lines = ["# DATA_INTEGRITY_REPORT", "", f"Generated: {phase2['generated_at']}", "",
        f"- SQLite schema version: `{integrity['schema_version']}`", f"- `PRAGMA quick_check`: `{integrity['quick_check']}`",
        f"- Foreign-key violations: `{integrity['foreign_key_errors']}`", f"- Duplicate evidence keys: `{integrity['duplicate_evidence_keys']}`",
        f"- Evidence rows: `{integrity['evidence_rows']}`; archived merged rows: `{integrity['evidence_archive_rows']}`", "",
        "## Table counts", "", "| Table | Rows |", "|---|---:|"]
    integrity_lines.extend(f"| `{name}` | {rows} |" for name, rows in integrity["tables"])
    integrity_lines.extend(["", "Identity keys with NULL/empty values:", "", "```json", json.dumps(integrity["null_identity_keys"], indent=2), "```"])
    (output_dir / "DATA_INTEGRITY_REPORT.md").write_text("\n".join(integrity_lines), encoding="utf-8")

    gh_lines = ["# GHIDRA_EXECUTION_REPORT", "", f"Ghidra headless runs recorded: `{len(ghidra_runs)}`", "",
                "Only runs present in `analysis_run` are counted. A completed run is static program analysis; it does not confirm runtime behavior.", ""]
    if not ghidra_runs:
        gh_lines.append("Status: UNKNOWN (no recorded Ghidra run).")
    for run in ghidra_runs:
        gh_lines.extend([f"## Run `{run['id']}` — {run.get('path') or 'unknown binary'}", "",
                         f"- Status: `{run['status']}`; checkpoint: `{run['checkpoint']}`",
                         f"- Analyzer: `{run['analyzer']} {run['analyzer_version']}`",
                         f"- Error: `{run['error_text'] or 'none'}`", ""])
        try:
            run_metadata = json.loads(run.get("metadata_json") or "{}")
            jsonl_path = Path(str(run_metadata.get("jsonl", "")))
            jsonl_records = sum(1 for _ in jsonl_path.open(encoding="utf-8")) if jsonl_path.is_file() else None
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError):
            jsonl_records = None
        gh_lines.append(f"- JSONL records on disk: `{jsonl_records if jsonl_records is not None else 'UNKNOWN'}`")
        if run.get("binary_id") is not None:
            bid = int(run["binary_id"])
            scoped = {
                "functions": _count(db, "function", "binary_id=?", [bid]),
                "basic_blocks": _count(db, "basic_block", "binary_id=?", [bid]),
                "instructions": _count(db, "instruction", "binary_id=?", [bid]),
                "callsites": int(db.connection.execute("SELECT COUNT(*) FROM callsite cs JOIN function f ON f.id=cs.caller_id WHERE f.binary_id=?", [bid]).fetchone()[0]),
                "cross_references": _count(db, "cross_reference", "from_binary_id=?", [bid]),
            }
            gh_lines.extend(["| Sample CFG relation | Rows |", "|---|---:|"] + [f"| {k} | {v} |" for k, v in scoped.items()] + [""])
    gh_lines.extend(["## Current CFG rows", "", "| Kind | Rows |", "|---|---:|"] + [f"| {k} | {v} |" for k, v in cfg.items()])
    (output_dir / "GHIDRA_EXECUTION_REPORT.md").write_text("\n".join(gh_lines), encoding="utf-8")

    xref_lines = ["# CROSS_REFERENCE_COVERAGE", "", "Counts come from SQLite rows, not symbol totals.", "",
                  "| Relation | Rows |", "|---|---:|"] + [f"| {k} | {v} |" for k, v in {**cfg, **linkage}.items()]
    xref_lines.extend(["", "Verified callsites and cross-references retain Ghidra JSONL evidence IDs. Unresolved indirect edges are stored separately and are not counted as resolved targets."])
    (output_dir / "CROSS_REFERENCE_COVERAGE.md").write_text("\n".join(xref_lines), encoding="utf-8")

    gap_lines = ["# ARCHITECTURE_GAPS", "", "These are measured gaps; absence is reported as UNKNOWN rather than treated as completion.", "",
                 f"- Lifecycle callbacks: `{gaps['lifecycle_with_function']}/{gaps['lifecycle_total']}` have a function link.",
                 f"- Unresolved edges: `{gaps['unresolved_edges']}`.", f"- Failed/error analysis runs: `{gaps['failed_analysis_runs']}`.",
                 f"- Candidate evidence: `{gaps['candidate_evidence']}`; unknown evidence: `{gaps['unknown_evidence']}`.", "",
                 "Still UNKNOWN until direct evidence is imported: runtime validation of CFG edges, complete JNI/Java method registration, OSAL queue producer/consumer resolution, semantic names for generated functions, and hardware/ioctl parameter layouts."]
    if failed_rows:
        gap_lines.extend(["", "## Recorded blockers", ""] + [f"- `{row['analyzer']}` `{row.get('path') or 'unknown'}`: `{row.get('error_text') or 'UNKNOWN'}`" for row in failed_rows])
    (output_dir / "ARCHITECTURE_GAPS.md").write_text("\n".join(gap_lines), encoding="utf-8")

    audit_lines = ["# PHASE2_AUDIT", "", f"Generated: {phase2['generated_at']}", "",
                   "## Implemented code paths", "", "- v3 integrity migration and evidence archive: `fwplatform/migration_v3.py`",
                   "- v4 Ghidra provenance columns: `fwplatform/migration_v4.py`",
                   "- deterministic Ghidra export and Auto Analysis wrapper: `ghidra-scripts/AnalyzeBinary.java`, `tools/run-ghidra-headless.ps1`",
                   "- JSONL importer with run/hash provenance: `fwplatform/ghidra_importer.py`",
                   "- ELF DT_NEEDED and unique export linkage: `fwplatform/linkage.py`",
                   "- call graph queries: `fwplatform/cli.py` (`callers`, `callees`, `callsite`, `trace --depth`)", "",
                   "## Measured status", "", f"- Schema: `{integrity['schema_version']}`; quick check `{integrity['quick_check']}`; FK errors `{integrity['foreign_key_errors']}`.",
                   f"- Ghidra runs: `{len(ghidra_runs)}`; CFG rows: `{cfg}`; linkage: `{linkage}`.",
                   f"- CLI smoke query counts (`callers open`, `callsite 0x11250`, `xrefs ...0x11250`, trace seed): `{cli_smoke}`.",
                   f"- Regression test log: `{test_summary}` (`reports/phase2-tests.txt`).",
                   "- Existing symbol index remains distinct from recovered CFG and semantic understanding.", "",
                   "## Not claimed", "", "No firmware patch, NAND/WBI modification, bootloader change, or runtime safety claim was made. Unknown and candidate relations remain explicitly marked."]
    (output_dir / "PHASE2_AUDIT.md").write_text("\n".join(audit_lines), encoding="utf-8")
    return {"phase2_audit": str(output_dir / "PHASE2_AUDIT.md"), "data_integrity": str(output_dir / "DATA_INTEGRITY_REPORT.md"),
            "ghidra": str(output_dir / "GHIDRA_EXECUTION_REPORT.md"), "xref": str(output_dir / "CROSS_REFERENCE_COVERAGE.md"),
            "gaps": str(output_dir / "ARCHITECTURE_GAPS.md")}
