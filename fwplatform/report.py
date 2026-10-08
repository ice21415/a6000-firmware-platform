from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .constants import DOMAINS
from .db import Database, utc_now


def coverage(db: Database) -> dict[str, Any]:
    def count(table: str, where: str = "", args: list[Any] | None = None) -> int:
        sql = f"SELECT COUNT(*) FROM {table}" + (f" WHERE {where}" if where else "")
        return int(db.connection.execute(sql, args or []).fetchone()[0])

    total_binaries = count("binary")
    known = count("binary", "format != 'unknown'")
    elf = count("binary", "format='elf_executable_or_shared_library'")
    analyzed_elf = count("binary", "format='elf_executable_or_shared_library' AND analysis_status LIKE 'ANALYZED%'")
    modules_by_domain = {}
    for domain in DOMAINS:
        module_count = count("module", "domain=?", [domain])
        evidence_count = count("module", "domain=? AND source_evidence_id IS NOT NULL", [domain])
        modules_by_domain[domain] = {"modules": module_count, "evidence_backed": evidence_count,
                                     "status": "INFERRED" if evidence_count else "UNKNOWN"}
    return {
        "generated_at": utc_now(),
        "definitions": {
            "inventory_known_format": "known-format binary rows / all binary rows",
            "elf_analyzed": "ELF rows with analysis_status ANALYZED* / all ELF rows",
            "function_index": "indexed function rows / functions exposed by imported research or analyzers (unknown denominator if no complete symbol source)",
            "verified_relation": "relations with VERIFIED_* status / all relation rows of that type",
            "domain_completion": "domain modules with evidence / domain module rows; absence is UNKNOWN, never zero percent claim",
        },
        "inventory": {"binaries": total_binaries, "known_format": known, "unknown_format": total_binaries - known,
                       "known_format_ratio": (known / total_binaries if total_binaries else None)},
        "elf": {"total": elf, "analyzed": analyzed_elf, "analysis_ratio": (analyzed_elf / elf if elf else None)},
        "functions": {"total": count("function"), "with_binary": count("function", "binary_id IS NOT NULL"),
                       "verified_static": count("function", "status='VERIFIED_STATIC'")},
        "callsites": {"total": count("callsite"), "verified": count("callsite", "status LIKE 'VERIFIED%'")},
        "cross_module_relations": {"total": count("module_dependency"), "verified": count("module_dependency", "status LIKE 'VERIFIED%'")},
        "events": {"ids": count("event_id"), "producers": count("event_producer"), "consumers": count("event_consumer")},
        "messages": {"queues": count("message_queue"), "ids": count("message_id")},
        "vtables": {"total": count("vtable"), "verified_static": count("vtable", "status='VERIFIED_STATIC'")},
        "sdk_descriptive_interfaces": {"jni": count("jni_bridge"), "ioctl": count("ioctl"), "lifecycle": count("lifecycle_callback")},
        "domains": modules_by_domain,
        "hypotheses": {"total": count("hypothesis"), "candidate": count("hypothesis", "status='CANDIDATE'"),
                       "disproven": count("hypothesis", "status='DISPROVEN'"), "unknown": count("hypothesis", "status='UNKNOWN'")},
        "failed_analysis_runs": count("analysis_run", "status IN ('FAILED','ERROR')"),
    }


def architecture_overview(db: Database) -> dict[str, Any]:
    modules = [dict(row) for row in db.query("SELECT id,name,domain,status,description FROM module ORDER BY domain,name")]
    dependencies = [dict(row) for row in db.query("SELECT f.name AS from_module,t.name AS to_module,d.kind,d.status FROM module_dependency d JOIN module f ON f.id=d.from_module_id JOIN module t ON t.id=d.to_module_id ORDER BY f.name,t.name")]
    machines = [dict(row) for row in db.query("SELECT sm.name,sm.status,m.name AS module FROM state_machine sm LEFT JOIN module m ON m.id=sm.module_id ORDER BY sm.name")]
    return {"generated_at": utc_now(), "firmware": "Sony ILCE-6000 3.21", "modules": modules,
            "module_dependencies": dependencies, "state_machines": machines,
            "domains": {domain: {"status": "INFERRED" if any(m.get("domain") == domain for m in modules) else "UNKNOWN",
                                  "modules": [m for m in modules if m.get("domain") == domain]}
                        for domain in DOMAINS}}


def unknowns(db: Database, limit: int = 100) -> dict[str, Any]:
    hypotheses = [dict(row) for row in db.query("SELECT id,subject_type,subject_id,statement,status FROM hypothesis WHERE status IN ('UNKNOWN','CANDIDATE') ORDER BY id LIMIT ?", [limit])]
    edges = [dict(row) for row in db.query("SELECT id,from_type,from_id,to_type,to_id,relation,reason,status FROM unresolved_edge WHERE status IN ('UNKNOWN','CANDIDATE') ORDER BY id LIMIT ?", [limit])]
    failed = [dict(row) for row in db.query("SELECT id,binary_id,analyzer,status,error_text FROM analysis_run WHERE status IN ('FAILED','ERROR') ORDER BY id LIMIT ?", [limit])]
    return {"generated_at": utc_now(), "hypotheses": hypotheses, "unresolved_edges": edges, "failed_analysis": failed}


def write_reports(db: Database, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    cov = coverage(db)
    arch = architecture_overview(db)
    unk = unknowns(db)
    (output_dir / "coverage.json").write_text(json.dumps(cov, ensure_ascii=False, indent=2), encoding="utf-8")
    (output_dir / "architecture-overview.json").write_text(json.dumps(arch, ensure_ascii=False, indent=2), encoding="utf-8")
    (output_dir / "unknowns.json").write_text(json.dumps(unk, ensure_ascii=False, indent=2), encoding="utf-8")
    lines = ["# Firmware Architecture Atlas (generated)", "", f"Firmware: {arch['firmware']}", "",
             f"Modules indexed: {len(arch['modules'])}", f"State machines indexed: {len(arch['state_machines'])}", "",
             "## Coverage", "", "```json", json.dumps(cov, ensure_ascii=False, indent=2), "```", "",
             "## Evidence and unknowns", "", f"Hypotheses needing verification: {len(unk['hypotheses'])}",
             f"Unresolved edges: {len(unk['unresolved_edges'])}", f"Failed analysis runs: {len(unk['failed_analysis'])}", ""]
    (output_dir / "architecture-overview.md").write_text("\n".join(lines), encoding="utf-8")
