from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .db import Database
from .importer import import_existing
from .inventory import build_manifest, export_manifest
from .report import architecture_overview, coverage, unknowns, write_reports
from .sdk import build_sdk_index


def _json_or_text(payload: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
        return
    if isinstance(payload, list):
        for row in payload:
            print(" | ".join(f"{k}={v}" for k, v in row.items()))
    elif isinstance(payload, dict):
        for key, value in payload.items():
            if isinstance(value, (dict, list)):
                print(f"{key}: {json.dumps(value, ensure_ascii=False, default=str)}")
            else:
                print(f"{key}: {value}")
    else:
        print(payload)


def _query(db: Database, kind: str, term: str) -> list[dict[str, Any]]:
    if kind == "function":
        rows = db.query("""SELECT f.id,f.name,f.address,f.status,f.size,b.path AS binary,m.name AS module,
                 f.vma,f.runtime_va,f.physical_offset,f.wbi_offset FROM function f
                 LEFT JOIN binary b ON b.id=f.binary_id LEFT JOIN module m ON m.id=f.module_id
                 WHERE f.name LIKE ? OR f.address LIKE ? ORDER BY f.name LIMIT 500""", [f"%{term}%", f"%{term}%"])
    elif kind == "event":
        rows = db.query("""SELECT e.id,e.namespace,e.value,e.name,e.status,e.description,
                 p.name AS producer_module,c.name AS consumer_module FROM event_id e
                 LEFT JOIN event_producer ep ON ep.event_id=e.id LEFT JOIN module p ON p.id=ep.module_id
                 LEFT JOIN event_consumer ec ON ec.event_id=e.id LEFT JOIN module c ON c.id=ec.module_id
                 WHERE e.value LIKE ? OR e.name LIKE ? OR e.description LIKE ? ORDER BY e.value LIMIT 500""",
                       [f"%{term}%", f"%{term}%", f"%{term}%"])
    elif kind == "module":
        rows = db.query("""SELECT m.id,m.name,m.domain,m.status,b.path AS binary,m.description,
                 (SELECT COUNT(*) FROM function f WHERE f.module_id=m.id) AS functions,
                 (SELECT COUNT(*) FROM lifecycle_callback l WHERE l.module_id=m.id) AS lifecycle_callbacks
                 FROM module m LEFT JOIN binary b ON b.id=m.binary_id WHERE m.name LIKE ? ORDER BY m.name LIMIT 500""", [f"%{term}%"])
    else:
        raise ValueError(f"unsupported query kind: {kind}")
    return [dict(row) for row in rows]


def _trace(db: Database, term: str, depth: int = 3) -> dict[str, Any]:
    rows = db.query("""SELECT m.name AS module,l.name AS callback,l.phase,l.status,f.name AS function,f.address
                      FROM lifecycle_callback l JOIN module m ON m.id=l.module_id
                      LEFT JOIN function f ON f.id=l.function_id
                      WHERE m.name LIKE ? OR l.name LIKE ? OR f.name LIKE ? ORDER BY m.name,l.phase""",
                    [f"%{term}%", f"%{term}%", f"%{term}%"])
    callgraph = db.query("""SELECT caller.name AS caller,caller.address AS caller_address,
                      callee.name AS callee,callee.address AS callee_address,
                      cs.address AS callsite,cs.kind,cs.status,
                      e.source_path AS evidence_source,e.status AS evidence_status
                      FROM callsite cs JOIN function caller ON caller.id=cs.caller_id
                      LEFT JOIN function callee ON callee.id=cs.callee_id
                      LEFT JOIN evidence e ON e.id=cs.source_evidence_id
                      WHERE caller.name LIKE ? OR callee.name LIKE ?
                      ORDER BY caller.name,cs.address LIMIT 1000""", [f"%{term}%", f"%{term}%"])
    paths: list[dict[str, Any]] = []
    frontier = [int(row[0]) for row in db.connection.execute("SELECT id FROM function WHERE name LIKE ? OR address LIKE ? LIMIT 100", [f"%{term}%", f"%{term}%"])]
    visited = set(frontier)
    for level in range(max(0, depth)):
        if not frontier:
            break
        placeholders = ",".join("?" for _ in frontier)
        edges = db.query(f"""SELECT cs.caller_id,cs.callee_id,cs.address,cs.kind,cs.status,
                             caller.name AS caller,callee.name AS callee,
                             e.source_path AS evidence_source,e.status AS evidence_status
                             FROM callsite cs JOIN function caller ON caller.id=cs.caller_id
                             LEFT JOIN function callee ON callee.id=cs.callee_id
                             LEFT JOIN evidence e ON e.id=cs.source_evidence_id
                             WHERE cs.caller_id IN ({placeholders}) ORDER BY cs.address""", frontier)
        next_frontier: list[int] = []
        for edge in edges:
            item = dict(edge); item["depth"] = level + 1; paths.append(item)
            if edge["callee_id"] is not None and int(edge["callee_id"]) not in visited:
                visited.add(int(edge["callee_id"])); next_frontier.append(int(edge["callee_id"]))
        frontier = next_frontier
    return {"lifecycle": [dict(row) for row in rows], "callgraph": [dict(row) for row in callgraph], "paths": paths, "dependencies": [dict(row) for row in db.query("""SELECT f.name AS from_module,t.name AS to_module,d.kind,d.status
                      FROM module_dependency d JOIN module f ON f.id=d.from_module_id JOIN module t ON t.id=d.to_module_id
                      WHERE f.name LIKE ? OR t.name LIKE ?""", [f"%{term}%", f"%{term}%"])]}


def _callers(db: Database, term: str) -> list[dict[str, Any]]:
    rows = db.query("""SELECT caller.id AS caller_id,caller.name AS caller,caller.address AS caller_address,
                      callee.id AS callee_id,callee.name AS callee,callee.address AS callee_address,
                      cs.address AS callsite,cs.kind,cs.status,
                      e.source_path AS evidence_source,e.status AS evidence_status
                      FROM callsite cs JOIN function caller ON caller.id=cs.caller_id
                      LEFT JOIN function callee ON callee.id=cs.callee_id
                      LEFT JOIN evidence e ON e.id=cs.source_evidence_id
                      WHERE callee.name LIKE ? OR callee.address LIKE ? OR cs.target LIKE ?
                      ORDER BY caller.name,cs.address LIMIT 1000""", [f"%{term}%", f"%{term}%", f"%{term}%"])
    return [dict(row) for row in rows]


def _callees(db: Database, term: str) -> list[dict[str, Any]]:
    rows = db.query("""SELECT caller.id AS caller_id,caller.name AS caller,caller.address AS caller_address,
                      callee.id AS callee_id,callee.name AS callee,callee.address AS callee_address,
                      cs.address AS callsite,cs.kind,cs.status,
                      e.source_path AS evidence_source,e.status AS evidence_status
                      FROM callsite cs JOIN function caller ON caller.id=cs.caller_id
                      LEFT JOIN function callee ON callee.id=cs.callee_id
                      LEFT JOIN evidence e ON e.id=cs.source_evidence_id
                      WHERE caller.name LIKE ? OR caller.address LIKE ?
                      ORDER BY caller.name,cs.address LIMIT 1000""", [f"%{term}%", f"%{term}%"])
    return [dict(row) for row in rows]


def _callsites(db: Database, value: str) -> list[dict[str, Any]]:
    rows = db.query("""SELECT cs.id,cs.address,cs.target,cs.kind,cs.status,cs.address_space,
                      caller.name AS caller,caller.address AS caller_address,
                      callee.name AS callee,callee.address AS callee_address,
                      e.source_path AS evidence_source,e.status AS evidence_status
                      FROM callsite cs JOIN function caller ON caller.id=cs.caller_id
                      LEFT JOIN function callee ON callee.id=cs.callee_id
                      LEFT JOIN evidence e ON e.id=cs.source_evidence_id
                      WHERE cs.address LIKE ? OR cs.target LIKE ? OR caller.name LIKE ? OR callee.name LIKE ?
                      ORDER BY cs.address LIMIT 1000""", [f"%{value}%", f"%{value}%", f"%{value}%", f"%{value}%"])
    return [dict(row) for row in rows]


def _xrefs(db: Database, value: str) -> list[dict[str, Any]]:
    binary, _, address = value.partition(":")
    rows = [dict(row) for row in db.query("""SELECT 'cross_reference' AS relation,x.kind,x.status,x.from_address,x.to_address,
        fb.path AS from_binary,tb.path AS to_binary FROM cross_reference x
        LEFT JOIN binary fb ON fb.id=x.from_binary_id LEFT JOIN binary tb ON tb.id=x.to_binary_id
        WHERE (fb.path LIKE ? AND x.from_address LIKE ?) OR (tb.path LIKE ? AND x.to_address LIKE ?)""",
        [f"%{binary}%", f"%{address}%", f"%{binary}%", f"%{address}%"])]
    rows.extend(dict(row) for row in db.query("""SELECT 'callsite' AS relation,cs.kind,cs.status,cs.address AS from_address,cs.target AS to_address,
        b.path AS from_binary,b.path AS to_binary FROM callsite cs JOIN function f ON f.id=cs.caller_id JOIN binary b ON b.id=f.binary_id
        WHERE b.path LIKE ? AND (cs.address LIKE ? OR cs.target LIKE ?)""",
        [f"%{binary}%", f"%{address}%", f"%{address}%"]))
    return rows


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fw", description="A6000 firmware inventory and evidence queries")
    parser.add_argument("--db", type=Path, default=Path("database/firmware.db"), help="SQLite database")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    manifest = commands.add_parser("manifest")
    manifest_sub = manifest.add_subparsers(dest="manifest_command", required=True)
    build = manifest_sub.add_parser("build"); build.add_argument("--root", type=Path, required=True); build.add_argument("--limit", type=int); build.add_argument("--json", action="store_true")
    export = manifest_sub.add_parser("export"); export.add_argument("--output", type=Path, default=Path("reports/manifest.json")); export.add_argument("--json", action="store_true")
    imp = commands.add_parser("import"); imp_sub = imp.add_subparsers(dest="import_command", required=True)
    existing = imp_sub.add_parser("existing"); existing.add_argument("--root", type=Path, required=True); existing.add_argument("--json", action="store_true")
    query = commands.add_parser("query"); query.add_argument("kind", choices=["function", "event", "module"]); query.add_argument("term"); query.add_argument("--json", action="store_true")
    trace = commands.add_parser("trace"); trace.add_argument("term"); trace.add_argument("--depth", type=int, default=3); trace.add_argument("--json", action="store_true")
    callers = commands.add_parser("callers"); callers.add_argument("term"); callers.add_argument("--json", action="store_true")
    callees = commands.add_parser("callees"); callees.add_argument("term"); callees.add_argument("--json", action="store_true")
    callsite = commands.add_parser("callsite"); callsite.add_argument("term"); callsite.add_argument("--json", action="store_true")
    xrefs = commands.add_parser("xrefs"); xrefs.add_argument("address"); xrefs.add_argument("--json", action="store_true")
    domain = commands.add_parser("domain"); domain.add_argument("name"); domain.add_argument("--json", action="store_true")
    for name in ("coverage", "unknowns", "architecture"):
        command = commands.add_parser(name); command.add_argument("--json", action="store_true")
    reports = commands.add_parser("reports"); reports.add_argument("--output-dir", type=Path, default=Path("reports")); reports.add_argument("--phase2", action="store_true"); reports.add_argument("--json", action="store_true")
    sdk = commands.add_parser("sdk"); sdk_sub = sdk.add_subparsers(dest="sdk_command", required=True)
    sdk_build = sdk_sub.add_parser("build"); sdk_build.add_argument("--output", type=Path, default=Path("sdk/sdk-index.json")); sdk_build.add_argument("--json", action="store_true")
    analyze = commands.add_parser("analyze"); analyze_sub = analyze.add_subparsers(dest="analyze_command", required=True)
    elf = analyze_sub.add_parser("elf"); elf.add_argument("--root", type=Path, required=True); elf.add_argument("--limit", type=int); elf.add_argument("--json", action="store_true")
    ghidra = analyze_sub.add_parser("ghidra"); ghidra.add_argument("--root", type=Path, required=True); ghidra.add_argument("--binary", type=Path, required=True); ghidra.add_argument("--jsonl", type=Path, required=True); ghidra.add_argument("--json", action="store_true")
    linkage = analyze_sub.add_parser("linkage"); linkage.add_argument("--root", type=Path, required=True); linkage.add_argument("--limit", type=int); linkage.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(message)s")
    db = Database(args.db)
    db.migrate()
    try:
        if args.command == "manifest" and args.manifest_command == "build":
            result = build_manifest(db, args.root, args.limit); _json_or_text(result, args.json)
        elif args.command == "manifest" and args.manifest_command == "export":
            result = {"rows": export_manifest(db, args.output), "output": str(args.output)}; _json_or_text(result, args.json)
        elif args.command == "import" and args.import_command == "existing":
            result = import_existing(db, args.root); _json_or_text(result, args.json)
        elif args.command == "query":
            _json_or_text(_query(db, args.kind, args.term), args.json)
        elif args.command == "trace":
            _json_or_text(_trace(db, args.term, args.depth), args.json)
        elif args.command == "callers":
            _json_or_text(_callers(db, args.term), args.json)
        elif args.command == "callees":
            _json_or_text(_callees(db, args.term), args.json)
        elif args.command == "callsite":
            _json_or_text(_callsites(db, args.term), args.json)
        elif args.command == "xrefs":
            _json_or_text(_xrefs(db, args.address), args.json)
        elif args.command == "domain":
            overview = architecture_overview(db); rows = overview["domains"].get(args.name, [])
            _json_or_text(rows, args.json)
        elif args.command == "coverage":
            _json_or_text(coverage(db), args.json)
        elif args.command == "unknowns":
            _json_or_text(unknowns(db), args.json)
        elif args.command == "architecture":
            _json_or_text(architecture_overview(db), args.json)
        elif args.command == "reports":
            write_reports(db, args.output_dir)
            result = {"output_dir": str(args.output_dir)}
            if args.phase2:
                from .phase2_reports import write_phase2_reports
                result.update(write_phase2_reports(db, args.output_dir))
            _json_or_text(result, args.json)
        elif args.command == "sdk" and args.sdk_command == "build":
            _json_or_text(build_sdk_index(db, args.output), args.json)
        elif args.command == "analyze" and args.analyze_command == "elf":
            from analyzers.runner import run_elf_batch
            _json_or_text(run_elf_batch(db, args.root, args.limit), args.json)
        elif args.command == "analyze" and args.analyze_command == "ghidra":
            from .ghidra_importer import import_ghidra_jsonl
            _json_or_text(import_ghidra_jsonl(db, args.root, args.binary, args.jsonl), args.json)
        elif args.command == "analyze" and args.analyze_command == "linkage":
            from .linkage import analyze_linkage
            _json_or_text(analyze_linkage(db, args.root, args.limit), args.json)
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
