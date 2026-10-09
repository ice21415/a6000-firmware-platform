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
from .semantic_graph import export_graph, sync_semantic_graph, validate_graph_provenance


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
    elif kind == "dex":
        rows = db.query("""SELECT id,source_path,source_sha256,observation_type,locator,
            value_json,status,source_evidence_id FROM research_observation
            WHERE observation_type IN (
                'dex_string','dex_descriptor_candidate','dex_signature_candidate',
                'dex_type_id','dex_class_definition','dex_method_reference'
            )
            AND value_json LIKE ? ORDER BY source_path,id LIMIT 500""", [f"%{term}%"])
    else:
        raise ValueError(f"unsupported query kind: {kind}")
    return [dict(row) for row in rows]


def _semantic_trace(db: Database, term: str, depth: int = 3) -> list[dict[str, Any]]:
    starts = db.query("SELECT id FROM semantic_node WHERE label LIKE ? OR identity_key LIKE ? ORDER BY id LIMIT 100", [f"%{term}%", f"%{term}%"])
    frontier = [int(row[0]) for row in starts]
    visited = set(frontier)
    paths: list[dict[str, Any]] = []
    for level in range(max(0, depth)):
        if not frontier:
            break
        placeholders = ",".join("?" for _ in frontier)
        edges = db.query(f"""SELECT e.*,s.label AS source_label,t.label AS target_label,t.node_type AS target_type
            FROM semantic_edge e JOIN semantic_node s ON s.id=e.source_node_id
            LEFT JOIN semantic_node t ON t.id=e.target_node_id
            WHERE e.source_node_id IN ({placeholders}) ORDER BY e.id""", frontier)
        next_frontier: list[int] = []
        for edge in edges:
            item = dict(edge); item["depth"] = level + 1; paths.append(item)
            if edge["target_node_id"] is not None and int(edge["target_node_id"]) not in visited:
                visited.add(int(edge["target_node_id"])); next_frontier.append(int(edge["target_node_id"]))
        frontier = next_frontier
    return paths


def _trace(db: Database, term: str, depth: int = 3, cross_module: bool = False) -> dict[str, Any]:
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
    result = {"lifecycle": [dict(row) for row in rows], "callgraph": [dict(row) for row in callgraph], "paths": paths, "dependencies": [dict(row) for row in db.query("""SELECT f.name AS from_module,t.name AS to_module,d.kind,d.status
                      FROM module_dependency d JOIN module f ON f.id=d.from_module_id JOIN module t ON t.id=d.to_module_id
                      WHERE f.name LIKE ? OR t.name LIKE ?""", [f"%{term}%", f"%{term}%"])]}
    if cross_module:
        sync_semantic_graph(db)
        result["semantic_paths"] = _semantic_trace(db, term, depth)
    return result


def _protocol_queue(db: Database, value: str) -> list[dict[str, Any]]:
    rows = db.query("""SELECT q.id AS queue_id,q.namespace,q.queue_value,q.name AS queue_name,q.semantics AS queue_semantics,q.status AS queue_status,
        m.id AS message_id,m.direction,m.semantics,m.payload_layout,m.timeout_ms,m.status,m.source_evidence_id,q.address_space,
        e.source_path AS evidence_source,e.source_sha256,e.status AS evidence_status,
        mi.namespace AS command_namespace,mi.value AS command_value,mi.name AS command_name,
        pf.name AS producer,cf.name AS consumer,cb.name AS callback,
        (SELECT GROUP_CONCAT(pm.name) FROM message_flow fp LEFT JOIN module pm ON pm.id=fp.module_id WHERE fp.osal_message_id=m.id AND fp.role='producer') AS producer_modules,
        (SELECT GROUP_CONCAT(cm.name) FROM message_flow fc LEFT JOIN module cm ON cm.id=fc.module_id WHERE fc.osal_message_id=m.id AND fc.role='consumer') AS consumer_modules
        FROM message_queue q LEFT JOIN osal_message m ON m.queue_id=q.id
        LEFT JOIN message_id mi ON mi.id=m.message_id LEFT JOIN function pf ON pf.id=m.producer_function_id
        LEFT JOIN function cf ON cf.id=m.consumer_function_id LEFT JOIN function cb ON cb.id=m.callback_function_id
        LEFT JOIN evidence e ON e.id=m.source_evidence_id
        WHERE q.queue_value LIKE ? OR q.address LIKE ? ORDER BY m.id""", [f"%{value}%", f"%{value}%"])
    output = []
    for row in rows:
        item = dict(row); missing = []
        if row["consumer"] is None and row["consumer_modules"] is None: missing.append("consumer")
        if row["callback"] is None and row["consumer_modules"] is None: missing.append("callback")
        if row["source_evidence_id"] is None: missing.append("evidence")
        item["missing_dependencies"] = missing; output.append(item)
    return output


def _state_query(db: Database, term: str) -> dict[str, Any]:
    machines = db.query("SELECT sm.*,m.name AS module FROM state_machine sm LEFT JOIN module m ON m.id=sm.module_id WHERE sm.name LIKE ? OR m.name LIKE ?", [f"%{term}%", f"%{term}%"])
    result = {"machines": [dict(row) for row in machines], "states": [], "transitions": []}
    ids = [int(row["id"]) for row in machines]
    if ids:
        marks = ",".join("?" for _ in ids)
        result["states"] = [dict(row) for row in db.query(f"SELECT * FROM state WHERE machine_id IN ({marks}) ORDER BY machine_id,id", ids)]
        result["transitions"] = [dict(row) for row in db.query(f"SELECT st.*,fs.name AS from_state,ts.name AS to_state,e.namespace,e.value AS event_value,e.name AS event_name FROM state_transition st LEFT JOIN state fs ON fs.id=st.from_state_id LEFT JOIN state ts ON ts.id=st.to_state_id LEFT JOIN event_id e ON e.id=st.event_id WHERE st.machine_id IN ({marks}) ORDER BY st.id", ids)]
    return result


def _api_query(db: Database, term: str) -> list[dict[str, Any]]:
    return [dict(row) for row in db.query("""SELECT s.*,m.name AS module,b.path AS binary,f.name AS function_name,f.address AS function_address
        FROM sdk_interface s LEFT JOIN module m ON m.id=s.module_id LEFT JOIN binary b ON b.id=s.binary_id LEFT JOIN function f ON f.id=s.function_id
        WHERE s.name LIKE ? OR s.domain LIKE ? OR m.name LIKE ? ORDER BY s.domain,s.name""", [f"%{term}%", f"%{term}%", f"%{term}%"])]


def _evidence_query(db: Database, term: str) -> list[dict[str, Any]]:
    rows = db.query("""SELECT e.id,e.identity_key,e.relation_type,e.status,e.provenance_kind,e.address_space,
        e.source_address,e.target_address,e.evidence_id,e.analyzer_version,
        ev.source_path,ev.source_sha256,ev.status AS evidence_status,
        s.label AS source,t.label AS target
        FROM semantic_edge e LEFT JOIN evidence ev ON ev.id=e.evidence_id
        LEFT JOIN semantic_node s ON s.id=e.source_node_id LEFT JOIN semantic_node t ON t.id=e.target_node_id
        WHERE CAST(e.id AS TEXT)=? OR e.identity_key LIKE ? OR s.label LIKE ? OR t.label LIKE ? OR e.relation_type LIKE ?
        ORDER BY e.id LIMIT 500""", [term, f"%{term}%", f"%{term}%", f"%{term}%", f"%{term}%"])
    output = []
    for row in rows:
        item = dict(row); item["missing_dependencies"] = []
        if row["evidence_id"] is None: item["missing_dependencies"].append("evidence")
        if row["target"] is None: item["missing_dependencies"].append("target")
        if row["source_address"] is not None and not row["address_space"]: item["missing_dependencies"].append("address_space")
        output.append(item)
    return output


def _unresolved_query(db: Database) -> list[dict[str, Any]]:
    return [dict(row) for row in db.query("""SELECT u.*,e.source_path,e.source_sha256 FROM unresolved_edge u
        LEFT JOIN evidence e ON e.id=u.source_evidence_id ORDER BY u.id""")]


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
    query = commands.add_parser("query"); query.add_argument("kind", choices=["function", "event", "module", "api", "dex"]); query.add_argument("term"); query.add_argument("--json", action="store_true")
    trace = commands.add_parser("trace"); trace.add_argument("term"); trace.add_argument("--depth", type=int, default=3); trace.add_argument("--cross-module", action="store_true"); trace.add_argument("--json", action="store_true")
    callers = commands.add_parser("callers"); callers.add_argument("term"); callers.add_argument("--json", action="store_true")
    callees = commands.add_parser("callees"); callees.add_argument("term"); callees.add_argument("--json", action="store_true")
    callsite = commands.add_parser("callsite"); callsite.add_argument("term"); callsite.add_argument("--json", action="store_true")
    xrefs = commands.add_parser("xrefs"); xrefs.add_argument("address"); xrefs.add_argument("--json", action="store_true")
    protocol = commands.add_parser("protocol"); protocol_sub = protocol.add_subparsers(dest="protocol_command", required=True)
    protocol_queue = protocol_sub.add_parser("queue"); protocol_queue.add_argument("value"); protocol_queue.add_argument("--json", action="store_true")
    state = commands.add_parser("state"); state.add_argument("term"); state.add_argument("--json", action="store_true")
    domain = commands.add_parser("domain"); domain.add_argument("name"); domain.add_argument("--json", action="store_true")
    coverage_cmd = commands.add_parser("coverage"); coverage_cmd.add_argument("--domain"); coverage_cmd.add_argument("--json", action="store_true")
    for name in ("unknowns", "architecture"):
        command = commands.add_parser(name); command.add_argument("--json", action="store_true")
    evidence = commands.add_parser("evidence"); evidence.add_argument("term"); evidence.add_argument("--json", action="store_true")
    unresolved = commands.add_parser("unresolved"); unresolved.add_argument("--json", action="store_true")
    reports = commands.add_parser("reports"); reports.add_argument("--output-dir", type=Path, default=Path("reports")); reports.add_argument("--phase2", action="store_true"); reports.add_argument("--phase3", action="store_true"); reports.add_argument("--phase3-1", action="store_true"); reports.add_argument("--json", action="store_true")
    sdk = commands.add_parser("sdk"); sdk_sub = sdk.add_subparsers(dest="sdk_command", required=True)
    sdk_build = sdk_sub.add_parser("build"); sdk_build.add_argument("--output", type=Path, default=Path("sdk/sdk-index.json")); sdk_build.add_argument("--json", action="store_true")
    sdk_cov = sdk_sub.add_parser("coverage"); sdk_cov.add_argument("--json", action="store_true")
    sdk_import = sdk_sub.add_parser("import"); sdk_import.add_argument("--fixture", type=Path, required=True); sdk_import.add_argument("--json", action="store_true")
    sdk_audit = sdk_sub.add_parser("audit"); sdk_audit.add_argument("--json", action="store_true")
    sdk_mock = sdk_sub.add_parser("mock"); sdk_mock.add_argument("--scenario", type=Path, required=True); sdk_mock.add_argument("--json", action="store_true")
    sdk_research = sdk_sub.add_parser("research")
    sdk_research.add_argument("--catalog", type=Path, default=Path("sdk/camera_3_21_static_candidates.json"))
    sdk_research.add_argument("--graph", type=Path, default=Path("sdk/camera_3_21_static_callgraph.json"))
    sdk_research.add_argument("--focus", default="")
    sdk_research.add_argument("--compare-db", type=Path)
    sdk_research.add_argument("--verify-elf", type=Path)
    sdk_research.add_argument("--json", action="store_true")
    sdk_rea_bridge = sdk_sub.add_parser("rea-bridge")
    sdk_rea_bridge.add_argument("--fixture", type=Path, default=Path("sdk/ui_camera_3_21_rea_bridge.json"))
    sdk_rea_bridge.add_argument("--ui-decompile", type=Path)
    sdk_rea_bridge.add_argument("--camera-audit", type=Path)
    sdk_rea_bridge.add_argument("--json", action="store_true")
    sdk_discover = sdk_sub.add_parser("discover")
    sdk_discover.add_argument("--name", default="")
    sdk_discover.add_argument("--binary-sha256", default="")
    sdk_discover.add_argument("--domain", default="")
    sdk_discover.add_argument("--include-internal", action="store_true")
    sdk_discover.add_argument("--include-generated", action="store_true")
    sdk_discover.add_argument("--limit", type=int, default=100)
    sdk_discover.add_argument("--json", action="store_true")
    sdk_investigate = sdk_sub.add_parser("investigate")
    sdk_investigate.add_argument("--domain", default="Camera")
    sdk_investigate.add_argument("--name", default="")
    sdk_investigate.add_argument("--binary-sha256", default="")
    sdk_investigate.add_argument("--include-internal", action="store_true")
    sdk_investigate.add_argument("--include-generated", action="store_true")
    sdk_investigate.add_argument("--limit", type=int, default=25)
    sdk_investigate.add_argument("--relation-limit", type=int, default=8)
    sdk_investigate.add_argument("--json", action="store_true")
    sdk_inspect = sdk_sub.add_parser("inspect")
    sdk_inspect.add_argument("--function-id", type=int, required=True)
    sdk_inspect.add_argument("--relation-limit", type=int, default=8)
    sdk_inspect.add_argument("--json", action="store_true")
    sdk_draft = sdk_sub.add_parser("draft")
    sdk_draft.add_argument("--output", type=Path, required=True)
    sdk_draft.add_argument("--firmware-version", default="3.21")
    sdk_draft.add_argument("--name", default="")
    sdk_draft.add_argument("--binary-sha256", default="")
    sdk_draft.add_argument("--domain", default="")
    sdk_draft.add_argument("--include-internal", action="store_true")
    sdk_draft.add_argument("--limit", type=int, default=100)
    sdk_draft.add_argument("--json", action="store_true")
    analyze = commands.add_parser("analyze"); analyze_sub = analyze.add_subparsers(dest="analyze_command", required=True)
    elf = analyze_sub.add_parser("elf"); elf.add_argument("--root", type=Path, required=True); elf.add_argument("--limit", type=int); elf.add_argument("--json", action="store_true")
    ghidra = analyze_sub.add_parser("ghidra"); ghidra.add_argument("--root", type=Path, required=True); ghidra.add_argument("--binary", type=Path, required=True); ghidra.add_argument("--jsonl", type=Path, required=True); ghidra.add_argument("--json", action="store_true")
    batch = analyze_sub.add_parser("ghidra-batch")
    batch.add_argument("--root", type=Path, required=True)
    batch.add_argument("--limit", type=int, default=5)
    batch.add_argument("--force", action="store_true")
    batch.add_argument("--execute", action="store_true")
    batch.add_argument("--ghidra-root", type=Path)
    batch.add_argument("--project-dir", type=Path)
    batch.add_argument("--output-dir", type=Path)
    batch.add_argument("--timeout", type=int, default=3600)
    batch.add_argument("--json", action="store_true")
    linkage = analyze_sub.add_parser("linkage"); linkage.add_argument("--root", type=Path, required=True); linkage.add_argument("--limit", type=int); linkage.add_argument("--json", action="store_true")
    osal = analyze_sub.add_parser("osal"); osal.add_argument("--fixture", type=Path, required=True); osal.add_argument("--json", action="store_true")
    jni = analyze_sub.add_parser("jni"); jni.add_argument("--fixture", type=Path, required=True); jni.add_argument("--json", action="store_true")
    dex = analyze_sub.add_parser("dex"); dex.add_argument("--path", type=Path, required=True); dex.add_argument("--json", action="store_true")
    semantic = analyze_sub.add_parser("semantic"); semantic.add_argument("--json", action="store_true")
    evidence_ingest = analyze_sub.add_parser("evidence"); evidence_ingest.add_argument("--root", type=Path, required=True); evidence_ingest.add_argument("--profile", default="targeted"); evidence_ingest.add_argument("--json", action="store_true")
    graph = commands.add_parser("graph"); graph_sub = graph.add_subparsers(dest="graph_command", required=True)
    graph_export = graph_sub.add_parser("export"); graph_export.add_argument("--format", choices=["json", "graphml"], default="json"); graph_export.add_argument("--output", type=Path, required=True); graph_export.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(message)s")
    if args.command == "sdk" and args.sdk_command == "mock":
        # Mock replay is pure: do not create or migrate a SQLite database.
        from .sdk_mock import simulate_protocol
        result = simulate_protocol(args.scenario)
        _json_or_text(result, args.json)
        return 0 if result["status"] == "PASS" else 2
    if args.command == "sdk" and args.sdk_command == "rea-bridge":
        from .rea_bridge import audit_rea_ui_camera_bridge
        result = audit_rea_ui_camera_bridge(
            args.fixture, ui_decompile=args.ui_decompile,
            camera_audit=args.camera_audit,
        )
        _json_or_text(result, args.json)
        return 0
    if args.command == "sdk" and args.sdk_command == "research":
        # Pure report validator: do not open/migrate any SQLite or firmware ELF.
        from .camera_research import inspect_camera_research
        result = inspect_camera_research(args.catalog, args.graph, focus=args.focus,
                                         compare_db=args.compare_db,
                                         verify_elf=args.verify_elf)
        _json_or_text(result, args.json)
        check = result["independent_elf_check"]
        return 2 if check is not None and not check["all_checked_instruction_sites_match"] else 0
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
            _json_or_text(_api_query(db, args.term) if args.kind == "api" else _query(db, args.kind, args.term), args.json)
        elif args.command == "trace":
            _json_or_text(_trace(db, args.term, args.depth, args.cross_module), args.json)
        elif args.command == "callers":
            _json_or_text(_callers(db, args.term), args.json)
        elif args.command == "callees":
            _json_or_text(_callees(db, args.term), args.json)
        elif args.command == "callsite":
            _json_or_text(_callsites(db, args.term), args.json)
        elif args.command == "xrefs":
            _json_or_text(_xrefs(db, args.address), args.json)
        elif args.command == "protocol" and args.protocol_command == "queue":
            _json_or_text(_protocol_queue(db, args.value), args.json)
        elif args.command == "state":
            _json_or_text(_state_query(db, args.term), args.json)
        elif args.command == "domain":
            overview = architecture_overview(db); rows = overview["domains"].get(args.name, [])
            _json_or_text(rows, args.json)
        elif args.command == "coverage":
            _json_or_text(coverage(db, args.domain), args.json)
        elif args.command == "unknowns":
            _json_or_text(unknowns(db), args.json)
        elif args.command == "architecture":
            _json_or_text(architecture_overview(db), args.json)
        elif args.command == "evidence":
            _json_or_text(_evidence_query(db, args.term), args.json)
        elif args.command == "unresolved":
            _json_or_text(_unresolved_query(db), args.json)
        elif args.command == "reports":
            write_reports(db, args.output_dir)
            result = {"output_dir": str(args.output_dir)}
            if args.phase2:
                from .phase2_reports import write_phase2_reports
                result.update(write_phase2_reports(db, args.output_dir))
            if args.phase3:
                from .phase3_reports import write_phase3_reports
                result.update(write_phase3_reports(db, args.output_dir))
            if args.phase3_1:
                from .phase3_1_reports import write_phase3_1_reports
                result.update(write_phase3_1_reports(db, args.output_dir))
            _json_or_text(result, args.json)
        elif args.command == "sdk" and args.sdk_command == "build":
            _json_or_text(build_sdk_index(db, args.output), args.json)
        elif args.command == "sdk" and args.sdk_command == "coverage":
            from .sdk_contracts import audit_sdk_contracts
            rows = db.query("SELECT verification_status,COUNT(*) AS count FROM sdk_interface GROUP BY verification_status ORDER BY verification_status")
            audit = audit_sdk_contracts(db)
            _json_or_text({"interfaces": [dict(row) for row in rows],
                           "static_contract_complete": audit["static_contract_complete"],
                           "domain_matrix": audit["domain_matrix"],
                           "runtime_callable_validated": None}, args.json)
        elif args.command == "sdk" and args.sdk_command == "import":
            from .sdk_contracts import import_sdk_contracts
            _json_or_text(import_sdk_contracts(db, args.fixture), args.json)
        elif args.command == "sdk" and args.sdk_command == "audit":
            from .sdk_contracts import audit_sdk_contracts
            _json_or_text(audit_sdk_contracts(db), args.json)
        elif args.command == "sdk" and args.sdk_command == "discover":
            from .sdk_discovery import discover_sdk_candidates
            _json_or_text(discover_sdk_candidates(
                db, name=args.name, binary_sha256=args.binary_sha256,
                domain=args.domain, include_internal=args.include_internal,
                include_generated=args.include_generated, limit=args.limit,
            ), args.json)
        elif args.command == "sdk" and args.sdk_command == "investigate":
            from .core_api import investigate_core_apis
            _json_or_text(investigate_core_apis(
                db, domain=args.domain, name=args.name,
                binary_sha256=args.binary_sha256,
                include_internal=args.include_internal,
                include_generated=args.include_generated,
                limit=args.limit, relation_limit=args.relation_limit,
            ), args.json)
        elif args.command == "sdk" and args.sdk_command == "inspect":
            from .function_inspection import inspect_function
            _json_or_text(inspect_function(
                db, function_id=args.function_id,
                relation_limit=args.relation_limit,
            ), args.json)
        elif args.command == "sdk" and args.sdk_command == "draft":
            from .sdk_review import draft_sdk_review
            _json_or_text(draft_sdk_review(
                db, args.output, firmware_version=args.firmware_version,
                name=args.name, binary_sha256=args.binary_sha256,
                domain=args.domain, include_internal=args.include_internal,
                limit=args.limit,
            ), args.json)
        elif args.command == "analyze" and args.analyze_command == "elf":
            from analyzers.runner import run_elf_batch
            _json_or_text(run_elf_batch(db, args.root, args.limit), args.json)
        elif args.command == "analyze" and args.analyze_command == "ghidra":
            from .ghidra_importer import import_ghidra_jsonl
            _json_or_text(import_ghidra_jsonl(db, args.root, args.binary, args.jsonl), args.json)
        elif args.command == "analyze" and args.analyze_command == "ghidra-batch":
            from .ghidra_batch import plan_ghidra_batch, run_ghidra_batch
            if args.execute:
                if args.ghidra_root is None or args.project_dir is None or args.output_dir is None:
                    parser.error("--execute requires --ghidra-root, --project-dir and --output-dir")
                result = run_ghidra_batch(
                    db, args.root, ghidra_root=args.ghidra_root,
                    project_dir=args.project_dir, output_dir=args.output_dir,
                    limit=args.limit, force=args.force, timeout=args.timeout,
                )
                _json_or_text(result, args.json)
                return 0 if result["status"] == "COMPLETE" else 2
            _json_or_text(plan_ghidra_batch(
                db, args.root, limit=args.limit, force=args.force,
            ), args.json)
        elif args.command == "analyze" and args.analyze_command == "linkage":
            from .linkage import analyze_linkage
            _json_or_text(analyze_linkage(db, args.root, args.limit), args.json)
        elif args.command == "analyze" and args.analyze_command == "osal":
            from .osal import import_osal_fixture
            _json_or_text(import_osal_fixture(db, args.fixture), args.json)
        elif args.command == "analyze" and args.analyze_command == "jni":
            from .jni import import_jni_fixture
            _json_or_text(import_jni_fixture(db, args.fixture), args.json)
        elif args.command == "analyze" and args.analyze_command == "dex":
            from .dex_index import index_dex
            _json_or_text(index_dex(db, args.path), args.json)
        elif args.command == "analyze" and args.analyze_command == "semantic":
            _json_or_text(sync_semantic_graph(db), args.json)
        elif args.command == "analyze" and args.analyze_command == "evidence":
            from .evidence_ingestion import ingest_research_evidence
            _json_or_text(ingest_research_evidence(db, args.root, args.profile), args.json)
        elif args.command == "graph" and args.graph_command == "export":
            sync_semantic_graph(db)
            _json_or_text(export_graph(db, args.output, args.format), args.json)
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
