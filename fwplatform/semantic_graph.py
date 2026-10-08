from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from . import __version__
from .db import Database, utc_now

RELATION_TYPES = {
    "CALLS", "REFERENCES", "IMPORTS", "EXPORTS", "DEPENDS_ON", "REGISTERS_CALLBACK",
    "SENDS_MESSAGE", "RECEIVES_MESSAGE", "DISPATCHES_EVENT", "HANDLES_EVENT",
    "TRANSITIONS_TO", "JNI_BRIDGE", "IMPLEMENTS", "ACCESSES_DEVICE", "INVOKES_IOCTL",
    "CONTROL_FLOW",
}


def _status(row: Any) -> str:
    if isinstance(row, dict):
        raw = row.get("status")
    else:
        raw = row["status"] if "status" in row.keys() else None
    value = str(raw or "UNKNOWN")
    return value if value in {"VERIFIED_STATIC", "VERIFIED_RUNTIME", "INFERRED", "CANDIDATE", "UNKNOWN", "DISPROVEN"} else "UNKNOWN"


def _provenance(db: Database, evidence_id: int | None, default: str = "NO_PRIMARY_EVIDENCE") -> str:
    if evidence_id is None:
        return default
    row = db.connection.execute("SELECT evidence_type,kind,source_path FROM evidence WHERE id=?", (evidence_id,)).fetchone()
    if not row:
        return "MISSING_EVIDENCE"
    text = " ".join(str(v or "").lower() for v in row)
    if "synthetic" in text or "fixture" in text or "test" in text:
        return "SYNTHETIC_FIXTURE"
    if "ghidra" in text:
        return "GHIDRA_DERIVED"
    if "elf" in text or "linkage" in text:
        return "ELF_DEPENDENCY"
    if any(token in text for token in ("research", "osal", "jni", "camera", "imdb", "vtable", "rea")):
        return "IMPORTED_RESEARCH"
    return "FILE_EVIDENCE"


def _node(db: Database, *, node_type: str, identity_key: str, entity_table: str | None,
          entity_id: int | None, label: str | None, namespace: str | None = None,
          binary_id: int | None = None, address: str | None = None,
          address_space: str | None = None, status: str = "UNKNOWN",
          evidence_id: int | None = None, analyzer_version: str | None = None,
          metadata: dict[str, Any] | None = None, provenance_kind: str | None = None) -> int:
    status = status if status in {"VERIFIED_STATIC", "VERIFIED_RUNTIME", "INFERRED", "CANDIDATE", "UNKNOWN", "DISPROVEN"} else "UNKNOWN"
    return db.upsert("semantic_node", {"node_type": node_type, "identity_key": identity_key,
        "entity_table": entity_table, "entity_id": entity_id, "label": label,
        "namespace": namespace, "binary_id": binary_id, "address": address,
        "address_space": address_space, "status": status,
        "confidence_id": db.confidence_id(status), "source_evidence_id": evidence_id,
        "analyzer_version": analyzer_version, "provenance_kind": provenance_kind or _provenance(db, evidence_id),
        "metadata_json": json.dumps(metadata or {}, ensure_ascii=False, sort_keys=True)},
        ("identity_key",))


def _edge(db: Database, *, source_id: int, target_id: int | None, relation: str,
          status: str, source_binary_id: int | None = None, target_binary_id: int | None = None,
          address_space: str | None = None, source_address: str | None = None,
          target_address: str | None = None, evidence_id: int | None = None,
          analyzer_version: str | None = None, metadata: dict[str, Any] | None = None,
          provenance_kind: str | None = None) -> int:
    if relation not in RELATION_TYPES:
        raise ValueError(f"unsupported semantic relation: {relation}")
    status = status if status in {"VERIFIED_STATIC", "VERIFIED_RUNTIME", "INFERRED", "CANDIDATE", "UNKNOWN", "DISPROVEN"} else "UNKNOWN"
    identity = "edge:" + ":".join(str(value or "") for value in (
        source_id, target_id, relation, address_space, source_address, target_address,
        evidence_id, json.dumps(metadata or {}, sort_keys=True)))
    return db.upsert("semantic_edge", {"identity_key": identity, "source_node_id": source_id,
        "target_node_id": target_id, "relation_type": relation, "source_binary_id": source_binary_id,
        "target_binary_id": target_binary_id, "address_space": address_space,
        "source_address": source_address, "target_address": target_address,
        "evidence_id": evidence_id, "status": status, "confidence_id": db.confidence_id(status),
        "analyzer_version": analyzer_version, "provenance_kind": provenance_kind or _provenance(db, evidence_id),
        "metadata_json": json.dumps(metadata or {}, ensure_ascii=False, sort_keys=True)},
        ("identity_key",))


def sync_semantic_graph(db: Database, analyzer_version: str = f"semantic-graph:{__version__}") -> dict[str, Any]:
    """Materialize typed database relations as an idempotent evidence graph."""
    run_key = f"semantic-graph:{analyzer_version}"
    run_id = db.upsert("semantic_graph_run", {"run_key": run_key, "analyzer": "semantic_graph",
        "analyzer_version": analyzer_version, "status": "RUNNING", "started_at": utc_now(),
        "completed_at": None, "node_count": 0, "edge_count": 0, "error_text": None,
        "metadata_json": "{}"}, ("run_key",))
    nodes: dict[tuple[str, int], int] = {}
    binaries = {int(row["id"]): dict(row) for row in db.query("SELECT * FROM binary")}
    try:
        for row in binaries.values():
            nodes[("binary", int(row["id"]))] = _node(db, node_type="Binary",
                identity_key=f"binary:{row['sha256']}:{row['path']}", entity_table="binary", entity_id=int(row["id"]),
                label=str(row["path"]), binary_id=int(row["id"]), address=str(row["entry_vma"] or "") or None,
                status="VERIFIED_STATIC", metadata={"sha256": row["sha256"], "format": row["format"]}, analyzer_version=analyzer_version)
        for row in db.query("SELECT * FROM module"):
            nodes[("module", int(row["id"]))] = _node(db, node_type="Module", identity_key=f"module:{row['identity_key']}",
                entity_table="module", entity_id=int(row["id"]), label=str(row["name"]), binary_id=row["binary_id"],
                status=_status(row), evidence_id=row["source_evidence_id"], analyzer_version=analyzer_version,
                metadata={"domain": row["domain"]})
        for row in db.query("SELECT f.*,b.sha256 AS binary_sha256 FROM function f LEFT JOIN binary b ON b.id=f.binary_id"):
            key = f"function:{row['binary_sha256'] or 'research'}:{row['address'] or ''}:{row['name'] or ''}:{row['id']}"
            nodes[("function", int(row["id"]))] = _node(db, node_type="Function", identity_key=key,
                entity_table="function", entity_id=int(row["id"]), label=str(row["name"] or "unknown"),
                binary_id=row["binary_id"], address=row["address"], address_space=row["address_space"], status=_status(row),
                evidence_id=row["source_evidence_id"], analyzer_version=analyzer_version,
                metadata={"origin": row["origin"], "prototype": row["prototype"]})
        for row in db.query("SELECT * FROM basic_block"):
            nodes[("basic_block", int(row["id"]))] = _node(db, node_type="BasicBlock",
                identity_key=f"basic-block:{row['binary_id']}:{row['start_vma']}", entity_table="basic_block", entity_id=int(row["id"]),
                label=str(row["start_vma"]), binary_id=row["binary_id"], address=row["start_vma"], address_space=row["address_space"],
                status=_status(row), evidence_id=row["source_evidence_id"] if "source_evidence_id" in row.keys() else None,
                analyzer_version=analyzer_version)
        simple_tables = (("vtable", "Vtable", "address", "class_name"), ("data_structure", "DataStructure", "base_address", "name"),
                         ("message_queue", "MessageQueue", "address", "name"), ("message_id", "MessageID", "value", "name"),
                         ("event_id", "EventID", "value", "name"), ("state_machine", "StateMachine", None, "name"),
                         ("state", "State", "value", "name"), ("java_method", "JavaMethod", None, "method_name"),
                         ("jni_bridge", "JNIEntry", "native_entry", "method_name"), ("driver_interface", "Driver", None, "name"),
                         ("ioctl", "Ioctl", "request_id", "name"), ("configuration_key", "ConfigurationKey", None, "key"))
        java_nodes: dict[tuple[str, str, str], int] = {}
        for table, node_type, address_column, label_column in simple_tables:
            for row in db.query(f"SELECT * FROM {table}"):
                identity = row["identity_key"] if "identity_key" in row.keys() and row["identity_key"] else f"{table}:{row['id']}"
                nodes[(table, int(row["id"]))] = _node(db, node_type=node_type, identity_key=f"{table}:{identity}",
                    entity_table=table, entity_id=int(row["id"]), label=str(row[label_column] or "unknown"),
                    namespace=row["namespace"] if "namespace" in row.keys() else None,
                    binary_id=row["binary_id"] if "binary_id" in row.keys() else None,
                    address=row[address_column] if address_column and address_column in row.keys() else None,
                    status=_status(row), evidence_id=row["source_evidence_id"] if "source_evidence_id" in row.keys() else None,
                    analyzer_version=analyzer_version)
                if table == "java_method":
                    java_nodes[(str(row["class_name"] or ""), str(row["method_name"] or ""), str(row["signature"] or ""))] = nodes[(table, int(row["id"]))]

        edge_count = 0
        for row in db.query("SELECT * FROM callsite"):
            source = nodes.get(("function", row["caller_id"]))
            target = nodes.get(("function", row["callee_id"])) if row["callee_id"] else None
            if source:
                edge_count += 1
                _edge(db, source_id=source, target_id=target, relation="CALLS", status=_status(row),
                      source_binary_id=(db.connection.execute("SELECT binary_id FROM function WHERE id=?", [row["caller_id"]]).fetchone()[0]
                                        if row["caller_id"] is not None else None),
                      address_space=row["address_space"], source_address=row["address"], target_address=row["target"],
                      evidence_id=row["source_evidence_id"], analyzer_version=analyzer_version,
                      metadata={"kind": row["kind"], "caller_resolution": row["caller_resolution"]})
        for row in db.query("SELECT * FROM cfg_edge"):
            source = nodes.get(("basic_block", row["from_block_id"])); target = nodes.get(("basic_block", row["to_block_id"]))
            if source:
                edge_count += 1
                _edge(db, source_id=source, target_id=target, relation="CONTROL_FLOW", status=_status(row),
                      source_binary_id=row["binary_id"], address_space=row["address_space"], source_address=row["from_address"],
                      target_address=row["to_address"], evidence_id=row["source_evidence_id"], analyzer_version=analyzer_version,
                      metadata={"edge_kind": row["edge_kind"]})
        for row in db.query("SELECT * FROM cross_reference"):
            source = nodes.get(("binary", row["from_binary_id"])); target = nodes.get(("binary", row["to_binary_id"]))
            if source:
                edge_count += 1
                _edge(db, source_id=source, target_id=target, relation="REFERENCES", status=_status(row),
                      source_binary_id=row["from_binary_id"], target_binary_id=row["to_binary_id"],
                      address_space=row["from_address_space"], source_address=row["from_address"], target_address=row["to_address"],
                      evidence_id=row["source_evidence_id"], analyzer_version=analyzer_version, metadata={"kind": row["kind"]})
        for row in db.query("SELECT * FROM module_dependency"):
            source = nodes.get(("module", row["from_module_id"])); target = nodes.get(("module", row["to_module_id"]))
            if source:
                edge_count += 1
                _edge(db, source_id=source, target_id=target, relation="DEPENDS_ON", status=_status(row),
                      evidence_id=row["source_evidence_id"], analyzer_version=analyzer_version,
                      metadata={"kind": row["kind"], "dependency_name": row["dependency_name"]})
        for row in db.query("SELECT mf.*,om.queue_id,om.message_id,om.source_evidence_id AS message_evidence FROM message_flow mf JOIN osal_message om ON om.id=mf.osal_message_id"):
            source = nodes.get(("function", row["function_id"])) or nodes.get(("module", row["module_id"]))
            target = nodes.get(("message_id", row["message_id"])) or nodes.get(("message_queue", row["queue_id"]))
            if source and target:
                edge_count += 1
                _edge(db, source_id=source, target_id=target, relation="SENDS_MESSAGE" if row["role"] == "producer" else "RECEIVES_MESSAGE" if row["role"] == "consumer" else "REGISTERS_CALLBACK", status=_status(row), evidence_id=row["source_evidence_id"] or row["message_evidence"], analyzer_version=analyzer_version, metadata={"role": row["role"], "queue_id": row["queue_id"]})
        for row in db.query("SELECT * FROM lifecycle_callback"):
            source = nodes.get(("module", row["module_id"])); target = nodes.get(("function", row["function_id"])) if row["function_id"] else None
            if source:
                edge_count += 1
                _edge(db, source_id=source, target_id=target, relation="REGISTERS_CALLBACK", status=_status(row),
                      evidence_id=row["source_evidence_id"], analyzer_version=analyzer_version, metadata={"phase": row["phase"], "name": row["name"]})
        for row in db.query("SELECT * FROM event_producer"):
            source = nodes.get(("function", row["function_id"])) or nodes.get(("module", row["module_id"])); target = nodes.get(("event_id", row["event_id"]))
            if source and target:
                edge_count += 1; _edge(db, source_id=source, target_id=target, relation="DISPATCHES_EVENT", status=_status(row), evidence_id=row["source_evidence_id"], analyzer_version=analyzer_version)
        for row in db.query("SELECT * FROM event_consumer"):
            source = nodes.get(("event_id", row["event_id"])); target = nodes.get(("function", row["function_id"])) or nodes.get(("module", row["module_id"]))
            if source and target:
                edge_count += 1; _edge(db, source_id=source, target_id=target, relation="HANDLES_EVENT", status=_status(row), evidence_id=row["source_evidence_id"], analyzer_version=analyzer_version)
        for row in db.query("SELECT * FROM state_transition"):
            source = nodes.get(("state", row["from_state_id"])) or nodes.get(("state_machine", row["machine_id"])); target = nodes.get(("state", row["to_state_id"]))
            if source and target:
                edge_count += 1; _edge(db, source_id=source, target_id=target, relation="TRANSITIONS_TO", status=_status(row), evidence_id=row["source_evidence_id"], analyzer_version=analyzer_version, metadata={"event_id": row["event_id"], "action": row["action"]})
        for row in db.query("SELECT * FROM jni_bridge"):
            source = nodes.get(("jni_bridge", row["id"]))
            target = java_nodes.get((str(row["class_name"] or ""), str(row["method_name"] or ""), str(row["signature"] or "")))
            native = nodes.get(("function", row["native_function_id"])) if row["native_function_id"] else None
            registration = nodes.get(("function", row["registration_function_id"])) if "registration_function_id" in row.keys() and row["registration_function_id"] else None
            if registration and source:
                edge_count += 1
                _edge(db, source_id=registration, target_id=source, relation="REGISTERS_CALLBACK", status=_status(row),
                      source_binary_id=row["module_id"], source_address=row["method_lookup_address"],
                      evidence_id=row["source_evidence_id"], analyzer_version=analyzer_version,
                      metadata={"direction": row["direction"] if "direction" in row.keys() else "unknown", "role": "jni_registration"})
            if native and source:
                edge_count += 1
                _edge(db, source_id=native, target_id=source, relation="JNI_BRIDGE", status=_status(row), evidence_id=row["source_evidence_id"], analyzer_version=analyzer_version, metadata={"direction": "native_to_jni"})
            if source and target:
                edge_count += 1; _edge(db, source_id=source, target_id=target, relation="JNI_BRIDGE", status=_status(row), evidence_id=row["source_evidence_id"], analyzer_version=analyzer_version)
        for row in db.query("SELECT * FROM ioctl"):
            source = nodes.get(("driver_interface", row["interface_id"])); target = nodes.get(("ioctl", row["id"]))
            if source and target:
                edge_count += 1; _edge(db, source_id=source, target_id=target, relation="INVOKES_IOCTL", status=_status(row), evidence_id=row["source_evidence_id"], analyzer_version=analyzer_version)
        db.connection.execute("UPDATE semantic_graph_run SET status='COMPLETE',completed_at=?,node_count=?,edge_count=?,error_text=NULL WHERE id=?", (utc_now(), len(nodes), edge_count, run_id))
        db.commit()
        return {"run_id": run_id, "status": "COMPLETE", "nodes": len(nodes), "edges": edge_count, "analyzer_version": analyzer_version}
    except Exception as exc:
        db.connection.execute("UPDATE semantic_graph_run SET status='FAILED',completed_at=?,error_text=? WHERE id=?", (utc_now(), str(exc), run_id))
        db.commit()
        raise


def export_graph(db: Database, output: Path, graph_format: str = "json") -> dict[str, Any]:
    nodes = [dict(row) for row in db.query("SELECT * FROM semantic_node ORDER BY id")]
    edges = [dict(row) for row in db.query("SELECT * FROM semantic_edge ORDER BY id")]
    output.parent.mkdir(parents=True, exist_ok=True)
    if graph_format == "graphml":
        graph = ET.Element("graphml", {"xmlns": "http://graphml.graphdrawing.org/xmlns"})
        keys = {
            "node_label": ("node", "label", "string"), "node_type": ("node", "type", "string"),
            "node_status": ("node", "status", "string"), "node_evidence": ("node", "evidence", "int"),
            "node_address": ("node", "address", "string"), "node_address_space": ("node", "address_space", "string"),
            "node_provenance": ("node", "provenance", "string"), "edge_relation": ("edge", "relation", "string"),
            "edge_status": ("edge", "status", "string"), "edge_evidence": ("edge", "evidence", "int"),
            "edge_address_space": ("edge", "address_space", "string"), "edge_provenance": ("edge", "provenance", "string"),
        }
        for key_id, (scope, name, kind) in keys.items():
            ET.SubElement(graph, "key", {"id": key_id, "for": scope, "attr.name": name, "attr.type": kind})
        graph_node = ET.SubElement(graph, "graph", {"id": "semantic", "edgedefault": "directed"})
        for node in nodes:
            element = ET.SubElement(graph_node, "node", {"id": f"n{node['id']}"})
            values = {"node_label": node.get("label") or "", "node_type": node.get("node_type") or "",
                      "node_status": node.get("status") or "UNKNOWN", "node_evidence": node.get("source_evidence_id") or "",
                      "node_address": node.get("address") or "", "node_address_space": node.get("address_space") or "",
                      "node_provenance": node.get("provenance_kind") or "NO_PRIMARY_EVIDENCE"}
            for key, value in values.items(): ET.SubElement(element, "data", {"key": key}).text = str(value)
        for edge in edges:
            target = f"n{edge['target_node_id']}" if edge.get("target_node_id") else f"u{edge['id']}"
            if not edge.get("target_node_id"):
                unresolved = ET.SubElement(graph_node, "node", {"id": target})
                ET.SubElement(unresolved, "data", {"key": "node_label"}).text = "UNRESOLVED"
                ET.SubElement(unresolved, "data", {"key": "node_type"}).text = "UnresolvedTarget"
            element = ET.SubElement(graph_node, "edge", {"id": f"e{edge['id']}", "source": f"n{edge['source_node_id']}", "target": target})
            values = {"edge_relation": edge.get("relation_type") or "", "edge_status": edge.get("status") or "UNKNOWN",
                      "edge_evidence": edge.get("evidence_id") or "", "edge_address_space": edge.get("address_space") or "",
                      "edge_provenance": edge.get("provenance_kind") or "NO_PRIMARY_EVIDENCE"}
            for key, value in values.items(): ET.SubElement(element, "data", {"key": key}).text = str(value)
        ET.ElementTree(graph).write(output, encoding="utf-8", xml_declaration=True)
    else:
        output.write_text(json.dumps({"schema": 1, "nodes": nodes, "edges": edges}, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return {"output": str(output), "format": graph_format, "nodes": len(nodes), "edges": len(edges)}


def validate_graph_provenance(db: Database, limit: int = 20) -> dict[str, Any]:
    rows = db.query("SELECT e.*,s.entity_table,s.entity_id FROM semantic_edge e LEFT JOIN semantic_node s ON s.id=e.source_node_id ORDER BY e.id")
    gaps: list[dict[str, Any]] = []
    counts = {"missing_evidence": 0, "missing_address_space": 0, "unresolved_target": 0, "status_mismatch": 0}
    for row in rows:
        issues: list[str] = []
        evidence_row = None
        if row["evidence_id"] is None:
            issues.append("missing_evidence"); counts["missing_evidence"] += 1
        else:
            evidence_row = db.connection.execute("SELECT status FROM evidence WHERE id=?", (row["evidence_id"],)).fetchone()
        if row["evidence_id"] is not None and not evidence_row:
            issues.append("missing_evidence"); counts["missing_evidence"] += 1
        elif evidence_row and row["status"] in ("VERIFIED_STATIC", "VERIFIED_RUNTIME") and evidence_row[0] not in ("VERIFIED_STATIC", "VERIFIED_RUNTIME"):
            issues.append("status_evidence_mismatch"); counts["status_mismatch"] += 1
        if row["source_address"] is not None and not row["address_space"]:
            issues.append("missing_address_space"); counts["missing_address_space"] += 1
        if row["target_node_id"] is None:
            issues.append("unresolved_target"); counts["unresolved_target"] += 1
        if issues:
            gaps.append({"edge_id": row["id"], "relation": row["relation_type"], "status": row["status"], "issues": issues})
    return {"total_edges": len(rows), "gaps": sum(counts.values()), "counts": counts, "samples": gaps[:limit]}
