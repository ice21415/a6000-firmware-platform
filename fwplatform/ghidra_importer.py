from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from . import __version__
from .db import Database, sha256_file, utc_now

LOG = logging.getLogger(__name__)


def _address(value: Any) -> str | None:
    if value is None or value == "":
        return None
    text = str(value)
    try:
        return hex(int(text, 0))
    except ValueError:
        return text


def _binary_id(db: Database, binary: Path, root: Path) -> int | None:
    normalized = binary.resolve().relative_to(root.resolve()).as_posix()
    row = db.connection.execute("SELECT id FROM binary WHERE path=?", (normalized,)).fetchone()
    if row:
        return int(row[0])
    row = db.connection.execute("SELECT id FROM binary WHERE path LIKE ? ORDER BY length(path) LIMIT 1",
                               (f"%{binary.name}",)).fetchone()
    return int(row[0]) if row else None


def _module(db: Database, binary_id: int) -> int:
    row = db.connection.execute("SELECT sha256,path FROM binary WHERE id=?", (binary_id,)).fetchone()
    if not row:
        raise ValueError(f"binary id {binary_id} not found")
    name = Path(str(row[1])).name
    key = f"binary-sha256:{row[0]}:{name}"
    return db.upsert("module", {"name": name, "identity_key": key, "binary_id": binary_id,
                                 "description": "Ghidra auto-analysis observations", "domain": None,
                                 "status": "VERIFIED_STATIC", "confidence_id": db.confidence_id("VERIFIED_STATIC"),
                                 "source_evidence_id": None}, ("identity_key",))


def _load(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="strict") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at line {line_no}: {exc}") from exc
            if not isinstance(value, dict) or not value.get("kind"):
                raise ValueError(f"invalid Ghidra record at line {line_no}")
            records.append(value)
    if not records or records[0].get("kind") != "metadata":
        raise ValueError("Ghidra JSONL has no metadata record")
    return records


def import_ghidra_jsonl(db: Database, root: Path, binary: Path, jsonl: Path) -> dict[str, Any]:
    """Import one deterministic Ghidra export and return row counts.

    The importer is intentionally strict about the input hash and metadata;
    malformed or mismatched exports become a FAILED analysis run rather than
    silently creating unrelated CFG rows.
    """
    root = root.resolve()
    binary = binary.resolve()
    jsonl = jsonl.resolve()
    binary_id = _binary_id(db, binary, root)
    if binary_id is None:
        raise ValueError(f"binary is not present in manifest: {binary}")
    binary_row = db.connection.execute("SELECT sha256 FROM binary WHERE id=?", (binary_id,)).fetchone()
    digest = str(binary_row[0]).lower()
    try:
        records = _load(jsonl)
    except Exception as exc:
        failed_id = db.upsert("analysis_run", {"binary_id": binary_id, "analyzer": "ghidra_headless",
            "analyzer_version": "ghidra:input-validation", "input_sha256": digest, "started_at": utc_now(),
            "completed_at": utc_now(), "status": "FAILED", "checkpoint": "input-validation", "error_text": str(exc),
            "metadata_json": json.dumps({"jsonl": str(jsonl), "retry": "rerun headless wrapper and re-import"}, sort_keys=True)},
            ("binary_id", "analyzer", "analyzer_version", "input_sha256"))
        db.commit()
        raise
    observed = str(records[0].get("binary_sha256") or "").lower()
    if observed and observed != digest:
        db.upsert("analysis_run", {"binary_id": binary_id, "analyzer": "ghidra_headless",
            "analyzer_version": "ghidra:input-validation", "input_sha256": digest, "started_at": utc_now(),
            "completed_at": utc_now(), "status": "FAILED", "checkpoint": "hash-validation",
            "error_text": f"Ghidra hash mismatch: manifest={digest} export={observed}",
            "metadata_json": json.dumps({"jsonl": str(jsonl), "retry": "rerun headless wrapper"}, sort_keys=True)},
            ("binary_id", "analyzer", "analyzer_version", "input_sha256"))
        db.commit()
        raise ValueError(f"Ghidra hash mismatch: manifest={digest} export={observed}")
    metadata = records[0]
    program_identity = json.dumps(metadata.get("program_identity") or {}, ensure_ascii=False, sort_keys=True)
    analyzer_version = f"ghidra:{metadata.get('analyzer_version', 'unknown')}"
    run_key = str(metadata.get("run_id") or f"ghidra-{digest}")
    evidence_id = db.evidence(str(jsonl.relative_to(root).as_posix()) if jsonl.is_relative_to(root) else str(jsonl),
                              sha256_file(jsonl), "ghidra_jsonl", "metadata", json.dumps(metadata, sort_keys=True),
                              "VERIFIED_STATIC", {"run_id": run_key, "program_identity": metadata.get("program_identity")},
                              evidence_type="ghidra_export", status_basis="ghidra_metadata")
    run_id = db.upsert("analysis_run", {"binary_id": binary_id, "analyzer": "ghidra_headless",
        "analyzer_version": analyzer_version, "input_sha256": digest, "started_at": utc_now(),
        "completed_at": None, "status": "RUNNING", "checkpoint": "metadata", "error_text": None,
        "metadata_json": json.dumps({"run_id": run_key, "program_identity": metadata.get("program_identity"),
                                      "jsonl": str(jsonl), "tool_version": __version__}, ensure_ascii=False, sort_keys=True)},
        ("binary_id", "analyzer", "analyzer_version", "input_sha256"))
    module_id = _module(db, binary_id)
    identity = metadata.get("program_identity") or {}
    db.connection.execute("UPDATE binary SET ghidra_program_identity=?,ghidra_image_base=?,ghidra_address_space=? WHERE id=?",
                          (program_identity, identity.get("image_base"), identity.get("address_space"), binary_id))
    function_ids: dict[str, int] = {}
    counts = {"metadata": 1, "functions": 0, "basic_blocks": 0, "instructions": 0,
              "callsites": 0, "cross_references": 0, "symbols": 0, "vtable_candidates": 0,
              "unresolved_edges": 0}
    try:
        # Function boundaries are loaded first so all later observations can
        # resolve caller/callee IDs without assuming a semantic name.
        for record in records:
            if record.get("kind") != "function":
                continue
            entry = _address(record.get("entry_vma"))
            if not entry:
                continue
            name = str(record.get("name") or f"FUN_{entry[2:]}")
            existing = db.connection.execute("SELECT id,identity_key FROM function WHERE binary_id=? AND address=? ORDER BY id LIMIT 1",
                                             (binary_id, entry)).fetchone()
            key = f"function:{binary_id}:{module_id}:{entry}:{name}"
            if existing:
                owner = db.connection.execute("SELECT id FROM function WHERE identity_key=? AND id<>? LIMIT 1", (key, existing[0])).fetchone()
                effective = key if owner is None else existing[1]
                db.connection.execute("UPDATE function SET module_id=?,name=?,identity_key=?,size=?,prototype=?,address_space=?,analysis_run_id=?,origin=?,status=?,confidence_id=? WHERE id=?",
                                      (module_id, name, effective, int(record.get("body_bytes") or 0), record.get("prototype"),
                                       identity.get("address_space"), run_id, "ghidra_auto_function", "VERIFIED_STATIC",
                                       db.confidence_id("VERIFIED_STATIC"), existing[0]))
                function_id = int(existing[0])
            else:
                function_id = db.upsert("function", {"binary_id": binary_id, "module_id": module_id, "name": name,
                    "identity_key": key, "address": entry, "size": int(record.get("body_bytes") or 0),
                    "calling_convention": None, "thumb_mode": None, "vma": entry, "runtime_va": None,
                    "physical_offset": None, "wbi_offset": None, "status": "VERIFIED_STATIC",
                    "confidence_id": db.confidence_id("VERIFIED_STATIC"), "source_evidence_id": evidence_id,
                    "generated_name": int(bool(record.get("generated"))), "origin": "ghidra_auto_function",
                    "analysis_run_id": run_id, "prototype": record.get("prototype"),
                    "address_space": identity.get("address_space")}, ("identity_key",))
            function_ids[entry] = function_id
            counts["functions"] += 1

        for record in records:
            kind = record.get("kind")
            if kind == "basic_block":
                start = _address(record.get("start_vma")); owner = function_ids.get(_address(record.get("function_entry")))
                if not start or owner is None:
                    continue
                db.upsert("basic_block", {"function_id": owner, "binary_id": binary_id, "start_vma": start,
                    "end_vma": _address(record.get("end_vma")), "size": None, "status": "VERIFIED_STATIC",
                    "address_space": identity.get("address_space"), "analysis_run_id": run_id}, ("function_id", "start_vma"))
                counts["basic_blocks"] += 1
            elif kind == "instruction":
                address = _address(record.get("address")); owner = function_ids.get(_address(record.get("function_entry")))
                if not address or owner is None:
                    continue
                db.upsert("instruction", {"function_id": owner, "binary_id": binary_id, "address": address,
                    "mnemonic": record.get("mnemonic"), "operands": record.get("operands"),
                    "bytes_hex": record.get("bytes_hex"), "mode": record.get("mode"),
                    "source_text": json.dumps(record, ensure_ascii=False, sort_keys=True),
                    "address_space": identity.get("address_space"), "analysis_run_id": run_id,
                    "source_evidence_id": evidence_id}, ("function_id", "address"))
                counts["instructions"] += 1
            elif kind == "callsite":
                from_address = _address(record.get("from_address")); target = _address(record.get("to_address"))
                caller = db.connection.execute("SELECT id FROM function WHERE binary_id=? AND address=? LIMIT 1", (binary_id, from_address)).fetchone()
                if not caller:
                    caller = db.connection.execute("SELECT id FROM function WHERE binary_id=? AND address<=? ORDER BY address DESC LIMIT 1", (binary_id, from_address)).fetchone()
                if not caller or not from_address:
                    continue
                callee = function_ids.get(_address(record.get("callee_entry")))
                relation = str(record.get("relation_kind") or "call")
                key = f"callsite:{binary_id}:{from_address}:{target or ''}:{relation}"
                db.upsert("callsite", {"caller_id": int(caller[0]), "callee_id": callee, "address": from_address,
                    "target": target, "kind": relation, "identity_key": key, "status": record.get("status") or ("VERIFIED_STATIC" if callee else "CANDIDATE"),
                    "source_evidence_id": evidence_id, "address_space": identity.get("address_space"), "analysis_run_id": run_id}, ("identity_key",))
                counts["callsites"] += 1
                if callee is None:
                    db.upsert("unresolved_edge", {"identity_key": f"indirect:{key}", "from_type": "function", "from_id": int(caller[0]),
                        "to_type": "address", "to_id": None, "relation": "indirect_call", "reason": "Ghidra reference has no containing function",
                        "status": "CANDIDATE", "source_evidence_id": evidence_id}, ("identity_key",))
                    counts["unresolved_edges"] += 1
            elif kind == "cross_reference":
                from_address = _address(record.get("from_address")); to_address = _address(record.get("to_address"))
                if not from_address or not to_address:
                    continue
                db.upsert("cross_reference", {"from_binary_id": binary_id, "from_address": from_address,
                    "to_binary_id": binary_id, "to_address": to_address, "kind": record.get("relation_kind") or "reference",
                    "status": record.get("status") or "VERIFIED_STATIC", "source_evidence_id": evidence_id,
                    "from_address_space": identity.get("address_space"), "to_address_space": identity.get("address_space"),
                    "analysis_run_id": run_id}, ("from_binary_id", "from_address", "to_binary_id", "to_address", "kind"))
                counts["cross_references"] += 1
            elif kind == "symbol":
                name = record.get("name"); address = _address(record.get("address"))
                if not name:
                    continue
                db.upsert("symbol", {"binary_id": binary_id, "name": name, "address": address, "size": None,
                    "type": record.get("symbol_type"), "binding": record.get("source"), "section": None,
                    "status": "VERIFIED_STATIC"}, ("binary_id", "name", "address"))
                counts["symbols"] += 1
            elif kind == "vtable_candidate":
                counts["vtable_candidates"] += 1
        db.connection.execute("UPDATE binary SET analysis_status='ANALYZED_GHIDRA' WHERE id=?", (binary_id,))
        db.connection.execute("UPDATE analysis_run SET completed_at=?,status='COMPLETE',checkpoint=?,error_text=NULL WHERE id=?",
                              (utc_now(), "cfg-xrefs", run_id))
        db.commit()
    except Exception as exc:
        db.connection.execute("UPDATE analysis_run SET completed_at=?,status='FAILED',checkpoint=?,error_text=? WHERE id=?",
                              (utc_now(), "error", str(exc), run_id))
        db.commit()
        raise
    counts.update({"run_id": run_key, "analysis_run_id": run_id, "binary_id": binary_id, "jsonl": str(jsonl),
                   "program_identity": identity, "evidence_id": evidence_id})
    return counts
