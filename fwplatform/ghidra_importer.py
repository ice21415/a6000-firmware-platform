from __future__ import annotations

import json
import logging
import re
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


def _address_int(value: Any) -> int | None:
    text = _address(value)
    if text is None:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def _binary_id(db: Database, binary: Path, root: Path) -> int | None:
    try:
        normalized = binary.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        normalized = None
    if normalized:
        row = db.connection.execute("SELECT id FROM binary WHERE path=?", (normalized,)).fetchone()
        if row:
            return int(row[0])
    # A basename fallback can silently select a different firmware version.
    # Resolve by the content identity only when it is unique.
    digest = sha256_file(binary)
    rows = db.connection.execute("SELECT id FROM binary WHERE sha256=? ORDER BY id", (digest,)).fetchall()
    if len(rows) == 1:
        return int(rows[0][0])
    if len(rows) > 1:
        raise ValueError(f"binary identity is ambiguous for {binary} ({len(rows)} rows)")
    return None


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
    if records[-1].get("kind") != "complete" or records[-1].get("export_status") != "complete":
        raise ValueError("Ghidra JSONL is truncated or has no complete marker")
    expected = records[-1].get("record_count")
    if not isinstance(expected, int) or expected != len(records) - 1:
        raise ValueError(f"Ghidra JSONL record count mismatch: expected={expected} actual={len(records) - 1}")
    return records


def _record_failure(db: Database, binary_id: int, digest: str, analyzer_version: str,
                    checkpoint: str, error: str, metadata: dict[str, Any]) -> int:
    run_id = db.upsert("analysis_run", {"binary_id": binary_id, "analyzer": "ghidra_headless",
        "analyzer_version": analyzer_version, "input_sha256": digest, "started_at": utc_now(),
        "completed_at": utc_now(), "status": "FAILED", "checkpoint": checkpoint, "error_text": error,
        "metadata_json": json.dumps(metadata, ensure_ascii=False, sort_keys=True),
        "run_key": str(metadata.get("run_id") or ""), "jsonl_sha256": metadata.get("jsonl_sha256"),
        "record_count": metadata.get("record_count"), "integrity_status": "FAILED"},
        ("binary_id", "analyzer", "analyzer_version", "input_sha256"))
    db.commit()
    return run_id


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
    if binary_row is None:
        raise ValueError(f"binary row disappeared during manifest lookup: {binary}")
    digest = str(binary_row[0]).lower()
    try:
        records = _load(jsonl)
    except Exception as exc:
        _record_failure(db, binary_id, digest, "ghidra:input-validation", "input-validation", str(exc),
                        {"jsonl": str(jsonl), "retry": "rerun headless wrapper and re-import"})
        raise
    observed = str(records[0].get("binary_sha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", observed):
        _record_failure(db, binary_id, digest, "ghidra:input-validation", "hash-validation",
                        "metadata binary_sha256 is required and must be a 64-character SHA-256",
                        {"jsonl": str(jsonl), "observed": observed, "retry": "rerun headless wrapper"})
        raise ValueError("Ghidra export must contain a valid metadata binary_sha256")
    if observed != digest:
        error = f"Ghidra hash mismatch: manifest={digest} export={observed}"
        _record_failure(db, binary_id, digest, "ghidra:input-validation", "hash-validation", error,
                        {"jsonl": str(jsonl), "observed": observed, "retry": "rerun headless wrapper"})
        raise ValueError(error)
    metadata = records[0]
    program_identity = json.dumps(metadata.get("program_identity") or {}, ensure_ascii=False, sort_keys=True)
    analyzer_version = f"ghidra:{metadata.get('analyzer_version', 'unknown')}"
    run_key = str(metadata.get("run_id") or f"ghidra-{digest}")
    jsonl_digest = sha256_file(jsonl)
    db.commit()
    db.connection.execute("SAVEPOINT ghidra_import")
    evidence_id = db.evidence(str(jsonl.relative_to(root).as_posix()) if jsonl.is_relative_to(root) else str(jsonl),
                              sha256_file(jsonl), "ghidra_jsonl", "metadata", json.dumps(metadata, sort_keys=True),
                              "VERIFIED_STATIC", {"run_id": run_key, "program_identity": metadata.get("program_identity")},
                              evidence_type="ghidra_export", status_basis="ghidra_metadata")
    run_id = db.upsert("analysis_run", {"binary_id": binary_id, "analyzer": "ghidra_headless",
        "analyzer_version": analyzer_version, "input_sha256": digest, "started_at": utc_now(),
        "completed_at": None, "status": "RUNNING", "checkpoint": "metadata", "error_text": None,
        "metadata_json": json.dumps({"run_id": run_key, "program_identity": metadata.get("program_identity"),
                                      "jsonl": str(jsonl), "tool_version": __version__,
                                      "record_count": len(records), "jsonl_sha256": jsonl_digest}, ensure_ascii=False, sort_keys=True),
        "run_key": run_key, "jsonl_sha256": jsonl_digest, "record_count": len(records), "integrity_status": "VALIDATED"},
        ("binary_id", "analyzer", "analyzer_version", "input_sha256"))
    module_id = _module(db, binary_id)
    identity = metadata.get("program_identity") or {}
    db.connection.execute("UPDATE binary SET ghidra_program_identity=?,ghidra_image_base=?,ghidra_address_space=? WHERE id=?",
                          (program_identity, identity.get("image_base"), identity.get("address_space"), binary_id))
    function_ids: dict[str, int] = {}
    block_ids: dict[str, int] = {}
    counts = {"metadata": 1, "functions": 0, "basic_blocks": 0, "instructions": 0,
              "cfg_edges": 0, "callsites": 0, "cross_references": 0, "symbols": 0, "vtable_candidates": 0,
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

        # Load the complete block set before resolving CFG edges.  A CFG edge
        # is never inferred from address proximity; both block identities must
        # be present in this run and address space.
        for record in records:
            if record.get("kind") != "basic_block":
                continue
            start = _address(record.get("start_vma")); owner = function_ids.get(_address(record.get("function_entry")))
            if not start or owner is None:
                continue
            block_id = db.upsert("basic_block", {"function_id": owner, "binary_id": binary_id, "start_vma": start,
                "end_vma": _address(record.get("end_vma")), "size": None, "status": "VERIFIED_STATIC",
                "address_space": identity.get("address_space"), "analysis_run_id": run_id}, ("function_id", "start_vma"))
            block_ids[start] = block_id

        for record in records:
            kind = record.get("kind")
            if kind == "basic_block":
                start = _address(record.get("start_vma"))
                if start in block_ids:
                    counts["basic_blocks"] += 1
            elif kind == "cfg_edge":
                from_address = _address(record.get("from_address")); to_address = _address(record.get("to_address"))
                source_block = block_ids.get(from_address or ""); target_block = block_ids.get(to_address or "")
                if not from_address or not to_address or source_block is None or target_block is None:
                    continue
                key = f"cfg:{binary_id}:{identity.get('address_space') or ''}:{from_address}:{to_address}:{record.get('edge_kind') or 'control_flow'}"
                db.upsert("cfg_edge", {"binary_id": binary_id, "function_id": function_ids.get(_address(record.get("function_entry"))),
                    "from_block_id": source_block, "to_block_id": target_block, "from_address": from_address,
                    "to_address": to_address, "address_space": identity.get("address_space"),
                    "edge_kind": record.get("edge_kind") or "control_flow", "status": "VERIFIED_STATIC",
                    "confidence_id": db.confidence_id("VERIFIED_STATIC"), "source_evidence_id": evidence_id,
                    "analysis_run_id": run_id, "identity_key": key, "metadata_json": json.dumps(record, sort_keys=True)},
                    ("identity_key",))
                counts["cfg_edges"] += 1
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
                caller_entry = _address(record.get("function_entry"))
                caller = function_ids.get(caller_entry or "")
                caller_row = db.connection.execute("SELECT id,size,address FROM function WHERE id=?", (caller,)).fetchone() if caller is not None else None
                from_number = _address_int(from_address); entry_number = _address_int(caller_entry)
                caller_resolution = "EXPLICIT_AND_RANGE_VALID"
                if caller_row is None or from_number is None or entry_number is None or int(caller_row[1] or 0) <= 0 or not (entry_number <= from_number < entry_number + int(caller_row[1])):
                    caller_resolution = "UNRESOLVED_OUT_OF_RANGE" if caller_row is not None else "UNRESOLVED_MISSING_ENTRY"
                    caller = None
                callee = function_ids.get(_address(record.get("callee_entry")))
                relation = str(record.get("relation_kind") or "call")
                key = f"callsite:{binary_id}:{caller_entry or ''}:{from_address or ''}:{target or ''}:{relation}"
                if not from_address:
                    continue
                db.upsert("callsite", {"caller_id": caller, "callee_id": callee, "address": from_address,
                    "target": target, "kind": relation, "identity_key": key, "status": record.get("status") or ("VERIFIED_STATIC" if callee else "CANDIDATE"),
                    "source_evidence_id": evidence_id, "address_space": identity.get("address_space"),
                    "target_address_space": identity.get("address_space"), "analysis_run_id": run_id,
                    "caller_entry": caller_entry, "caller_resolution": caller_resolution,
                    "analyzer_version": analyzer_version}, ("identity_key",))
                counts["callsites"] += 1
                if callee is None or caller is None:
                    db.upsert("unresolved_edge", {"identity_key": f"indirect:{key}", "from_type": "function", "from_id": caller,
                        "to_type": "address", "to_id": None, "relation": "indirect_call" if callee is None else "callsite_caller",
                        "reason": "Ghidra reference has no containing callee function" if callee is None else caller_resolution,
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
        db.connection.execute("UPDATE analysis_run SET completed_at=?,status='COMPLETE',checkpoint=?,error_text=NULL,integrity_status='VALIDATED',record_count=?,jsonl_sha256=? WHERE id=?",
                              (utc_now(), "cfg-xrefs", len(records), jsonl_digest, run_id))
        db.connection.execute("RELEASE SAVEPOINT ghidra_import")
        db.commit()
    except Exception as exc:
        db.connection.execute("ROLLBACK TO SAVEPOINT ghidra_import")
        db.connection.execute("RELEASE SAVEPOINT ghidra_import")
        _record_failure(db, binary_id, digest, analyzer_version, "error", str(exc),
                        {"run_id": run_key, "jsonl": str(jsonl), "jsonl_sha256": jsonl_digest,
                         "record_count": len(records), "retry": "rerun headless wrapper and re-import"})
        raise
    counts.update({"run_id": run_key, "analysis_run_id": run_id, "binary_id": binary_id, "jsonl": str(jsonl),
                   "program_identity": identity, "evidence_id": evidence_id})
    return counts
