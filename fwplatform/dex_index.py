from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from analyzers.dex_analyzer import analyze_dex

from .db import Database, sha256_file, utc_now


ANALYZER_VERSION = "dex_inventory:2"


def index_dex(db: Database, path: Path) -> dict[str, Any]:
    """Store static DEX observations; never infer Java or JNI implementations.

    The type, class_def and method_id tables are evidence about DEX structure.
    In particular a method_id is a reference and not a Java method definition.
    """
    path = path.resolve()
    parsed = analyze_dex(path)  # Validate the entire file before any DB write.
    # Retain the digest of the exact parsed bytes, and reject changing inputs
    # before storing provenance. The validation read is not used as identity.
    digest = parsed["sha256"]
    if sha256_file(path) != digest:
        raise ValueError("DEX input changed during analysis; retry with a stable snapshot")
    rows = db.query("SELECT id FROM binary WHERE lower(sha256)=? ORDER BY id", (digest,))
    binary_id = int(rows[0]["id"]) if len(rows) == 1 else None
    db.connection.execute("SAVEPOINT dex_index")
    try:
        evidence_id = db.evidence(
            str(path), digest, "dex_inventory", "header",
            json.dumps({
                "dex_version": parsed["version"],
                "strings": len(parsed["strings"]),
                "type_ids": len(parsed["type_descriptors"]),
                "class_defs": len(parsed["defined_classes"]),
                "method_ids": len(parsed["method_references"]),
                "semantic_status": "INDEXED_ONLY",
            }, sort_keys=True),
            "VERIFIED_STATIC", {"analyzer": ANALYZER_VERSION},
            evidence_type="dex_structure_inventory", status_basis="dex_tables",
        )
        run_key = f"dex-inventory:{digest}:{path.as_posix()}"
        run_id = db.upsert("evidence_adapter_run", {
            "run_key": run_key, "adapter": "dex_inventory",
            "adapter_version": ANALYZER_VERSION, "root_path": str(path.parent),
            "input_file_count": 1, "observation_count": 0, "relation_count": 0,
            "status": "RUNNING", "started_at": utc_now(), "completed_at": None,
            "error_text": None,
            "metadata_json": json.dumps({"path": str(path), "sha256": digest}, sort_keys=True),
        }, ("run_key",))
        count = 0

        def observe(kind: str, locator: str, value: dict[str, Any], status: str) -> None:
            nonlocal count
            db.upsert("research_observation", {
                "source_evidence_id": evidence_id, "source_sha256": digest,
                "source_path": str(path), "binary_id": binary_id,
                "binary_sha256": digest, "function_id": None, "function_name": None,
                "address": None, "address_space": None,
                "observation_type": kind, "locator": locator,
                "value_json": json.dumps(value, ensure_ascii=False, sort_keys=True),
                "status": status, "confidence_id": db.confidence_id(status),
                "derived_relation": None, "analyzer_version": ANALYZER_VERSION,
                "adapter_run_id": run_id,
                "identity_key": f"dex:{digest}:{path.as_posix()}:{kind}:{locator}",
            }, ("identity_key",))
            count += 1

        # Literal string table records are direct static observations, whereas
        # heuristic pattern matches remain candidate classifications.
        descriptors = set(parsed["class_descriptors"])
        signatures = set(parsed["method_signature_candidates"])
        for index, value in enumerate(parsed["strings"]):
            locator = f"string[{index}]"
            observe("dex_string", locator, {"index": index, "value": value}, "VERIFIED_STATIC")
            if value in descriptors:
                observe("dex_descriptor_candidate", locator, {"index": index, "value": value}, "CANDIDATE")
            if value in signatures:
                observe("dex_signature_candidate", locator, {"index": index, "value": value}, "CANDIDATE")

        # Unlike a string heuristic, these IDs are parsed from concrete tables.
        for index, descriptor in enumerate(parsed["type_descriptors"]):
            observe("dex_type_id", f"type_id[{index}]", {
                "index": index, "descriptor": descriptor,
            }, "VERIFIED_STATIC")
        for item in parsed["defined_classes"]:
            observe("dex_class_definition", f"class_def[{item['index']}]", item, "VERIFIED_STATIC")
        for item in parsed["method_references"]:
            observe("dex_method_reference", f"method_id[{item['index']}]", item, "VERIFIED_STATIC")

        db.connection.execute(
            "UPDATE evidence_adapter_run SET status='COMPLETE',completed_at=?,observation_count=? WHERE id=?",
            (utc_now(), count, run_id),
        )
        db.connection.execute("RELEASE SAVEPOINT dex_index")
        db.commit()
    except Exception:
        db.connection.execute("ROLLBACK TO SAVEPOINT dex_index")
        db.connection.execute("RELEASE SAVEPOINT dex_index")
        raise

    return {
        "status": "COMPLETE", "semantic_status": "INDEXED_ONLY",
        "sha256": digest, "dex_version": parsed["version"],
        "strings": len(parsed["strings"]),
        "descriptor_candidates": len(parsed["class_descriptors"]),
        "signature_candidates": len(parsed["method_signature_candidates"]),
        "type_ids": len(parsed["type_descriptors"]),
        "class_defs": len(parsed["defined_classes"]),
        "method_references": len(parsed["method_references"]),
        "observations": count, "evidence_id": evidence_id, "adapter_run_id": run_id,
        "binary_id": binary_id,
        "limitations": parsed["limitations"],
    }
