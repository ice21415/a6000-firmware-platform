from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from analyzers.dex_analyzer import analyze_dex

from .db import Database, sha256_file, utc_now


ANALYZER_VERSION = "dex_inventory:1"


def index_dex(db: Database, path: Path) -> dict[str, Any]:
    """Persist evidence-bound DEX strings, not inferred Java method behavior.

    String-table entries are static facts. Descriptor and signature matches are
    search candidates only; they are not proof of class or method definitions.
    """
    path = path.resolve()
    parsed = analyze_dex(path)
    digest = sha256_file(path)
    rows = db.query("SELECT id FROM binary WHERE lower(sha256)=? ORDER BY id", (digest,))
    binary_id = int(rows[0]["id"]) if len(rows) == 1 else None
    evidence_id = db.evidence(
        str(path), digest, "dex_inventory", "header",
        json.dumps({
            "dex_version": parsed["version"], "strings": len(parsed["strings"]),
            "descriptor_strings": len(parsed["class_descriptors"]),
            "signature_strings": len(parsed["method_signature_candidates"]),
            "semantic_status": "INDEXED_ONLY",
        }, sort_keys=True),
        "VERIFIED_STATIC", {"analyzer": ANALYZER_VERSION},
        evidence_type="dex_string_inventory", status_basis="dex_string_table",
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

    # Each indexed item retains its literal string-table position. Descriptors
    # and signatures are searchable classifications of those literals.
    classes = set(parsed["class_descriptors"])
    signatures = set(parsed["method_signature_candidates"])
    count = 0
    for index, value in enumerate(parsed["strings"]):
        categories = ["dex_string"]
        if value in classes:
            categories.append("dex_descriptor_candidate")
        if value in signatures:
            categories.append("dex_signature_candidate")
        for category in categories:
            status = "VERIFIED_STATIC" if category == "dex_string" else "CANDIDATE"
            db.upsert("research_observation", {
                "source_evidence_id": evidence_id, "source_sha256": digest,
                "source_path": str(path), "binary_id": binary_id,
                "binary_sha256": digest, "function_id": None, "function_name": None,
                "address": None, "address_space": None,
                "observation_type": category, "locator": f"string[{index}]",
                "value_json": json.dumps({"index": index, "value": value}, ensure_ascii=False),
                "status": status, "confidence_id": db.confidence_id(status),
                "derived_relation": None, "analyzer_version": ANALYZER_VERSION,
                "adapter_run_id": run_id,
                "identity_key": f"dex:{digest}:{path.as_posix()}:{category}:{index}",
            }, ("identity_key",))
            count += 1
    db.connection.execute(
        "UPDATE evidence_adapter_run SET status='COMPLETE',completed_at=?,observation_count=? WHERE id=?",
        (utc_now(), count, run_id),
    )
    db.commit()
    return {
        "status": "COMPLETE", "semantic_status": "INDEXED_ONLY",
        "sha256": digest, "dex_version": parsed["version"],
        "strings": len(parsed["strings"]),
        "descriptor_candidates": len(parsed["class_descriptors"]),
        "signature_candidates": len(parsed["method_signature_candidates"]),
        "observations": count, "evidence_id": evidence_id, "adapter_run_id": run_id,
        "binary_id": binary_id,
        "limitations": parsed["limitations"],
    }
