"""Produce a manual-review SDK fixture from static candidate search results."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .db import Database
from .sdk_discovery import discover_sdk_candidates


def draft_sdk_review(
    db: Database, output: Path, *, firmware_version: str = "3.21",
    name: str = "", binary_sha256: str = "", domain: str = "",
    include_internal: bool = False, limit: int = 100,
) -> dict[str, Any]:
    """Emit an importable *unverified* review fixture, never SDK implementations.

    Choosing a domain from symbol text is unsafe: even a strong lexical hint
    stays as metadata, and every generated contract has domain=Other until a
    reviewer supplies independent semantic evidence.
    """
    if not isinstance(firmware_version, str) or not firmware_version.strip():
        raise ValueError("SDK draft requires a non-empty firmware version")
    discovery = discover_sdk_candidates(
        db, name=name, binary_sha256=binary_sha256, domain=domain,
        include_internal=include_internal, limit=limit,
    )
    entries = []
    seen_identities: dict[tuple[str, str, str], int] = {}
    duplicate_candidates_collapsed = 0
    for row in discovery["candidates"]:
        # Multiple inventoried paths may share the same ELF SHA-256.
        # The contract fixture keys by digest+entry, not local file path;
        # emitting both creates an invalid duplicate interface identity.
        identity = (row["symbol_name"], row["binary_sha256"], row["address"])
        if identity in seen_identities:
            duplicate_candidates_collapsed += 1
            entries[seen_identities[identity]]["review"]["candidate_binary_paths"].append(row["binary_path"])
            continue
        seen_identities[identity] = len(entries)
        entries.append({
            "name": row["symbol_name"],
            "domain": "Other",  # Always requires conscious human domain review.
            "binary_sha256": row["binary_sha256"],
            "address": row["address"],
            "verification_status": "CANDIDATE",
            "runtime_safety": "DESCRIPTIVE_ONLY",
            "abi": None,
            "parameter_layout": None,
            "return_semantics": None,
            **({"source_evidence_id": row["identity_evidence_id"]}
               if row["identity_evidence_id"] is not None else {}),
            "review": {
                "domain_search_hints": row["domain_search_hints"],
                "location_evidence_valid": row["entry_location_evidence_valid"],
                "unique_binary_identity": row["unique_binary_identity"],
                "unique_function_entry": row["unique_function_entry"],
                "candidate_binary_paths": [row["binary_path"]],
                "ghidra_prototype_unverified": row["prototype_text"],
                "required_work": row["next_evidence"],
                "semantic_status": "NOT_REVIEWED",
                "runtime_status": "NOT_VERIFIED",
            },
        })
    payload = {
        "schema_version": 1,
        "firmware_version": firmware_version.strip(),
        "generated_for": "human_offline_review_only",
        "automatically_verified_api_count": 0,
        "symbol_search_has_more_results": discovery["more_candidates_possible"],
        "duplicate_candidates_collapsed": duplicate_candidates_collapsed,
        "interfaces": entries,
        "rule": "Never auto-promote a symbol or Ghidra prototype to a confirmed API or ABI.",
    }
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {
        "status": "REVIEW_ONLY", "output": str(output), "interfaces": len(entries),
        "more_candidates_possible": discovery["more_candidates_possible"],
        "duplicate_candidates_collapsed": duplicate_candidates_collapsed,
        "verified_api_count": 0, "requires_human_semantic_review": True,
    }
