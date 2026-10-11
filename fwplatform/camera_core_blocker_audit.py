"""Fail-closed, *metadata-only* audit of the Camera Core blocker ledger.

This checks consistency across curated public SDK records. It does not read
firmware bytes and must never be represented as fresh ELF instruction proof.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BASELINE_BLOCKERS = frozenset({
    "event.consumer.model_camera",
    "event.keys.model_camera",
    "event_manager.dispatch_target",
    "event_manager.completion_target",
    "request.selector_transform.semantic",
})


def audit_blocker_contracts(
    contract: dict[str, Any],
    ledger: dict[str, Any],
    progress: dict[str, Any],
) -> dict[str, Any]:
    """Cross-check graph, ledger and progress without promoting ELF evidence."""
    errors: list[str] = []
    verified = contract.get("verified_edges")
    unresolved = contract.get("unresolved_edges")
    conditional = (
        contract.get("observations", {})
        .get("camera_registry_dispatch", {})
        .get("conditional_relations")
    )
    blockers = ledger.get("blockers")
    if not all(isinstance(part, list) for part in (verified, unresolved, conditional, blockers)):
        return {"valid": False, "errors": ["missing_edge_or_blocker_list"]}

    def ids(rows: list[dict[str, Any]], category: str) -> list[str]:
        output = [item.get("id") if isinstance(item, dict) else None for item in rows]
        if any(not isinstance(value, str) or not value for value in output):
            errors.append(f"invalid_{category}_id")
        if len(output) != len(set(output)):
            errors.append(f"duplicate_{category}_id")
        return output

    primary_ids = ids(verified, "primary")
    inferred_ids = ids(conditional, "inferred")
    unresolved_ids = ids(unresolved, "unresolved")
    blocker_ids = ids(blockers, "blocker")
    if len(set(primary_ids + inferred_ids + unresolved_ids)) != (
        len(primary_ids) + len(inferred_ids) + len(unresolved_ids)
    ):
        errors.append("cross_graph_duplicate_id")

    active_blocker_ids = {
        row.get("id") for row in blockers
        if isinstance(row, dict) and row.get("blocker_resolved") is False
    }
    if active_blocker_ids != set(unresolved_ids):
        errors.append("ledger_unresolved_id_mismatch")
    if set(blocker_ids) != BASELINE_BLOCKERS:
        errors.append("baseline_blocker_ids_changed")

    sha = contract.get("binary_sha256")
    if not isinstance(sha, str) or len(sha) != 64 or any(ch not in "0123456789abcdef" for ch in sha):
        errors.append("binary_identity_format")
    if ledger.get("binary_sha256") != sha or progress.get("verification", {}).get("primary_elf_sha256") != sha:
        errors.append("cross_file_binary_identity")
    if contract.get("firmware_version") != ledger.get("firmware_version") or ledger.get("firmware_version") != progress.get("firmware_version"):
        errors.append("firmware_version_mismatch")

    counts = {
        "tracked_core_edges": len(primary_ids) + len(inferred_ids) + len(unresolved_ids),
        "primary_elf_verified_edges": len(primary_ids),
        "static_inferred_edges": len(inferred_ids),
        "unresolved_edges": len(unresolved_ids),
    }
    if any(progress.get(key) != value for key, value in counts.items()):
        errors.append("progress_graph_count_mismatch")
    for edge in verified:
        if not isinstance(edge, dict) or edge.get("verification_status") != "PRIMARY_ELF_VERIFIED":
            errors.append("unsupported_primary_edge_status")
            continue
        if edge.get("evidence", {}).get("source_binary_sha256") != sha:
            errors.append("primary_edge_sha_mismatch")
    for edge in conditional:
        if not isinstance(edge, dict) or edge.get("verification_status") != "STATIC_INFERRED":
            errors.append("unsupported_inferred_edge_status")
    for edge in unresolved:
        if not isinstance(edge, dict) or edge.get("status") not in {"UNKNOWN", "CANDIDATE", "INFERRED"}:
            errors.append("unresolved_edge_promotion")

    by_id = {row.get("id"): row for row in blockers if isinstance(row, dict)}
    for blocker_id in BASELINE_BLOCKERS:
        entry = by_id.get(blocker_id)
        if not isinstance(entry, dict):
            continue
        if entry.get("blocker_resolved") is True:
            proof_ids = entry.get("resolution_evidence_ids")
            if (entry.get("current_status") != "RESOLVED"
                or not isinstance(proof_ids, list) or not proof_ids
                or any(proof_id not in primary_ids for proof_id in proof_ids)):
                errors.append(f"unsupported_blocker_resolution:{blocker_id}")
        elif entry.get("blocker_resolved") is False:
            if entry.get("current_status") != "UNRESOLVED":
                errors.append(f"unsupported_blocker_resolution:{blocker_id}")
            if not isinstance(entry.get("missing_evidence"), list) or not entry["missing_evidence"]:
                errors.append(f"missing_blocker_proof_requirements:{blocker_id}")
        else:
            errors.append(f"unsupported_blocker_resolution:{blocker_id}")
        for field in ("verified_segments", "new_findings", "candidate_exclusions"):
            if not isinstance(entry.get(field), list):
                errors.append(f"invalid_blocker_field:{blocker_id}:{field}")
        if not isinstance(entry.get("minimal_next_proof"), str) or not entry["minimal_next_proof"].strip():
            errors.append(f"missing_next_proof:{blocker_id}")

    # A pre-enqueue adapter can itself be the candidate called at 0x7ef988.
    # It is not an Application Router, but those are different statements.
    dispatch = by_id.get("event_manager.dispatch_target", {})
    excluded = " ".join(dispatch.get("candidate_exclusions", [])) if isinstance(dispatch.get("candidate_exclusions"), list) else ""
    if "0x11130c" in excluded and ("not 0x7ef988 target" in excluded or "not main dispatch" in excluded):
        errors.append("incorrect_conditional_callback_exclusion")

    v = contract.get("verification", {})
    if (v.get("runtime_verified") is not False or v.get("safe_to_invoke") is not False
        or v.get("callable") is not False
        or progress.get("runtime_verified_apis") != 0 or progress.get("safe_to_invoke_apis") != 0):
        errors.append("unsupported_runtime_promotion")
    return {"valid": not errors, "errors": sorted(set(errors)), "counts": counts,
            "unresolved_ids": sorted(unresolved_ids),
            "scope": "PUBLIC_METADATA_CONSISTENCY_ONLY"}


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit public Camera Core metadata; no ELF claims")
    parser.add_argument("--sdk", type=Path, default=ROOT / "sdk/camera_core_3_21.json")
    parser.add_argument("--ledger", type=Path, default=ROOT / "sdk/camera_core_blockers_3_21.json")
    parser.add_argument("--progress", type=Path, default=ROOT / "sdk/camera_core_progress_3_21.json")
    args = parser.parse_args()
    sdk = json.loads(args.sdk.read_text(encoding="utf-8"))
    ledger = json.loads(args.ledger.read_text(encoding="utf-8"))
    progress = json.loads(args.progress.read_text(encoding="utf-8"))
    result = audit_blocker_contracts(sdk, ledger, progress)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
