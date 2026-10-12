"""Evidence-bound ranking for unresolved Camera Core indirect targets.

Ranking is triage only: it never converts a candidate into a verified edge.
"""
from __future__ import annotations

from typing import Any, Iterable


def rank_indirect_candidates(candidates: Iterable[dict[str, Any]], *, source_sha256: str,
                             source_address_space: str = "ELF_VMA",
                             required_slot: int | None = None) -> list[dict[str, Any]]:
    ranked: list[dict[str, Any]] = []
    for candidate in candidates:
        score = 0
        reasons: list[str] = []
        if candidate.get("binary_sha256") == source_sha256:
            score += 3; reasons.append("same_binary")
        if candidate.get("address_space") == source_address_space:
            score += 2; reasons.append("same_address_space")
        if required_slot is not None and candidate.get("vtable_slot") == required_slot:
            score += 3; reasons.append("matching_vtable_slot")
        if candidate.get("instruction_evidence"):
            score += 2; reasons.append("instruction_evidence")
        if candidate.get("relocation_evidence"):
            score += 1; reasons.append("relocation_evidence")
        item = dict(candidate)
        item.update({"candidate_score": score, "ranking_reasons": reasons,
                     "status": candidate.get("status", "CANDIDATE"),
                     "selection": "UNRESOLVED_UNTIL_UNIQUE_PRIMARY_EVIDENCE"})
        ranked.append(item)
    return sorted(ranked, key=lambda item: (-int(item["candidate_score"]), str(item.get("target_vma", ""))))


__all__ = ["rank_indirect_candidates"]
