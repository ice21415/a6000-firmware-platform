"""Synthetic mutation tests for public Camera Core ledger invariants.

These do not validate private ELF bytes or establish runtime API safety.
"""
from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from fwplatform.camera_core_blocker_audit import audit_blocker_contracts

ROOT = Path(__file__).resolve().parents[1]


class CameraCoreBlockerAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sdk = json.loads((ROOT / "sdk/camera_core_3_21.json").read_text(encoding="utf-8"))
        cls.ledger = json.loads((ROOT / "sdk/camera_core_blockers_3_21.json").read_text(encoding="utf-8"))
        cls.progress = json.loads((ROOT / "sdk/camera_core_progress_3_21.json").read_text(encoding="utf-8"))

    def data(self):
        return copy.deepcopy(self.sdk), copy.deepcopy(self.ledger), copy.deepcopy(self.progress)

    def check_error(self, expected, sdk, ledger, progress):
        result = audit_blocker_contracts(sdk, ledger, progress)
        self.assertFalse(result["valid"])
        self.assertIn(expected, result["errors"])

    def test_committed_contracts_agree(self):
        result = audit_blocker_contracts(*self.data())
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["scope"], "PUBLIC_METADATA_CONSISTENCY_ONLY")
        self.assertEqual(result["counts"]["tracked_core_edges"], 70)
        self.assertEqual(result["counts"]["primary_elf_verified_edges"], 60)
        self.assertEqual(result["counts"]["unresolved_edges"], 5)

    def test_duplicate_edge_does_not_inflate_progress(self):
        sdk, ledger, progress = self.data()
        sdk["verified_edges"].append(copy.deepcopy(sdk["verified_edges"][0]))
        self.check_error("duplicate_primary_id", sdk, ledger, progress)

    def test_ledger_ids_must_match_unresolved_graph(self):
        sdk, ledger, progress = self.data()
        ledger["blockers"][0]["id"] = "fake.completed.camera"
        self.check_error("ledger_unresolved_id_mismatch", sdk, ledger, progress)

    def test_count_discrepancy_detected(self):
        sdk, ledger, progress = self.data()
        progress["primary_elf_verified_edges"] += 1
        self.check_error("progress_graph_count_mismatch", sdk, ledger, progress)

    def test_binary_hash_provenance_is_required(self):
        sdk, ledger, progress = self.data()
        sdk["verified_edges"][0]["evidence"]["source_binary_sha256"] = "0" * 64
        self.check_error("primary_edge_sha_mismatch", sdk, ledger, progress)

    def test_unsupported_resolution_without_proof_is_rejected(self):
        sdk, ledger, progress = self.data()
        item = ledger["blockers"][0]
        item["blocker_resolved"] = True
        item["current_status"] = "RESOLVED"
        self.check_error("unsupported_blocker_resolution:" + item["id"], sdk, ledger, progress)

    def test_real_proof_would_be_supported_without_freezing_old_five(self):
        sdk, ledger, progress = self.data()
        target = "request.selector_transform.semantic"
        index = next(i for i, row in enumerate(sdk["unresolved_edges"]) if row["id"] == target)
        sdk["unresolved_edges"].pop(index)
        proof = copy.deepcopy(sdk["verified_edges"][0])
        proof["id"] = "request.selector_transform.complete_semantic_proof"
        sdk["verified_edges"].append(proof)
        item = next(row for row in ledger["blockers"] if row["id"] == target)
        item["blocker_resolved"] = True
        item["current_status"] = "RESOLVED"
        item["resolution_evidence_ids"] = [proof["id"]]
        progress["primary_elf_verified_edges"] += 1
        progress["unresolved_edges"] -= 1
        result = audit_blocker_contracts(sdk, ledger, progress)
        self.assertTrue(result["valid"], result["errors"])
        # A metadata audit accepts proof references, but cannot authenticate
        # synthetic ELF claims. Only a separate SHA-pinned ELF re-read can.
        self.assertEqual(result["scope"], "PUBLIC_METADATA_CONSISTENCY_ONLY")

    def test_conditional_callback_cannot_be_excluded_by_its_semantics(self):
        sdk, ledger, progress = self.data()
        item = next(row for row in ledger["blockers"] if row["id"] == "event_manager.dispatch_target")
        item["candidate_exclusions"].append("0x11130c is pre-enqueue adapter, not main dispatch")
        self.check_error("incorrect_conditional_callback_exclusion", sdk, ledger, progress)

    def test_runtime_api_promotion_is_rejected(self):
        sdk, ledger, progress = self.data()
        progress["safe_to_invoke_apis"] = 1
        self.check_error("unsupported_runtime_promotion", sdk, ledger, progress)

    def test_missing_blocker_conditions_rejected(self):
        sdk, ledger, progress = self.data()
        item = ledger["blockers"][0]
        item["missing_evidence"] = []
        self.check_error("missing_blocker_proof_requirements:" + item["id"], sdk, ledger, progress)


if __name__ == "__main__":
    unittest.main()
