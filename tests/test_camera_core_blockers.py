import json
import unittest
from pathlib import Path


class CameraCoreBlockerLedgerTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1]
        self.ledger = json.loads((root / "sdk/camera_core_blockers_3_21.json").read_text(encoding="utf-8"))

    def test_all_baseline_blockers_are_explicit_and_unresolved(self):
        blockers = {row["id"]: row for row in self.ledger["blockers"]}
        expected = {
            "event.consumer.model_camera",
            "event.keys.model_camera",
            "event_manager.dispatch_target",
            "event_manager.completion_target",
            "request.selector_transform.semantic",
        }
        self.assertEqual(set(blockers), expected)
        self.assertTrue(all(not row["blocker_resolved"] for row in blockers.values()))

    def test_ledger_preserves_runtime_boundary(self):
        self.assertEqual(self.ledger["binary_sha256"], "8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a")
        self.assertIn("record +0x1c identity", blockers_missing(self.ledger, "event.consumer.model_camera"))


def blockers_missing(ledger, blocker_id):
    for row in ledger["blockers"]:
        if row["id"] == blocker_id:
            return row["missing_evidence"]
    return []


if __name__ == "__main__":
    unittest.main()
