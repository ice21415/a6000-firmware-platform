"""Offline guard tests; synthetic inputs never certify firmware bytes."""
import tempfile
import unittest
from pathlib import Path

from fwplatform.event_manager_provider_probe import callback_event_eligibility, probe_callback_behavior
from fwplatform.camera_core_chain import summarize_core_graph


class CallbackBehaviorTests(unittest.TestCase):
    def test_request_and_descriptor_namespaces_are_distinct(self):
        self.assertEqual(callback_event_eligibility(0x11004003, True), "DESCRIPTOR_ARM_SKIPPED")
        self.assertEqual(callback_event_eligibility(0x11013008, True), "DESCRIPTOR_ARM_CANDIDATE")

    def test_mutable_enable_state_is_not_assumed(self):
        self.assertEqual(callback_event_eligibility(0x11013008, None), "ENABLE_STATE_UNKNOWN")
        self.assertEqual(callback_event_eligibility(0x11013008, False), "DESCRIPTOR_ARM_SKIPPED")

    def test_forged_report_cannot_replace_primary_elf(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.json"
            path.write_text('{"verification":"PRIMARY_ELF_VERIFIED"}')
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                probe_callback_behavior(path)

    def test_counts_deduplicate_and_reject_conflicts(self):
        edge = {"id": "synthetic.edge", "verification_status": "STATIC_INFERRED"}
        report = {"edges": [edge, dict(edge)], "unresolved_edges": []}
        self.assertEqual(summarize_core_graph(report)["tracked_core_edges"], 1)
        self.assertEqual(summarize_core_graph(report)["primary_elf_verified_edges"], 0)
        report["edges"][1]["verification_status"] = "PRIMARY_ELF_VERIFIED"
        with self.assertRaisesRegex(ValueError, "conflicting"):
            summarize_core_graph(report)
