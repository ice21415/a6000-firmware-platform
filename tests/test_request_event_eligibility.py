"""Synthetic condition models; no Sony bytes or runtime verification."""
from pathlib import Path
import tempfile
import unittest

from fwplatform.camera_request_event_probe import assess_request_event_eligibility, probe_request_event_eligibility


class RequestEligibilityTests(unittest.TestCase):
    def assess(self, event_id=0x11004003, queue_class=0, destination=2, **conditions):
        return assess_request_event_eligibility(event_id, queue_class, destination, **conditions)

    def test_initial_request_bypasses_queue1_and_hook(self):
        result = self.assess()
        self.assertEqual(result["queue_selected"], "QUEUE0")
        self.assertFalse(result["requires_queue1_transfer"])
        self.assertFalse(result["requires_pre_enqueue_callback"])
        self.assertTrue(result["destination_pass"])

    def test_class1_requires_independent_hook_and_transfer(self):
        result = self.assess(queue_class=1)
        self.assertEqual(result["queue_selected"], "QUEUE1")
        self.assertIn("pre_enqueue_callback_effect", result["unresolved_conditions"])
        self.assertIn("queue1_transfer_trigger", result["unresolved_conditions"])

    def test_unknown_class_is_not_guessed(self):
        result = self.assess(queue_class=None)
        self.assertEqual(result["queue_selected"], "UNKNOWN")
        self.assertIn("queue_class", result["unresolved_conditions"])

    def test_other_class_takes_no_observed_queue_branch(self):
        self.assertEqual(self.assess(queue_class=2)["status"], "INELIGIBLE_UNDER_MODEL_INPUTS")

    def test_numeric_destination_mask_is_two_not_four(self):
        self.assertFalse(self.assess(destination=4)["destination_pass"])
        self.assertTrue(self.assess(destination=3)["destination_pass"])
        self.assertEqual(self.assess()["destination_bit_index"], 1)

    def test_destination_overwrite_can_remove_eligibility(self):
        self.assertEqual(self.assess(destination=0)["status"], "INELIGIBLE_UNDER_MODEL_INPUTS")

    def test_receiver_gate_blocks_request_handling(self):
        self.assertEqual(self.assess(receiver_enabled=False)["status"], "INELIGIBLE_UNDER_MODEL_INPUTS")

    def test_wrong_namespace_does_not_pass_request_id_filter(self):
        result = self.assess(event_id=0x11013008)
        self.assertFalse(result["consumer_event_id_pass"])
        self.assertEqual(result["status"], "INELIGIBLE_UNDER_MODEL_INPUTS")

    def test_append_refusal_and_empty_pointer_flow_block(self):
        for conditions in ({"append_accepts": False}, {"pointer_preserved": False}):
            self.assertEqual(self.assess(**conditions)["status"], "INELIGIBLE_UNDER_MODEL_INPUTS")

    def test_pointer_alias_ambiguity_remains_unknown(self):
        self.assertIn("pointer_preserved", self.assess(pointer_preserved=None)["unresolved_conditions"])

    def test_unknown_scheduling_is_not_runtime_delivery(self):
        result = self.assess()
        self.assertIn("scheduling", result["unresolved_conditions"])
        self.assertFalse(result["runtime_verified"])

    def test_all_model_booleans_never_make_callable_api(self):
        result = self.assess(receiver_enabled=True, append_accepts=True, pointer_preserved=True, scheduled=True)
        self.assertFalse(result["runtime_verified"])
        self.assertFalse(result["safe_to_invoke"])
        self.assertEqual(result["evidence_level"], "OFFLINE_MODEL_ONLY")

    def test_status_strings_are_not_trusted_booleans(self):
        with self.assertRaises(ValueError):
            self.assess(receiver_enabled="VERIFIED_STATIC")
        with self.assertRaises(ValueError):
            self.assess(queue_class=True)

    def test_invalid_word_and_byte_rejected(self):
        with self.assertRaises(ValueError):
            self.assess(event_id=-1)
        with self.assertRaises(ValueError):
            self.assess(destination=256)

    def test_fake_primary_evidence_rejected_by_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.json"
            path.write_text('{"status":"PRIMARY_ELF_VERIFIED"}')
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                probe_request_event_eligibility(path)
