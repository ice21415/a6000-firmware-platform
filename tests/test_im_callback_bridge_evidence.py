"""Cross-check Phase 4.44 read-only ELF metadata without bundling Sony binaries."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class IMCallbackBridgeEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bridge = json.loads((ROOT / "sdk" / "im_callback_bridge_3_21.json").read_text(encoding="utf-8"))
        cls.sender = json.loads((ROOT / "sdk" / "im_event_sender_3_21.json").read_text(encoding="utf-8"))
        cls.core = json.loads((ROOT / "sdk" / "camera_core_progress_3_21.json").read_text(encoding="utf-8"))

    def test_source_sha_matches_sender(self):
        self.assertEqual(self.bridge["source_sha256"], self.sender["source"]["sha256"])
        self.assertEqual(self.bridge["source_sha256"], "f0f181426af4add55a8510c5441ff86c3121678fd1f7e0467152070e870d803a")

    def test_registered_stage_handler_flows_through_same_field(self):
        a = self.bridge["main_register_stage_handler"]
        recv = self.bridge["main_receive_and_indirect_dispatch"]
        self.assertEqual(a["callback_literal_word"], a["stage_handler_thumb_entry"])
        self.assertEqual(a["callback_field_address"], "0x000153ec")
        self.assertIn("+0x8", a["store_callback_instruction"])
        self.assertIn("+0x8", a["getter_instruction"])
        self.assertEqual(recv["callback_getter_call"], "0x9e9a: bl 0xac18")
        self.assertEqual(recv["indirect_handler_call"], "0x9eb2: blx r5")
        self.assertIn("osal_rcv_msg_tmo", recv["receive_import"])

    def test_callback_changes_across_states(self):
        states = self.bridge["callback_state_variants"]
        self.assertGreaterEqual(len(states), 3)
        by_state = {(s["state"], s["callback_thumb"]) for s in states}
        self.assertIn((3, "0x0000a06d"), by_state)
        self.assertIn((5, "0x00009339"), by_state)
        self.assertNotEqual("0x0000a06d", "0x00009339")

    def test_two_distinct_handle_fields_and_callbacks(self):
        queues = self.bridge["distinct_queue_facts"]
        sync = queues["sync_callback_registration"]
        recv = queues["async_receive_queue"]
        self.assertNotEqual(sync["saved_global_address"], recv["global_address"])
        self.assertEqual(sync["callback_thumb"], "0x000095b1")
        self.assertEqual(sync["id_word"], "0x0094016a")
        self.assertEqual(recv["used_by_receive"], "0x9e94: bl 0xa580")
        self.assertNotEqual(sync["callback_thumb"], self.bridge["main_register_stage_handler"]["stage_handler_thumb_entry"])

    def test_no_runtime_claim_or_graph_count_promotion(self):
        self.assertEqual(self.bridge["runtime_verified_apis"], 0)
        self.assertEqual(self.bridge["safe_to_invoke_apis"], 0)
        self.assertEqual(self.bridge["camera_core_graph"]["tracked"], 84)
        self.assertFalse(self.bridge["camera_core_graph"]["changed"])
        self.assertEqual(self.core["primary_elf_verified_edges"], 74)
        self.assertEqual(self.core["tracked_core_edges"], 84)


if __name__ == "__main__":
    unittest.main()
