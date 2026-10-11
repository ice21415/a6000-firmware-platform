"""Metadata consistency checks for Stage 4.47 callback routing audit."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class FixedQueueForwarderAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.audit = json.loads((ROOT / "sdk" / "im_ipc_forwarder_boundary_3_21.json").read_text(encoding="utf-8"))
        cls.kernel = json.loads((ROOT / "sdk" / "uipc_kernel_dispatch_3_21.json").read_text(encoding="utf-8"))
        cls.bridge = json.loads((ROOT / "sdk" / "im_callback_bridge_3_21.json").read_text(encoding="utf-8"))
        cls.core = json.loads((ROOT / "sdk" / "camera_core_progress_3_21.json").read_text(encoding="utf-8"))

    def test_original_sources_pinned(self):
        self.assertEqual(self.audit["source_sha256"]["im"], self.bridge["source_sha256"])
        self.assertEqual(self.audit["source_sha256"]["uipc_module"], self.kernel["kernel_module"]["sha256"])
        self.assertEqual(len(set(self.audit["source_sha256"].values())), 3)

    def test_sync_callback_cases_do_not_include_stage_events(self):
        cb = self.audit["sync_callback"]
        matched = {int(x["message_id"], 16) for x in cb["direct_cases"]}
        matched |= {int(x, 16) for x in cb["forward_case_values"]}
        self.assertEqual(len(matched), 10)
        self.assertTrue({0x940036, 0x940037}.isdisjoint(matched))
        self.assertEqual(cb["unknown_format_string"],
                         "imelf_sync_api_cb: err: cmd:0x%x\\n")
        self.assertEqual(cb["forward_destination_id"], "0x0094016a")
        self.assertFalse(cb["explicit_compare_event_36"])
        self.assertFalse(cb["explicit_compare_event_37"])

    def test_fixed_id_outside_dynamic_pool(self):
        fixed = int(self.audit["sync_callback"]["fixed_queue_id"], 16)
        low = int(self.kernel["dynamic_id"]["pool_base"], 16)
        hi = low + int(self.kernel["dynamic_id"]["pool_size"], 16) - 1
        self.assertEqual(fixed, 0x94016a)
        self.assertFalse(low <= (fixed & 0xffff) <= hi)
        self.assertEqual(self.audit["kernel_sender"]["low16_extraction"], "0x3bf4 uxth r8,r0")

    def test_no_runtime_claim_or_camera_core_promotion(self):
        self.assertEqual(self.audit["runtime_verified_apis"], 0)
        self.assertEqual(self.audit["safe_to_invoke_apis"], 0)
        self.assertEqual(self.audit["core_tracking"]["graph_count_delta"], 0)
        self.assertEqual(self.core["tracked_core_edges"], 84)
        self.assertEqual(self.core["primary_elf_verified_edges"], 74)


if __name__ == "__main__":
    unittest.main()
