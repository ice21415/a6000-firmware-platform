"""Synthetic-free metadata consistency checks; no proprietary firmware needed in CI."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ImBootstrapEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.im = json.loads((ROOT / "sdk" / "im_bootstrap_3_21.json").read_text(encoding="utf-8"))
        cls.imdb = json.loads((ROOT / "sdk" / "imdb_registry_3_21.json").read_text(encoding="utf-8"))
        cls.progress = json.loads((ROOT / "sdk" / "camera_core_progress_3_21.json").read_text(encoding="utf-8"))

    def test_pinned_firmware_sources_are_separate(self):
        self.assertEqual(self.im["source_sha256"], "f0f181426af4add55a8510c5441ff86c3121678fd1f7e0467152070e870d803a")
        self.assertEqual(self.imdb["source_sha256"], "9ceb21092a4987ec782fd980818aee687cde649af0999608bd6c40e1f46a84ea")
        self.assertNotEqual(self.im["source_sha256"], self.imdb["source_sha256"])

    def test_default_mask_has_unambiguous_matching_row(self):
        info = self.im["phase4_39_target_and_flag_witness"]
        self.assertEqual(info["default_target"]["value"], "default")
        self.assertEqual(info["initial_target_pointer"]["static_file_contents"], "0x00000000")
        self.assertTrue(info["default_target"]["source_if_target_pointer_null"])
        mask = int(info["default_imdb_mask"], 16)
        matching = [row["index"] for row in self.imdb["row_examples"] if int(row["target_bit_mask"], 16) & mask]
        self.assertEqual(matching, [99])
        self.assertEqual([r["matches_default"] for r in info["target_id_0x83_candidates"]], [True, False])

    def test_conditional_configuration_path_kept_distinct(self):
        info = self.im["phase4_39_target_and_flag_witness"]
        self.assertEqual(info["config_flag_provenance"]["flag_bit"], "0x4000")
        row = self.im["static_conditional_appfw_trace"]["row"]
        self.assertIn("AdjChkConfig.so", row["config_if_flag_0x4000"])
        self.assertIn("AppConfig.so", row["config_if_flag_zero"])
        self.assertEqual(self.im["runtime_verified_apis"], 0)
        self.assertEqual(self.im["safe_to_invoke_apis"], 0)

    def test_camera_core_graph_stays_unpromoted(self):
        self.assertEqual(self.progress["tracked_core_edges"], 84)
        self.assertEqual(self.progress["primary_elf_verified_edges"], 74)
        self.assertEqual(self.im["camera_core_graph"]["new_core_graph_edges"], 0)
        self.assertTrue(self.im["phase4_39_target_and_flag_witness"]["camera_core_graph_counts_unchanged"])


if __name__ == "__main__":
    unittest.main()
