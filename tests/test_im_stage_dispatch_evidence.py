"""Static metadata regression checks, not execution of proprietary firmware."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class IMStageDispatchEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads((ROOT / "sdk" / "im_stage_dispatch_3_21.json").read_text(encoding="utf-8"))
        cls.loader = json.loads((ROOT / "sdk" / "im_loader_alias_3_21.json").read_text(encoding="utf-8"))
        cls.im = json.loads((ROOT / "sdk" / "im_bootstrap_3_21.json").read_text(encoding="utf-8"))
        cls.registry = json.loads((ROOT / "sdk" / "imdb_registry_3_21.json").read_text(encoding="utf-8"))
        cls.core = json.loads((ROOT / "sdk" / "camera_core_progress_3_21.json").read_text(encoding="utf-8"))

    def test_pin_three_sources(self):
        self.assertEqual(self.data["sources"]["im_elf_sha256"], self.im["source_sha256"])
        self.assertEqual(self.data["sources"]["libimdb_sha256"], self.registry["source_sha256"])
        self.assertEqual(self.data["sources"]["im_elf_sha256"], self.loader["source_fingerprints"]["im_elf"])

    def test_stage_marker_strides(self):
        markers = self.data["markers"]
        self.assertEqual([v["type"] for v in markers], list(range(1, 9)))
        self.assertEqual([v["index"] for v in markers], [0, 9, 19, 31, 33, 94, 98, 101])
        base = int(self.registry["imdb_raw"]["descriptor_base"], 16)
        for m in markers:
            self.assertEqual(int(m["vma"], 16), base + m["index"] * 44)

    def test_event_37_targets_appfw_interval(self):
        events = self.data["event_dispatch"]["events"]
        self.assertEqual(len(events), 7)
        self.assertEqual([int(x["event_id"], 16) for x in events], list(range(0x940031, 0x940038)))
        self.assertEqual(events[0]["scan_to_marker"], 1)
        self.assertEqual(events[5]["process_until_marker"], 7)
        self.assertEqual(events[6]["skip_to_marker"], 7)
        self.assertEqual(events[6]["process_until_marker"], 8)
        appfw = self.data["fallback_candidates"]["appfw_row"]
        self.assertEqual(appfw["index"], 99)
        self.assertEqual(appfw["stage7_to8_event_id"], "0x00940037")
        self.assertEqual(self.registry["row_examples"][0]["index"], 99)

    def test_earlier_loader_candidates_are_partitioned(self):
        rec = self.data["fallback_candidates"]
        sections = rec["stage_marker_intervals"]
        self.assertEqual([x["count"] for x in sections], [1, 30])
        self.assertEqual(rec["total"], sum(x["count"] for x in sections))
        self.assertEqual(rec["stage_3_to_4_candidate_indices"], [29])
        self.assertEqual(len(rec["stage_5_to_7_candidate_indices"]), 30)
        self.assertEqual(rec["stage5_to7_event_id"], "0x00940036")
        self.assertTrue(max(rec["stage_5_to_7_candidate_indices"]) < rec["appfw_row"]["index"])

    def test_static_defaults_do_not_claim_runtime(self):
        self.assertEqual(self.data["main"]["static_global_option_word"]["value"], "0x00000003")
        self.assertEqual(self.data["main"]["stage_4_gate"]["flag"], "0x80000")
        self.assertEqual(self.data["core_graph"], {"primary": 74, "inferred": 5, "unresolved": 5, "tracked": 84, "promoted": 0})
        self.assertEqual(self.core["tracked_core_edges"], 84)
        self.assertEqual(self.data["runtime_verified_apis"], 0)


if __name__ == "__main__":
    unittest.main()
