"""Non-firmware regression checks for Phase 4.41 cross-ELF loader evidence."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class LoaderAliasEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.loader = json.loads((ROOT / "sdk/im_loader_alias_3_21.json").read_text(encoding="utf-8"))
        cls.im = json.loads((ROOT / "sdk/im_bootstrap_3_21.json").read_text(encoding="utf-8"))
        cls.imdb = json.loads((ROOT / "sdk/imdb_registry_3_21.json").read_text(encoding="utf-8"))
        cls.progress = json.loads((ROOT / "sdk/camera_core_progress_3_21.json").read_text(encoding="utf-8"))

    def test_independent_binary_provenance(self):
        sha = self.loader["source_fingerprints"]
        self.assertEqual(sha["im_elf"], self.im["source_sha256"])
        self.assertEqual(sha["imdb"], self.imdb["source_sha256"])
        self.assertEqual(len(set(sha.values())), 3)

    def test_conditional_logical_vs_concrete_module(self):
        loader = self.loader["conditional_fallback_loader"]
        self.assertEqual(loader["accepted_types"], ["0x20000001", "0x20000002", "0x20000003"])
        self.assertEqual(loader["fallback_literal_text"], "/usr/lib/libObj.so")
        self.assertEqual(loader["dlopen_callsite"], "0xb278")
        self.assertEqual(loader["high_halfword_at_row_plus_0x0e_vma"], "0xb266")
        self.assertEqual(loader["fallback_literal_pointer_slot"], "0xb2c8")

    def test_distinct_appfw_loader(self):
        path = self.loader["conditional_appfw_loader"]
        self.assertEqual(path["type"], "0x20000004")
        self.assertEqual(path["record_index"], 99)
        self.assertEqual(path["choose_null_vma"], "0xb1ea")
        self.assertEqual(path["dlopen_callsite"], "0xb1ec")
        self.assertEqual(path["dlsym_callsite"], "0xb20e")
        self.assertEqual(path["init_symbol_name"], "Application_System_Init")

    def test_flags_and_counted_candidate_rows(self):
        flags = self.loader["startup_default_dlopen_flags"]
        self.assertEqual(flags["source_default_word"], "0x00000101")
        self.assertEqual(flags["state_default_word"], "0x00000101")
        self.assertEqual(flags["main_get_call_vma"], "0x9b70")
        self.assertEqual(flags["main_set_call_vma"], "0x9b74")
        records = self.loader["imdb_default_target_fallback_candidates"]
        self.assertEqual(sum(records["distribution_by_record_type"].values()), 31)
        self.assertEqual(sum(records["distribution_by_row_group"].values()), 31)
        self.assertEqual(records["indices_before_appfw_record99"], 31)
        self.assertEqual(records["nonzero_high_halfword_rows_matching_default"], 31)

    def test_runtime_blockers_not_promoted(self):
        self.assertEqual(self.loader["runtime_verified_apis"], 0)
        self.assertEqual(self.loader["safe_to_invoke_apis"], 0)
        self.assertFalse(self.loader["camera_core_original_graph_counts"]["changed"])
        self.assertEqual(self.progress["tracked_core_edges"], 84)
        self.assertEqual(self.progress["primary_elf_verified_edges"], 74)


if __name__ == "__main__":
    unittest.main()
