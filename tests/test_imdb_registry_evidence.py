"""Offline, synthetic-independent consistency checks for Phase 4.36 IMDB evidence."""
import json
from pathlib import Path
import unittest

BASE = Path(__file__).resolve().parents[1]
IMDB = BASE / "sdk" / "imdb_registry_3_21.json"
PROGRESS = BASE / "sdk" / "camera_core_progress_3_21.json"


class IMDBRegistryEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.record = json.loads(IMDB.read_text(encoding="utf-8"))
        cls.progress = json.loads(PROGRESS.read_text(encoding="utf-8"))

    def test_independent_source_identity(self):
        r = self.record
        self.assertEqual(r["source_sha256"], "9ceb21092a4987ec782fd980818aee687cde649af0999608bd6c40e1f46a84ea")
        self.assertEqual(r["source_file"], "libIMDB.so")
        self.assertEqual(r["address_space"], "ELF_VMA")
        self.assertEqual(r["primary_evidence"], "PRIVATE_ELF_DIRECT_STATIC")

    def test_143_rows_and_single_end_sentinel(self):
        x = self.record["imdb_raw"]
        base = int(x["descriptor_base"], 16)
        stride = int(x["record_stride"], 16)
        count = x["valid_record_count"]
        self.assertEqual(count, 143)
        self.assertEqual(stride, 44)
        self.assertEqual(base + count * stride, int(x["termination_record_address"], 16))
        self.assertEqual(int(x["termination_record_address"], 16) + stride, int(x["fixed_end_before_dynamic"], 16))
        self.assertEqual(x["termination_tag"], "0x28")

    def test_appfw_subapp_mask_and_equal_target(self):
        a, b = self.record["row_examples"]
        x = self.record["imdb_raw"]
        base = int(x["descriptor_base"], 16)
        stride = int(x["record_stride"], 16)
        for item in (a, b):
            self.assertEqual(base + item["index"]*stride, int(item["address"], 16))
            self.assertEqual(item["compared_target_id_16"], "0x83")
        self.assertEqual(int(a["target_bit_mask"], 16) & int(b["target_bit_mask"], 16), 0)
        self.assertEqual(a["init_symbol_name"], "Application_System_Init")
        self.assertEqual(b["init_symbol_name"], "subapp_init")
        self.assertEqual(x["target_names"][6], "resub")

    def test_exported_lookups_have_instruction_witnesses(self):
        names = [r["name"] for r in self.record["functions"]]
        self.assertEqual(names, ["IMDB_find_entry", "IMDB_get_entries", "IMDB_find_target_bit"])
        self.assertIn(["0x24e4", "adds", "r3, #0x2c"], self.record["functions"][0]["instruction_witnesses"])
        self.assertIn(["0x24ea", "cmp", "r5, #0x28"], self.record["functions"][0]["instruction_witnesses"])
        self.assertIn(["0x250c", "adds", "r0, #0x84"], self.record["functions"][1]["instruction_witnesses"])

    def test_no_runtime_or_sdk_graph_promotion(self):
        self.assertEqual(self.record["camera_core_existing_graph_count_change"], 0)
        self.assertEqual(self.record["runtime_verified_apis"], 0)
        self.assertEqual(self.record["safe_to_invoke_apis"], 0)
        self.assertEqual(self.progress["tracked_core_edges"], 84)
        self.assertEqual(self.progress["primary_elf_verified_edges"], 74)


if __name__ == "__main__":
    unittest.main()
