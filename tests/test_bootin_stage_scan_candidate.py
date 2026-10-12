"""Regression checks for a user-run, read-only 649-ELF scan; no vendor binaries in CI."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BootinScanCandidateEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = json.loads((ROOT / "sdk" / "bootin_stage_event_scan_3_21.json").read_text(encoding="utf-8"))
        cls.core = json.loads((ROOT / "sdk" / "camera_core_progress_3_21.json").read_text(encoding="utf-8"))

    def test_counts_partition(self):
        c = self.s["stats"]
        self.assertEqual(c["elf_read"], 649)
        self.assertEqual(c["literal_bearing_elf"], 19)
        self.assertEqual(c["high"] + c["medium"] + c["literal_only"], 19)

    def test_bootin_is_prioritized_but_not_xref_verified(self):
        c = self.s["high_candidates"]
        self.assertEqual(len(c), 2)
        self.assertTrue(c[0]["path"].endswith("/bin/bootin.elf"))
        self.assertFalse(c[0]["uploaded_to_chat"])
        self.assertEqual(c[0]["stage_036_literal_vma"], "0x00009c28")
        self.assertEqual(c[0]["stage_037_literal_vma"], "0x00009c30")
        self.assertEqual(c[0]["fixed_dest_literal_vma"], "0x00009c50")
        self.assertIn("osal_snd_msg", c[0]["imports"])
        self.assertEqual(self.s["status"], "CANDIDATE_DISCOVERY_NOT_PRIMARY_XREF_VERIFICATION")

    def test_kernel_modules_not_treated_as_dynamic_import_free(self):
        r = self.s["literal_only"][0]
        self.assertTrue(r["path"].endswith("kmod/upm.ko"))
        self.assertIn(".symtab", r["caveat"])
        self.assertIn(".rel.text", r["caveat"])

    def test_do_not_inflate_core_graph_or_runtime_proofs(self):
        self.assertEqual(self.s["original_core_graph"]["new_core_edges"], 0)
        self.assertEqual(self.s["runtime_verified_apis"], 0)
        self.assertEqual(self.core["primary_elf_verified_edges"], 74)
        self.assertEqual(self.core["tracked_core_edges"], 84)


if __name__ == "__main__":
    unittest.main()
