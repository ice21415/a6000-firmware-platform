"""Metadata regressions: bootin firmware 3.21 absent/empty dmode fallback.

The Sony vendor ELF is NOT committed, copied, executed or required in CI.
"""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BootinDmodeFallbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.e = json.loads((ROOT / "sdk" / "bootin_dmode_fallback_3_21.json").read_text(encoding="utf-8"))
        cls.previous = json.loads((ROOT / "sdk" / "bootin_multistage_launch_3_21.json").read_text(encoding="utf-8"))
        cls.core = json.loads((ROOT / "sdk" / "camera_core_progress_3_21.json").read_text(encoding="utf-8"))

    def test_source_file_is_sha_pinned(self):
        s = self.e["original_source"]
        self.assertEqual(s["sha256"], self.previous["source"]["sha256"])
        self.assertEqual(s["size_bytes"], 13384)
        self.assertEqual(self.e["exact_file_probe"]["path"], "/setting/mode/dmode")

    def test_negative_open_branch_skips_any_mode_pointer_write(self):
        p = self.e["exact_file_probe"]
        self.assertIn("0x9494 blt 0x950e", p["fd_negative_guard"])
        self.assertIn("bypassing", p["open_failure_branch"])
        self.assertIn("0x9506", p["open_failure_branch"])
        self.assertEqual(p["argc_argv_loop"].split()[0], "0x9728")

    def test_empty_read_preserves_prior_mode_pointer(self):
        p = self.e["exact_file_probe"]
        self.assertIn("preexisting", p["read_default_pointer"])
        self.assertIn("0x9500", p["read_length_loop"])
        self.assertIn("If read returns 0", p["read_length_nonpositive"])

    def test_real_elf_file_bytes_select_ascii_digit_three(self):
        d = self.e["default_init"]
        self.assertEqual(bytes.fromhex(d["raw_pointer_word_little_endian"]), bytes.fromhex("95a60000"))
        self.assertEqual(d["mode_pointer_field_vma"], "0x12aa0")
        self.assertEqual(int.from_bytes(bytes.fromhex(d["raw_pointer_word_little_endian"]), "little"), 0xa695)
        self.assertEqual(bytes.fromhex(d["raw_string_hex"]), bytes([0x33, 0x20, 0x00]))
        self.assertEqual(d["full_stage_string"], "s g r u l i a ")
        self.assertEqual(d["bitfield_initial_word_at_global_base"], "0x00000000")
        self.assertEqual(d["ascii_mode_choice_map"]["3"], "s g r u l i a ")

    def test_mode_branch_has_explicit_bypass_and_argv_override(self):
        p = self.e["exact_file_probe"]
        self.assertIn("0x9732", p["stage_bypass_guard"])
        self.assertIn("can overwrite mode", p["argc_argv_loop"])
        self.assertIn("If opening", self.e["conditional_conclusion"])
        self.assertIn("NOT an observation", self.e["conditional_conclusion"])

    def test_unpacked_search_cannot_prove_live_file_absence(self):
        o = self.e["user_observation"]
        self.assertEqual(o["output"], "File Not Found")
        self.assertIn("does NOT prove", o["interpretation"])

    def test_camera_core_evidence_stays_static(self):
        self.assertEqual(self.e["runtime_verified_apis"], 0)
        self.assertEqual(self.e["safe_to_invoke_apis"], 0)
        self.assertEqual(self.e["core_graph"]["added"], 0)
        self.assertEqual(self.e["core_graph"]["primary"], 74)
        self.assertEqual(self.core["tracked_core_edges"], 84)


if __name__ == "__main__":
    unittest.main()
