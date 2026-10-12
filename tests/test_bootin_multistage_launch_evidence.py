"""Metadata-only evidence regression for Sony A6000 3.21 bootin mode paths."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BootinMultistageModeEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.e = json.loads((ROOT / "sdk" / "bootin_multistage_launch_3_21.json").read_text(encoding="utf-8"))
        cls.bootin = json.loads((ROOT / "sdk" / "bootin_stage_launcher_3_21.json").read_text(encoding="utf-8"))
        cls.im = json.loads((ROOT / "sdk" / "im_event_sender_3_21.json").read_text(encoding="utf-8"))
        cls.core = json.loads((ROOT / "sdk" / "camera_core_progress_3_21.json").read_text(encoding="utf-8"))

    def test_original_binary_hashes(self):
        self.assertEqual(self.e["source"]["sha256"], self.bootin["binary"]["sha256"])
        self.assertEqual(self.e["secondary_source"]["sha256"], self.im["source"]["sha256"])

    def test_four_mode_choices_and_original_vmas(self):
        choices = self.e["bootin_stage_mode_selector"]["character_branches"]
        self.assertEqual([x["input_first_char"] for x in choices], list("0123"))
        self.assertEqual([x["stage_string"] for x in choices],
                         ["s ", "s g r u ", "s g r u l ", "s g r u l i a "])
        self.assertEqual([x["chosen_rodata_vma"] for x in choices],
                         ["0xa5af", "0xa4e6", "0xa4ef", "0xa4fa"])
        self.assertEqual(self.e["bootin_stage_mode_selector"]["selected_pointer_write"],
                         "0x975a stores selection in global+0x0c")

    def test_same_state_field_is_appended_and_single_launch_exists(self):
        c = self.e["bootin_composed_command"]
        self.assertEqual(c["command_executor"], "0x9a54 BLX 0x8c30 (system@GLIBC_2.4; GOT R_ARM_JUMP_SLOT 0x12a04)")
        self.assertIn("r4+0x0c", c["argv_stage_append"])
        self.assertEqual(c["append_helper"], "0x9260 -> strncat@0x8cdc")
        self.assertIn("im.elf ", c["initial_im_prefix_options"])

    def test_source_mode_file_is_read_only_evidence(self):
        m = self.e["bootin_mode_source"]
        self.assertEqual(m["configuration_path"], "/setting/mode/dmode")
        self.assertEqual(m["literal_string_vma"], "0x9ef1")
        self.assertIn("open@GLIBC_2.4", m["open_plt"])
        self.assertIn("read@GLIBC_2.4", m["read_instruction"])
        self.assertTrue(m["user_file_content_not_provided"])

    def test_original_file_backed_default_mode_is_three(self):
        d = self.e["bootin_compiled_mode_default"]
        self.assertEqual(d["selector_pointer_vma"], "0x00012aa0")
        self.assertEqual(d["file_initialized_pointer"], "0x0000a695")
        self.assertEqual(d["literal_string_value"], "3 ")
        self.assertEqual(d["literal_string_vma"], "0x0000a695")
        self.assertTrue(d["source_data_verified"])
        self.assertFalse(d["runtime_mode_observed"])

    def test_actual_main_reaches_combined_command_builder(self):
        m = self.e["bootin_main_reachability"]
        self.assertEqual(m["main_entry"], "0x9c64")
        self.assertIn("0x9c65", m["start_libc_main_pointer_literal"])
        self.assertEqual(m["main_parser_call"], "0x9c7a BL 0x97d0 (mode/options parser)")
        self.assertEqual(m["main_combined_command_caller"], "0x9ca2 BL 0x9914")
        self.assertEqual(m["combined_command_system_call"], "0x9a54 BLX 0x8c30 (system)")

    def test_event_launcher_is_distinct_path(self):
        s = self.e["separate_event_stage_path"]
        self.assertEqual(s["event_i"], "0x940036 -> system('im.elf i &') at 0x9b3a")
        self.assertEqual(s["event_a"], "0x940037 -> system('im.elf a &') at 0x9b3a")
        self.assertNotEqual(s["dispatcher"], self.e["bootin_composed_command"]["builder"])

    def test_no_runtime_or_core_promotions(self):
        self.assertEqual(self.e["runtime_verified"], 0)
        self.assertEqual(self.e["safe_to_invoke"], 0)
        self.assertEqual(self.e["core_original_counts"]["added"], 0)
        self.assertEqual(self.core["tracked_core_edges"], 84)
        self.assertEqual(self.core["primary_elf_verified_edges"], 74)


if __name__ == "__main__":
    unittest.main()
