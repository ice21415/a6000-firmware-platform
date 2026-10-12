"""Offline metadata tests; no Sony firmware ELF file is bundled or executed."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BootinStageLauncherEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.e = json.loads((ROOT / "sdk" / "bootin_stage_launcher_3_21.json").read_text(encoding="utf-8"))
        cls.scan = json.loads((ROOT / "sdk" / "bootin_stage_event_scan_3_21.json").read_text(encoding="utf-8"))
        cls.im = json.loads((ROOT / "sdk" / "im_event_sender_3_21.json").read_text(encoding="utf-8"))
        cls.core = json.loads((ROOT / "sdk" / "camera_core_progress_3_21.json").read_text(encoding="utf-8"))

    def test_direct_elf_provenance(self):
        source = self.e["binary"]
        self.assertEqual(source["sha256"], "d2bc0c51d4523052170520607fb60709020e48811e5d5ad65843f5e97ffaa983")
        self.assertEqual(source["size_bytes"], 13384)
        self.assertEqual(self.e["cross_binary"]["im_elf_sha256"], self.im["source"]["sha256"])
        self.assertEqual(self.scan["bootin_local_copy_report"]["reported_sha256"], source["sha256"])

    def test_stage_comparisons_launch_exact_bounded_shell_commands(self):
        pairs = self.e["dispatcher"]["literal_pairs"]
        self.assertEqual(len(pairs), 7)
        self.assertEqual([int(x["event"], 16) for x in pairs], list(range(0x940031, 0x940038)))
        self.assertEqual([x["command"] for x in pairs],
                         [f"im.elf {letter} &" for letter in "sgrulia"])
        self.assertEqual(pairs[5]["literal_event_vma"], "0x9c28")
        self.assertEqual(pairs[6]["literal_event_vma"], "0x9c30")
        self.assertEqual(self.e["dispatcher"]["launch_system_symbol"], "system@GLIBC_2.4")
        self.assertEqual(self.e["dispatcher"]["launch_system_call"], "0x9b3a")

    def test_distinct_inbox_vs_im_sender(self):
        ids = self.e["distinct_uipc_identity"]
        self.assertEqual(ids["bootin_inbox"], "0x0094020a")
        self.assertEqual(ids["im_stage_sender_fixed_dest"], "0x0094016a")
        self.assertNotEqual(ids["bootin_inbox"], ids["im_stage_sender_fixed_dest"])
        self.assertEqual(self.e["bootin_receive"]["loop_receive_call"], "0x9cd0")

    def test_actual_cross_elf_control_code_stays_separate(self):
        ipc = self.e["cross_elf_confirmed_im_to_bootin_control_message"]
        self.assertEqual(ipc["message_code"], "0x00940005")
        self.assertEqual(ipc["message_destination"], self.e["bootin_receive"]["recv_destination"])
        self.assertEqual(ipc["im_record_type_literal"], "0xb514")
        self.assertEqual(ipc["im_message_send"], "0xb4d8 (osal_snd_msg PLT 0x8fc8)")
        self.assertEqual(ipc["bootin_event_compare"], "0x9ba8..0x9bac (literal 0x9c54 = 0x940005)")
        self.assertNotIn(ipc["message_code"], [self.e["dispatcher"]["literal_pairs"][i]["event"] for i in (5, 6)])

    def test_distinct_processes_not_shared_loader_scope(self):
        self.assertEqual(self.e["cross_binary"]["im_single_letter_i_flag"], "0x200000")
        self.assertEqual(self.e["cross_binary"]["im_single_letter_a_flag"], "0x400000")
        self.assertEqual(self.e["runtime_verified_apis"], 0)
        self.assertEqual(self.e["safe_to_invoke_apis"], 0)
        self.assertEqual(self.e["camera_core_tracking"]["core_edges_added"], 0)
        self.assertEqual(self.core["primary_elf_verified_edges"], 74)
        self.assertEqual(self.core["tracked_core_edges"], 84)


if __name__ == "__main__":
    unittest.main()
