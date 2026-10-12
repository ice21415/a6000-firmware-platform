"""Regression checks for offline im dynamic receiver ID announcement and state machine."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))


class ImDynamicAnnouncementEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.e = json.loads((ROOT / "sdk" / "im_dynamic_queue_announcement_3_21.json").read_text(encoding="utf-8"))
        cls.kernel = json.loads((ROOT / "sdk" / "uipc_kernel_dispatch_3_21.json").read_text(encoding="utf-8"))
        cls.progress = json.loads((ROOT / "sdk" / "camera_core_progress_3_21.json").read_text(encoding="utf-8"))

    def test_pinned_source_and_allocator(self):
        self.assertEqual(self.e["source"]["sha256"], self.kernel["related_sources"]["im_elf_sha256"])
        self.assertEqual(self.e["dynamic_id_allocator"]["wrapper"], "0x92bc")
        self.assertEqual(self.e["dynamic_id_allocator"]["kernel_pool_if_success"], "0x946000..0x946fff")

    def test_wrapper_has_four_actual_written_words(self):
        w = self.e["message_constructor"]
        self.assertEqual(w["entry"], "0x91a4")
        self.assertEqual(w["send"], "0x91dc BLX 0x8fc8 osal_snd_msg")
        self.assertEqual([w[f"word{i}"].split()[0] for i in range(4)],
                         ["0x91d2", "0x91d4", "0x91d6", "0x91da"])

    def test_main_announcement_contains_return_address_at_word_2(self):
        m = self.e["main_id_advertisement"]
        self.assertEqual(m["send_callsite"], "0x9e6c BL 0x91a4")
        self.assertEqual(m["destination_id"], "0x0094016a")
        self.assertEqual(m["message_code"], "0x0094001a")
        self.assertIn("dynamic receiver queue ID", m["caller_fields"]["r3"])
        self.assertEqual(m["constructed_message_words"][2], "allocated receiver ID 0x946000..0x946fff if successful")
        self.assertEqual(m["constructed_message_words"][-1], "0x00000003")

    def test_alternate_announcer_is_tag_two(self):
        a = self.e["alternate_id_advertisement"]
        self.assertEqual(a["send_callsite"], "0x96f8 BL 0x91a4")
        self.assertEqual(a["message_code"], self.e["main_id_advertisement"]["message_code"])
        self.assertEqual(a["constructed_message_words"][-1], "0x00000002")

    def test_state5_is_not_stage_handler(self):
        s = self.e["callback_fsm"]
        self.assertEqual(s["post_init_wait"], "0x9e4a..0x9e4e calls ac08(state=5,callback=0x9339)")
        self.assertEqual(s["late_event_reactivation"], "0x9edc..0x9ef2 conditionally calls ac08(state=3,callback=0xa06d), then 0x9ef6 calls ad0c(state=2)")
        self.assertEqual(s["state5_handler"]["message1"], "0x00940007 at 0x939c")
        self.assertEqual(s["state5_handler"]["message2"], "0x00940001 at 0x93a4")
        self.assertEqual(s["stage_handler"], "0xa06c used only when pointer is a06d")

    def test_scanner_words_are_leads_not_runtime_proof(self):
        import scan_a6000_uipc_registration as scanner
        self.assertEqual(scanner.WORDS[0x0094001A], "announce_01a")
        self.assertEqual(scanner.WORDS[0x0094016A], "fixed_dest")
        self.assertEqual(scanner.WORDS[0x00940036], "stage_036")
        self.assertIsNone(scanner.check_elf(b"not an ELF"))

    def test_no_runtime_promotion(self):
        self.assertEqual(self.e["runtime_verified_apis"], 0)
        self.assertEqual(self.e["safe_to_invoke_apis"], 0)
        self.assertEqual(self.e["original_camera_core_counts"]["new_original_core_relations"], 0)
        self.assertEqual(self.progress["primary_elf_verified_edges"], 74)
        self.assertEqual(self.progress["tracked_core_edges"], 84)


if __name__ == "__main__":
    unittest.main()
