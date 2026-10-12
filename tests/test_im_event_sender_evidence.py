"""Metadata-only checks for ARM im.elf boot stage producer witnesses."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class IMEventProducerEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.producer = json.loads((ROOT / "sdk" / "im_event_sender_3_21.json").read_text(encoding="utf-8"))
        cls.stages = json.loads((ROOT / "sdk" / "im_stage_dispatch_3_21.json").read_text(encoding="utf-8"))
        cls.im = json.loads((ROOT / "sdk" / "im_bootstrap_3_21.json").read_text(encoding="utf-8"))
        cls.core = json.loads((ROOT / "sdk" / "camera_core_progress_3_21.json").read_text(encoding="utf-8"))

    def test_independent_source(self):
        self.assertEqual(self.producer["source"]["sha256"], self.im["source_sha256"])
        self.assertEqual(self.producer["source"]["sha256"], self.stages["sources"]["im_elf_sha256"])

    def test_all_seven_phase_send_calls_in_source_order(self):
        events = self.producer["event_send_sites"]
        self.assertEqual(len(events), 7)
        self.assertEqual([int(x["event"], 16) for x in events], list(range(0x940031, 0x940038)))
        self.assertEqual([int(x["flag"], 16) for x in events],
                         [0x10000, 0x20000, 0x40000, 0x80000, 0x100000, 0x200000, 0x400000])
        self.assertEqual([int(x["call"], 16) for x in events], sorted(int(x["call"], 16) for x in events))
        self.assertEqual(events[5]["call"], "0x9d72")
        self.assertEqual(events[6]["call"], "0x9d88")

    def test_boot_cli_selectors_correspond_to_sender(self):
        info = self.producer["boot_option_parser"]
        self.assertEqual(info["prefix"], "boot=")
        self.assertEqual(info["special_all"]["flag_mask"], "0x7f0000")
        self.assertEqual({x["selector"]: x["flag"] for x in info["options"]},
                         {"s": "0x10000", "u": "0x80000", "l": "0x100000", "i": "0x200000", "a": "0x400000"})
        sender = {int(v["flag"], 16) for v in self.producer["event_send_sites"]}
        for entry in info["options"]:
            self.assertIn(int(entry["flag"], 16), sender)

    def test_sender_is_not_same_as_registration_callback(self):
        d = self.producer["destination"]
        h = self.producer["local_handler"]
        self.assertEqual(d["value"], "0x0094016a")
        self.assertEqual(d["callback_registered"]["callback_thumb"], "0x95b1")
        self.assertEqual(h["address_thumb"], "0xa06d")
        self.assertNotEqual(d["callback_registered"]["callback_thumb"], h["address_thumb"])
        self.assertEqual(self.producer["send_wrapper"]["send_symbol"], "osal_snd_msg")
        self.assertEqual(self.producer["send_wrapper"]["send_callsite"], "0x91dc")

    def test_no_runtime_promotion(self):
        self.assertEqual(self.producer["core_counts_unchanged"],
                         {"primary": 74, "inferred": 5, "unresolved": 5, "tracked": 84})
        self.assertEqual(self.producer["runtime_verified"], 0)
        self.assertEqual(self.producer["safe_to_invoke"], 0)
        self.assertEqual(self.core["primary_elf_verified_edges"], 74)
        self.assertEqual(self.core["tracked_core_edges"], 84)


if __name__ == "__main__":
    unittest.main()
