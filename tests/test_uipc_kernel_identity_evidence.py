"""Metadata-only regressions for original A6000 3.21 UIPC kernel module evidence."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class UIPCKernelIdentityEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kernel = json.loads((ROOT / "sdk" / "uipc_kernel_dispatch_3_21.json").read_text(encoding="utf-8"))
        cls.osal = json.loads((ROOT / "sdk" / "osal_uipc_routing_3_21.json").read_text(encoding="utf-8"))
        cls.im = json.loads((ROOT / "sdk" / "im_callback_bridge_3_21.json").read_text(encoding="utf-8"))
        cls.core = json.loads((ROOT / "sdk" / "camera_core_progress_3_21.json").read_text(encoding="utf-8"))

    def test_pinned_original_kernel_module(self):
        m = self.kernel["kernel_module"]
        self.assertEqual(m["sha256"], "82a92bd4bd00d7e28237b647c93278f57d53dee241f96075798fad8a87926ab1")
        self.assertEqual(m["size_bytes"], 37264)
        self.assertIn("ET_REL", m["elf"])
        self.assertEqual(self.kernel["related_sources"]["userspace_osal_sha256"], self.osal["sha256"])
        self.assertEqual(self.kernel["related_sources"]["im_elf_sha256"], self.im["source_sha256"])

    def test_four_ioctl_dispatch_handlers_are_linked(self):
        entries = self.kernel["ioctl_kernel_dispatch"]["mapping"]
        self.assertEqual([(int(x["userspace_request"], 16), x["handler"]) for x in entries], [
            (0x80000004, "__k_4u_snd_msg"),
            (0x80000007, "__k_4u_rcv_msg_tmo"),
            (0x80000008, "__k_4u_reg_msg_queue_cb"),
            (0x8000000c, "__k_4u_dynamic_id"),
        ])
        for x in entries:
            self.assertEqual(int(x["rodata_table_offset"], 16), 0x28 + 4*x["masked_index"])

    def test_dynamic_receiver_never_directly_equals_sender(self):
        d = self.kernel["dynamic_id"]
        opts = int(d["im_elf_arguments"]["r0_options"], 16)
        self.assertTrue(opts & 0x2)
        self.assertFalse(opts & 0x4)
        self.assertFalse(opts & 0x10)
        self.assertFalse(opts & 0x40)
        base, count = int(d["pool_base"], 16), int(d["pool_size"], 16)
        self.assertEqual((base, count), (0x6000, 0x1000))
        sender = int(d["fixed_im_send_destination"], 16)
        first = (int(d["im_elf_arguments"]["r1_namespace"], 16) << 16) | base
        last = first + count - 1
        self.assertEqual((first, last), (0x946000, 0x946fff))
        self.assertFalse(first <= sender <= last)
        self.assertEqual(d["identity_test"].split(":")[0], "PROVEN_STATIC_NON_EQUAL")

    def test_no_runtime_or_original_core_graph_promotion(self):
        self.assertEqual(self.kernel["runtime_verified_apis"], 0)
        self.assertEqual(self.kernel["safe_to_invoke_apis"], 0)
        self.assertEqual(self.kernel["core_graph_unchanged"]["primary"], 74)
        self.assertEqual(self.core["primary_elf_verified_edges"], 74)
        self.assertEqual(self.core["tracked_core_edges"], 84)


if __name__ == "__main__":
    unittest.main()
