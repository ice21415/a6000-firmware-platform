"""Offline metadata regressions for firmware 3.21 OSAL kernel UIPC evidence."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class OSALUIPCRoutingEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.osal = json.loads((ROOT / "sdk" / "osal_uipc_routing_3_21.json").read_text(encoding="utf-8"))
        cls.im = json.loads((ROOT / "sdk" / "im_callback_bridge_3_21.json").read_text(encoding="utf-8"))
        cls.core = json.loads((ROOT / "sdk" / "camera_core_progress_3_21.json").read_text(encoding="utf-8"))

    def test_binary_provenance(self):
        self.assertEqual(cls_source := self.osal["sha256"],
                         "0c6b87a012eb757dbe0a5b9b7b19fb91fc27c1dafc0e78facb126114416cf1ef")
        self.assertNotEqual(cls_source, self.im["source_sha256"])
        self.assertEqual(self.osal["size_bytes"], 26636)

    def test_critical_public_bit_dispatch(self):
        apis = self.osal["api_dispatch"]
        self.assertEqual([a["api"] for a in apis],
                         ["osal_snd_msg", "osal_rcv_msg_tmo", "osal_reg_sync_msg_queue_cb"])
        self.assertTrue(all("0x8000" in x["bit_test"] for x in apis))
        self.assertTrue(all("u_osal_" in x["if_clear"] for x in apis))

    def test_uipc_ioctl_instructions_have_disjoint_requests(self):
        kernel = self.osal["kernel_device"]
        self.assertEqual(kernel["literal"], "/dev/uipc")
        self.assertEqual(kernel["ioctl_plt"], "0x1740")
        mapping = {x["api"]: int(x["request"], 16) for x in self.osal["remote_uipc_ioctl"]}
        self.assertEqual(mapping, {"u_osal_snd_msg": 0x80000004,
                                   "u_osal_rcv_msg_tmo": 0x80000007,
                                   "u_osal_reg_sync_msg_queue_cb": 0x80000008,
                                   "u_osal_dynamic_id": 0x8000000c})

    def test_im_receiver_does_not_claim_id_equality(self):
        match = self.osal["cross_elf"]
        self.assertEqual(match["im_elf_sha256"], self.im["source_sha256"])
        self.assertEqual(int(match["im_destination"], 16) & 0x8000, 0)
        self.assertFalse(match["destination_0x8000_bit_set"])
        self.assertEqual(match["receiver_creation"],
                         "im.elf 0x92bc passes option r0=0x2a and namespace r1=0x94 to osal_dynamic_id")
        self.assertEqual(0x2a & 0x2, 0x2)
        self.assertIn("NOT PROVIDED", self.osal["important_distinction"]["kernel_module_binary"])

    def test_no_runtime_or_camera_graph_promotion(self):
        self.assertEqual(self.osal["runtime_verified_apis"], 0)
        self.assertEqual(self.osal["safe_to_invoke"], 0)
        self.assertEqual(self.osal["graph_counts"]["additional_core_edges"], 0)
        self.assertEqual(self.core["primary_elf_verified_edges"], 74)
        self.assertEqual(self.core["tracked_core_edges"], 84)


if __name__ == "__main__":
    unittest.main()
