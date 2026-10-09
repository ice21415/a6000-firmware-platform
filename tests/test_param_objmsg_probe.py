"""Synthetic fail-closed checks for the PrmObjMsg probe metadata."""
import unittest

from fwplatform.param_objmsg_probe import TARGETS, validate_param_objmsg
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


def _report():
    return {
        "binary_file_sha256": EXPECTED_LIBOBJ_SHA,
        "address_space": "ELF_VMA",
        "runtime_verified": False,
        "callable": False,
        "observations": {target["name"]: {"status": "PRIMARY_ELF_VERIFIED"} for target in TARGETS},
    }


class ParamObjMsgProbeTests(unittest.TestCase):
    def test_static_report_is_valid(self):
        result = validate_param_objmsg(_report())
        self.assertTrue(result["valid"])
        self.assertEqual(result["errors"], [])

    def test_wrong_binary_is_rejected(self):
        report = _report()
        report["binary_file_sha256"] = "0" * 64
        result = validate_param_objmsg(report)
        self.assertFalse(result["valid"])
        self.assertIn("binary_identity", result["errors"])

    def test_missing_target_is_rejected(self):
        report = _report()
        del report["observations"]["objmsg_getter"]
        result = validate_param_objmsg(report)
        self.assertFalse(result["valid"])
        self.assertIn("missing:objmsg_getter", result["errors"])

    def test_callable_promotion_is_rejected(self):
        report = _report()
        report["callable"] = True
        result = validate_param_objmsg(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])


if __name__ == "__main__":
    unittest.main()
