"""Synthetic fail-closed checks for the Point/Dimension family probe."""
import unittest

from fwplatform.param_pair_probe import FAMILY_PROFILES, validate_param_pair
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


def _report():
    return {
        "binary_file_sha256": EXPECTED_LIBOBJ_SHA,
        "address_space": "ELF_VMA",
        "runtime_verified": False,
        "callable": False,
        "types": {
            profile["name"]: {
                "verification": "PRIMARY_ELF_VERIFIED",
                "discriminator": profile["discriminator"],
                "vtable": {"status": "PRIMARY_ELF_VERIFIED"},
                "runtime_verified": False,
                "callable": False,
                **{
                    phase: {"status": "PRIMARY_ELF_VERIFIED"}
                    for phase in ("constructor", "destructor", "deleting_destructor", "clone")
                },
            }
            for profile in FAMILY_PROFILES
        },
    }


class ParamPairProbeTests(unittest.TestCase):
    def test_static_report_is_valid(self):
        result = validate_param_pair(_report())
        self.assertTrue(result["valid"])
        self.assertEqual(result["errors"], [])

    def test_wrong_binary_is_rejected(self):
        report = _report()
        report["binary_file_sha256"] = "0" * 64
        result = validate_param_pair(report)
        self.assertFalse(result["valid"])
        self.assertIn("binary_identity", result["errors"])

    def test_missing_family_is_rejected(self):
        report = _report()
        del report["types"]["PrmDimension"]
        result = validate_param_pair(report)
        self.assertFalse(result["valid"])
        self.assertIn("missing:PrmDimension", result["errors"])

    def test_runtime_promotion_is_rejected(self):
        report = _report()
        report["types"]["PrmPoint"]["callable"] = True
        result = validate_param_pair(report)
        self.assertFalse(result["valid"])
        self.assertIn("unsafe:PrmPoint", result["errors"])


if __name__ == "__main__":
    unittest.main()
