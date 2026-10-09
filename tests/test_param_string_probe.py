"""Synthetic fail-closed checks for the PrmString probe."""
import unittest

from fwplatform.param_string_probe import validate_param_string
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


def _report():
    return {
        "binary_file_sha256": EXPECTED_LIBOBJ_SHA,
        "address_space": "ELF_VMA",
        "discriminator": 2,
        "allocation_size_bytes": 0x10,
        "runtime_verified": False,
        "callable": False,
        "observations": {
            name: {"status": "PRIMARY_ELF_VERIFIED"}
            for name in ("vtable", "constructor", "destructor", "deleting_destructor", "clone")
        },
    }


class ParamStringProbeTests(unittest.TestCase):
    def test_static_report_is_valid(self):
        result = validate_param_string(_report())
        self.assertTrue(result["valid"])
        self.assertEqual(result["errors"], [])

    def test_wrong_binary_is_rejected(self):
        report = _report()
        report["binary_file_sha256"] = "0" * 64
        result = validate_param_string(report)
        self.assertFalse(result["valid"])
        self.assertIn("binary_identity", result["errors"])

    def test_missing_observation_is_rejected(self):
        report = _report()
        del report["observations"]["destructor"]
        result = validate_param_string(report)
        self.assertFalse(result["valid"])
        self.assertIn("missing:destructor", result["errors"])

    def test_runtime_promotion_is_rejected(self):
        report = _report()
        report["callable"] = True
        result = validate_param_string(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])

    def test_wrong_discriminator_is_rejected(self):
        report = _report()
        report["discriminator"] = 3
        result = validate_param_string(report)
        self.assertFalse(result["valid"])
        self.assertIn("discriminator", result["errors"])


if __name__ == "__main__":
    unittest.main()
