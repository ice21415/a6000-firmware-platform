"""Synthetic fail-closed checks for the PrmSet primary probe."""
import unittest

from fwplatform.param_set_probe import TARGETS, validate_param_set
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


def _report():
    return {
        "binary_file_sha256": EXPECTED_LIBOBJ_SHA,
        "address_space": "ELF_VMA",
        "type": "PrmSet",
        "discriminator": 7,
        "allocation_size_bytes": 0x24,
        "runtime_verified": False,
        "callable": False,
        "observations": {
            target["name"]: {"status": "PRIMARY_ELF_VERIFIED"}
            for target in TARGETS
        },
    }


class ParamSetProbeTests(unittest.TestCase):
    def test_static_report_is_valid(self):
        result = validate_param_set(_report())
        self.assertTrue(result["valid"])
        self.assertEqual(result["errors"], [])

    def test_wrong_binary_is_rejected(self):
        report = _report()
        report["binary_file_sha256"] = "0" * 64
        result = validate_param_set(report)
        self.assertFalse(result["valid"])
        self.assertIn("binary_identity", result["errors"])

    def test_missing_payload_observation_is_rejected(self):
        report = _report()
        del report["observations"]["payload_copy_wrapper"]
        result = validate_param_set(report)
        self.assertFalse(result["valid"])
        self.assertIn("missing_observations", result["errors"])

    def test_callable_promotion_is_rejected(self):
        report = _report()
        report["callable"] = True
        result = validate_param_set(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])


if __name__ == "__main__":
    unittest.main()
