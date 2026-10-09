"""Synthetic fail-closed checks for Camera selector metadata."""
import unittest

from fwplatform.camera_selector_probe import validate_camera_selector
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


def _report():
    return {
        "binary_file_sha256": EXPECTED_LIBOBJ_SHA,
        "address_space": "ELF_VMA",
        "runtime_verified": False,
        "callable": False,
        "observation": {"status": "PRIMARY_ELF_VERIFIED"},
    }


class CameraSelectorProbeTests(unittest.TestCase):
    def test_static_report_is_valid(self):
        result = validate_camera_selector(_report())
        self.assertTrue(result["valid"])
        self.assertEqual(result["errors"], [])

    def test_wrong_binary_is_rejected(self):
        report = _report()
        report["binary_file_sha256"] = "0" * 64
        result = validate_camera_selector(report)
        self.assertFalse(result["valid"])
        self.assertIn("binary_identity", result["errors"])

    def test_missing_observation_status_is_rejected(self):
        report = _report()
        report["observation"] = {}
        result = validate_camera_selector(report)
        self.assertFalse(result["valid"])
        self.assertIn("observation_status", result["errors"])

    def test_runtime_or_callable_promotion_is_rejected(self):
        report = _report()
        report["callable"] = True
        result = validate_camera_selector(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])


if __name__ == "__main__":
    unittest.main()
