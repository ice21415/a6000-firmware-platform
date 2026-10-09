"""Synthetic fail-closed checks for the Camera prepare envelope metadata."""
import unittest

from fwplatform.camera_prepare_envelope_probe import validate_camera_prepare_envelope
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


def _report():
    binding = {"status": "VERIFIED_STATIC"}
    return {
        "binary_file_sha256": EXPECTED_LIBOBJ_SHA,
        "address_space": "ELF_VMA",
        "runtime_verified": False,
        "callable": False,
        "observation": {
            "status": "PRIMARY_ELF_VERIFIED",
            "bindings": {"allocator": binding, "event_add_parameter": binding},
        },
    }


class CameraPrepareEnvelopeProbeTests(unittest.TestCase):
    def test_static_report_is_valid(self):
        result = validate_camera_prepare_envelope(_report())
        self.assertTrue(result["valid"])
        self.assertEqual(result["errors"], [])

    def test_wrong_binary_is_rejected(self):
        report = _report()
        report["binary_file_sha256"] = "0" * 64
        result = validate_camera_prepare_envelope(report)
        self.assertFalse(result["valid"])
        self.assertIn("binary_identity", result["errors"])

    def test_missing_event_binding_is_rejected(self):
        report = _report()
        report["observation"]["bindings"]["event_add_parameter"] = {}
        result = validate_camera_prepare_envelope(report)
        self.assertFalse(result["valid"])
        self.assertIn("event_add_parameter_binding", result["errors"])

    def test_callable_promotion_is_rejected(self):
        report = _report()
        report["callable"] = True
        result = validate_camera_prepare_envelope(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])


if __name__ == "__main__":
    unittest.main()
