"""Synthetic fail-closed checks for EventManager::push metadata."""
import unittest

from fwplatform.event_manager_push_probe import TARGET, validate_event_manager_push
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


def _report():
    return {
        "binary_file_sha256": EXPECTED_LIBOBJ_SHA,
        "address_space": "ELF_VMA",
        "runtime_verified": False,
        "callable": False,
        "target": {"entry": TARGET["entry"]},
        "observation": {"status": "PRIMARY_ELF_VERIFIED"},
    }


class EventManagerPushProbeTests(unittest.TestCase):
    def test_static_report_is_valid(self):
        result = validate_event_manager_push(_report())
        self.assertTrue(result["valid"])
        self.assertEqual(result["errors"], [])

    def test_wrong_binary_is_rejected(self):
        report = _report()
        report["binary_file_sha256"] = "0" * 64
        result = validate_event_manager_push(report)
        self.assertFalse(result["valid"])
        self.assertIn("binary_identity", result["errors"])

    def test_wrong_entry_is_rejected(self):
        report = _report()
        report["target"]["entry"] = 0x7EF962
        result = validate_event_manager_push(report)
        self.assertFalse(result["valid"])
        self.assertIn("target_entry", result["errors"])

    def test_runtime_promotion_is_rejected(self):
        report = _report()
        report["runtime_verified"] = True
        result = validate_event_manager_push(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])


if __name__ == "__main__":
    unittest.main()
