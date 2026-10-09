"""Synthetic fail-closed checks for EventManager layout metadata."""
import unittest

from fwplatform.event_manager_init_probe import TARGET, validate_event_manager_init
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


def _report():
    binding = {"status": "VERIFIED_STATIC"}
    return {
        "binary_file_sha256": EXPECTED_LIBOBJ_SHA,
        "address_space": "ELF_VMA",
        "runtime_verified": False,
        "callable": False,
        "target": {"entry": TARGET["entry"]},
        "observation": {
            "status": "PRIMARY_ELF_VERIFIED",
            "bindings": {"mutex_init": binding, "state_array_alloc": binding, "state_word_alloc": binding},
        },
    }


class EventManagerInitProbeTests(unittest.TestCase):
    def test_static_report_is_valid(self):
        result = validate_event_manager_init(_report())
        self.assertTrue(result["valid"])
        self.assertEqual(result["errors"], [])

    def test_wrong_binary_is_rejected(self):
        report = _report()
        report["binary_file_sha256"] = "0" * 64
        result = validate_event_manager_init(report)
        self.assertFalse(result["valid"])
        self.assertIn("binary_identity", result["errors"])

    def test_missing_binding_is_rejected(self):
        report = _report()
        report["observation"]["bindings"]["mutex_init"] = {}
        result = validate_event_manager_init(report)
        self.assertFalse(result["valid"])
        self.assertIn("binding:mutex_init", result["errors"])

    def test_callable_promotion_is_rejected(self):
        report = _report()
        report["callable"] = True
        result = validate_event_manager_init(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])


if __name__ == "__main__":
    unittest.main()
