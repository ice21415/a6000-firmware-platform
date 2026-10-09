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
            "state_initialization": {
                "status": "PRIMARY_ELF_VERIFIED",
                "semantic_level": "STATIC_INFERRED",
                "helper_entry": "0x7f09be",
                "helper_chain": ["0x1111cc", "0x1111b8", "0x1111ac", "0x1111a2", "0x1114b0"],
                "state_object_size": 8,
                "state_object_layout": {
                    "+0x00": "link word; exact self-link store is [object] = object",
                    "+0x04": "link word; exact self-link store is [object + 4] = object",
                },
                "initialization": "bounded helper invokes zero-then-self-link and a clear-path that ends with self-link",
                "source_container_type": "UNKNOWN; no source-level class or standard-container identity is proven",
                "ownership": "UNKNOWN; allocation/deallocation pairing is not established by this helper chain",
            },
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

    def test_state_semantic_promotion_is_rejected(self):
        report = _report()
        report["observation"]["state_initialization"]["semantic_level"] = "PRIMARY_ELF_VERIFIED"
        result = validate_event_manager_init(report)
        self.assertFalse(result["valid"])
        self.assertIn("state_initialization_semantics", result["errors"])

    def test_missing_state_evidence_is_rejected(self):
        report = _report()
        report["observation"].pop("state_initialization")
        result = validate_event_manager_init(report)
        self.assertFalse(result["valid"])
        self.assertIn("state_initialization_status", result["errors"])


if __name__ == "__main__":
    unittest.main()
