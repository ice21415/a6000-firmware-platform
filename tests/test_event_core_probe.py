"""Synthetic fail-closed checks for Event core metadata."""
import unittest

from fwplatform.event_core_probe import TARGETS, validate_event_core
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


def _report():
    observations = {
        name: {"status": "PRIMARY_ELF_VERIFIED"}
        for name in ("constructor", "copy_constructor", "destructor", "set_param_list", "add_parameter", "get_parameter")
    }
    observations["constructor"]["bindings"] = {"allocator": {"status": "VERIFIED_STATIC"}, "paramlist_constructor": {"status": "VERIFIED_STATIC"}}
    for name in ("destructor", "set_param_list"):
        observations[name]["bindings"] = {"paramlist_destructor": {"status": "VERIFIED_STATIC"}, "operator_delete": {"status": "VERIFIED_STATIC"}}
    observations["add_parameter"]["target_binding"] = {"status": "VERIFIED_STATIC"}
    observations["get_parameter"]["target_binding"] = {"status": "VERIFIED_STATIC"}
    return {
        "binary_file_sha256": EXPECTED_LIBOBJ_SHA,
        "address_space": "ELF_VMA",
        "runtime_verified": False,
        "callable": False,
        "symbols": {item["symbol"]: {"size": item["size"]} for item in TARGETS},
        "observations": observations,
    }


class EventCoreProbeTests(unittest.TestCase):
    def test_static_report_is_valid(self):
        result = validate_event_core(_report())
        self.assertTrue(result["valid"])
        self.assertEqual(result["errors"], [])

    def test_wrong_binary_is_rejected(self):
        report = _report()
        report["binary_file_sha256"] = "0" * 64
        result = validate_event_core(report)
        self.assertFalse(result["valid"])
        self.assertIn("binary_identity", result["errors"])

    def test_missing_forwarder_binding_is_rejected(self):
        report = _report()
        report["observations"]["add_parameter"]["target_binding"] = {}
        result = validate_event_core(report)
        self.assertFalse(result["valid"])
        self.assertIn("binding:add_parameter:target", result["errors"])

    def test_callable_promotion_is_rejected(self):
        report = _report()
        report["callable"] = True
        result = validate_event_core(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])


if __name__ == "__main__":
    unittest.main()
