"""Synthetic fail-closed checks for the request-model Event factory."""
import unittest

from fwplatform.camera_request_event_probe import (
    EVENT_ID_LITERAL,
    TARGET,
    validate_request_event_factory,
)
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


def _report():
    binding = {"status": "VERIFIED_STATIC"}
    return {
        "binary_file_sha256": EXPECTED_LIBOBJ_SHA,
        "address_space": "ELF_VMA",
        "runtime_verified": False,
        "callable": False,
        "target": {"entry": TARGET["entry"], "size": TARGET["size"]},
        "symbol": {"name": TARGET["symbol"]},
        "observation": {
            "status": "PRIMARY_ELF_VERIFIED",
            "event": {"id": hex(EVENT_ID_LITERAL["value"])},
            "bindings": {
                "allocator": binding,
                "event_constructor": binding,
                "set_param_list": binding,
                "add_parameter": binding,
                "operator_delete": binding,
                "exception_cleanup": binding,
            },
        },
    }


class CameraRequestEventProbeTests(unittest.TestCase):
    def test_static_report_is_valid(self):
        result = validate_request_event_factory(_report())
        self.assertTrue(result["valid"])
        self.assertEqual(result["errors"], [])

    def test_wrong_event_id_is_rejected(self):
        report = _report()
        report["observation"]["event"]["id"] = "0"
        result = validate_request_event_factory(report)
        self.assertFalse(result["valid"])
        self.assertIn("event_id", result["errors"])

    def test_missing_binding_is_rejected(self):
        report = _report()
        report["observation"]["bindings"]["add_parameter"] = {}
        result = validate_request_event_factory(report)
        self.assertFalse(result["valid"])
        self.assertIn("binding:add_parameter", result["errors"])

    def test_callable_promotion_is_rejected(self):
        report = _report()
        report["callable"] = True
        result = validate_request_event_factory(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])


if __name__ == "__main__":
    unittest.main()
