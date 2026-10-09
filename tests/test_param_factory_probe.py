"""Synthetic fail-closed checks for the ParamBase factory caller probe."""
import unittest

from fwplatform.param_factory_probe import validate_param_factory_probe
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


def _report():
    return {
        "binary_file_sha256": EXPECTED_LIBOBJ_SHA,
        "address_space": "ELF_VMA",
        "factory_entry": "0x42acd4",
        "dynamic_table_values_recovered": False,
        "ownership_verified": False,
        "runtime_verified": False,
        "callable": False,
        "callers": [{
            "factory_target_status": "PRIMARY_ELF_VERIFIED",
            "argument_provenance": {
                "r0": {"provenance_status": "STATIC_INFERRED"},
                "r1": {"provenance_status": "STATIC_INFERRED"},
                "r2": {"provenance_status": "STATIC_INFERRED"},
            },
            "result_guard": {"status": "PRIMARY_ELF_VERIFIED"},
            "post_success_add": {"status": "UNKNOWN"},
        }],
    }


class ParamFactoryProbeTests(unittest.TestCase):
    def test_dynamic_values_and_runtime_claims_remain_closed(self):
        result = validate_param_factory_probe(_report())
        self.assertTrue(result["valid"])
        self.assertEqual(result["caller_count"], 1)

    def test_unknown_argument_provenance_is_allowed(self):
        report = _report()
        report["callers"][0]["argument_provenance"]["r1"]["provenance_status"] = "UNKNOWN"
        self.assertTrue(validate_param_factory_probe(report)["valid"])

    def test_callable_claim_is_rejected(self):
        report = _report()
        report["callable"] = True
        result = validate_param_factory_probe(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])

    def test_static_provenance_cannot_be_relabelled_runtime(self):
        report = _report()
        report["callers"][0]["argument_provenance"]["r2"]["provenance_status"] = "VERIFIED_RUNTIME"
        result = validate_param_factory_probe(report)
        self.assertFalse(result["valid"])
        self.assertIn("r2_provenance", result["errors"])

    def test_binary_identity_is_required(self):
        report = _report()
        report["binary_file_sha256"] = "0" * 64
        result = validate_param_factory_probe(report)
        self.assertFalse(result["valid"])
        self.assertIn("binary_identity", result["errors"])


if __name__ == "__main__":
    unittest.main()
