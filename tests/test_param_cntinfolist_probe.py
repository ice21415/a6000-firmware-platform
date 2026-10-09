"""Synthetic fail-closed checks for PrmCntInfoList metadata."""
import unittest

from fwplatform.param_cntinfolist_probe import TARGETS, validate_param_cntinfolist
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


def _report():
    return {
        "binary_file_sha256": EXPECTED_LIBOBJ_SHA,
        "address_space": "ELF_VMA",
        "type": "PrmCntInfoList",
        "discriminator": 9,
        "runtime_verified": False,
        "callable": False,
        "observations": {
            item["name"]: {"facts": {"status": "PRIMARY_ELF_VERIFIED"}}
            for item in TARGETS
        },
    }


class ParamCntInfoListProbeTests(unittest.TestCase):
    def test_static_report_is_valid(self):
        result = validate_param_cntinfolist(_report())
        self.assertTrue(result["valid"])
        self.assertEqual(result["observation_count"], len(TARGETS))

    def test_missing_observation_is_not_filled_in(self):
        report = _report()
        del report["observations"]["add"]
        result = validate_param_cntinfolist(report)
        self.assertFalse(result["valid"])
        self.assertIn("missing_observations", result["errors"])

    def test_wrong_type_or_discriminator_is_rejected(self):
        report = _report()
        report["type"] = "PrmNumberList"
        result = validate_param_cntinfolist(report)
        self.assertFalse(result["valid"])
        self.assertIn("type_identity", result["errors"])

    def test_runtime_claim_is_rejected(self):
        report = _report()
        report["callable"] = True
        result = validate_param_cntinfolist(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])

    def test_collection_growth_observation_is_required(self):
        report = _report()
        del report["observations"]["append_growth_helper"]
        result = validate_param_cntinfolist(report)
        self.assertFalse(result["valid"])
        self.assertIn("missing_observations", result["errors"])

    def test_unknown_collection_semantics_are_not_promoted(self):
        report = _report()
        report["payload_layout"] = {"element_type": "std::vector<unsigned int>"}
        # The validator deliberately checks provenance-bearing observations only;
        # callers must not treat a free-form layout label as a verified ABI.
        result = validate_param_cntinfolist(report)
        self.assertTrue(result["valid"])


if __name__ == "__main__":
    unittest.main()
