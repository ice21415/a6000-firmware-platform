"""Synthetic fail-closed checks for ParamList lifetime metadata."""
import unittest

from fwplatform.paramlist_mutation_probe import validate_paramlist_mutation
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


def _report():
    return {
        "binary_file_sha256": EXPECTED_LIBOBJ_SHA,
        "address_space": "ELF_VMA",
        "copy_on_write_verified": False,
        "thread_safety_verified": False,
        "runtime_verified": False,
        "callable": False,
        "targets": {
            "paramlist_clear_wrapper": {"facts": {"status": "PRIMARY_ELF_VERIFIED"}},
            "paramlist_clear_impl_candidate": {"facts": {"status": "PRIMARY_ELF_VERIFIED"}},
            "paramlist_destructor": {"facts": {"status": "PRIMARY_ELF_VERIFIED"}},
            "paramlist_assignment_like_candidate": {"facts": {"status": "PRIMARY_ELF_VERIFIED"}},
        },
    }


class ParamListMutationProbeTests(unittest.TestCase):
    def test_static_lifetime_report_is_valid_without_runtime_claims(self):
        result = validate_paramlist_mutation(_report())
        self.assertTrue(result["valid"])
        self.assertEqual(result["target_count"], 4)

    def test_missing_target_is_not_filled_in(self):
        report = _report()
        del report["targets"]["paramlist_destructor"]
        result = validate_paramlist_mutation(report)
        self.assertFalse(result["valid"])
        self.assertIn("missing_targets", result["errors"])

    def test_copy_on_write_claim_is_rejected(self):
        report = _report()
        report["copy_on_write_verified"] = True
        result = validate_paramlist_mutation(report)
        self.assertFalse(result["valid"])
        self.assertIn("copy_on_write_claim", result["errors"])

    def test_runtime_claim_is_rejected(self):
        report = _report()
        report["runtime_verified"] = True
        result = validate_paramlist_mutation(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])


if __name__ == "__main__":
    unittest.main()
