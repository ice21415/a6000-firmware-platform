"""Synthetic fail-closed checks for the PrmSet primary probe."""
import json
import unittest
from pathlib import Path

from fwplatform.param_set_probe import TARGETS, validate_param_set
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


def _report():
    insert_binding = {
        "status": "VERIFIED_STATIC",
        "candidates": [{
            "symbol": "_ZSt29_Rb_tree_insert_and_rebalancebPSt18_Rb_tree_node_baseS0_RS_",
        }],
    }
    return {
        "binary_file_sha256": EXPECTED_LIBOBJ_SHA,
        "address_space": "ELF_VMA",
        "type": "PrmSet",
        "discriminator": 7,
        "allocation_size_bytes": 0x24,
        "runtime_verified": False,
        "callable": False,
        "inheritance": {
            "status": "PRIMARY_ELF_VERIFIED",
            "base_type": "ParamBase",
            "rtti_name": "6PrmSet",
            "vtable_address_point": "0x1019d20",
        },
        "payload_layout": {
            "tree_evidence": {
                "status": "PRIMARY_ELF_VERIFIED",
                "node_size_bytes": 0x14,
                "node_value_offset": 0x10,
                "header_sentinel_offset": 0x04,
                "node_count_offset": 0x14,
                "source_type": "UNKNOWN",
                "likely_source_family": "STATIC_INFERRED; libstdc++ _Rb_tree-like ordered container",
                "insert_rebalance_binding": insert_binding,
            },
        },
        "observations": {
            target["name"]: {"status": "PRIMARY_ELF_VERIFIED"}
            for target in TARGETS
        },
    }


class ParamSetProbeTests(unittest.TestCase):
    def test_checked_in_contract_keeps_tree_source_unknown(self):
        path = Path(__file__).parents[1] / "sdk" / "param_set_3_21.json"
        contract = json.loads(path.read_text(encoding="utf-8"))
        tree = contract["layout"]["tree_evidence"]
        self.assertEqual(contract["binary_sha256"], EXPECTED_LIBOBJ_SHA)
        self.assertEqual(tree["status"], "PRIMARY_ELF_VERIFIED")
        self.assertEqual(tree["node_size_bytes"], 0x14)
        self.assertEqual(tree["node_value_offset"], 0x10)
        self.assertEqual(tree["source_type"], "UNKNOWN")
        self.assertFalse(contract["runtime_verified"])
        self.assertFalse(contract["callable"])

    def test_static_report_is_valid(self):
        result = validate_param_set(_report())
        self.assertTrue(result["valid"])
        self.assertEqual(result["errors"], [])

    def test_wrong_binary_is_rejected(self):
        report = _report()
        report["binary_file_sha256"] = "0" * 64
        result = validate_param_set(report)
        self.assertFalse(result["valid"])
        self.assertIn("binary_identity", result["errors"])

    def test_missing_payload_observation_is_rejected(self):
        report = _report()
        del report["observations"]["payload_copy_wrapper"]
        result = validate_param_set(report)
        self.assertFalse(result["valid"])
        self.assertIn("missing_observations", result["errors"])

    def test_callable_promotion_is_rejected(self):
        report = _report()
        report["callable"] = True
        result = validate_param_set(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])

    def test_tree_node_size_is_evidence_gated(self):
        report = _report()
        report["payload_layout"]["tree_evidence"]["node_size_bytes"] = 0x10
        result = validate_param_set(report)
        self.assertFalse(result["valid"])
        self.assertIn("tree_node_size", result["errors"])

    def test_tree_symbol_mismatch_is_rejected(self):
        report = _report()
        report["payload_layout"]["tree_evidence"]["insert_rebalance_binding"]["candidates"][0]["symbol"] = "_ZSt18_Rb_tree_incrementPSt18_Rb_tree_node_base"
        result = validate_param_set(report)
        self.assertFalse(result["valid"])
        self.assertIn("tree_insert_symbol", result["errors"])

    def test_missing_tree_evidence_is_rejected(self):
        report = _report()
        del report["payload_layout"]["tree_evidence"]
        result = validate_param_set(report)
        self.assertFalse(result["valid"])
        self.assertIn("missing_tree_evidence", result["errors"])

    def test_wrong_derived_vtable_is_rejected(self):
        report = _report()
        report["inheritance"]["vtable_address_point"] = "0xfe6e38"
        result = validate_param_set(report)
        self.assertFalse(result["valid"])
        self.assertIn("inheritance_vtable", result["errors"])

    def test_exact_source_type_promotion_is_rejected(self):
        report = _report()
        report["payload_layout"]["tree_evidence"]["source_type"] = "std::set<uint32_t>"
        result = validate_param_set(report)
        self.assertFalse(result["valid"])
        self.assertIn("tree_source_type_promotion", result["errors"])


if __name__ == "__main__":
    unittest.main()
