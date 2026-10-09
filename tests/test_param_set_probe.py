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
    report = {
        "binary_file_sha256": EXPECTED_LIBOBJ_SHA,
        "address_space": "ELF_VMA",
        "type": "PrmSet",
        "discriminator": 7,
        "allocation_size_bytes": 0x24,
        "exception_unwind": {
            "status": "PRIMARY_ELF_VERIFIED",
            "format": "ARM EHABI .ARM.exidx metadata",
            "targets": {
                "copy_constructor_candidate": {
                    "status": "PRIMARY_ELF_VERIFIED",
                    "address_space": "ELF_VMA",
                    "entry_vma": "0x7efb6c",
                    "exidx_entry_vma": "0xfb2a74",
                    "extab_vma": "0xf19718",
                    "unwind_kind": "EXTAB",
                },
                "clone_candidate": {
                    "status": "PRIMARY_ELF_VERIFIED",
                    "address_space": "ELF_VMA",
                    "entry_vma": "0x7efbb4",
                    "exidx_entry_vma": "0xfb2a7c",
                    "extab_vma": "0xf19730",
                    "unwind_kind": "EXTAB",
                },
            },
        },
        "runtime_verified": False,
        "callable": False,
        "bindings": {
            "end_cleanup": {
                "status": "VERIFIED_STATIC",
                "entry_vma": "0xdd4f8",
                "got_slot": "0x102d660",
                "candidates": [{"symbol": "__cxa_end_cleanup"}],
            },
        },
        "inheritance": {
            "status": "PRIMARY_ELF_VERIFIED",
            "base_type": "ParamBase",
            "rtti_name": "6PrmSet",
            "vtable_address_point": "0x1019d20",
            "vtable_slots": {
                "status": "PRIMARY_ELF_VERIFIED",
                "address_space": "ELF_VMA",
                "vtable_prefix_vma": "0x1019d18",
                "address_point_vma": "0x1019d20",
                "prefix": {
                    "offset_to_top": "0x0",
                    "typeinfo_pointer": "0x1019d08",
                },
                "slots": {
                    "+0x00": {
                        "role": "clone_candidate",
                        "entry_vma": "0x7efbb4",
                        "raw_thumb_value": "0x7efbb5",
                        "thumb_tag": True,
                        "status": "PRIMARY_ELF_VERIFIED",
                        "address_space": "ELF_VMA",
                    },
                    "+0x04": {
                        "role": "nondeleting_destructor",
                        "entry_vma": "0x7efb2c",
                        "raw_thumb_value": "0x7efb2d",
                        "thumb_tag": True,
                        "status": "PRIMARY_ELF_VERIFIED",
                        "address_space": "ELF_VMA",
                    },
                    "+0x08": {
                        "role": "deleting_destructor",
                        "entry_vma": "0x7efb58",
                        "raw_thumb_value": "0x7efb59",
                        "thumb_tag": True,
                        "status": "PRIMARY_ELF_VERIFIED",
                        "address_space": "ELF_VMA",
                    },
                },
            },
        },
        "payload_layout": {
            "header_layout": {
                "status": "PRIMARY_ELF_VERIFIED",
                "base_offset": "+0x04",
                "compatibility": "STATIC_INFERRED; compatible header shape",
            },
            "tree_evidence": {
                "status": "PRIMARY_ELF_VERIFIED",
                "node_size_bytes": 0x14,
                "node_value_offset": 0x10,
                "node_value_width_bytes": 4,
                "header_sentinel_offset": 0x04,
                "node_count_offset": 0x14,
                "node_layout": {
                    "status": "PRIMARY_ELF_VERIFIED",
                    "+0x10": "one-word value storage",
                    "compatibility": "STATIC_INFERRED; compatible node shape",
                },
                "source_type": "UNKNOWN",
                "value_type": "UNKNOWN; one-word storage with an unsigned-order comparator candidate",
                "likely_source_family": "STATIC_INFERRED; libstdc++ _Rb_tree-like ordered container",
                "insert_rebalance_binding": insert_binding,
                "insert_callers": {
                    "status": "PRIMARY_ELF_VERIFIED",
                    "prmset_mutator_entry": "UNKNOWN",
                },
            },
        },
        "safety_boundaries": {
            "get_set_null_receiver": {
                "status": "PRIMARY_ELF_VERIFIED",
            },
            "get_set_lifetime": {
                "status": "STATIC_INFERRED",
            },
            "destructor_payload_guard": {
                "status": "PRIMARY_ELF_VERIFIED",
            },
            "invalid_element": {
                "status": "UNKNOWN",
            },
            "concurrency": {
                "status": "UNKNOWN",
            },
            "runtime_safe": False,
        },
        "observations": {
            target["name"]: {"status": "PRIMARY_ELF_VERIFIED"}
            for target in TARGETS
        },
    }
    report["observations"]["prmset_payload_helper"]["exception_cleanup"] = {
        "status": "STATIC_INFERRED",
        "landing_pad_candidate": "0x7efb9c",
        "calls": ["0xffe0c", "0xe4734", "0xdd4f8"],
    }
    report["observations"]["prmset_clone"]["exception_cleanup"] = {
        "status": "STATIC_INFERRED",
        "landing_pad_candidate": "0x7efbce",
        "calls": ["0xdd620", "0xdd4f8"],
    }
    return report


class ParamSetProbeTests(unittest.TestCase):
    def test_checked_in_contract_keeps_tree_source_unknown(self):
        path = Path(__file__).parents[1] / "sdk" / "param_set_3_21.json"
        contract = json.loads(path.read_text(encoding="utf-8"))
        tree = contract["layout"]["tree_evidence"]
        self.assertEqual(contract["binary_sha256"], EXPECTED_LIBOBJ_SHA)
        self.assertEqual(tree["status"], "PRIMARY_ELF_VERIFIED")
        self.assertEqual(tree["node_size_bytes"], 0x14)
        self.assertEqual(tree["node_value_offset"], 0x10)
        self.assertEqual(tree["node_value_width_bytes"], 4)
        self.assertEqual(tree["source_type"], "UNKNOWN")
        self.assertEqual(tree["value_type"].split(";", 1)[0], "UNKNOWN")
        header = contract["layout"]["header_layout"]
        self.assertEqual(header["status"], "PRIMARY_ELF_VERIFIED")
        self.assertEqual(header["base_offset"], "+0x04")
        self.assertTrue(header["compatibility"].startswith("STATIC_INFERRED"))
        node = tree["node_layout"]
        self.assertEqual(node["status"], "PRIMARY_ELF_VERIFIED")
        self.assertEqual(node["+0x10"], "one-word value storage")
        self.assertTrue(node["compatibility"].startswith("STATIC_INFERRED"))
        self.assertEqual(tree["insert_callers"]["direct_callsite_addresses"], [
            "0xfff4e", "0xfff86", "0x7f4402",
        ])
        self.assertEqual(tree["value_copy_evidence"]["entry"], "0xecd7a")
        self.assertEqual(tree["value_compare_evidence"]["entry"], "0xefe6c")
        inheritance = contract["inheritance"]
        slots = inheritance["vtable_slots"]
        self.assertEqual(slots["status"], "PRIMARY_ELF_VERIFIED")
        self.assertEqual(slots["address_space"], "ELF_VMA")
        self.assertEqual(slots["prefix"]["typeinfo_pointer"], "0x1019d08")
        self.assertEqual(slots["slots"]["+0x00"]["raw_thumb_value"], "0x7efbb5")
        self.assertEqual(slots["slots"]["+0x04"]["raw_thumb_value"], "0x7efb2d")
        self.assertEqual(slots["slots"]["+0x08"]["raw_thumb_value"], "0x7efb59")
        self.assertFalse(contract["runtime_verified"])
        self.assertFalse(contract["callable"])
        self.assertFalse(contract["safety_boundaries"]["runtime_safe"])
        self.assertEqual(contract["safety_boundaries"]["concurrency"]["status"], "UNKNOWN")
        unwind = contract["exception_unwind"]
        self.assertEqual(unwind["status"], "PRIMARY_ELF_VERIFIED")
        self.assertEqual(unwind["format"], "ARM EHABI .ARM.exidx metadata")
        self.assertEqual(unwind["targets"]["copy_constructor_candidate"]["extab_vma"], "0xf19718")
        self.assertEqual(unwind["targets"]["clone_candidate"]["extab_vma"], "0xf19730")
        self.assertEqual(
            contract["methods"]["copy_constructor_candidate"]["exception_cleanup"]["status"],
            "STATIC_INFERRED",
        )
        self.assertEqual(
            contract["methods"]["clone_candidate"]["exception_cleanup"]["landing_pad_candidate"],
            "0x7efbce",
        )

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

    def test_tree_value_width_is_evidence_gated(self):
        report = _report()
        report["payload_layout"]["tree_evidence"]["node_value_width_bytes"] = 8
        result = validate_param_set(report)
        self.assertFalse(result["valid"])
        self.assertIn("tree_node_value_width", result["errors"])

    def test_header_layout_is_evidence_gated(self):
        report = _report()
        report["payload_layout"]["header_layout"]["status"] = "INFERRED"
        result = validate_param_set(report)
        self.assertFalse(result["valid"])
        self.assertIn("header_layout_status", result["errors"])

    def test_node_layout_is_evidence_gated(self):
        report = _report()
        report["payload_layout"]["tree_evidence"]["node_layout"]["+0x10"] = "unknown"
        result = validate_param_set(report)
        self.assertFalse(result["valid"])
        self.assertIn("node_layout_value_offset", result["errors"])

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

    def test_vtable_slot_target_or_thumb_tag_is_rejected(self):
        report = _report()
        report["inheritance"]["vtable_slots"]["slots"]["+0x08"]["raw_thumb_value"] = "0x7efb58"
        result = validate_param_set(report)
        self.assertFalse(result["valid"])
        self.assertIn("inheritance_vtable_slot_raw:+0x08", result["errors"])

    def test_missing_vtable_slot_evidence_is_rejected(self):
        report = _report()
        del report["inheritance"]["vtable_slots"]["slots"]["+0x04"]
        result = validate_param_set(report)
        self.assertFalse(result["valid"])
        self.assertIn("inheritance_vtable_slot:+0x04", result["errors"])

    def test_safety_promotion_is_rejected(self):
        report = _report()
        report["safety_boundaries"]["concurrency"]["status"] = "PRIMARY_ELF_VERIFIED"
        result = validate_param_set(report)
        self.assertFalse(result["valid"])
        self.assertIn("safety_status:concurrency", result["errors"])

    def test_exact_source_type_promotion_is_rejected(self):
        report = _report()
        report["payload_layout"]["tree_evidence"]["source_type"] = "std::set<uint32_t>"
        result = validate_param_set(report)
        self.assertFalse(result["valid"])
        self.assertIn("tree_source_type_promotion", result["errors"])

    def test_exact_value_type_promotion_is_rejected(self):
        report = _report()
        report["payload_layout"]["tree_evidence"]["value_type"] = "uint32_t"
        result = validate_param_set(report)
        self.assertFalse(result["valid"])
        self.assertIn("tree_value_type_promotion", result["errors"])

    def test_prmset_mutator_identity_remains_unknown(self):
        report = _report()
        report["payload_layout"]["tree_evidence"]["insert_callers"]["prmset_mutator_entry"] = "0x7f4390"
        result = validate_param_set(report)
        self.assertFalse(result["valid"])
        self.assertIn("tree_mutator_promotion", result["errors"])

    def test_exception_cleanup_promotion_is_rejected(self):
        report = _report()
        report["observations"]["prmset_clone"]["exception_cleanup"]["status"] = "PRIMARY_ELF_VERIFIED"
        result = validate_param_set(report)
        self.assertFalse(result["valid"])
        self.assertIn("exception_cleanup:prmset_clone", result["errors"])

    def test_missing_exception_unwind_is_rejected(self):
        report = _report()
        del report["exception_unwind"]
        result = validate_param_set(report)
        self.assertFalse(result["valid"])
        self.assertIn("missing_exception_unwind", result["errors"])

    def test_exception_target_locator_is_rejected(self):
        report = _report()
        report["exception_unwind"]["targets"]["clone_candidate"]["extab_vma"] = "0x0"
        result = validate_param_set(report)
        self.assertFalse(result["valid"])
        self.assertIn("exception_unwind_extab:clone_candidate", result["errors"])

    def test_end_cleanup_binding_is_rejected(self):
        report = _report()
        report["bindings"]["end_cleanup"]["candidates"][0]["symbol"] = "_ZdlPv"
        result = validate_param_set(report)
        self.assertFalse(result["valid"])
        self.assertIn("end_cleanup_symbol", result["errors"])


if __name__ == "__main__":
    unittest.main()
