"""Fail-closed tests for the integrated Camera Core chain contract."""
import json
import unittest
from pathlib import Path

from fwplatform.camera_core_chain import validate_camera_core_chain, normalize_compact_model_event
def _report() -> dict:
    contract = json.loads(
        Path("sdk/camera_core_3_21.json").read_text(encoding="utf-8")
    )
    return {
        "schema_version": 1,
        "status": "LOCAL_PRIMARY_ELF_CAMERA_CORE_CHAIN_EVIDENCE_ONLY",
        "firmware_version": "3.21",
        "binary_file_sha256": contract["binary_sha256"],
        "address_space": contract["address_space"],
        "verification": contract["verification"],
        "chain_summary": contract["chain_summary"],
        "observations": contract["observations"],
        "edges": contract["verified_edges"],
        "unresolved_edges": contract["unresolved_edges"],
        "ghidra_crosscheck": contract["ghidra_crosscheck"],
    }


class CameraCoreChainTests(unittest.TestCase):
    def test_sanitized_static_chain_is_valid(self):
        result = validate_camera_core_chain(_report())
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["errors"], [])

    def test_event_consumer_promotion_is_rejected(self):
        report = _report()
        report["chain_summary"]["event_consumer_model_camera"] = "PRIMARY_ELF_VERIFIED"
        result = validate_camera_core_chain(report)
        self.assertFalse(result["valid"])
        self.assertIn("unresolved:event_consumer_model_camera", result["errors"])

    def test_missing_edge_evidence_is_rejected(self):
        report = _report()
        report["edges"][0]["evidence"].pop("source_binary_sha256")
        result = validate_camera_core_chain(report)
        self.assertFalse(result["valid"])
        self.assertTrue(any(item.startswith("edge_evidence:") for item in result["errors"]))

    def test_callable_promotion_is_rejected(self):
        report = _report()
        report["verification"]["callable"] = True
        result = validate_camera_core_chain(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_promotion", result["errors"])

    def test_wrong_binary_identity_is_rejected(self):
        report = _report()
        report["binary_file_sha256"] = "0" * 64
        result = validate_camera_core_chain(report)
        self.assertFalse(result["valid"])
        self.assertIn("binary_identity", result["errors"])

    def test_contract_keeps_unknown_receiver_edges(self):
        report = _report()
        unresolved = {row["id"]: row for row in report["unresolved_edges"]}
        self.assertEqual(unresolved["event.consumer.model_camera"]["status"], "UNKNOWN")
        self.assertEqual(report["chain_summary"]["event_keys_7_8_to_model_camera"], "UNKNOWN")
        self.assertFalse(report["verification"]["runtime_verified"])

    def test_targeted_ghidra_metadata_is_not_auto_analysis(self):
        contract = json.loads(
            Path("sdk/camera_core_3_21.json").read_text(encoding="utf-8")
        )
        ghidra = contract["ghidra_crosscheck"]
        self.assertEqual(ghidra["process_exit"], 0)
        self.assertEqual(ghidra["completion_marker"], "COMPLETE_TARGET_EXPORT")
        self.assertFalse(ghidra["auto_analysis_completed"])
        self.assertTrue(ghidra["raw_export_private"])

    def test_event_manager_owner_setup_edges_are_present(self):
        report = _report()
        edges = {row["id"]: row for row in report["edges"]}
        for edge_id in (
            "event_manager.owner.init",
            "event_manager.owner.push",
            "event_manager.init.callback_factory",
            "event_manager.init.dispatch_state_store",
        ):
            self.assertIn(edge_id, edges)
            self.assertEqual(edges[edge_id]["verification_status"], "PRIMARY_ELF_VERIFIED")
            self.assertEqual(
                edges[edge_id]["evidence"]["source_binary_sha256"],
                report["binary_file_sha256"],
            )
        self.assertEqual(edges["event_manager.owner.push"]["target_vma"], "0x7ef960")
        self.assertEqual(edges["event_manager.owner.push"]["callsite_vma"], "0x7ef35a")
        self.assertIsNone(edges["event_manager.init.callback_factory"]["target_vma"])

    def test_owner_setup_target_tampering_is_rejected(self):
        report = _report()
        for edge in report["edges"]:
            if edge["id"] == "event_manager.owner.push":
                edge["target_vma"] = "0x1234"
                break
        else:
            self.fail("owner push edge missing")
        # The contract validator must continue to require the exact verified
        # setup edge; changing its VMA must not silently pass as a new edge.
        result = validate_camera_core_chain(report)
        self.assertFalse(result["valid"])
        self.assertIn("edge_target:event_manager.owner.push", result["errors"])

    def test_event_literal_inventory_does_not_promote_consumer(self):
        contract = json.loads(
            Path("sdk/camera_core_3_21.json").read_text(encoding="utf-8")
        )
        scan = contract["observations"]["event_id_literal_scan"]
        self.assertEqual(scan["status"], "PRIMARY_ELF_VERIFIED")
        self.assertEqual(scan["value"], "0x11004003")
        self.assertEqual(scan["literal_vmas"], ["0x463448", "0x4637e4", "0x7f0b74"])
        self.assertIn("does not identify", scan["consumer_relation"])
        self.assertEqual(contract["chain_summary"]["event_consumer_model_camera"], "UNKNOWN")

    def test_provider_vtable_candidate_stays_unresolved(self):
        contract = json.loads(
            Path("sdk/camera_core_3_21.json").read_text(encoding="utf-8")
        )
        candidate = contract["observations"]["event_manager_provider_candidate"]
        self.assertEqual(candidate["status"], "PRIMARY_ELF_VERIFIED")
        self.assertEqual(candidate["constructor_candidate"]["rtti_identity"], "11AppConfigAC")
        self.assertEqual(candidate["provider_slot"]["target_vma"], "0x45ee64")
        self.assertEqual(candidate["returned_callback_candidate"]["returned_target_vma"], "0x45ee5c")
        self.assertEqual(candidate["provider_selection"]["selected_branch"], "UNKNOWN")
        self.assertIn("not proven", candidate["event_manager_link"])
        self.assertIn("does not establish", candidate["model_camera_consumer"])

    def test_computed_consumer_id_cannot_be_changed(self):
        report = _report()
        report["observations"]["request_consumer"]["computed_event_id"]["subtract"] = 2
        self.assertIn("consumer_event_id_derivation", validate_camera_core_chain(report)["errors"])

    def test_model_registry_does_not_self_attest_camera_identity(self):
        report = _report()
        report["observations"]["request_consumer"]["model_camera_identity"] = "ModelCamera"
        self.assertIn("consumer_model_identity_promotion", validate_camera_core_chain(report)["errors"])
        report = _report()
        report["observations"]["request_consumer"]["final_dispatch"]["target"] = "0x4cfb9c"
        self.assertIn("consumer_virtual_target_promotion", validate_camera_core_chain(report)["errors"])

    def test_parameter_recovery_is_distinct_from_model_identity(self):
        c = _report()["observations"]["request_consumer"]
        self.assertEqual(c["parameters"]["7"]["missing"], "0xffffffff")
        self.assertEqual(c["parameters"]["8"]["missing"], "zero")
        self.assertEqual(c["final_dispatch"]["event_store"], "receiver +0x14 at 0x7efcd0")
        self.assertEqual(c["final_dispatch"]["target"], "UNKNOWN")

    def test_consumer_edge_requires_original_target_and_identity(self):
        report = _report()
        edge = next(e for e in report["edges"] if e["id"] == "consumer.model_handoff")
        edge["target_vma"] = "0x4cfb9c"
        self.assertIn("edge_target:consumer.model_handoff", validate_camera_core_chain(report)["errors"])
        report = _report()
        report["edges"][-1]["evidence"]["source_binary_sha256"] = "0" * 64
        self.assertTrue(any(e.startswith("edge_identity:") for e in validate_camera_core_chain(report)["errors"]))

    def test_compact_event_encoding_preserves_namespaces_and_existing_ids(self):
        self.assertEqual(normalize_compact_model_event(11, 0xF01), 0x1200BF01)
        self.assertNotEqual(normalize_compact_model_event(11, 0xF01), 0x11004003)
        self.assertEqual(normalize_compact_model_event(11, 0x1200BF01), 0x1200BF01)
        for model_id in (0, 11, 0xFFF):
            for selector in (0, 1, 0xF01, 0xFFF):
                event = normalize_compact_model_event(model_id, selector)
                self.assertEqual((event - 0x12000000) >> 12, model_id)
                self.assertEqual(event & 0xFFF, selector)

    def test_offline_argument_guards_do_not_accept_host_values(self):
        for model, selector in ((-1, 0), (0x1000, 0), (11, -1), (11, 0x100000000), (True, 0)):
            with self.assertRaises(ValueError):
                normalize_compact_model_event(model, selector)

    def test_library_resolution_cannot_be_promoted_by_factory_name(self):
        report = _report()
        report["observations"]["camera_registry_dispatch"]["instance_identity"] = "PRIMARY_ELF_VERIFIED"
        self.assertIn("registry_instance_promotion", validate_camera_core_chain(report)["errors"])
        report = _report()
        report["observations"]["camera_registry_dispatch"]["loader"]["library_alias_identity"] = "libObj.so"
        self.assertIn("registry_loader_promotion", validate_camera_core_chain(report)["errors"])

    def test_final_virtual_slot_is_not_the_action_entry(self):
        report = _report()
        registry = report["observations"]["camera_registry_dispatch"]
        self.assertEqual(registry["slots"]["0x18"], "0x132624")
        self.assertEqual(registry["slots"]["0x44"], "0x4d02e4")
        registry["slots"]["0x18"] = "0x4cfb9c"
        self.assertIn("registry_camera_vtable", validate_camera_core_chain(report)["errors"])

    def test_action_index_and_selector_cannot_be_merged(self):
        report = _report()
        report["observations"]["compact_model_selector"]["checker"]["action_index"] = 0xF01
        self.assertIn("compact_selector_namespace", validate_camera_core_chain(report)["errors"])

    def test_conditional_instance_dispatch_cannot_be_promoted(self):
        report = _report()
        edge = report["observations"]["camera_registry_dispatch"]["conditional_relations"][0]
        edge["verification_status"] = "PRIMARY_ELF_VERIFIED"
        self.assertIn("registry_conditional_edge_promotion", validate_camera_core_chain(report)["errors"])
        report = _report()
        edge = report["observations"]["camera_registry_dispatch"]["conditional_relations"][-1]
        edge["target_vma"] = "0x4cfb9c"
        self.assertIn("registry_conditional_target", validate_camera_core_chain(report)["errors"])


if __name__ == "__main__":
    unittest.main()
