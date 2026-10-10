"""Fail-closed tests for the integrated Camera Core chain contract."""
import json
import unittest
from pathlib import Path

from fwplatform.camera_core_chain import validate_camera_core_chain
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


if __name__ == "__main__":
    unittest.main()
