"""Synthetic fail-closed checks for the owner-field construction witness."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from fwplatform.event_manager_owner_probe import (
    TARGET,
    validate_event_manager_owner_init,
)
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


ROOT = Path(__file__).resolve().parents[1]


def _report() -> dict:
    return {
        "schema_version": 1,
        "status": "LOCAL_PRIMARY_ELF_EVENT_MANAGER_OWNER_INIT_CANDIDATE",
        "firmware_version": "3.21",
        "binary_file_sha256": EXPECTED_LIBOBJ_SHA,
        "address_space": "ELF_VMA",
        "target": {"entry": TARGET["entry"], "size": TARGET["size"]},
        "event_initializer_entry": "0x7ef894",
        "runtime_verified": False,
        "callable": False,
        "observation": {
            "status": "PRIMARY_ELF_VERIFIED",
            "semantic_level": "STATIC_INFERRED",
            "function_identity": "UNKNOWN; no unique ELF symbol or source-level class identity",
            "allocation": {
                "size_immediate": "0x24",
                "status": "PRIMARY_ELF_VERIFIED",
                "allocator_binding": {
                    "status": "VERIFIED_STATIC",
                    "candidates": [{"symbol": "_Znwj"}],
                },
            },
            "initializer_call": {
                "entry": "0x7ef894",
                "callsite": "0x7ef2ca",
                "status": "PRIMARY_ELF_VERIFIED",
            },
            "owner_store": {
                "callsite": "0x7ef2d4",
                "field_offset": "+0x10",
                "status": "PRIMARY_ELF_VERIFIED",
            },
            "lifetime_pair": {
                "interpretation": "STATIC_INFERRED; matches the separately verified cleanup-then-_ZdlPv witness",
                "owner_type": "UNKNOWN",
            },
        },
    }


class EventManagerOwnerProbeTests(unittest.TestCase):
    def test_static_witness_is_valid(self) -> None:
        result = validate_event_manager_owner_init(_report())
        self.assertTrue(result["valid"], result["errors"])

    def test_checked_in_contract_preserves_owner_store(self) -> None:
        contract = json.loads(
            (ROOT / "sdk" / "event_manager_owner_init_3_21.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(contract["binary_file_sha256"], EXPECTED_LIBOBJ_SHA)
        self.assertEqual(contract["target"]["entry"], TARGET["entry"])
        self.assertEqual(contract["observation"]["allocation"]["size_immediate"], "0x24")
        self.assertEqual(contract["observation"]["initializer_call"]["callsite"], "0x7ef2ca")
        self.assertEqual(contract["observation"]["owner_store"]["field_offset"], "+0x10")
        self.assertEqual(contract["observation"]["lifetime_pair"]["owner_type"], "UNKNOWN")
        crosscheck = contract["ghidra_crosscheck"]
        self.assertEqual(crosscheck["status"], "VERIFIED_STATIC")
        self.assertEqual(crosscheck["version"], "12.1.3")
        self.assertEqual(crosscheck["language"], "ARM:LE:32:v8")
        self.assertEqual(crosscheck["image_base"], "0x10000")
        self.assertEqual(crosscheck["completion_marker"], "COMPLETE_TARGET_EXPORT")
        self.assertEqual(crosscheck["target_count"], 4)
        self.assertEqual(crosscheck["instruction_count"], 157)
        self.assertEqual(crosscheck["basic_block_count"], 20)
        self.assertEqual(crosscheck["cfg_edge_count"], 70)
        self.assertFalse(crosscheck["semantic_names_verified"])
        self.assertTrue(crosscheck["raw_export_private"])
        self.assertFalse(contract["runtime_verified"])
        self.assertFalse(contract["callable"])

    def test_wrong_identity_is_rejected(self) -> None:
        report = _report()
        report["binary_file_sha256"] = "0" * 64
        result = validate_event_manager_owner_init(report)
        self.assertFalse(result["valid"])
        self.assertIn("binary_identity", result["errors"])

    def test_runtime_or_callable_promotion_is_rejected(self) -> None:
        report = _report()
        report["runtime_verified"] = True
        report["callable"] = True
        result = validate_event_manager_owner_init(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])

    def test_constructor_identity_promotion_is_rejected(self) -> None:
        report = _report()
        report["observation"]["function_identity"] = "OwnerClass::OwnerClass"
        result = validate_event_manager_owner_init(report)
        self.assertFalse(result["valid"])
        self.assertIn("function_identity_scope", result["errors"])

    def test_field_or_size_tampering_is_rejected(self) -> None:
        report = copy.deepcopy(_report())
        report["observation"]["allocation"]["size_immediate"] = "0x28"
        report["observation"]["owner_store"]["field_offset"] = "+0x14"
        result = validate_event_manager_owner_init(report)
        self.assertFalse(result["valid"])
        self.assertIn("allocation_size", result["errors"])
        self.assertIn("owner_store", result["errors"])

    def test_ghidra_crosscheck_promotion_is_rejected(self) -> None:
        report = json.loads(
            (ROOT / "sdk" / "event_manager_owner_init_3_21.json").read_text(
                encoding="utf-8"
            )
        )
        report["ghidra_crosscheck"]["semantic_names_verified"] = True
        result = validate_event_manager_owner_init(report)
        self.assertFalse(result["valid"])
        self.assertIn("ghidra_semantic_name_claim", result["errors"])


if __name__ == "__main__":
    unittest.main()
