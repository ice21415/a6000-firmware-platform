"""Synthetic fail-closed checks for the EventManager cleanup candidate."""
from __future__ import annotations

import json
from pathlib import Path
import unittest

from fwplatform.event_manager_destroy_probe import (
    OWNER_TARGET,
    TARGET,
    validate_event_manager_destroy,
)
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


ROOT = Path(__file__).resolve().parents[1]


def _report() -> dict:
    symbols = {
        "operator_delete": "_ZdlPv",
        "operator_delete_array": "_ZdaPv",
        "pthread_mutex_destroy": "pthread_mutex_destroy",
    }
    return {
        "schema_version": 1,
        "binary_file_sha256": EXPECTED_LIBOBJ_SHA,
        "address_space": "ELF_VMA",
        "runtime_verified": False,
        "callable": False,
        "target": {"entry": TARGET["entry"], "size": TARGET["size"]},
        "owner_target": {"entry": OWNER_TARGET["entry"], "size": OWNER_TARGET["size"]},
        "observation": {
            "status": "PRIMARY_ELF_VERIFIED",
            "semantic_level": "STATIC_INFERRED",
            "destructor_role": "STATIC_INFERRED; cleanup body shares the receiver fields and mutex wrappers used by EventManager methods",
            "bindings": {
                key: {"status": "VERIFIED_STATIC", "candidates": [{"symbol": value}]}
                for key, value in symbols.items()
            },
        },
        "owner_observation": {
            "status": "PRIMARY_ELF_VERIFIED",
            "semantic_level": "STATIC_INFERRED",
            "owner_function_entry": "0x7ef3d8",
            "cleanup_callsite": "0x7ef432",
            "field_offset": "+0x10",
            "delete_binding": {
                "status": "VERIFIED_STATIC",
                "candidates": [{"symbol": "_ZdlPv"}],
            },
        },
    }


class EventManagerDestroyProbeTests(unittest.TestCase):
    def test_static_candidate_is_valid(self):
        result = validate_event_manager_destroy(_report())
        self.assertTrue(result["valid"])
        self.assertEqual(result["errors"], [])

    def test_checked_in_contract_is_static_only(self):
        contract = json.loads(
            (ROOT / "sdk" / "event_manager_destroy_3_21.json").read_text(encoding="utf-8")
        )
        self.assertEqual(contract["binary_file_sha256"], EXPECTED_LIBOBJ_SHA)
        self.assertEqual(contract["target"]["entry"], TARGET["entry"])
        self.assertEqual(contract["owner_target"]["entry"], OWNER_TARGET["entry"])
        self.assertEqual(contract["owner_observation"]["cleanup_callsite"], "0x7ef432")
        self.assertEqual(contract["observation"]["destructor_role"], "STATIC_INFERRED; cleanup body shares the receiver fields and mutex wrappers used by EventManager methods")
        self.assertEqual(contract["ghidra_crosscheck"]["target_count"], 6)
        self.assertEqual(contract["ghidra_crosscheck"]["basic_block_count"], 30)
        self.assertEqual(contract["ghidra_crosscheck"]["cfg_edge_count"], 70)
        self.assertFalse(contract["ghidra_full_auto_analysis"]["completion_marker"])
        self.assertFalse(contract["runtime_verified"])
        self.assertFalse(contract["callable"])

    def test_wrong_binary_is_rejected(self):
        report = _report()
        report["binary_file_sha256"] = "0" * 64
        result = validate_event_manager_destroy(report)
        self.assertFalse(result["valid"])
        self.assertIn("binary_identity", result["errors"])

    def test_source_destructor_promotion_is_rejected(self):
        report = _report()
        report["observation"]["destructor_role"] = "PRIMARY_ELF_VERIFIED"
        result = validate_event_manager_destroy(report)
        self.assertFalse(result["valid"])
        self.assertIn("destructor_role", result["errors"])

    def test_binding_promotion_is_rejected(self):
        report = _report()
        report["observation"]["bindings"]["operator_delete_array"]["candidates"][0]["symbol"] = "_ZdlPv"
        result = validate_event_manager_destroy(report)
        self.assertFalse(result["valid"])
        self.assertIn("binding:operator_delete_array", result["errors"])

    def test_runtime_promotion_is_rejected(self):
        report = _report()
        report["runtime_verified"] = True
        result = validate_event_manager_destroy(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])

    def test_owner_callsite_tampering_is_rejected(self):
        report = _report()
        report["owner_observation"]["cleanup_callsite"] = "0x7ef430"
        result = validate_event_manager_destroy(report)
        self.assertFalse(result["valid"])
        self.assertIn("owner_cleanup_callsite", result["errors"])

    def test_owner_delete_binding_promotion_is_rejected(self):
        report = _report()
        report["owner_observation"]["delete_binding"]["candidates"][0]["symbol"] = "_ZdaPv"
        result = validate_event_manager_destroy(report)
        self.assertFalse(result["valid"])
        self.assertIn("owner_delete_binding", result["errors"])

    def test_missing_owner_evidence_is_rejected(self):
        report = _report()
        report.pop("owner_target")
        report.pop("owner_observation")
        result = validate_event_manager_destroy(report)
        self.assertFalse(result["valid"])
        self.assertIn("owner_target_identity", result["errors"])
        self.assertIn("owner_observation_status", result["errors"])


if __name__ == "__main__":
    unittest.main()
