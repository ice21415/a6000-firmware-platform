"""Synthetic fail-closed checks for EventManager::count metadata."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from fwplatform.event_manager_count_probe import TARGET, validate_event_manager_count
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


ROOT = Path(__file__).resolve().parents[1]


def _report() -> dict:
    return {
        "schema_version": 1,
        "binary_file_sha256": EXPECTED_LIBOBJ_SHA,
        "address_space": "ELF_VMA",
        "runtime_verified": False,
        "callable": False,
        "target": {"entry": TARGET["entry"], "size": TARGET["size"]},
        "observation": {
            "status": "PRIMARY_ELF_VERIFIED",
            "helper": {
                "status": "PRIMARY_ELF_VERIFIED",
                "semantic_level": "STATIC_INFERRED",
            },
            "synchronization": {
                "lock_wrapper": {
                    "entry": "0x7ef8f4",
                    "receiver_field": "+0x0c",
                    "binding": {
                        "status": "VERIFIED_STATIC",
                        "candidates": [{"symbol": "pthread_mutex_lock"}],
                    },
                },
                "unlock_wrapper": {
                    "entry": "0x7ef902",
                    "receiver_field": "+0x0c",
                    "binding": {
                        "status": "VERIFIED_STATIC",
                        "candidates": [{"symbol": "pthread_mutex_unlock"}],
                    },
                },
            },
            "safety": {
                "local_bounds_check": "no conditional index-bound check observed in this bounded body",
                "global_invariant": "UNKNOWN; state allocation and valid index range are not proven",
                "container_validity": "UNKNOWN; helper assumes a terminating forward-link chain",
            },
        },
    }


class EventManagerCountProbeTests(unittest.TestCase):
    def test_static_report_is_valid(self):
        result = validate_event_manager_count(_report())
        self.assertTrue(result["valid"])
        self.assertEqual(result["errors"], [])

    def test_checked_in_contract_is_static_only(self):
        contract = json.loads(
            (ROOT / "sdk" / "event_manager_count_3_21.json").read_text(encoding="utf-8")
        )
        self.assertEqual(contract["binary_sha256"], EXPECTED_LIBOBJ_SHA)
        self.assertEqual(contract["entry"], "0x7ef9fc")
        self.assertFalse(contract["runtime_verified"])
        self.assertFalse(contract["callable"])

    def test_wrong_binary_is_rejected(self):
        report = _report()
        report["binary_file_sha256"] = "0" * 64
        result = validate_event_manager_count(report)
        self.assertFalse(result["valid"])
        self.assertIn("binary_identity", result["errors"])

    def test_runtime_promotion_is_rejected(self):
        report = _report()
        report["runtime_verified"] = True
        result = validate_event_manager_count(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])

    def test_bounds_scope_promotion_is_rejected(self):
        report = _report()
        report["observation"]["safety"]["local_bounds_check"] = "verified safe"
        result = validate_event_manager_count(report)
        self.assertFalse(result["valid"])
        self.assertIn("bounds_scope", result["errors"])

    def test_mutex_binding_promotion_is_rejected(self):
        report = _report()
        report["observation"]["synchronization"]["lock_wrapper"]["binding"]["candidates"][0]["symbol"] = "pthread_mutex_trylock"
        result = validate_event_manager_count(report)
        self.assertFalse(result["valid"])
        self.assertIn("synchronization:lock_wrapper:binding", result["errors"])

    def test_helper_semantic_promotion_is_rejected(self):
        report = _report()
        report["observation"]["helper"]["semantic_level"] = "PRIMARY_ELF_VERIFIED"
        result = validate_event_manager_count(report)
        self.assertFalse(result["valid"])
        self.assertIn("helper_evidence", result["errors"])


if __name__ == "__main__":
    unittest.main()
