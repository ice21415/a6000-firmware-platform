"""Synthetic fail-closed checks for ParamList add/replacement evidence."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from fwplatform.paramlist_add_probe import validate_paramlist_add
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


ROOT = Path(__file__).resolve().parents[1]


def _report() -> dict:
    return {
        "schema_version": 1,
        "binary_file_sha256": EXPECTED_LIBOBJ_SHA,
        "address_space": "ELF_VMA",
        "runtime_verified": False,
        "callable": False,
        "observations": {
            "key_setter": {"status": "PRIMARY_ELF_VERIFIED"},
            "add": {
                "status": "PRIMARY_ELF_VERIFIED",
                "payload_behavior": "no write to the incoming object's +0x0c payload occurs in this body",
            },
            "replacement": {
                "status": "PRIMARY_ELF_VERIFIED",
                "locking": "no lock or atomic operation observed in this bounded body; thread safety UNKNOWN",
            },
            "remove_slot": {"status": "PRIMARY_ELF_VERIFIED"},
            "storage_append": {"status": "PRIMARY_ELF_VERIFIED"},
        },
        "lifetime": {"concurrency_verified": False},
    }


class ParamListAddProbeTests(unittest.TestCase):
    def test_static_report_is_valid_without_runtime_claims(self):
        result = validate_paramlist_add(_report())
        self.assertTrue(result["valid"])
        self.assertEqual(result["observation_count"], 5)

    def test_checked_in_contract_preserves_replacement_boundary(self):
        contract = json.loads(
            (ROOT / "sdk" / "paramlist_add_3_21.json").read_text(encoding="utf-8")
        )
        self.assertEqual(contract["binary_sha256"], EXPECTED_LIBOBJ_SHA)
        self.assertFalse(contract["runtime_verified"])
        self.assertFalse(contract["callable"])
        self.assertEqual(contract["targets"]["paramlist_add"]["entry"], "0x7ee0e6")
        self.assertEqual(
            contract["observations"]["replacement_candidate"]["source_level_name"],
            "UNKNOWN",
        )

    def test_missing_observation_is_not_filled_in(self):
        report = _report()
        del report["observations"]["replacement"]
        result = validate_paramlist_add(report)
        self.assertFalse(result["valid"])
        self.assertIn("missing_observations", result["errors"])

    def test_runtime_or_callable_promotion_is_rejected(self):
        report = _report()
        report["runtime_verified"] = True
        result = validate_paramlist_add(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])

    def test_payload_scope_promotion_is_rejected(self):
        report = _report()
        report["observations"]["add"]["payload_behavior"] = "writes payload"
        result = validate_paramlist_add(report)
        self.assertFalse(result["valid"])
        self.assertIn("payload_scope", result["errors"])

    def test_concurrency_promotion_is_rejected(self):
        report = _report()
        report["lifetime"]["concurrency_verified"] = True
        result = validate_paramlist_add(report)
        self.assertFalse(result["valid"])
        self.assertIn("concurrency_claim", result["errors"])


if __name__ == "__main__":
    unittest.main()
