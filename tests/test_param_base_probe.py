"""Fail-closed checks for the ParamBase foundation contract."""
from __future__ import annotations

import json
from pathlib import Path
import unittest

from fwplatform.param_base_probe import validate_param_base
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


CONTRACT = Path(__file__).parents[1] / "sdk" / "param_base_3_21.json"


def _contract() -> dict:
    return json.loads(CONTRACT.read_text(encoding="utf-8"))


class ParamBaseProbeTests(unittest.TestCase):
    def test_checked_in_contract_is_valid_and_static_only(self):
        report = _contract()
        result = validate_param_base(report)
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["derived_count"], 10)
        self.assertFalse(report["runtime_verified"])
        self.assertFalse(report["callable"])
        self.assertEqual(report["base"]["constructor"]["writes"]["key_plus_08"],
                         "NOT_WRITTEN_IN_BOUNDED_BASE_BODY")

    def test_wrong_identity_is_rejected(self):
        report = _contract()
        report["binary_file_sha256"] = "0" * 64
        result = validate_param_base(report)
        self.assertFalse(result["valid"])
        self.assertIn("binary_identity", result["errors"])

    def test_runtime_or_callable_promotion_is_rejected(self):
        report = _contract()
        report["callable"] = True
        result = validate_param_base(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])

    def test_base_clone_must_remain_pure_virtual(self):
        report = _contract()
        report["base"]["rtti"]["slot_plus_8_clone"]["target"] = "0x1234"
        result = validate_param_base(report)
        self.assertFalse(result["valid"])
        self.assertIn("base_clone_slot", result["errors"])

    def test_missing_direct_family_is_rejected(self):
        report = _contract()
        report["direct_derived"] = [
            item for item in report["direct_derived"] if item["name"] != "PrmObjMsg"
        ]
        result = validate_param_base(report)
        self.assertFalse(result["valid"])
        self.assertIn("missing:expected_direct_derived", result["errors"])

    def test_ghidra_crosscheck_cannot_be_relabelled_public(self):
        report = _contract()
        report["ghidra_crosscheck"]["raw_export_private"] = False
        result = validate_param_base(report)
        self.assertFalse(result["valid"])
        self.assertIn("ghidra_public_raw_export", result["errors"])

    def test_contract_uses_pinned_hash(self):
        self.assertEqual(_contract()["binary_file_sha256"], EXPECTED_LIBOBJ_SHA)


if __name__ == "__main__":
    unittest.main()
