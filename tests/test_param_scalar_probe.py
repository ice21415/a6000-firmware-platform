"""Fail-closed regression checks for the scalar ParamBase lifecycle probe."""
from __future__ import annotations

import json
from pathlib import Path
import unittest

from fwplatform.param_scalar_probe import validate_param_scalars
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


CONTRACT = Path(__file__).resolve().parents[1] / "sdk" / "param_scalar_lifetime_3_21.json"


def _contract() -> dict:
    return json.loads(CONTRACT.read_text(encoding="utf-8"))


class ParamScalarProbeTests(unittest.TestCase):
    def test_checked_in_contract_is_static_and_complete(self) -> None:
        report = _contract()
        result = validate_param_scalars(report)
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["type_count"], 2)
        self.assertEqual(report["binary_file_sha256"], EXPECTED_LIBOBJ_SHA)
        self.assertFalse(report["runtime_verified"])
        self.assertFalse(report["callable"])

    def test_wrong_identity_is_rejected(self) -> None:
        report = _contract()
        report["binary_file_sha256"] = "0" * 64
        result = validate_param_scalars(report)
        self.assertFalse(result["valid"])
        self.assertIn("binary_identity", result["errors"])

    def test_runtime_promotion_is_rejected(self) -> None:
        report = _contract()
        report["types"][0]["callable"] = True
        result = validate_param_scalars(report)
        self.assertFalse(result["valid"])
        self.assertIn("unsafe:PrmBool", result["errors"])

    def test_key_constructor_claim_cannot_be_promoted(self) -> None:
        report = _contract()
        report["types"][0]["key"]["constructor"] = "VERIFIED_STATIC"
        result = validate_param_scalars(report)
        self.assertFalse(result["valid"])
        self.assertIn("key_constructor_scope:PrmBool", result["errors"])

    def test_missing_scalar_family_is_rejected(self) -> None:
        report = _contract()
        report["types"] = [item for item in report["types"] if item["name"] != "PrmNumber"]
        result = validate_param_scalars(report)
        self.assertFalse(result["valid"])
        self.assertIn("missing:PrmNumber", result["errors"])

    def test_payload_lifecycle_status_is_required(self) -> None:
        report = _contract()
        report["types"][1]["clone"]["status"] = "STATIC_INFERRED"
        result = validate_param_scalars(report)
        self.assertFalse(result["valid"])
        self.assertIn("clone:PrmNumber", result["errors"])


if __name__ == "__main__":
    unittest.main()
