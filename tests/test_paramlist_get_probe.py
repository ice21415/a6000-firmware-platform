"""Fail-closed tests for the primary ParamList query contract."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from fwplatform.paramlist_get_probe import validate_paramlist_get
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "sdk" / "paramlist_get_3_21.json"


def _contract() -> dict:
    return json.loads(CONTRACT.read_text(encoding="utf-8"))


class ParamListGetProbeTests(unittest.TestCase):
    def test_checked_in_contract_is_static_only(self) -> None:
        report = _contract()
        result = validate_paramlist_get(report)
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(report["binary_file_sha256"], EXPECTED_LIBOBJ_SHA)
        self.assertEqual(report["target"]["entry"], 0x7EDACA)
        self.assertFalse(report["safety"]["runtime_verified"])
        self.assertFalse(report["safety"]["callable"])

    def test_field_roles_are_explicit(self) -> None:
        fields = _contract()["accessors"]["fields"]
        self.assertEqual(fields["+0x04"]["role"], "discriminator/value-type word")
        self.assertEqual(fields["+0x08"]["role"], "lookup key word")
        self.assertEqual(fields["+0x0c"]["role"], "payload word returned by 0xe5b18")

    def test_wrong_binary_identity_is_rejected(self) -> None:
        report = _contract()
        report["binary_file_sha256"] = "0" * 64
        result = validate_paramlist_get(report)
        self.assertFalse(result["valid"])
        self.assertIn("binary_identity", result["errors"])

    def test_return_type_promotion_is_rejected(self) -> None:
        report = _contract()
        report["get"]["return_cpp_type_verified"] = True
        result = validate_paramlist_get(report)
        self.assertFalse(result["valid"])
        self.assertIn("return_type_promotion", result["errors"])

    def test_ownership_promotion_is_rejected(self) -> None:
        report = _contract()
        report["get"]["ownership_verified"] = True
        result = validate_paramlist_get(report)
        self.assertFalse(result["valid"])
        self.assertIn("ownership_promotion", result["errors"])

    def test_key_and_discriminator_cannot_be_swapped(self) -> None:
        report = copy.deepcopy(_contract())
        report["get"]["abi"]["r1"] = report["get"]["abi"]["r2"]
        result = validate_paramlist_get(report)
        self.assertFalse(result["valid"])
        self.assertIn("key_role", result["errors"])

    def test_plt_binding_must_remain_unique_and_static(self) -> None:
        report = _contract()
        report["forwarders"]["get_forwarder"]["plt_binding"]["candidates"] = []
        result = validate_paramlist_get(report)
        self.assertFalse(result["valid"])
        self.assertIn("get_plt_binding", result["errors"])


if __name__ == "__main__":
    unittest.main()
