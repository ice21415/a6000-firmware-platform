"""Fail-closed tests for the ParamList owner/use evidence contract."""
from __future__ import annotations

import json
from pathlib import Path
import unittest

from fwplatform.paramlist_owner_use_probe import validate_paramlist_owner_use
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


CONTRACT = Path(__file__).resolve().parents[1] / "sdk" / "paramlist_owner_use_3_21.json"


def _contract() -> dict:
    return json.loads(CONTRACT.read_text(encoding="utf-8"))


class ParamListOwnerUseProbeTests(unittest.TestCase):
    def test_checked_in_contract_is_primary_static_only(self) -> None:
        report = _contract()
        result = validate_paramlist_owner_use(report)
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(report["binary_file_sha256"], EXPECTED_LIBOBJ_SHA)
        self.assertFalse(report["runtime_verified"])
        self.assertFalse(report["callable"])
        self.assertEqual(result["observation_count"], 1)

    def test_function_identity_is_preserved(self) -> None:
        report = _contract()
        function = report["observations"]["input_service_owner_use"]
        self.assertEqual(function["symbol_identity"]["entry_vma"], "0x114104")
        self.assertEqual(function["symbol_identity"]["size_bytes"], 356)
        self.assertEqual(function["first_lookup"]["key"]["value"], "0x17005003")
        self.assertEqual(function["second_lookup"]["key"]["value"], "0x17005008")

    def test_local_constructor_add_rebind_destructor_chain_is_present(self) -> None:
        function = _contract()["observations"]["input_service_owner_use"]
        self.assertEqual(function["local_paramlists"]["list_one"]["stack_offset"], "0x18")
        self.assertEqual(function["local_paramlists"]["list_two"]["stack_offset"], "0x20")
        self.assertEqual(function["add"]["callsite"], "0x11419a")
        self.assertEqual(function["rebind"]["callsite"], "0x1141e2")
        self.assertEqual(function["destruction"]["callsite_two"], "0x1141fe")

    def test_wrong_binary_identity_is_rejected(self) -> None:
        report = _contract()
        report["binary_file_sha256"] = "0" * 64
        result = validate_paramlist_owner_use(report)
        self.assertFalse(result["valid"])
        self.assertIn("binary_identity", result["errors"])

    def test_runtime_and_callable_promotion_is_rejected(self) -> None:
        report = _contract()
        report["runtime_verified"] = True
        report["callable"] = True
        result = validate_paramlist_owner_use(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])

    def test_static_member_form_promotion_is_rejected(self) -> None:
        report = _contract()
        report["lifetime"]["source_level_static_member_form"] = "STATIC"
        result = validate_paramlist_owner_use(report)
        self.assertFalse(result["valid"])
        self.assertIn("static_member_form_promotion", result["errors"])

    def test_rebind_identity_promotion_is_rejected(self) -> None:
        report = _contract()
        report["observations"]["input_service_owner_use"]["rebind"]["source_level_identity"] = "operator="
        result = validate_paramlist_owner_use(report)
        self.assertFalse(result["valid"])
        self.assertIn("rebind_identity_promotion", result["errors"])

    def test_return_type_promotion_is_rejected(self) -> None:
        report = _contract()
        report["observations"]["input_service_owner_use"]["return"]["source_level_return_type"] = "int"
        result = validate_paramlist_owner_use(report)
        self.assertFalse(result["valid"])
        self.assertIn("return_type_promotion", result["errors"])

    def test_lookup_key_tampering_is_rejected(self) -> None:
        report = _contract()
        report["observations"]["input_service_owner_use"]["first_lookup"]["key"]["value"] = "0x72"
        result = validate_paramlist_owner_use(report)
        self.assertFalse(result["valid"])
        self.assertIn("lookup_key_evidence", result["errors"])

    def test_binding_symbol_tampering_is_rejected(self) -> None:
        report = _contract()
        report["bindings"]["add"]["candidates"][0]["symbol"] = "_ZdlPv"
        result = validate_paramlist_owner_use(report)
        self.assertFalse(result["valid"])
        self.assertIn("binding:add", result["errors"])

    def test_missing_function_observation_is_rejected(self) -> None:
        report = _contract()
        del report["observations"]["input_service_owner_use"]
        result = validate_paramlist_owner_use(report)
        self.assertFalse(result["valid"])
        self.assertIn("function_observation", result["errors"])


if __name__ == "__main__":
    unittest.main()
