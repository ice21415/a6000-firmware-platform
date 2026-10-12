"""Fail-closed checks for the ParamBase D1/D0 lifecycle audit."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from fwplatform.param_destructor_probe import validate_param_destructors
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


CONTRACT = Path(__file__).parents[1] / "sdk" / "param_destructor_3_21.json"


class ParamDestructorProbeTests(unittest.TestCase):
    def _contract(self) -> dict:
        return json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_checked_in_contract_is_valid_and_exhaustive(self) -> None:
        report = self._contract()
        result = validate_param_destructors(report)
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(report["binary_sha256"], EXPECTED_LIBOBJ_SHA)
        self.assertEqual(report["aggregate"]["family_count"], 10)
        self.assertEqual(report["aggregate"]["nondeleting_with_base_destructor_call"], 10)
        self.assertEqual(report["aggregate"]["deleting_with_family_d1_and_operator_delete"], 10)
        self.assertEqual(report["aggregate"]["families_with_payload_cleanup_call_candidate"], 6)

    def test_deleting_wrappers_preserve_family_d1_and_delete_order_evidence(self) -> None:
        report = self._contract()
        for family in report["families"]:
            calls = family["deleting_destructor"]["direct_observations"]["calls"]
            roles = [call["role"] for call in calls]
            self.assertIn("FAMILY_NONDELETING_DESTRUCTOR", roles, family["name"])
            self.assertIn("OPERATOR_DELETE_PLT", roles, family["name"])

    def test_payload_cleanup_candidates_are_not_promoted_to_ownership(self) -> None:
        report = self._contract()
        by_name = {family["name"]: family for family in report["families"]}
        for name in ("PrmString", "PrmStruct", "PrmSet", "PrmNumberList", "PrmCntInfoList", "PrmObjMsg"):
            self.assertTrue(
                by_name[name]["nondeleting_destructor"]["direct_observations"]["payload_cleanup_call_candidates"],
                name,
            )
        self.assertEqual(report["lifetime_boundary"]["ownership_semantics"],
                         "STATIC_INFERRED at most; allocation provenance and external ownership remain UNKNOWN")

    def test_key_field_is_not_invented_in_destructor_paths(self) -> None:
        report = self._contract()
        for family in report["families"]:
            self.assertFalse(family["nondeleting_destructor"]["direct_observations"]["key_directly_accessed"])
            self.assertFalse(family["deleting_destructor"]["direct_observations"]["key_directly_accessed"])

    def test_missing_delete_call_is_rejected(self) -> None:
        report = copy.deepcopy(self._contract())
        calls = report["families"][0]["deleting_destructor"]["direct_observations"]["calls"]
        report["families"][0]["deleting_destructor"]["direct_observations"]["calls"] = [
            call for call in calls if call["role"] != "OPERATOR_DELETE_PLT"
        ]
        result = validate_param_destructors(report)
        self.assertFalse(result["valid"])
        self.assertIn("d0_delete_call:PrmBool", result["errors"])

    def test_runtime_promotion_is_rejected(self) -> None:
        report = copy.deepcopy(self._contract())
        report["runtime_verified"] = True
        result = validate_param_destructors(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])

    def test_binary_identity_and_ghidra_identity_are_required(self) -> None:
        report = copy.deepcopy(self._contract())
        report["binary_sha256"] = "0" * 64
        result = validate_param_destructors(report)
        self.assertFalse(result["valid"])
        self.assertIn("binary_identity", result["errors"])

        report = self._contract()
        report["ghidra_crosscheck"]["program_sha256"] = "0" * 64
        result = validate_param_destructors(report)
        self.assertFalse(result["valid"])
        self.assertIn("ghidra_binary_identity", result["errors"])


if __name__ == "__main__":
    unittest.main()
