"""Fail-closed checks for the ParamBase lifecycle field-access audit."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from fwplatform.param_lifecycle_probe import validate_param_lifecycle
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


CONTRACT = Path(__file__).parents[1] / "sdk" / "param_lifecycle_3_21.json"


class ParamLifecycleProbeTests(unittest.TestCase):
    def _contract(self) -> dict:
        return json.loads(CONTRACT.read_text(encoding="utf-8"))

    def test_checked_in_audit_is_valid_and_exhaustive(self) -> None:
        report = self._contract()
        result = validate_param_lifecycle(report)
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(report["binary_sha256"], EXPECTED_LIBOBJ_SHA)
        self.assertEqual(report["aggregate"]["family_count"], 10)
        self.assertEqual(report["aggregate"]["constructors_without_direct_key_access"], 10)
        self.assertEqual(report["aggregate"]["clones_without_direct_key_access"], 10)
        self.assertEqual(report["aggregate"]["clones_with_direct_payload_access"], 9)

    def test_key_is_not_promoted_from_a_missing_direct_access(self) -> None:
        report = self._contract()
        for family in report["families"]:
            self.assertFalse(family["constructor"]["direct_field_access"]["key_directly_accessed"])
            self.assertFalse(family["clone"]["direct_field_access"]["key_directly_accessed"])
        self.assertEqual(report["key_assignment_boundary"]["setter_vma"], "0x7eda84")

    def test_payload_shapes_remain_family_specific(self) -> None:
        report = self._contract()
        by_name = {item["name"]: item for item in report["families"]}
        point_offsets = {
            row["offset"] for row in by_name["PrmPoint"]["clone"]["direct_field_access"]["payload_accesses"]
        }
        self.assertEqual(point_offsets, {0x0C, 0x10})
        set_access = by_name["PrmSet"]["clone"]["direct_field_access"]["payload_accesses"]
        self.assertEqual({row["offset"] for row in set_access}, {0x0C})
        self.assertEqual(
            by_name["PrmObjMsg"]["clone"]["payload_source"],
            "NO_DIRECT_RECEIVER_PAYLOAD_ACCESS_OBSERVED",
        )

    def test_runtime_or_callable_promotion_is_rejected(self) -> None:
        report = self._contract()
        report["runtime_verified"] = True
        result = validate_param_lifecycle(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])

    def test_key_access_promotion_is_rejected(self) -> None:
        report = self._contract()
        report["families"][0]["constructor"]["direct_field_access"]["key_directly_accessed"] = True
        result = validate_param_lifecycle(report)
        self.assertFalse(result["valid"])
        self.assertIn("constructor_key_promotion:PrmBool", result["errors"])

    def test_wrong_hash_is_rejected(self) -> None:
        report = copy.deepcopy(self._contract())
        report["binary_sha256"] = "0" * 64
        result = validate_param_lifecycle(report)
        self.assertFalse(result["valid"])
        self.assertIn("binary_identity", result["errors"])

    def test_ghidra_program_identity_is_required(self) -> None:
        report = copy.deepcopy(self._contract())
        report["ghidra_crosscheck"]["program_sha256"] = "0" * 64
        result = validate_param_lifecycle(report)
        self.assertFalse(result["valid"])
        self.assertIn("ghidra_binary_identity", result["errors"])


if __name__ == "__main__":
    unittest.main()
