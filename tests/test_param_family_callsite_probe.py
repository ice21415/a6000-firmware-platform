"""Fail-closed checks for normalized ParamBase callsite observations."""
from __future__ import annotations

import json
from pathlib import Path
from contextlib import redirect_stdout
from io import StringIO
import unittest

from fwplatform.param_family_callsite_probe import (
    validate_param_family_callsites,
)
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


class ParamFamilyCallsiteProbeTests(unittest.TestCase):
    def _contract(self) -> dict:
        return json.loads(
            (Path(__file__).resolve().parents[1] / "sdk/param_family_callsites_3_21.json")
            .read_text(encoding="utf-8")
        )

    def test_checked_in_contract_has_five_primary_callsite_targets(self):
        report = self._contract()
        result = validate_param_family_callsites(report)
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["observation_count"], 5)
        self.assertEqual(report["binary_sha256"], EXPECTED_LIBOBJ_SHA)
        self.assertEqual(
            [item["family"] for item in report["observations"]],
            ["PrmBool", "PrmNumber", "PrmString", "PrmPoint", "PrmStruct"],
        )

    def test_constructor_target_tampering_is_rejected(self):
        report = self._contract()
        report["observations"][0]["constructor_call"]["status"] = "UNVERIFIED"
        result = validate_param_family_callsites(report)
        self.assertFalse(result["valid"])
        self.assertIn("constructor_call:0", result["errors"])

    def test_runtime_or_callable_promotion_is_rejected(self):
        report = self._contract()
        report["runtime_verified"] = True
        result = validate_param_family_callsites(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])

    def test_cli_filters_callsite_contract_without_database(self):
        from fwplatform.cli import main
        output = StringIO()
        with redirect_stdout(output):
            result = main([
                "sdk", "parameter-family-callsites", "--family", "PrmPoint", "--json"
            ])
        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(len(payload["observations"]), 1)
        self.assertEqual(payload["observations"][0]["family"], "PrmPoint")


if __name__ == "__main__":
    unittest.main()
