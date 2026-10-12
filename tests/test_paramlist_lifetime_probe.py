"""Fail-closed tests for the ParamList shared-counter evidence contract."""
from __future__ import annotations

import json
from pathlib import Path
import unittest

from fwplatform.paramlist_lifetime_probe import validate_paramlist_lifetime
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


CONTRACT = Path(__file__).resolve().parents[1] / "sdk" / "paramlist_lifetime_3_21.json"


def _contract() -> dict:
    return json.loads(CONTRACT.read_text(encoding="utf-8"))


class ParamListLifetimeProbeTests(unittest.TestCase):
    def test_checked_in_contract_is_static_and_complete(self) -> None:
        report = _contract()
        result = validate_paramlist_lifetime(report)
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["observation_count"], 6)
        self.assertEqual(report["binary_file_sha256"], EXPECTED_LIBOBJ_SHA)
        self.assertFalse(report["runtime_verified"])
        self.assertFalse(report["callable"])

    def test_wrong_identity_is_rejected(self) -> None:
        report = _contract()
        report["binary_file_sha256"] = "0" * 64
        result = validate_paramlist_lifetime(report)
        self.assertFalse(result["valid"])
        self.assertIn("binary_identity", result["errors"])

    def test_layout_tampering_is_rejected(self) -> None:
        report = _contract()
        report["layout"]["shared_counter_pointer_offset"] = "0x8"
        result = validate_paramlist_lifetime(report)
        self.assertFalse(result["valid"])
        self.assertIn("layout", result["errors"])

    def test_runtime_and_callable_promotion_is_rejected(self) -> None:
        report = _contract()
        report["runtime_verified"] = True
        report["callable"] = True
        result = validate_paramlist_lifetime(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])

    def test_concurrency_promotion_is_rejected(self) -> None:
        report = _contract()
        report["lifetime"]["concurrency_verified"] = True
        result = validate_paramlist_lifetime(report)
        self.assertFalse(result["valid"])
        self.assertIn("concurrency_claim", result["errors"])

    def test_copy_on_write_claim_is_rejected(self) -> None:
        report = _contract()
        report["lifetime"]["copy_on_write"] = False
        result = validate_paramlist_lifetime(report)
        self.assertFalse(result["valid"])
        self.assertIn("copy_on_write_claim", result["errors"])

    def test_missing_last_owner_observation_is_rejected(self) -> None:
        report = _contract()
        del report["observations"]["destructor"]
        result = validate_paramlist_lifetime(report)
        self.assertFalse(result["valid"])
        self.assertIn("missing_observations", result["errors"])

    def test_shared_rebind_must_remain_primary_bounded_evidence(self) -> None:
        report = _contract()
        report["observations"]["shared_rebind_candidate"]["status"] = "STATIC_INFERRED"
        result = validate_paramlist_lifetime(report)
        self.assertFalse(result["valid"])
        self.assertIn("observation_status:shared_rebind_candidate", result["errors"])


if __name__ == "__main__":
    unittest.main()
