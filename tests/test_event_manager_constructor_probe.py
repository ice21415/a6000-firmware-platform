"""Fail-closed tests for the owner-constructor candidate contract."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from fwplatform.event_manager_constructor_probe import (
    CONSTRUCTOR,
    validate_event_manager_constructor,
)
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "sdk" / "event_manager_constructor_3_21.json"


def _contract() -> dict:
    return json.loads(CONTRACT.read_text(encoding="utf-8"))


class EventManagerConstructorProbeTests(unittest.TestCase):
    def test_checked_in_candidate_is_valid_and_static_only(self) -> None:
        report = _contract()
        result = validate_event_manager_constructor(report)
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(report["binary_file_sha256"], EXPECTED_LIBOBJ_SHA)
        self.assertEqual(report["target"]["entry"], CONSTRUCTOR["entry"])
        self.assertEqual(report["constructor"]["provider"]["field"], "+0x14")
        self.assertFalse(report["runtime_verified"])
        self.assertFalse(report["callable"])

    def test_string_provider_witness_is_preserved(self) -> None:
        helper = _contract()["name_helper"]
        self.assertEqual(helper["length_limit"], "0x14 bytes")
        self.assertEqual(helper["receiver_name_storage"],
                         "+0x2c through bounded strncpy, terminator byte at +0x3f")
        self.assertEqual(helper["status"], "PRIMARY_ELF_VERIFIED")

    def test_unknown_provider_type_cannot_be_promoted(self) -> None:
        report = _contract()
        report["constructor"]["provider"]["type"] = "EventSender*"
        result = validate_event_manager_constructor(report)
        self.assertFalse(result["valid"])
        self.assertIn("provider_type_scope", result["errors"])

    def test_constructor_identity_cannot_be_promoted(self) -> None:
        report = _contract()
        report["method_identity"]["constructor_identity"] = "EventManager::EventManager"
        result = validate_event_manager_constructor(report)
        self.assertFalse(result["valid"])
        self.assertIn("constructor_identity_scope", result["errors"])

    def test_layout_relation_must_remain_inferred(self) -> None:
        report = _contract()
        report["method_identity"]["layout_relation"] = "VERIFIED_STATIC_CLASS_IDENTITY"
        result = validate_event_manager_constructor(report)
        self.assertFalse(result["valid"])
        self.assertIn("layout_relation_scope", result["errors"])

    def test_runtime_and_callable_promotion_is_rejected(self) -> None:
        report = _contract()
        report["runtime_verified"] = True
        report["callable"] = True
        result = validate_event_manager_constructor(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])

    def test_wrong_target_or_allocator_is_rejected(self) -> None:
        report = copy.deepcopy(_contract())
        report["target"]["bounded_size"] += 2
        report["allocator_binding"]["candidates"][0]["symbol"] = "malloc"
        result = validate_event_manager_constructor(report)
        self.assertFalse(result["valid"])
        self.assertIn("target_identity", result["errors"])
        self.assertIn("allocator_binding", result["errors"])

    def test_ghidra_crosscheck_is_targeted_and_pinned(self) -> None:
        report = _contract()
        crosscheck = report["ghidra_crosscheck"]
        self.assertEqual(crosscheck["binary_sha256"], EXPECTED_LIBOBJ_SHA)
        self.assertEqual(crosscheck["program_sha256"], EXPECTED_LIBOBJ_SHA)
        self.assertEqual(crosscheck["execution"]["exit_code"], 0)
        self.assertTrue(crosscheck["execution"]["completion_marker"])
        self.assertFalse(crosscheck["execution"]["auto_analysis_completed"])
        self.assertEqual(crosscheck["target_count"], 5)
        self.assertEqual(crosscheck["instruction_count"], 260)
        self.assertEqual(crosscheck["basic_block_count"], 18)
        self.assertEqual(crosscheck["cfg_edge_count"], 65)
        self.assertTrue(crosscheck["raw_export_private"])

    def test_ghidra_crosscheck_cannot_be_promoted_or_repointed(self) -> None:
        report = copy.deepcopy(_contract())
        report["ghidra_crosscheck"]["binary_sha256"] = "0" * 64
        report["ghidra_crosscheck"]["execution"]["auto_analysis_completed"] = True
        result = validate_event_manager_constructor(report)
        self.assertFalse(result["valid"])
        self.assertIn("ghidra_binary_identity", result["errors"])
        self.assertIn("ghidra_auto_analysis_scope", result["errors"])


if __name__ == "__main__":
    unittest.main()
