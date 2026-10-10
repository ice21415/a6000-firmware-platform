"""Fail-closed validation tests for primary Appframework evidence."""
from __future__ import annotations

import json
import unittest
from pathlib import Path

from fwplatform.app_event_primary_probe import (
    EXPECTED_LIBOBJ_SHA,
    validate_app_event_primary,
)
from fwplatform.cli import build_parser


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "sdk" / "app_event_primary_3_21.json"


def _report() -> dict:
    return json.loads(CONTRACT.read_text(encoding="utf-8-sig"))


class AppEventPrimaryProbeTests(unittest.TestCase):
    def test_contract_identity_and_static_boundaries(self):
        report = _report()
        result = validate_app_event_primary(report)
        self.assertEqual(result, {"valid": True, "errors": []})
        self.assertEqual(report["binary"]["sha256"], EXPECTED_LIBOBJ_SHA)
        self.assertFalse(report["event_id_consumer_verified"])
        self.assertFalse(report["model_camera_consumer_verified"])
        self.assertEqual(
            report["observation"]["semaphore_dispatch_gate"]["wait_binding"]["candidates"][0]["symbol"],
            "osal_wai_sem_tmo",
        )
        ghidra = report["ghidra_crosscheck"]
        self.assertEqual(ghidra["exit_code"], 0)
        self.assertEqual(ghidra["completion_marker"], "COMPLETE_TARGET_EXPORT")
        self.assertEqual(
            (ghidra["targets"], ghidra["instructions"], ghidra["basic_blocks"], ghidra["cfg_edges"]),
            (8, 81, 11, 20),
        )
        self.assertFalse(ghidra["auto_analysis_completed"])

    def test_wrong_binary_is_rejected(self):
        report = _report()
        report["binary"]["sha256"] = "0" * 64
        self.assertIn("binary_identity", validate_app_event_primary(report)["errors"])

    def test_event_consumer_promotion_is_rejected(self):
        report = _report()
        report["event_id_consumer_verified"] = True
        self.assertIn("unsafe_promotion", validate_app_event_primary(report)["errors"])

    def test_missing_semaphore_literal_is_rejected(self):
        report = _report()
        report["observation"]["semaphore_application_gate"]["semaphore_literals"][0]["value"] = "0x0"
        self.assertIn(
            "semaphore_application_gate_literal",
            validate_app_event_primary(report)["errors"],
        )

    def test_gate_status_cannot_be_downgraded_or_fabricated(self):
        report = _report()
        report["observation"]["semaphore_dispatch_gate"]["status"] = "STATIC_INFERRED"
        self.assertIn(
            "observation_semaphore_dispatch_gate",
            validate_app_event_primary(report)["errors"],
        )

    def test_cli_exposes_primary_command(self):
        args = build_parser().parse_args([
            "sdk", "app-event-primary", "--elf", "fixture.so", "--json",
        ])
        self.assertEqual(args.sdk_command, "app-event-primary")
        self.assertEqual(args.elf, Path("fixture.so"))


if __name__ == "__main__":
    unittest.main()
