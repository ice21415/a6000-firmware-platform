"""Fail-closed checks for the reusable ParamList cross-ELF profile."""
from __future__ import annotations

import copy
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from fwplatform.paramlist_cross_elf import (
    PARAMLIST_SYMBOLS,
    probe_paramlist_cross_elf,
    validate_paramlist_cross_elf,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "sdk" / "paramlist_cross_elf_3_21.json"


def _contract() -> dict:
    return json.loads(CONTRACT.read_text(encoding="utf-8"))


class ParamListCrossELFTests(unittest.TestCase):
    def test_checked_in_profile_is_valid_and_identity_scoped(self) -> None:
        report = _contract()
        result = validate_paramlist_cross_elf(report)
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(tuple(report["symbols"]), PARAMLIST_SYMBOLS)
        self.assertEqual(result["report_count"], 3)
        self.assertEqual(result["import_observation_count"], 86)
        self.assertFalse(report["runtime_verified"])
        self.assertFalse(report["callable"])
        self.assertEqual(report["provider"]["name"], "libObj.so")

    def test_provider_exports_are_distinct_and_thumb_tagged(self) -> None:
        report = _contract()
        exports = [item["provider"]["export"] for item in report["reports"]]
        self.assertEqual([item["symbol"] for item in exports], list(PARAMLIST_SYMBOLS))
        self.assertEqual([item["value_vma"] for item in exports], ["0x7ee0e7", "0x7edacb", "0x7edd09"])
        self.assertTrue(
            all(item["provider"]["address_space"] == "ELF_VMA" for item in report["reports"])
        )
        for item in report["reports"]:
            self.assertTrue(all(row["relocations"] for row in item["observations"]))
            self.assertTrue(all(row["plt"] for row in item["observations"]))

    def test_empty_synthetic_profile_is_reusable_without_firmware(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = probe_paramlist_cross_elf(
                Path(directory), symbols=("_ZSyntheticOnev", "_ZSyntheticTwov")
            )
        self.assertEqual(report["symbols"], ["_ZSyntheticOnev", "_ZSyntheticTwov"])
        self.assertEqual([item["observations"] for item in report["reports"]], [[], []])
        result = validate_paramlist_cross_elf(report)
        self.assertTrue(result["valid"], result["errors"])

    def test_runtime_and_duplicate_promotions_are_rejected(self) -> None:
        report = _contract()
        report["runtime_verified"] = True
        result = validate_paramlist_cross_elf(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])

        report = _contract()
        report["reports"][1] = copy.deepcopy(report["reports"][0])
        result = validate_paramlist_cross_elf(report)
        self.assertFalse(result["valid"])
        self.assertTrue(any("duplicate_report_symbol" in item for item in result["errors"]))

    def test_provider_mismatch_is_rejected(self) -> None:
        report = _contract()
        report["reports"][0]["provider"]["sha256"] = "0" * 64
        result = validate_paramlist_cross_elf(report)
        self.assertFalse(result["valid"])
        self.assertIn("provider_mismatch:0", result["errors"])

    def test_ghidra_crosscheck_is_identity_and_status_scoped(self) -> None:
        report = _contract()
        crosscheck = report["ghidra_crosschecks"][0]
        self.assertEqual(crosscheck["process_exit"], 0)
        self.assertEqual(crosscheck["address_space"], "ram")
        self.assertFalse(crosscheck["runtime_verified"])
        self.assertFalse(crosscheck["callable"])
        crosscheck["binary_sha256"] = "0" * 64
        result = validate_paramlist_cross_elf(report)
        self.assertFalse(result["valid"])
        self.assertIn("ghidra_crosscheck_identity:0", result["errors"])

        report = _contract()
        report["ghidra_crosschecks"][0]["observations"][0]["status"] = "VERIFIED_RUNTIME"
        result = validate_paramlist_cross_elf(report)
        self.assertFalse(result["valid"])
        self.assertIn("ghidra_crosscheck_observation_status:0", result["errors"])

        report = _contract()
        report["ghidra_crosschecks"][0]["source_relative_path"] = "C:/private/viewUnified4.so"
        result = validate_paramlist_cross_elf(report)
        self.assertFalse(result["valid"])
        self.assertIn("ghidra_crosscheck_path:0", result["errors"])

    def test_cli_uses_profile_or_explicit_symbol_set_without_sqlite(self) -> None:
        from fwplatform.cli import main

        with tempfile.TemporaryDirectory() as directory:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main([
                    "sdk", "parameter-cross-elf-set", "--root", directory,
                    "--symbol", "_ZSyntheticOnev", "--json",
                ])
        self.assertEqual(status, 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["symbols"], ["_ZSyntheticOnev"])
        self.assertEqual(result["reports"][0]["observations"], [])


if __name__ == "__main__":
    unittest.main()
