"""Fail-closed tests for cross-ELF dynamic import evidence."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from fwplatform.cross_elf_import_probe import (
    probe_cross_elf_imports,
    validate_cross_elf_import_contract,
)


CONTRACT = Path(__file__).resolve().parents[1] / "sdk" / "input_service_cross_elf_3_21.json"


def _contract() -> dict:
    return json.loads(CONTRACT.read_text(encoding="utf-8"))


class CrossELFImportProbeTests(unittest.TestCase):
    def test_checked_in_contract_is_identity_scoped(self) -> None:
        report = _contract()
        result = validate_cross_elf_import_contract(report)
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["observation_count"], 9)
        self.assertEqual(report["provider"]["name"], "libObj.so")
        self.assertFalse(report["runtime_verified"])
        self.assertFalse(report["callable"])

    def test_each_import_has_relocation_and_plt_evidence(self) -> None:
        report = _contract()
        for item in report["observations"]:
            self.assertEqual(
                item["import"]["symbol"],
                "_ZN12InputService19getInputEventStatusEP9ParamListPKS0_",
            )
            self.assertTrue(item["relocations"])
            self.assertTrue(item["plt"])
            self.assertTrue(all(row["address_space"] == "ELF_VMA" for row in item["relocations"]))
            self.assertFalse(item["runtime_verified"])
            self.assertFalse(item["callable"])

    def test_private_ghidra_crosscheck_is_identity_scoped(self) -> None:
        report = _contract()
        item = next(row for row in report["observations"] if row["source_binary"]["name"] == "viewUnified4.so")
        crosscheck = item["ghidra_crosscheck"]
        self.assertEqual(crosscheck["status"], "VERIFIED_STATIC")
        self.assertEqual(crosscheck["process_exit"], 0)
        self.assertEqual(crosscheck["language"], "ARM:LE:32:v8")
        self.assertEqual(crosscheck["image_base"], "0x10000")
        self.assertEqual(crosscheck["exact_mangled_symbol_lookup"]["status"], "UNRESOLVED")
        imported = crosscheck["demangled_import_observation"]
        self.assertEqual(imported["status"], "PRIMARY_ELF_VERIFIED")
        self.assertEqual(imported["plt_entry_address_elf_vma"], "0x3d434")
        self.assertEqual(imported["got_reference_address_elf_vma"], "0x1ae5c8")
        self.assertTrue(crosscheck["raw_export_private"])
        self.assertFalse(crosscheck["runtime_verified"])
        self.assertFalse(crosscheck["callable"])

    def test_ghidra_crosscheck_tampering_is_rejected(self) -> None:
        report = _contract()
        item = next(row for row in report["observations"] if row["source_binary"]["name"] == "viewUnified4.so")
        item["ghidra_crosscheck"]["binary_sha256"] = report["provider"]["sha256"]
        result = validate_cross_elf_import_contract(report)
        self.assertFalse(result["valid"])
        self.assertIn("ghidra_crosscheck_identity:3", result["errors"])

    def test_direct_call_negative_scan_does_not_become_unused_claim(self) -> None:
        report = _contract()
        self.assertTrue(all(not item["direct_calls"] for item in report["observations"]))
        self.assertTrue(all(item["direct_call_scan"]["status"] == "UNKNOWN" for item in report["observations"]))
        self.assertIn("register-indirect", report["limitations"][2])

    def test_runtime_or_callable_promotion_is_rejected(self) -> None:
        report = _contract()
        report["runtime_verified"] = True
        result = validate_cross_elf_import_contract(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])

    def test_symbol_and_provider_tampering_is_rejected(self) -> None:
        report = _contract()
        report["symbol"] = "_Zfakev"
        result = validate_cross_elf_import_contract(report)
        self.assertFalse(result["valid"])
        self.assertIn("import:0", result["errors"])

        report = _contract()
        report["provider"]["export_status"] = "VERIFIED_RUNTIME"
        result = validate_cross_elf_import_contract(report)
        self.assertFalse(result["valid"])
        self.assertIn("provider_export_status", result["errors"])

    def test_duplicate_or_absolute_source_identity_is_rejected(self) -> None:
        report = _contract()
        report["observations"][1]["source_binary"]["relative_path"] = report["observations"][0]["source_binary"]["relative_path"]
        result = validate_cross_elf_import_contract(report)
        self.assertFalse(result["valid"])
        self.assertTrue(any(error.startswith("duplicate_source") for error in result["errors"]))

        report = _contract()
        report["observations"][0]["source_binary"]["relative_path"] = "C:/private/lib.so"
        result = validate_cross_elf_import_contract(report)
        self.assertFalse(result["valid"])
        self.assertIn("source_path:0", result["errors"])

    def test_generic_symbol_is_not_syncandroid_or_inputservice_hardcoded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = probe_cross_elf_imports(Path(directory), symbol_name="_ZCustomProbev")
        self.assertEqual(report["symbol"], "_ZCustomProbev")
        self.assertEqual(report["observations"], [])
        self.assertFalse(report["runtime_verified"])
        self.assertFalse(report["callable"])


if __name__ == "__main__":
    unittest.main()
