"""Synthetic tests for the metadata-only ParamBase usage adapter."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import json
from contextlib import redirect_stdout
from io import StringIO

from fwplatform.param_family_usage import (
    parse_param_family_usage_export,
    summarize_param_family_usage,
    validate_param_family_usage,
)
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


def _export(*, complete: bool = True, sha: str = EXPECTED_LIBOBJ_SHA) -> str:
    tail = "COMPLETE_FAMILY_USAGE_EXPORT" if complete else "TRUNCATED"
    return "\n".join([
        f"PROGRAM_SHA256={sha}",
        "IMAGE_BASE=00010000",
        "LANGUAGE=ARM:LE:32:v8",
        "ADDRESS_SPACE=ram",
        "ANALYSIS_SCOPE=PARAMBASE_CONSTRUCTOR_XREF_METADATA",
        "FAMILY=PrmBool TARGET=0xe50e8 LOCATOR=ELF_VMA SYMBOL=",
        "XREF FAMILY=PrmBool TARGET=0xe50e8 FROM_GHIDRA=00110010 "
        "FROM_ELF_VMA=0x10010 CALLER=FUN_00100000 "
        "CALLER_ENTRY_GHIDRA=00110000 CALLER_ENTRY_ELF_VMA=0x10000 "
        "ADDRESS_SPACE=ram TYPE=UNCONDITIONAL_CALL",
        "FAMILY=PrmSet TARGET=0x7efb00 LOCATOR=ELF_VMA SYMBOL=",
        "FAMILY_COUNT=2",
        "XREF_COUNT=1",
        tail,
        "",
    ])


class ParamFamilyUsageTests(unittest.TestCase):
    def test_parse_and_summarize_preserves_callsite_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "usage.txt"
            path.write_text(_export(), encoding="utf-8")
            parsed = parse_param_family_usage_export(path)
        self.assertEqual(parsed["binary_sha256"], EXPECTED_LIBOBJ_SHA)
        self.assertEqual(parsed["xref_count"], 1)
        contract = summarize_param_family_usage(
            parsed,
            analysis_status="PARTIAL_TIMEOUT",
            analyzer_version="synthetic",
            timeout_seconds=1,
        )
        self.assertEqual(contract["families"][0]["call_xref_count"], 1)
        self.assertEqual(
            contract["families"][0]["callsite_examples"][0]["callsite_elf_vma"],
            "0x10010",
        )
        self.assertFalse(contract["runtime_verified"])
        self.assertFalse(contract["callable"])

    def test_truncated_export_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "usage.txt"
            path.write_text(_export(complete=False), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "truncated"):
                parse_param_family_usage_export(path)

    def test_sha_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "usage.txt"
            path.write_text(_export(sha="0" * 64), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                parse_param_family_usage_export(path)

    def test_public_contract_validator_rejects_runtime_promotion(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "usage.txt"
            path.write_text(_export(), encoding="utf-8")
            parsed = parse_param_family_usage_export(path)
        contract = summarize_param_family_usage(
            parsed, analysis_status="COMPLETE", analyzer_version="synthetic"
        )
        self.assertTrue(validate_param_family_usage(
            contract, expected_families=("PrmBool", "PrmSet")
        )["valid"])
        contract["callable"] = True
        result = validate_param_family_usage(contract)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])

    def test_checked_in_contract_is_fail_closed_and_has_all_families(self):
        path = Path(__file__).resolve().parents[1] / "sdk/parameter_family_usage_3_21.json"
        contract = json.loads(path.read_text(encoding="utf-8"))
        expected = (
            "PrmBool", "PrmNumber", "PrmString", "PrmPoint", "PrmDimension",
            "PrmStruct", "PrmSet", "PrmNumberList", "PrmCntInfoList", "PrmObjMsg",
        )
        result = validate_param_family_usage(contract, expected_families=expected)
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(contract["xref_count"], 858)
        self.assertEqual(contract["analyzer"]["analysis_status"], "PARTIAL_TIMEOUT")

    def test_cli_reads_usage_contract_without_opening_database(self):
        from fwplatform.cli import main
        output = StringIO()
        with redirect_stdout(output):
            result = main(["sdk", "parameter-family-usage", "--family", "PrmObjMsg", "--json"])
        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["family_count"], 1)
        self.assertEqual(payload["xref_count"], 3)
        self.assertEqual(payload["families"][0]["name"], "PrmObjMsg")


if __name__ == "__main__":
    unittest.main()
