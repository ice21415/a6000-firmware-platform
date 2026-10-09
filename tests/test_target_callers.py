"""Synthetic validation for address-space-aware Ghidra caller metadata."""
from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from fwplatform.target_callers import (
    parse_target_callers_export,
    summarize_target_callers,
    validate_target_callers_contract,
)


SHA = "a" * 64


def _export(*, complete: bool = True, body: str = "[[0010fed0, 0010ffb5]]", caller: str = "0010fed0") -> str:
    lines = [
        f"PROGRAM_SHA256={SHA}",
        "IMAGE_BASE=00010000",
        "LANGUAGE=ARM:LE:32:v8",
        "ADDRESS_SPACE=ram",
        "ANALYSIS_SCOPE=TARGET_CALLER_METADATA",
        "ANALYZER_VERSION=target-callers-1",
        "TARGET=0xffe70 GHIDRA=0010fe70 SYMBOL=FUN_0010fe70",
        (
            "XREF TARGET=0xffe70 FROM_GHIDRA=0010ff4e FROM_ELF_VMA=0xfff4e "
            f"CALLER=FUN_0010fed0 CALLER_ENTRY_GHIDRA={caller} "
            f"CALLER_ENTRY_ELF_VMA=0xffed0 CALLER_BODY={body} "
            "ADDRESS_SPACE=ram TYPE=UNCONDITIONAL_CALL"
        ),
        "TARGET_COUNT=1",
        "REFERENCE_COUNT=1",
    ]
    if complete:
        lines.append("COMPLETE_TARGET_CALLER_EXPORT")
    return "\n".join(lines) + "\n"


class TargetCallerTests(unittest.TestCase):
    def _parse(self, text: str, *, expected: str = SHA):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "callers.txt"
            path.write_text(text, encoding="utf-8")
            return parse_target_callers_export(path, expected_sha256=expected)

    def test_maps_body_ranges_and_keeps_generated_name_nonsemantic(self):
        parsed = self._parse(_export())
        xref = parsed["targets"][0]["xrefs"][0]
        self.assertEqual(xref["from_elf_vma"], "0xfff4e")
        self.assertEqual(xref["caller_body_ranges"][0]["start_elf_vma"], "0xffed0")
        self.assertEqual(xref["caller_body_ranges"][0]["end_elf_vma"], "0xfffb5")
        result = summarize_target_callers(parsed, capstone_callsites={0xffe70: [0xfff4e]})
        self.assertFalse(result["targets"][0]["symbol_semantic"])
        self.assertEqual(
            result["targets"][0]["xrefs"][0]["callsite_status"],
            "PRIMARY_ELF_VERIFIED",
        )

    def test_capstone_only_callsite_keeps_unknown_caller(self):
        parsed = self._parse(_export())
        result = summarize_target_callers(
            parsed, capstone_callsites={0xffe70: [0xfff4e, 0xfffc0]}
        )
        self.assertEqual(result["counts"]["capstone_only_callsites"], 1)
        self.assertEqual(
            result["capstone_only_callsites"][0]["caller_entry_elf_vma"],
            "UNKNOWN",
        )

    def test_truncated_export_is_rejected(self):
        with self.assertRaises(ValueError):
            self._parse(_export(complete=False))

    def test_hash_mismatch_is_rejected(self):
        with self.assertRaises(ValueError):
            self._parse(_export(), expected="b" * 64)

    def test_callsite_outside_body_is_rejected(self):
        with self.assertRaises(ValueError):
            self._parse(_export(body="[[0010fed0, 0010fee0]]"))

    def test_noncontiguous_body_ranges_are_preserved(self):
        parsed = self._parse(
            _export(body="[[0010fed0, 0010fed5],[0010ff40, 0010ffb5]]")
        )
        self.assertEqual(
            len(parsed["targets"][0]["xrefs"][0]["caller_body_ranges"]), 2
        )

    def test_unknown_caller_is_preserved(self):
        text = _export(body="UNKNOWN", caller="UNKNOWN").replace(
            "CALLER_ENTRY_ELF_VMA=0xffed0", "CALLER_ENTRY_ELF_VMA=UNKNOWN"
        )
        parsed = self._parse(text)
        self.assertIsNone(parsed["targets"][0]["xrefs"][0]["caller_body_ranges"])
        result = summarize_target_callers(parsed)
        self.assertEqual(
            result["targets"][0]["xrefs"][0]["caller_identity_status"],
            "UNKNOWN",
        )

    def test_checked_in_contract_is_fail_closed(self):
        contract_path = Path(__file__).parents[1] / "sdk" / "param_set_tree_callers_3_21.json"
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        result = validate_target_callers_contract(contract, expected_sha256=contract["binary_sha256"])
        self.assertTrue(result["valid"], result["errors"])
        self.assertFalse(contract["runtime_verified"])
        self.assertFalse(contract["callable"])

    def test_count_tampering_is_rejected(self):
        contract_path = Path(__file__).parents[1] / "sdk" / "param_set_tree_callers_3_21.json"
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
        contract["counts"]["primary_verified_callsites"] -= 1
        result = validate_target_callers_contract(contract, expected_sha256=contract["binary_sha256"])
        self.assertFalse(result["valid"])
        self.assertIn("primary_count", result["errors"])

    def test_cli_reads_checked_in_contract(self):
        from fwplatform.cli import main

        output = StringIO()
        with redirect_stdout(output):
            result = main(["sdk", "parameter-set-callers", "--json"])
        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["counts"]["primary_verified_callsites"], 8)
        self.assertEqual(payload["counts"]["capstone_only_callsites"], 0)


if __name__ == "__main__":
    unittest.main()
