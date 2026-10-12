"""Synthetic checks for cross-ELF imported-symbol evidence handling."""
from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from fwplatform.paramset_cross_elf import (
    GET,
    GET_SET,
    load_imported_symbol_export,
    validate_paramset_cross_elf,
)


def _jsonl(*, legacy: bool = False, complete_count: int | None = None) -> str:
    digest = "a" * 64
    if legacy:
        records = [
            {"kind": "metadata", "binary_sha256": digest, "image_base": "0x10000"},
            {"kind": "symbol", "name": "getSet", "address": "0x20000", "namespace": "PrmSet"},
            {"kind": "reference", "symbol": "getSet", "target_address": "0x20000",
             "from_address": "0x21000", "caller_entry": "0x21000", "is_call": True},
        ]
    else:
        records = [
            {"kind": "metadata", "binary_sha256": digest, "image_base": "0x10000"},
            {"kind": "symbol", "name": "getSet", "qualified_name": "PrmSet::getSet",
             "ghidra_address": "0x20000", "elf_vma": "0x10000", "namespace": "PrmSet"},
            {"kind": "symbol", "name": "GET", "qualified_name": "PrmSet::GET",
             "ghidra_address": "0x20100", "elf_vma": "0x10100", "namespace": "PrmSet"},
            {"kind": "reference", "symbol": "getSet", "target_address_ghidra": "0x20000",
             "target_address_elf_vma": "0x10000", "from_address_ghidra": "0x21000",
             "from_address_elf_vma": "0x11000", "caller_entry_ghidra": "0x21000",
             "caller_entry_elf_vma": "0x11000", "is_call": True},
            {"kind": "reference", "symbol": "GET", "target_address_ghidra": "0x20100",
             "target_address_elf_vma": "0x10100", "from_address_ghidra": "0x21010",
             "from_address_elf_vma": "0x11010", "caller_entry_ghidra": "0x21000",
             "caller_entry_elf_vma": "0x11000", "is_call": True},
        ]
    count = len(records) if complete_count is None else complete_count
    records.append({"kind": "complete", "binary_sha256": digest,
                    "record_count": count, "export_status": "complete"})
    return "\n".join(json.dumps(row) for row in records) + "\n"


class ParamSetCrossElfTests(unittest.TestCase):
    def test_normalizes_new_address_spaces(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "refs.jsonl"
            path.write_text(_jsonl(), encoding="utf-8")
            result = load_imported_symbol_export(path, expected_binary_sha256="a" * 64)
        reference = next(row for row in result["records"] if row["kind"] == "reference")
        self.assertEqual(reference["from_address_elf_vma"], "0x11000")
        self.assertEqual(result["ghidra_image_base"], "0x10000")

    def test_accepts_legacy_address_fields_but_separates_vma(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "refs.jsonl"
            path.write_text(_jsonl(legacy=True), encoding="utf-8")
            result = load_imported_symbol_export(path)
        symbol = next(row for row in result["records"] if row["kind"] == "symbol")
        reference = next(row for row in result["records"] if row["kind"] == "reference")
        self.assertEqual(symbol["elf_vma"], "0x10000")
        self.assertEqual(reference["from_address_elf_vma"], "0x11000")

    def test_truncated_export_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "refs.jsonl"
            path.write_text(_jsonl(complete_count=99), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_imported_symbol_export(path)

    def test_checked_in_contract_is_static_only(self):
        contract = json.loads((Path(__file__).parents[1] / "sdk" / "paramset_cross_elf_3_21.json").read_text(encoding="utf-8"))
        self.assertTrue(validate_paramset_cross_elf(contract)["valid"])
        self.assertEqual({row["target_symbol"] for row in contract["relations"]}, {GET, GET_SET})
        self.assertFalse(contract["runtime_verified"])
        self.assertFalse(contract["callable"])
        self.assertEqual(contract["chains"][0]["event_parameter_lookup"]["r1_value"], "0x19")

    def test_runtime_promotion_is_rejected(self):
        contract = json.loads((Path(__file__).parents[1] / "sdk" / "paramset_cross_elf_3_21.json").read_text(encoding="utf-8"))
        contract["runtime_verified"] = True
        result = validate_paramset_cross_elf(contract)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])

    def test_same_name_wrong_plt_target_is_rejected(self):
        contract = json.loads((Path(__file__).parents[1] / "sdk" / "paramset_cross_elf_3_21.json").read_text(encoding="utf-8"))
        contract["relations"][0]["target_address_elf_vma"] = contract["plt_bindings"][GET]["plt_vma"]
        result = validate_paramset_cross_elf(contract)
        self.assertFalse(result["valid"])
        self.assertIn("relation_target_address", result["errors"])

    def test_cli_reads_checked_in_contract(self):
        from fwplatform.cli import main

        output = StringIO()
        with redirect_stdout(output):
            result = main(["sdk", "parameter-set-cross-elf", "--json"])
        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["chain_status"], "PRIMARY_ELF_VERIFIED")
        self.assertEqual(payload["chain_semantic_status"], "STATIC_INFERRED")
        self.assertFalse(payload["runtime_verified"])
        self.assertFalse(payload["callable"])


if __name__ == "__main__":
    unittest.main()
