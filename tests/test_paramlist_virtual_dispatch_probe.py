"""Fail-closed tests for the ParamList virtual destruction dispatch audit."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from fwplatform.cli import build_parser
from fwplatform.paramlist_virtual_dispatch_probe import (
    BASE_RTTI_VMA,
    CLEAR_HELPER_VMA,
    EXPECTED_LIBOBJ_SHA,
    validate_paramlist_virtual_dispatch,
)


CONTRACT = (
    Path(__file__).resolve().parents[1]
    / "sdk"
    / "paramlist_virtual_dispatch_3_21.json"
)


def _contract() -> dict:
    return json.loads(CONTRACT.read_text(encoding="utf-8"))


class ParamListVirtualDispatchProbeTests(unittest.TestCase):
    def test_checked_in_contract_is_primary_static_and_complete(self) -> None:
        report = _contract()
        result = validate_paramlist_virtual_dispatch(report)
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(report["binary_sha256"], EXPECTED_LIBOBJ_SHA)
        self.assertEqual(report["aggregate"]["family_count"], 10)
        self.assertEqual(report["aggregate"]["exact_deleting_slot_matches"], 10)
        self.assertFalse(report["runtime_verified"])
        self.assertFalse(report["callable"])

    def test_clear_site_has_explicit_thumb_dispatch_sequence(self) -> None:
        report = _contract()
        clear = report["clear_dispatch"]
        self.assertEqual(clear["helper_vma"], hex(CLEAR_HELPER_VMA))
        self.assertEqual(
            [(row["instruction_vma"], row["mnemonic"]) for row in clear["instructions"]],
            [("0x7edb60", "ldr"), ("0x7edb62", "ldr"), ("0x7edb64", "blx")],
        )
        self.assertIn("null", clear["null_slot_guard"])

    def test_every_family_maps_vptr_plus_eight_to_deleting_slot(self) -> None:
        report = _contract()
        for family in report["families"]:
            self.assertEqual(family["base_rtti_vma"], hex(BASE_RTTI_VMA))
            self.assertEqual(family["clear_dispatch_target_role"], "deleting_destructor")
            slots = family["slots"]
            self.assertEqual([slot["role"] for slot in slots], [
                "clone", "nondeleting_destructor", "deleting_destructor",
            ])
            self.assertEqual([slot["slot_offset_from_prefix"] for slot in slots], [8, 12, 16])
            self.assertEqual([slot["slot_offset_from_object_vptr"] for slot in slots], [0, 4, 8])
            self.assertEqual(family["object_vptr_address_point"],
                             hex(int(family["vtable_prefix_vma"], 16) + 8))

    def test_relocation_backed_non_deleting_slots_are_not_downgraded(self) -> None:
        report = _contract()
        rows = {
            family["name"]: family for family in report["families"]
        }
        for name in ("PrmBool", "PrmDimension", "PrmNumberList", "PrmCntInfoList"):
            slot = rows[name]["slots"][1]
            self.assertEqual(slot["source"], "ELF_RELOCATION", name)
            self.assertTrue(slot["relocation_symbol"], name)

    def test_ghidra_body_range_keeps_address_spaces_separate(self) -> None:
        report = _contract()
        record = report["ghidra_crosscheck"]["target_records"][0]
        self.assertEqual(record["elf_address_space"], "ELF_VMA")
        self.assertEqual(record["address_space"], "ram")
        self.assertEqual(record["body_range_address_space"], "ram")
        self.assertEqual(record["body_ranges"], [{
            "start": "0x007fdb40", "end": "0x007fdb75",
        }])

    def test_wrong_binary_identity_is_rejected(self) -> None:
        report = _contract()
        report["binary_sha256"] = "0" * 64
        result = validate_paramlist_virtual_dispatch(report)
        self.assertFalse(result["valid"])
        self.assertIn("binary_identity", result["errors"])

    def test_slot_or_body_tampering_is_rejected(self) -> None:
        report = copy.deepcopy(_contract())
        report["families"][0]["slots"][2]["slot_offset_from_prefix"] = 20
        result = validate_paramlist_virtual_dispatch(report)
        self.assertFalse(result["valid"])
        self.assertIn("slot_layout:PrmBool", result["errors"])

        report = _contract()
        report["ghidra_crosscheck"]["target_records"][0]["body_ranges"][0]["end"] = "0x007fdb74"
        result = validate_paramlist_virtual_dispatch(report)
        self.assertFalse(result["valid"])
        self.assertIn("ghidra_target_body_ranges", result["errors"])

    def test_runtime_or_callable_promotion_is_rejected(self) -> None:
        report = _contract()
        report["runtime_verified"] = True
        report["callable"] = True
        result = validate_paramlist_virtual_dispatch(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])

    def test_cli_parser_exposes_read_only_audit_command(self) -> None:
        args = build_parser().parse_args([
            "sdk", "paramlist-virtual-dispatch-audit", "--elf", "fixture.so", "--json",
        ])
        self.assertEqual(args.sdk_command, "paramlist-virtual-dispatch-audit")
        self.assertEqual(str(args.elf), "fixture.so")
        self.assertTrue(args.json)


if __name__ == "__main__":
    unittest.main()
