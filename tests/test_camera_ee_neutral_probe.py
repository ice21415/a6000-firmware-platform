"""Fail-closed tests for the Camera EE-neutral primary evidence probe."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import unittest

from fwplatform.camera_ee_neutral_probe import (
    COMMAND_ENTRY,
    EXPECTED_LIBOBJ_SHA,
    SENDER_ENTRY,
    validate_camera_ee_neutral,
)
from fwplatform.cli import build_parser


CONTRACT = (
    Path(__file__).resolve().parents[1]
    / "sdk"
    / "camera_3_21_ee_neutral_3_21.json"
)


def _contract() -> dict:
    return json.loads(CONTRACT.read_text(encoding="utf-8"))


class CameraEeNeutralProbeTests(unittest.TestCase):
    def test_checked_in_contract_is_primary_static_only(self) -> None:
        report = _contract()
        result = validate_camera_ee_neutral(report)
        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(report["binary_sha256"], EXPECTED_LIBOBJ_SHA)
        self.assertFalse(report["runtime_verified"])
        self.assertFalse(report["callable"])
        self.assertEqual(report["sender"]["entry_vma"], hex(SENDER_ENTRY))
        self.assertEqual(report["command"]["entry_vma"], hex(COMMAND_ENTRY))

    def test_unique_issue_command_relocation_is_recorded(self) -> None:
        report = _contract()
        binding = report["sender"]["bindings"]["0xdc144"]
        self.assertEqual(binding["status"], "VERIFIED_STATIC")
        self.assertEqual(
            binding["candidates"][0]["symbol"],
            "_ZN3MWF5ObjIf17IssueCommandAsyncEPvPNS_6ObjMsgE",
        )
        abi = report["abi_contracts"][0]["issue_command_async_abi"]
        self.assertIn("ObjIf::IssueCommandAsync", abi["symbol"])
        self.assertIn("UNKNOWN", abi["r2"])

    def test_message_header_and_cleanup_facts_are_pinned(self) -> None:
        report = _contract()
        message = report["sender"]["local_message"]
        self.assertEqual(message["header_group_r1"], "0x3100")
        self.assertEqual(message["header_command_r2"], "0x7502")
        self.assertEqual(report["sender"]["cleanup"]["replacement_allocation_size"], 8)

    def test_command_field_and_selector_facts_are_pinned(self) -> None:
        report = _contract()
        command = report["command"]
        self.assertEqual(command["relay_counter"]["field_offset"], "0x2700")
        self.assertEqual(command["pending_byte"]["field_offset"], "0x26fc")
        self.assertEqual(command["pending_byte"]["stored_value"], 1)
        self.assertEqual(
            [row["r1"] for row in command["selector_helpers"]["calls"]],
            ["0x11", "0x12"],
        )
        self.assertEqual(command["event_or_action_helper"]["r2"], "0x33ba")

    def test_helper_chain_and_envelope_layout_are_pinned(self) -> None:
        report = _contract()
        helpers = report["helper_evidence"]
        selector = helpers["selector_getter"]
        self.assertEqual(selector["receiver_field_offset"], "0x20")
        self.assertEqual(
            selector["tail_target_symbol"],
            "_ZN12ModelManager11checkStatusEi",
        )
        envelope = helpers["envelope_builder"]
        self.assertEqual(envelope["payload"]["length"], 0x14)
        self.assertIn("strncpy", envelope["payload"]["optional_pointer_copy"])
        self.assertEqual(helpers["local_word_getter"]["receiver_field_offset"], "0x18")
        self.assertEqual(helpers["set_blog_data"]["set_blog_data_symbol"], "setBlogData")

    def test_pc_relative_label_provenance_is_pinned(self) -> None:
        label = _contract()["command"]["pc_relative_label"]
        self.assertEqual(label["literal_slot_vma"], "0x4b1aa8")
        self.assertEqual(label["label_vma"], "0xce8d7b")
        self.assertEqual(label["copied_bytes"], 8)
        self.assertEqual(label["text_prefix"], "NeutrOn")

    def test_helper_relation_provenance_is_pinned(self) -> None:
        report = _contract()
        relations = {
            (
                row.get("source_vma"),
                row.get("target_symbol", row.get("target_vma")),
                row["relation"],
            )
            for row in report["relations"]
        }
        self.assertIn(
            ("0x131e94", "_ZN12ModelManager11checkStatusEi", "PLT_CALL"),
            relations,
        )
        self.assertIn(("0x1323b4", "0x13228c", "DIRECT_CALL"), relations)
        self.assertIn(("0x13228c", "setBlogData", "PLT_CALL"), relations)

    def test_helper_status_tampering_is_rejected(self) -> None:
        report = copy.deepcopy(_contract())
        report["helper_evidence"]["selector_getter"]["status"] = "VERIFIED_RUNTIME"
        result = validate_camera_ee_neutral(report)
        self.assertFalse(result["valid"])
        self.assertIn("selector_helper", result["errors"])

    def test_ghidra_keeps_elf_and_image_addresses_separate(self) -> None:
        crosscheck = _contract()["ghidra_crosscheck"]
        self.assertEqual(crosscheck["exit_code"], 0)
        self.assertFalse(crosscheck["auto_analysis_completed"])
        self.assertEqual(
            crosscheck["aggregate"],
            {"targets": 7, "instructions": 166, "basic_blocks": 16, "cfg_edges": 39},
        )
        records = {row["elf_vma"]: row for row in crosscheck["target_records"]}
        self.assertEqual(records["0x443d14"]["ghidra_vma"], "0x00453d14")
        self.assertEqual(records["0x4b1a20"]["ghidra_vma"], "0x004c1a20")
        self.assertEqual(records["0x443d14"]["address_space"], "ram")

    def test_wrong_hash_is_rejected(self) -> None:
        report = _contract()
        report["binary_sha256"] = "0" * 64
        result = validate_camera_ee_neutral(report)
        self.assertFalse(result["valid"])
        self.assertIn("binary_identity", result["errors"])

    def test_header_tampering_is_rejected(self) -> None:
        report = copy.deepcopy(_contract())
        report["sender"]["local_message"]["header_command_r2"] = "0x73"
        result = validate_camera_ee_neutral(report)
        self.assertFalse(result["valid"])
        self.assertIn("message_command", result["errors"])

    def test_binding_tampering_is_rejected(self) -> None:
        report = copy.deepcopy(_contract())
        report["sender"]["bindings"]["0xdc144"]["candidates"][0]["symbol"] = "fake"
        result = validate_camera_ee_neutral(report)
        self.assertFalse(result["valid"])
        self.assertIn("binding:0xdc144", result["errors"])

    def test_relation_tampering_is_rejected(self) -> None:
        report = copy.deepcopy(_contract())
        report["relations"][0]["target_vma"] = "0xdead"
        report["relations"][1]["target_symbol"] = "fake"
        result = validate_camera_ee_neutral(report)
        self.assertFalse(result["valid"])
        self.assertIn("sender_relation", result["errors"])
        self.assertIn("issue_relation", result["errors"])

    def test_ghidra_crosscheck_tampering_is_rejected(self) -> None:
        report = copy.deepcopy(_contract())
        report["ghidra_crosscheck"]["auto_analysis_completed"] = True
        result = validate_camera_ee_neutral(report)
        self.assertFalse(result["valid"])
        self.assertIn("ghidra_crosscheck", result["errors"])

    def test_runtime_or_callable_promotion_is_rejected(self) -> None:
        report = _contract()
        report["runtime_verified"] = True
        report["callable"] = True
        result = validate_camera_ee_neutral(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])

    def test_cli_parser_exposes_read_only_audit_command(self) -> None:
        args = build_parser().parse_args([
            "sdk", "camera-ee-neutral-audit", "--elf", "fixture.so", "--json",
        ])
        self.assertEqual(args.sdk_command, "camera-ee-neutral-audit")
        self.assertEqual(str(args.elf), "fixture.so")
        self.assertTrue(args.json)


if __name__ == "__main__":
    unittest.main()
