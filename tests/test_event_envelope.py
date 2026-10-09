"""Synthetic tests for reported model-execute event envelope; no Sony ELF files."""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from fwplatform.cli import main
from fwplatform.event_envelope import (
    FACTORY_SITES, FRONT_SITES, audit_model_execute_event,
)


ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "sdk" / "camera_3_21_model_execute_envelope.json"


def synthetic_report(front=FRONT_SITES, factory=FACTORY_SITES):
    def asm_lines(sites):
        return "\n".join(f"{site}: {opcode}" for site, opcode in sites) + "\n"
    return ("\nENTRY 0x12106e _ZN8ViewBase19requestModelExecuteEPKcmP9ParamList\n"
            + asm_lines(front)
            + "\nENTRY 0x7f0b0c _ZN22AbstractUtilityManager30createRequestModelExecuteEventEimP9ParamList\n"
            + asm_lines(factory))


class ModelExecuteEventEnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fixture = json.loads(CATALOG.read_text(encoding="utf-8"))
        self.path = self.root / "envelope.json"
        self.disasm = self.root / "saved-research.txt"
        self.disasm.write_text(synthetic_report(), encoding="utf-8")
        self._save()

    def tearDown(self):
        self.temp.cleanup()

    def _save(self):
        self.path.write_text(json.dumps(self.fixture), encoding="utf-8")

    def _run(self, use_report=True):
        self._save()
        return audit_model_execute_event(
            self.path, saved_disassembly=self.disasm if use_report else None)

    def test_report_guard_and_remaining_unknowns(self):
        result = self._run()
        self.assertEqual(result["status"], "SAVED_STATIC_EVENT_ENVELOPE_TEXT_MATCH")
        self.assertEqual(result["event_id"], "0x11004003")
        self.assertEqual(result["event_parameter_keys"], [7, 8])
        self.assertEqual(result["audit"]["front_end_opcode_sites_checked"], len(FRONT_SITES))
        self.assertEqual(result["audit"]["factory_opcode_sites_checked"], len(FACTORY_SITES))
        self.assertFalse(result["audit"]["original_elf_instruction_bytes_verified"])
        self.assertFalse(result["modelcamera_dispatch_link_verified"])
        self.assertFalse(result["factory_import_dynamic_target_resolved"])
        self.assertFalse(result["ABI_and_runtime_callability_verified"])
        self.assertGreaterEqual(len(result["remaining_unknowns"]), 4)

    def test_without_saved_report_no_false_instruction_proof(self):
        result = self._run(use_report=False)
        self.assertEqual(result["status"], "EVENT_ENVELOPE_CANDIDATE_ONLY")
        self.assertFalse(result["audit"]["report_text_verified"])
        self.assertEqual(result["audit"]["front_end_opcode_sites_checked"], 0)
        self.assertEqual(result["audit"]["factory_opcode_sites_checked"], 0)

    def test_wrong_parameter_id_or_abi_claim_rejected(self):
        self.fixture["factory_implementation_lead"]["event_id"] = "0x11004004"
        with self.assertRaisesRegex(ValueError, "event envelope ID"):
            self._run()
        self.fixture = json.loads(CATALOG.read_text())
        self.fixture["factory_implementation_lead"]["parameter_keys"][1]["key"] = 9
        with self.assertRaisesRegex(ValueError, "parameter-key layout"):
            self._run()
        self.fixture = json.loads(CATALOG.read_text())
        self.fixture["complete_abi_count"] = 1
        with self.assertRaisesRegex(ValueError, "completed ABI"):
            self._run()

    def test_false_dynamic_link_or_runtime_delivery_claim_rejected(self):
        self.fixture["factory_implementation_lead"]["dynamic_linked_to_frontend_plt_verified"] = True
        with self.assertRaisesRegex(ValueError, "resolution or Camera delivery"):
            self._run()
        self.fixture = json.loads(CATALOG.read_text())
        self.fixture["request_frontend"]["application_submit"]["delivers_to_camera_dispatcher_verified"] = True
        with self.assertRaisesRegex(ValueError, "resolution or Camera delivery"):
            self._run()

    def test_wrong_instruction_or_key_8_is_rejected(self):
        bad = synthetic_report().replace("0x7f0b5c: movs     r1, #8",
                                         "0x7f0b5c: movs     r1, #9")
        self.disasm.write_text(bad)
        with self.assertRaisesRegex(ValueError, "0x7f0b5c"):
            self._run()

    def test_wrong_transformation_target_or_missing_event_constructor_is_rejected(self):
        self.disasm.write_text(synthetic_report().replace(
            "0x12108c: bl       #0x12d780", "0x12108c: bl       #0x12d782"))
        with self.assertRaisesRegex(ValueError, "0x12108c"):
            self._run()
        self.disasm.write_text(synthetic_report().replace(
            "0x7f0b26: blx      #0xdb66c ; _ZN5EventC1Emhh", "0x7f0b26: nop"))
        with self.assertRaisesRegex(ValueError, "0x7f0b26"):
            self._run()

    def test_duplicate_ambiguous_function_entry_or_opcode_address_rejected(self):
        self.disasm.write_text(synthetic_report() +
            "\nENTRY 0x12106e _ZN8ViewBase19requestModelExecuteEPKcmP9ParamList\n"
            "0x121098: _ZN22AbstractUtilityManager30createRequestModelExecuteEventEimP9ParamList\n")
        with self.assertRaisesRegex(ValueError, "ambiguous function entry"):
            self._run()
        self.disasm.write_text(synthetic_report() + "0x7f0b60: extra\n")
        with self.assertRaisesRegex(ValueError, "duplicated"):
            self._run()

    def test_wrong_plt_target_even_with_matching_symbol_name_rejected(self):
        current = synthetic_report()
        self.disasm.write_text(current.replace(
            "0x121098: blx      #0xdfbdc ; _ZN22AbstractUtilityManager30createRequestModelExecuteEventEimP9ParamList",
            "0x121098: blx      #0xdfbe0 ; _ZN22AbstractUtilityManager30createRequestModelExecuteEventEimP9ParamList",
        ))
        with self.assertRaisesRegex(ValueError, "0x121098"):
            self._run()

    def test_register_dataflow_to_event_parameter_8_is_required(self):
        self.disasm.write_text(synthetic_report().replace(
            "0x7f0b52: mov      r1, r8", "0x7f0b52: mov      r1, r6"))
        with self.assertRaisesRegex(ValueError, "0x7f0b52"):
            self._run()

    def test_wrong_frontend_pointer_provenance_rejected(self):
        self.disasm.write_text(synthetic_report().replace(
            "0x121076: ldr.w    sb, [r0, #0x7c]",
            "0x121076: ldr.w    sb, [r0, #0x80]"))
        with self.assertRaisesRegex(ValueError, "0x121076"):
            self._run()

    def test_cli_never_creates_or_migrates_sqlite(self):
        self._save()
        new_db = self.root / "not-created.sqlite"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["--db", str(new_db), "sdk", "event-envelope",
                         "--fixture", str(self.path), "--saved-disassembly",
                         str(self.disasm), "--json"])
        self.assertEqual(code, 0)
        self.assertFalse(new_db.exists())
        self.assertTrue(json.loads(output.getvalue())["audit"]["report_text_verified"])

    def test_fixture_count_and_provenance_as_descriptive_only(self):
        report = json.loads(CATALOG.read_text(encoding="utf-8"))
        self.assertEqual(report["factory_implementation_lead"]["event_id"], "0x11004003")
        self.assertEqual(report["binary"]["sha256"],
                         "8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a")
        self.assertEqual(report["complete_abi_count"], 0)
        self.assertEqual(report["confirmed_runtime_camera_apis"], 0)
        self.assertFalse(report["factory_implementation_lead"]["dynamic_linked_to_frontend_plt_verified"])


if __name__ == "__main__":
    unittest.main()
