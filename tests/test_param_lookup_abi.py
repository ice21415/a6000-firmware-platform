"""Synthetic register ABI tests for 0x42ac00 / 0x42abdc; no Sony ELF."""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from fwplatform.cli import main
from fwplatform.param_lookup_abi import (
    LOOKUP_CASES, ALT_SITES, audit_parameter_lookup_abi,
)


ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "sdk" / "camera_3_21_param_lookup_abi.json"


def saved_synthetic_code(mut=None):
    edits = mut or {}
    lines = ["FILE synthetic-no-sony-code.txt"]
    for entry, details in LOOKUP_CASES.items():
        lines.append(f"ENTRY {entry} ")
        for site, opcode in details["sites"]:
            lines.append(f"{site}: {edits.get(site, opcode)}")
        lines.append("")
    lines.append("ENTRY 0x4cf7a8 ")
    for site, opcode in ALT_SITES:
        lines.append(f"{site}: {edits.get(site, opcode)}")
    lines.append("")
    return "\n".join(lines)


class ParameterLookupABIResearchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.fixture = self.root / "param_lookup.json"
        self.saved = self.root / "synthetic_model_camera.txt"
        self.saved.write_text(saved_synthetic_code(), encoding="utf-8")
        self._save()

    def tearDown(self):
        self.temp.cleanup()

    def _save(self):
        self.fixture.write_text(json.dumps(self.data), encoding="utf-8")

    def _audit(self, source=True):
        self._save()
        return audit_parameter_lookup_abi(
            self.fixture, saved_libobj=self.saved if source else None,
        )

    def test_two_independent_lookup_cases_and_easy_mode_return(self):
        report = self._audit()
        self.assertEqual(report["status"], "SAVED_CALLER_OUTPUT_PARAMETER_ABI_TEXT_MATCH")
        self.assertEqual(report["action_case_count_checked"], 2)
        self.assertEqual(report["case_sites_checked"], sum(
            len(v["sites"]) for v in LOOKUP_CASES.values()))
        self.assertEqual(report["alternate_easy_mode_sites_checked"], len(ALT_SITES))
        self.assertEqual(report["input_register_roles"]["r1"], "numeric parameter ID")
        self.assertEqual(report["input_register_roles"]["r2"], "address of caller-provided output slot")
        self.assertIn("UNKNOWN", report["input_register_roles"]["r3"])
        self.assertEqual(report["sampled_output_slot_width_bytes"], 4)
        self.assertFalse(report["output_slot_cpp_type_verified"])
        self.assertFalse(report["fourth_register_parameter_verified"])
        self.assertFalse(report["helper_0x42abdc_cpp_abi_verified"])
        self.assertFalse(report["primary_elf_bytes_decoded_now"])
        self.assertEqual(report["verified_callable_camera_core_apis"], 0)

    def test_no_private_saved_instruction_source_is_candidate_only(self):
        result = self._audit(source=False)
        self.assertEqual(result["status"], "PARAMETER_LOOKUP_ABI_CANDIDATE_ONLY")
        self.assertEqual(result["case_sites_checked"], 0)
        self.assertEqual(result["alternate_easy_mode_sites_checked"], 0)

    def test_wrong_id_or_output_pointer_register_rejected(self):
        for addr, bad in (
            ("0x4baca6", "movw     r1, #0x3ff"),
            ("0x4bacaa", "add.w    r1, r7, #0x34"),
            ("0x4baccc", "add.w    r3, r7, #0x30"),
            ("0x4aff4c", "mov.w    r1, #0x1b9"),
            ("0x4aff50", "add.w    r3, r7, #0x14"),
        ):
            with self.subTest(addr=addr):
                self.saved.write_text(saved_synthetic_code({addr: bad}))
                with self.assertRaisesRegex(ValueError, addr):
                    self._audit()

    def test_zero_result_output_consumer_or_error_path_mismatch_rejected(self):
        for addr, bad in (
            ("0x4bacb8", "cbnz     r0, #0x4bacc4"),
            ("0x4bacd6", "cbnz     r0, #0x4bace6"),
            ("0x4bacd0", "ldr      r5, [r7, #0x30]"),
            ("0x4bacde", "PIC candidate 'Invalid Event'"),
            ("0x4aff58", "cbz      r0, #0x4aff6a"),
            ("0x4aff5a", "ldr      r3, [r7, #0x10]"),
            ("0x4aff64", "str.w    r3, [r4, #0x204]"),
            ("0x4aff7a", "cbz      r0, #0x4aff8a"),
            ("0x4aff86", "str.w    r3, [r4, #0x200]"),
        ):
            with self.subTest(addr=addr):
                self.saved.write_text(saved_synthetic_code({addr: bad}))
                with self.assertRaisesRegex(ValueError, addr):
                    self._audit()

    def test_separate_alt_easy_mode_lookup_is_not_silently_merged(self):
        for addr, bad in (
            ("0x4cf854", "ldr r1, [pc] ; literal 0x12000006"),
            ("0x4cf85e", "bl       #0x42ac00"),
            ("0x4cf864", "beq      #0x4cf8dc"),
            ("0x4cf866", "ldr.w    r3, [r7, #0x6c4]"),
            ("0x4cf86a", "cmp      r3, #0"),
        ):
            with self.subTest(addr=addr):
                self.saved.write_text(saved_synthetic_code({addr: bad}))
                with self.assertRaisesRegex(ValueError, addr):
                    self._audit()

    def test_forged_full_cpp_abi_and_fourth_input_not_allowed(self):
        self.data["helper_0x42ac00"]["register_roles"]["r3"] = "int default_value"
        with self.assertRaisesRegex(ValueError, "prototype exceeds"):
            self._audit(False)
        self.data = json.loads(FIXTURE.read_text())
        self.data["helper_0x42ac00"]["source_cpp_type_verified"] = True
        with self.assertRaisesRegex(ValueError, "prototype exceeds"):
            self._audit(False)
        self.data = json.loads(FIXTURE.read_text())
        self.data["helper_0x42abdc"]["comparison_relation_to_0x42ac00"] = "IDENTICAL_ABI"
        with self.assertRaisesRegex(ValueError, "separate unknown"):
            self._audit(False)
        self.data = json.loads(FIXTURE.read_text())
        self.data["complete_core_camera_apis"] = 1
        with self.assertRaisesRegex(ValueError, "only a local register contract"):
            self._audit(False)

    def test_source_entry_missing_and_duplicate_rejected(self):
        original = saved_synthetic_code()
        self.saved.write_text(original.replace("ENTRY 0x4bac78 ", "ENTRY 0x4bac7a "))
        with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
            self._audit()
        self.saved.write_text(original + "\nENTRY 0x4bac78 \n0x4bacb4: bl #0x42ac00\n")
        with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
            self._audit()

    def test_manifest_duplicate_or_wrong_source_identity_rejected(self):
        self.data["helper_0x42ac00"]["cases"][1]["entry"] = "0x4bac78"
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self._audit(False)
        self.data = json.loads(FIXTURE.read_text())
        self.data["elf"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "Sony ELF source"):
            self._audit(False)

    def test_cli_offline_reads_source_but_never_creates_db(self):
        db = self.root / "absent.sqlite"
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = main([
                "--db", str(db), "sdk", "param-lookup",
                "--fixture", str(self.fixture),
                "--saved-libobj", str(self.saved), "--json",
            ])
        self.assertEqual(rc, 0)
        self.assertFalse(db.exists())
        payload = json.loads(out.getvalue())
        self.assertEqual(payload["case_sites_checked"], 29)
        self.assertFalse(payload["primary_elf_bytes_decoded_now"])
        self.assertEqual(payload["verified_callable_camera_core_apis"], 0)


if __name__ == "__main__":
    unittest.main()
