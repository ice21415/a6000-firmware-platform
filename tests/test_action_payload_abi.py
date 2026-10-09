"""Synthetic cross-action payload ABI tests with no proprietary firmware data."""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from fwplatform.action_payload_abi import CASES, OPAQUE_TYPE, audit_action_payload_abi
from fwplatform.cli import main


ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "sdk" / "camera_3_21_action_payload_leads.json"


def synthetic_saved_assembly(changes=None):
    edits = changes or {}
    result = ["FILE synthetic-camera-methods.txt"]
    for (entry, context), sites in CASES.items():
        result.append(f"ENTRY {entry} ")
        for site, opcode in sites:
            result.append(f"{site}: {edits.get(site, opcode)}")
        result.append("")
    return "\n".join(result) + "\n"


class CameraActionPayloadABIResearchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.fixture = json.loads(CATALOG.read_text(encoding="utf-8"))
        self.fixture_file = self.root / "payload.json"
        self.saved = self.root / "synthetic-model-camera-methods.txt"
        self.saved.write_text(synthetic_saved_assembly(), encoding="utf-8")
        self._save()

    def tearDown(self):
        self.tmp.cleanup()

    def _save(self):
        self.fixture_file.write_text(json.dumps(self.fixture), encoding="utf-8")

    def _audit(self, with_saved=True):
        self._save()
        return audit_action_payload_abi(
            self.fixture_file,
            saved_libobj=self.saved if with_saved else None,
        )

    def test_five_consumers_and_explicit_no_cpp_return_type(self):
        result = self._audit()
        self.assertEqual(result["status"], "SAVED_OPAQUE_ACTION_PAYLOAD_REGISTER_USES_MATCHED")
        self.assertEqual(result["actions_with_saved_text_checked"], 5)
        self.assertEqual(result["saved_instruction_text_sites_checked"],
                         sum(len(items) for items in CASES.values()))
        self.assertEqual(result["getter_vma"], "0x13200a")
        self.assertEqual(result["getter_return_category"], OPAQUE_TYPE)
        self.assertEqual(result["key_lookup_helper_vma"], "0x42ac00")
        self.assertEqual(result["observed_key_literals"], ["0x3fe", "0x3ff"])
        self.assertTrue(result["actionsetinit_param1_received_from_this_getter"])
        for key in ("getter_cpp_return_type_verified", "action_wrapper_cpp_signature_verified",
                    "actionsetinit_param1_type_verified", "event_0x11004003_consumer_to_camera_proven",
                    "original_sony_elf_machine_bytes_revalidated"):
            self.assertFalse(result[key])
        self.assertEqual(result["callable_core_camera_apis"], 0)

    def test_without_private_text_is_only_candidate(self):
        result = self._audit(with_saved=False)
        self.assertEqual(result["status"], "OPAQUE_ACTION_PAYLOAD_CONTRACT_CANDIDATE_ONLY")
        self.assertEqual(result["actions_with_saved_text_checked"], 0)
        self.assertEqual(result["saved_instruction_text_sites_checked"], 0)

    def test_getter_result_to_wrapper_and_setinit_registers_not_exchangeable(self):
        for site, wrong in (
            ("0x4aea22", "mov      r1, r4"),
            ("0x4aea28", "bl       #0x42abce"),
            ("0x4bac98", "mov      r0, r1"),
            ("0x4afcc4", "bl       #0x42ac00"),
            ("0x4cf7ee", "mov      r1, r4"),
            ("0x4cf7f0", "bl       #0x42abca"),
        ):
            with self.subTest(site=site):
                self.saved.write_text(synthetic_saved_assembly({site: wrong}))
                with self.assertRaisesRegex(ValueError, site):
                    self._audit()

    def test_key_literals_and_paramlist_error_path_must_match(self):
        for site, wrong in (
            ("0x4baca6", "movw     r1, #0x3ff"),
            ("0x4bacb8", "cbz      r0, #0x4bacd2"),
            ("0x4bacc0", "PIC candidate 'Invalid Message'"),
            ("0x4bacd2", "bl       #0x42abcc"),
            ("0x4bacde", "PIC candidate 'Invalid Message'"),
        ):
            with self.subTest(site=site):
                self.saved.write_text(synthetic_saved_assembly({site: wrong}))
                with self.assertRaisesRegex(ValueError, site):
                    self._audit()

    def test_other_action_consumes_getter_in_message_constructor(self):
        for site, wrong in (
            ("0x4ae94c", "bl       #0x131fd2"),
            ("0x4ae950", "mov      r1, r4"),
            ("0x4ae952", "mov.w    r2, #0x1100"),
            ("0x4ae95c", "bl       #0x44a280"),
        ):
            with self.subTest(site=site):
                self.saved.write_text(synthetic_saved_assembly({site: wrong}))
                with self.assertRaisesRegex(ValueError, site):
                    self._audit()

    def test_fabricated_paramlist_type_and_runtime_consumer_rejected(self):
        self.fixture["opaque_getter"]["cpp_return_type"] = "ParamList*"
        with self.assertRaisesRegex(ValueError, "not proven"):
            self._audit(False)
        self.fixture = json.loads(CATALOG.read_text())
        self.fixture["candidate_contract"]["getter_return_cpp_type"] = "ParamList*"
        with self.assertRaisesRegex(ValueError, "may not claim ABI"):
            self._audit(False)
        self.fixture = json.loads(CATALOG.read_text())
        self.fixture["candidate_contract"]["callable_sony_camera_api"] = True
        with self.assertRaisesRegex(ValueError, "may not claim ABI"):
            self._audit(False)
        self.fixture = json.loads(CATALOG.read_text())
        self.fixture["action_selector_provenance"]["event_0x11004003_direct_mapping_verified"] = True
        with self.assertRaisesRegex(ValueError, "still unresolved"):
            self._audit(False)

    def test_missing_duplicate_case_and_different_firmware_rejected(self):
        self.fixture["observations"].append(self.fixture["observations"][0].copy())
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self._audit(False)
        self.fixture = json.loads(CATALOG.read_text())
        self.fixture["observations"][3] = self.fixture["observations"][0]
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self._audit(False)
        self.fixture = json.loads(CATALOG.read_text())
        self.fixture["elf"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "firmware/source"):
            self._audit(False)

    def test_missing_or_ambiguous_saved_function_rejected(self):
        original = synthetic_saved_assembly()
        self.saved.write_text(original.replace("ENTRY 0x4bac78 ", "ENTRY 0x4bac7a "))
        with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
            self._audit()
        self.saved.write_text(original + "\nENTRY 0x4bac78 \n0x4bac94: bl #0x13200a\n")
        with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
            self._audit()

    def test_cli_no_sqlite_write_or_device_execution(self):
        no_db = self.root / "never-created.sqlite"
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            result = main(["--db", str(no_db), "sdk", "action-payload",
                           "--fixture", str(self.fixture_file),
                           "--saved-libobj", str(self.saved), "--json"])
        self.assertEqual(result, 0)
        self.assertFalse(no_db.exists())
        o = json.loads(out.getvalue())
        self.assertFalse(o["getter_cpp_return_type_verified"])
        self.assertEqual(o["actions_with_saved_text_checked"], 5)


if __name__ == "__main__":
    unittest.main()
