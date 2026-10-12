"""Dual model request wrapper static research tests (all synthetic text)."""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from fwplatform.cli import main
from fwplatform.model_request_frontends import EXPECTED, audit_model_request_frontends


ROOT = Path(__file__).resolve().parent.parent
FRONTENDS = ROOT / "sdk/camera_3_21_model_request_frontends.json"
ENVELOPE = ROOT / "sdk/camera_3_21_model_execute_envelope.json"


def synthetic_report() -> str:
    output = []
    for spec in EXPECTED.values():
        output.append(f"ENTRY {spec['entry_vma']} {spec['symbol']}")
        output.extend(f"{addr}: {instruction}" for addr,instruction in spec["instructions"])
        output.append("")
    return "\n".join(output)


class DualModelRequestFrontendsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fixture = json.loads(FRONTENDS.read_text(encoding="utf-8"))
        self.path = self.root / "candidate.json"
        self.textfile = self.root / "research.txt"
        self.textfile.write_text(synthetic_report(), encoding="utf-8")
        self._save()

    def tearDown(self):
        self.temp.cleanup()

    def _save(self):
        self.path.write_text(json.dumps(self.fixture), encoding="utf-8")

    def check(self, text=True, envelope=False):
        self._save()
        return audit_model_request_frontends(
            self.path,
            saved_disassembly=self.textfile if text else None,
            event_envelope=ENVELOPE if envelope else None,
        )

    def test_saved_frontends_are_distinct_but_share_helper_and_factory(self):
        r = self.check(envelope=True)
        self.assertEqual(r["status"], "BOTH_SAVED_FRONTEND_PATHS_RECHECKED")
        self.assertEqual(r["frontend_count"], 2)
        self.assertEqual(r["shared_selector_transform_entry"], "0x12d780")
        self.assertEqual(r["shared_named_event_factory_import"], "0xdfbdc")
        self.assertEqual(r["event_envelope_crosscheck"], "EXACT_ELF_IDENTITY_AND_VIEWBASE_FUNCTION_MATCH")
        self.assertEqual(r["total_saved_text_opcode_sites_checked"], sum(
            len(spec["instructions"]) for spec in EXPECTED.values()))
        self.assertEqual(r["frontends"][0]["submit_target"], "0xdb578")
        self.assertEqual(r["frontends"][1]["submit_target"], "0x125084")
        self.assertFalse(r["event_consumer_resolved"])
        self.assertFalse(r["selector_transform_body_recovered"])
        self.assertFalse(r["runtime_callable"])
        self.assertFalse(r["independent_raw_elf_bytes_checked_now"])
        self.assertEqual(r["verified_complete_abi_contracts"], 0)

    def test_fixture_only_does_not_falsely_prove_instruction_report(self):
        r = self.check(text=False)
        self.assertEqual(r["status"], "TWO_FRONTEND_RESEARCH_LEADS_ONLY")
        self.assertEqual(r["total_saved_text_opcode_sites_checked"], 0)
        self.assertEqual(r["event_envelope_crosscheck"], "NOT_PROVIDED")

    def test_wrong_second_helper_target_is_rejected(self):
        self.fixture["recorded_frontends"][1]["selector_transform"]["target"] = "0x12d784"
        with self.assertRaisesRegex(ValueError, "selector_transform"):
            self.check()

    def test_second_path_distinct_submit_target_must_not_be_assumed_identical(self):
        self.fixture["recorded_frontends"][1]["submit"]["target"] = "0xdb578"
        with self.assertRaisesRegex(ValueError, "submit tail branch"):
            self.check()

    def test_invented_helper_semantics_or_callable_status_rejected(self):
        self.fixture["shared_observation"]["selector_transform_semantics_verified"] = True
        with self.assertRaisesRegex(ValueError, "cannot be promoted"):
            self.check()
        self.fixture = json.loads(FRONTENDS.read_text())
        self.fixture["sdk_callable_api_count"] = 1
        with self.assertRaisesRegex(ValueError, "complete ABI or callable"):
            self.check()

    def test_wrong_source_register_after_second_helper_is_rejected(self):
        self.textfile.write_text(synthetic_report().replace(
            "0x1250ea: mov      r2, r0",
            "0x1250ea: mov      r2, r6"))
        with self.assertRaisesRegex(ValueError, "0x1250ea"):
            self.check()

    def test_wrong_named_factory_plt_target_is_rejected_even_if_name_unchanged(self):
        self.textfile.write_text(synthetic_report().replace(
            "0x1250ee: blx      #0xdfbdc ;",
            "0x1250ee: blx      #0xdfbe0 ;"))
        with self.assertRaisesRegex(ValueError, "0x1250ee"):
            self.check()

    def test_duplicate_function_entry_rejected(self):
        self.textfile.write_text(synthetic_report()
            + "\nENTRY 0x1250c0 _ZN13viewManagerIf19requestModelExecuteEPKcmP9ParamList\n")
        with self.assertRaisesRegex(ValueError, "ambiguous function entry"):
            self.check()

    def test_deleted_frontend_and_hash_mismatch_against_envelope_rejected(self):
        self.fixture["recorded_frontends"].pop()
        with self.assertRaisesRegex(ValueError, "two distinct"):
            self.check()
        self.fixture = json.loads(FRONTENDS.read_text())
        self.fixture["binary_sha256"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "mismatched ELF"):
            self.check(envelope=True)

    def test_cli_readonly_no_database_creation(self):
        dbpath = self.root / "never-sqlite.db"
        out = io.StringIO()
        self._save()
        with contextlib.redirect_stdout(out):
            code = main(["--db", str(dbpath), "sdk", "request-frontends",
                        "--fixture", str(self.path),
                        "--saved-disassembly", str(self.textfile),
                        "--event-envelope", str(ENVELOPE), "--json"])
        self.assertEqual(code, 0)
        self.assertFalse(dbpath.exists())
        r = json.loads(out.getvalue())
        self.assertEqual(r["status"], "BOTH_SAVED_FRONTEND_PATHS_RECHECKED")


if __name__ == "__main__":
    unittest.main()
