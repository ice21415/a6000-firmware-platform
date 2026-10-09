"""Synthetic Appframework event-loop evidence checks without firmware distribution."""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from fwplatform.app_event_loop import EXPECTED, audit_application_event_loop
from fwplatform.cli import main


ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "sdk" / "camera_3_21_application_event_loop.json"


def synthetic_saved_assembly(modification=None):
    chunks = ["FILE synthetic/libObj.so SHA256 synthetic"]
    for (name, entry), sites in EXPECTED.items():
        chunks.append(f"FUNCTION {name} {entry}")
        for vma, instr in sites:
            line = f"{vma}: {instr}"
            if modification and vma in modification:
                line = f"{vma}: {modification[vma]}"
            chunks.append(line)
        chunks.append("")
    return "\n".join(chunks) + "\n"


class AppEventLoopBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.fixture_path = self.root / "fixture.json"
        self.saved = self.root / "synthetic-saved.txt"
        self.saved.write_text(synthetic_saved_assembly(), encoding="utf-8")
        self._save()

    def tearDown(self):
        self.tmp.cleanup()

    def _save(self):
        self.fixture_path.write_text(json.dumps(self.fixture), encoding="utf-8")

    def _inspect(self, source=True):
        self._save()
        return audit_application_event_loop(
            self.fixture_path, saved_disassembly=self.saved if source else None)

    def test_source_scoped_22_observations_without_event_consumer_claim(self):
        result = self._inspect()
        self.assertEqual(result["status"], "SAVED_APP_EVENT_LOOP_TEXT_MATCH_EVENT_CONSUMER_UNPROVEN")
        self.assertEqual(result["opcode_text_sites_checked"], 22)
        self.assertEqual(result["function_regions_checked"], 4)
        self.assertTrue(result["saved_report_text_verified"])
        for unknown in ("original_elf_instruction_bytes_verified",
                        "queue_consumer_of_this_event_id_verified",
                        "dispatch_or_callback_runtime_verified",
                        "event_key_7_8_to_camera_action_verified", "abi_verified"):
            self.assertFalse(result[unknown])
        self.assertEqual(result["event_id_under_investigation"], "0x11004003")

    def test_no_source_means_no_claim_of_instruction_validation(self):
        result = self._inspect(source=False)
        self.assertEqual(result["status"], "APP_EVENT_LOOP_BOUNDARY_CANDIDATES_ONLY")
        self.assertEqual(result["opcode_text_sites_checked"], 0)
        self.assertEqual(result["function_regions_checked"], 0)
        self.assertFalse(result["saved_report_text_verified"])

    def test_saved_wrong_branch_target_and_queue_gate_rejected(self):
        self.saved.write_text(synthetic_saved_assembly({
            "0x7eecb6": "b.w      #0x7f21ec"}))
        with self.assertRaisesRegex(ValueError, "0x7eecb6"):
            self._inspect()
        self.saved.write_text(synthetic_saved_assembly({
            "0x7ef180": "bl       #0x7eeed0"}))
        with self.assertRaisesRegex(ValueError, "0x7ef180"):
            self._inspect()

    def test_semaphore_guard_opcode_mismatch_rejected(self):
        self.saved.write_text(synthetic_saved_assembly({
            "0x7f221a": "ldr      r0, [pc] ; literal 0x830452"}))
        with self.assertRaisesRegex(ValueError, "0x7f221a"):
            self._inspect()

    def test_fake_event_consumer_or_abi_promotion_rejected(self):
        self.fixture["boundary"]["event_id_11004003_dispatched_by_these_sites_verified"] = True
        with self.assertRaisesRegex(ValueError, "cannot claim"):
            self._inspect()
        self.fixture["boundary"]["event_id_11004003_dispatched_by_these_sites_verified"] = False
        self.fixture["boundary"]["event_consumer_abi_verified"] = True
        with self.assertRaisesRegex(ValueError, "cannot claim"):
            self._inspect()

    def test_wrong_binary_or_forged_event_id_rejected(self):
        self.fixture["binary"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "identity"):
            self._inspect()
        self.fixture["binary"]["sha256"] = json.loads(FIXTURE.read_text())["binary"]["sha256"]
        self.fixture["factory_envelope_event_id"] = "0x11004004"
        with self.assertRaisesRegex(ValueError, "scope"):
            self._inspect()

    def test_duplicate_site_and_duplicate_function_label_rejected(self):
        duplicate = self.fixture["observed_functions"][0]["sites"][0].copy()
        self.fixture["observed_functions"][0]["sites"].append(duplicate)
        with self.assertRaisesRegex(ValueError, "expected instruction sites"):
            self._inspect()
        self.fixture = json.loads(FIXTURE.read_text())
        self.saved.write_text(synthetic_saved_assembly()
            + "\nFUNCTION app_event_queue_receive 0x7eeec8\n"
            + "0x7eeed0: bl       #0x7f29ec\n")
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            self._inspect()

    def test_cli_reads_only_explicit_fixture_and_disassembly_no_db(self):
        db = self.root / "not-created.sqlite"
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = main(["--db", str(db), "sdk", "event-loop",
                       "--fixture", str(self.fixture_path),
                       "--saved-disassembly", str(self.saved), "--json"])
        self.assertEqual(rc, 0)
        self.assertFalse(db.exists())
        result = json.loads(out.getvalue())
        self.assertEqual(result["opcode_text_sites_checked"], 22)
        self.assertFalse(result["queue_consumer_of_this_event_id_verified"])


if __name__ == "__main__":
    unittest.main()
