"""Synthetic source-tier checks for static Appframework semaphore/status reports."""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from fwplatform.app_sync_research import (
    EXPECTED_STATES, EXPECTED_WAIT, PRIMARY_SITES, audit_app_status_sync,
)
from fwplatform.cli import main


ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "sdk" / "camera_3_21_app_status_sync.json"


def synthetic_saved_asm(changes=None):
    edits = changes or {}
    result = ["FILE synthetic/libObj.so", ""]
    for (name, addr), items in PRIMARY_SITES.items():
        result.append(f"FUNCTION {name} {addr}")
        for vma, opcode in items:
            result.append(f"{vma}: {edits.get(vma, opcode)}")
        result.append("")
    return "\n".join(result)


def synthetic_saved_status_chain():
    nodes = [
        {"address": "0x7eeee8", "name": "application_thread_body",
         "calls": ["0x7eeec8", "0x7eec00", "0x7f2210"]},
        {"address": "0x7eeec8", "name": "app_event_queue_receive", "checks": [
            {"address": "0x7f29ec", "field": "+0x28", "role": "guard"},
            {"address": "0x7eaa14", "field": "+0xa4", "role": "ModelManager state nonzero"}]},
        {"address": "0x7eec00", "name": "application_poll_wait"},
        {"address": "0x7eea44", "name": "timer_delta_to_timeout"},
    ]
    names = {
        "0x7f21e8": "event_dispatch_wait",
        "0x7f2210": "application_event_candidate",
        "0x7f2238": "event_callback_wait",
    }
    for addr, (completion, callers) in EXPECTED_WAIT.items():
        n = {
            "address": addr, "name": names[addr],
            "wait": "osal_wai_sem_tmo", "timeout_argument": -1,
            "semaphore_literal": "0x830451",
            "completion": completion + " then osal_sig_sem",
        }
        if addr != "0x7f2210":
            n["callers"] = list(callers)
        nodes.append(n)
    nodes.append({"address": "0x7eb118", "name": "ModelManager status setter", "field": "+0xa4"})
    return {
        "target": "libObj.so (Sony ILCE-6000 firmware 3.21)",
        "purpose": "Static evidence for the application-thread wait chain observed during the cold-boot gap",
        "nodes": nodes,
        "exact_status_setter_callsites": [
            {"callsite": c, "new_state": state} for c, state in EXPECTED_STATES],
        "observed_gap_ms": {"duration": 11615},
        "conclusion": "The wait mechanism is confirmed, but the producer responsible for the 11.615 s instance is not identified statically.",
    }


class AppStatusSyncTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.record = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.fixture = self.root / "record.json"
        self.asm = self.root / "saved-asm.txt"
        self.secondary = self.root / "saved-status.json"
        self.asm.write_text(synthetic_saved_asm(), encoding="utf-8")
        self.status = synthetic_saved_status_chain()
        self._save()

    def tearDown(self):
        self.tmp.cleanup()

    def _save(self):
        self.fixture.write_text(json.dumps(self.record), encoding="utf-8")
        self.secondary.write_text(json.dumps(self.status), encoding="utf-8")

    def _run(self, arm=True, secondary=True):
        self._save()
        return audit_app_status_sync(
            self.fixture, saved_disassembly=self.asm if arm else None,
            saved_status_chain=self.secondary if secondary else None)

    def test_two_source_tiers_with_eighteen_site_checks_and_no_false_consumer(self):
        result = self._run()
        self.assertEqual(result["status"], "BOTH_SAVED_SOURCES_MATCH_CONSUMER_UNVERIFIED")
        self.assertEqual(result["saved_instruction_sites_checked"], 18)
        self.assertTrue(result["secondary_status_report_consistent"])
        self.assertEqual(result["status_field_offset"], "0xa4")
        self.assertEqual(result["queue_gate_vma"], "0x7eeec8")
        self.assertEqual(result["app_loop_zero_queue_result_branches_to"], "0x7eeefa")
        self.assertEqual(result["on_guard_pass_model_status_nonzero"]["model_status_plus_0xa4_zero"],
                         "queue_gate_result_1")
        self.assertEqual(result["on_guard_pass_model_status_nonzero"]["model_status_plus_0xa4_nonzero"],
                         "queue_gate_result_0")
        self.assertEqual(result["reported_status_transition_callsites"], 5)
        self.assertEqual(len(result["secondary_wait_wrappers"]), 3)
        for flag in ("event_0x11004003_consumer_verified",
                     "event_7_8_payload_to_camera_verified",
                     "event_dispatch_wait_original_elf_opcode_verified",
                     "single_boot_delay_cause_proven",
                     "camera_ready_state_proven", "abi_verified",
                     "original_elf_bytes_analyzed_in_this_run"):
            self.assertFalse(result[flag])

    def test_without_saved_sources_no_false_verification(self):
        result = self._run(arm=False, secondary=False)
        self.assertEqual(result["status"], "CANDIDATE_FIXTURE_ONLY")
        self.assertEqual(result["saved_instruction_sites_checked"], 0)
        self.assertFalse(result["secondary_status_report_consistent"])

    def test_independent_saved_arm_and_status_tiers(self):
        self.assertEqual(self._run(arm=True, secondary=False)["status"],
                         "SAVED_ARM_GATE_TEXT_MATCH_ONLY")
        self.assertEqual(self._run(arm=False, secondary=True)["status"],
                         "SAVED_SECONDARY_SYNC_REPORT_MATCH_ONLY")

    def test_saved_arm_nonzero_to_boolean_and_inversion_guard_tampering_rejected(self):
        for where, wrong in [
            ("0x7eaa14", "ldr.w    r0, [r0, #0xa8]"),
            ("0x7eaa20", "movne    r0, #0"),
            ("0x7eeedc", "eor      r0, r0, #2"),
            ("0x7eeed4", "cbz     r0, #0x7eeee4"),
            ("0x7ef188", "bne.w    #0x7eeefa"),
        ]:
            with self.subTest(vma=where):
                self.asm.write_text(synthetic_saved_asm({where: wrong}))
                with self.assertRaisesRegex(ValueError, where):
                    self._run(secondary=False)

    def test_adjacent_status_switch_not_assigned_same_cpp_function(self):
        self.assertEqual(self.record["adjacent_state_selection_lead"]["semantic_relation_to_status_reader"],
                         "UNRESOLVED")
        self.record["adjacent_state_selection_lead"]["semantic_relation_to_status_reader"] = "VERIFIED_SAME_CPP_FUNCTION"
        with self.assertRaisesRegex(ValueError, "semantic boundaries"):
            self._run()
        self.record = json.loads(FIXTURE.read_text())
        self.asm.write_text(synthetic_saved_asm({"0x7eaa6e": "cmp.w    r3, #0x40000"}))
        with self.assertRaisesRegex(ValueError, "0x7eaa6e"):
            self._run(secondary=False)

    def test_wrong_shared_semaphore_or_wait_completion_rejected(self):
        self.status["nodes"][4]["semaphore_literal"] = "0x830452"
        with self.assertRaisesRegex(ValueError, "wait wrapper mismatch"):
            self._run(arm=False)
        self.status = synthetic_saved_status_chain()
        self.status["nodes"][4]["completion"] = "0x7f0aac then osal_sig_sem"
        with self.assertRaisesRegex(ValueError, "wait wrapper mismatch"):
            self._run(arm=False)

    def test_model_manager_status_transition_callsites_not_self_attesting(self):
        self.status["exact_status_setter_callsites"][2]["new_state"] = "0x60000"
        with self.assertRaisesRegex(ValueError, "transition observations"):
            self._run(arm=False)
        self.status = synthetic_saved_status_chain()
        self.record["secondary_report_status_setter"]["callsite_to_reported_new_state"][2]["state"] = "0x60000"
        with self.assertRaisesRegex(ValueError, "status setter"):
            self._run(arm=False)

    def test_forged_camera_ready_consumer_and_original_elf_proof_rejected(self):
        for key in ("event_0x11004003_consumed_by_this_loop",
                    "status_field_exact_CPP_type_or_object_owner",
                    "wait_wrappers_0x7f21e8_0x7f2238_redecoded_from_original_elf",
                    "camera_ready_semantics", "actual_boot_delay_caused_by_semaphore",
                    "sony_abi_or_callable_sdk"):
            with self.subTest(key=key):
                self.record["unverified"][key] = True
                with self.assertRaisesRegex(ValueError, "cannot promote"):
                    self._run(arm=False, secondary=False)
                self.record["unverified"][key] = False

    def test_duplicate_or_wrong_scope_saved_report_entry_rejected(self):
        self.status["nodes"].append(self.status["nodes"][4].copy())
        with self.assertRaisesRegex(ValueError, "duplicate secondary"):
            self._run(arm=False)
        self.status = synthetic_saved_status_chain()
        self.status["target"] = "libObj.so (firmware 3.20)"
        with self.assertRaisesRegex(ValueError, "target/scope"):
            self._run(arm=False)

    def test_cli_does_not_create_sqlite_and_matches_synthetic_sources(self):
        db = self.root / "must-not-exist.sqlite"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            rc = main(["--db", str(db), "sdk", "app-sync",
                       "--fixture", str(self.fixture),
                       "--saved-disassembly", str(self.asm),
                       "--saved-status-chain", str(self.secondary),
                       "--json"])
        self.assertEqual(rc, 0)
        self.assertFalse(db.exists())
        report = json.loads(output.getvalue())
        self.assertEqual(report["status"], "BOTH_SAVED_SOURCES_MATCH_CONSUMER_UNVERIFIED")
        self.assertFalse(report["abi_verified"])


if __name__ == "__main__":
    unittest.main()
