"""REA/Ghidra saved evidence bridge: synthetic inputs, no Sony firmware bytes."""
from __future__ import annotations

import contextlib
import io
import json
import struct
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from fwplatform.cli import main
from fwplatform.rea_bridge import _verify_saved_movw, audit_rea_ui_camera_bridge


ROOT = Path(__file__).resolve().parent.parent


def encode_movw(rd: int, value: int) -> bytes:
    """Synthetic MOVW T3 encoder used solely to test the byte decoder."""
    h1 = 0xF240 | (((value >> 11) & 1) << 10) | ((value >> 12) & 15)
    h2 = (((value >> 8) & 7) << 12) | (rd << 8) | (value & 255)
    return struct.pack("<HH", h1, h2)


def encode_bl(site: int, target: int) -> bytes:
    relative = target - site - 4
    if relative % 2 or not -(1 << 24) <= relative < (1 << 24):
        raise ValueError("test branch must fit Thumb BL range")
    bits = relative & ((1 << 25) - 1)
    s, i1, i2 = (bits >> 24) & 1, (bits >> 23) & 1, (bits >> 22) & 1
    j1, j2 = 1 ^ (i1 ^ s), 1 ^ (i2 ^ s)
    h1 = 0xF000 | (s << 10) | ((bits >> 12) & 0x3FF)
    h2 = 0xD000 | (j1 << 13) | (j2 << 11) | ((bits >> 1) & 0x7FF)
    return struct.pack("<HH", h1, h2)


class REABridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fixture = json.loads((ROOT / "sdk" / "ui_camera_3_21_rea_bridge.json").read_text())
        self.fixture["ui"].update({
            "elf_vma": "0x2000", "ghidra_vma": "0x12000",
            "selector": "0x1234", "observed_call_sites_in_saved_decompile": 1,
            "other_destination_call_sites_in_saved_decompile": 1,
        })
        self.fixture["camera"].update({
            "dispatcher_elf_vma": "0x3000", "source_bytes_elf_vma": "0x3000",
            "compare_selector_instruction_elf_vma": "0x3000",
            "branch_instruction_elf_vma": "0x3010",
            "selector": "0x1234", "callee_elf_vma": "0x3100",
        })
        self.path = self.root / "bridge.json"
        self.ui = self.root / "rea-pseudocode.c"
        self.audit_path = self.root / "audit.json"
        self.ui.write_text(
            "CmnViewBigModelUtil13setInitForRec\n"
            'requestModelExecuteEPKcmP9ParamList(param_2,"model/CAMERA",0x1234,iVar3);\n'
            'requestModelExecuteEPKcmP9ParamList(param_2,"model/STILL_REC",0x1234,iVar12);\n'
        )
        raw = encode_movw(3, 0x1234) + bytes(12) + encode_bl(0x3010, 0x3100)
        self.audit = {
            "source_sha256": self.fixture["camera"]["sha256"],
            "evidence_type": "raw-ELF-Capstone-static-audit-not-REA",
            "ranges": [{
                "ELF_address": "0x3000", "bytes": raw.hex(),
                "instructions": [
                    {"address": "0x3000", "mnemonic": "movw", "operands": "r3, #0x1234"},
                    {"address": "0x3010", "mnemonic": "bl", "operands": "#0x3100"},
                ],
            }],
        }
        self._save()

    def tearDown(self):
        self.temp.cleanup()

    def _save(self):
        self.path.write_text(json.dumps(self.fixture))
        self.audit_path.write_text(json.dumps(self.audit))

    def _inspect(self, use_ui=True, use_camera=True):
        self._save()
        return audit_rea_ui_camera_bridge(
            self.path,
            ui_decompile=self.ui if use_ui else None,
            camera_audit=self.audit_path if use_camera else None,
        )

    def test_grounded_rea_fixture_contains_distinct_elf_ids_and_unproven_route(self):
        original = json.loads((ROOT / "sdk" / "ui_camera_3_21_rea_bridge.json").read_text())
        self.assertEqual(original["ui"]["ghidra_vma"], "0x1b2504")
        self.assertEqual(original["ui"]["elf_vma"], "0x1a2504")
        self.assertEqual(original["ui"]["ghidra_image_bias"], "0x10000")
        self.assertEqual(original["camera"]["branch_instruction_elf_vma"], "0x4cfe98")
        self.assertEqual(original["camera"]["callee_elf_vma"], "0x4cf7a8")
        self.assertFalse(original["boundary"]["proven_end_to_end"])
        self.assertNotEqual(original["ui"]["sha256"], original["camera"]["sha256"])
        self.assertEqual(original["ui"]["observed_call_sites_in_saved_decompile"], 20)
        self.assertEqual(original["ui"]["other_destination_call_sites_in_saved_decompile"], 6)

    def test_synthetic_saved_capstone_bytes_and_ui_decomp_rechecked(self):
        report = self._inspect()
        self.assertEqual(report["status"], "BOTH_SAVED_ENDPOINTS_RECHECKED_MESSAGE_ROUTE_UNVERIFIED")
        self.assertEqual(report["saved_ui_callsite_counts"]["ui_camera_selector_request_sites"], 1)
        self.assertEqual(report["saved_ui_callsite_counts"]["ui_still_selector_request_sites"], 1)
        self.assertEqual(report["saved_artifact_checks"]["camera_saved_raw_instruction_slice"],
                         "THUMB_MOVW_SELECTOR_AND_BL_TARGET_MATCH")
        self.assertFalse(report["end_to_end_message_delivery_verified"])
        self.assertFalse(report["independent_full_original_elf_checked_now"])
        self.assertFalse(report["sony_abi_verified"])

    def test_without_original_saved_inputs_not_misrepresented_as_verified(self):
        report = self._inspect(use_ui=False, use_camera=False)
        self.assertIn("PARTIALLY", report["status"])
        self.assertEqual(report["saved_artifact_checks"]["ui_saved_pseudocode"], "NOT_PROVIDED")
        self.assertIsNone(report["saved_ui_callsite_counts"]["ui_camera_selector_request_sites"])
        self.assertFalse(report["device_callability_verified"])

    def test_correctly_reject_mismatched_rebasing_and_selector(self):
        self.fixture["ui"]["ghidra_image_bias"] = "0x20000"
        with self.assertRaisesRegex(ValueError, "address mapping"):
            self._inspect()
        self.fixture["ui"]["ghidra_image_bias"] = "0x10000"
        self.fixture["camera"]["selector"] = "0x4321"
        with self.assertRaisesRegex(ValueError, "selectors differ"):
            self._inspect()

    def test_correctly_reject_false_cross_elf_route_or_wrong_identity(self):
        self.fixture["boundary"]["proven_end_to_end"] = True
        with self.assertRaisesRegex(ValueError, "verified firmware"):
            self._inspect()
        self.fixture["boundary"]["proven_end_to_end"] = False
        self.fixture["camera"]["sha256"] = self.fixture["ui"]["sha256"]
        with self.assertRaisesRegex(ValueError, "independent ELF"):
            self._inspect()
        self.fixture["camera"]["sha256"] = self.audit["source_sha256"]
        self.audit["source_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "source or evidence"):
            self._inspect()

    def test_raw_movw_and_branch_target_and_audit_metadata_are_not_self_attesting(self):
        self.assertTrue(_verify_saved_movw(encode_movw(3, 0x1234), 0x1234))
        self.assertFalse(_verify_saved_movw(encode_movw(3, 0x1235), 0x1234))
        self.assertFalse(_verify_saved_movw(bytes(4), 0x1234))
        with self.assertRaisesRegex(ValueError, "Capstone metadata"):
            self.audit["ranges"][0]["instructions"][1]["operands"] = "#0x3200"
            self._inspect()
        self.audit["ranges"][0]["instructions"][1]["operands"] = "#0x3100"
        raw = bytearray.fromhex(self.audit["ranges"][0]["bytes"])
        raw[-1] ^= 1
        self.audit["ranges"][0]["bytes"] = raw.hex()
        with self.assertRaisesRegex(ValueError, "BL target"):
            self._inspect()

    def test_ui_saved_decompiler_count_checked_not_equated_to_runtime_frequency(self):
        self.ui.write_text(
            "CmnViewBigModelUtil13setInitForRec\n"
            'requestModelExecuteEPKcmP9ParamList(param_2,"model/CAMERA",0x1234,iVar3);\n'
        )
        with self.assertRaisesRegex(ValueError, "request site count"):
            self._inspect()
        self.assertTrue(self.fixture["ui"]["runtime_frequency_unknown"])

    def test_cli_does_not_create_sqlite_and_can_validate_two_saved_artifacts(self):
        dbfile = self.root / "must-not-exist.sqlite"
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            result = main([
                "--db", str(dbfile), "sdk", "rea-bridge",
                "--fixture", str(self.path),
                "--ui-decompile", str(self.ui),
                "--camera-audit", str(self.audit_path), "--json",
            ])
        self.assertEqual(result, 0)
        self.assertFalse(dbfile.exists())
        output = json.loads(stdout.getvalue())
        self.assertEqual(output["status"], "BOTH_SAVED_ENDPOINTS_RECHECKED_MESSAGE_ROUTE_UNVERIFIED")


if __name__ == "__main__":
    unittest.main()
