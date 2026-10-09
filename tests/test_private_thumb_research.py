"""Synthetic ELF tests for read-only, bounded A6000 Thumb helper research."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path

from fwplatform.cli import main
from fwplatform.private_thumb_research import (
    EXPECTED_LIBOBJ_SHA, trace_private_selector_elf,
)


def _thumb_bl(pc: int, target: int) -> bytes:
    v = (target - pc - 4) & 0x1FFFFFF
    s, i1, i2 = (v >> 24) & 1, (v >> 23) & 1, (v >> 22) & 1
    j1, j2 = 1 ^ (i1 ^ s), 1 ^ (i2 ^ s)
    return struct.pack("<HH", 0xF000 | (s << 10) | (v >> 12 & 0x3ff),
                       0xD000 | (j1 << 13) | (j2 << 11) | (v >> 1 & 0x7ff))


def _synthetic_elf(path: Path, *, duplicate_load: bool = False,
                   code_flags: int = 5, event_value: int = 0x11004003):
    """Only generated test code. Not a Sony firmware fragment."""
    data = bytearray(0x400)
    ident = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9)
    phnum = 2 if duplicate_load else 1
    data[:52] = struct.pack("<16sHHIIIIIHHHHHH",
                             ident, 3, 40, 1, 0x1010, 52, 0, 0, 52, 32,
                             phnum, 0, 0, 0)
    ph = struct.pack("<IIIIIIII", 1, 0x100, 0x1000, 0x1000,
                     0x180, 0x180, code_flags, 0x100)
    data[52:84] = ph
    if duplicate_load:
        data[84:116] = ph
    at = lambda v: 0x100 + v - 0x1000
    data[at(0x1010):at(0x1014)] = _thumb_bl(0x1010, 0x1040)
    data[at(0x1014):at(0x1016)] = bytes.fromhex("0048")  # LDR r0, [pc,#0]
    data[at(0x1016):at(0x1018)] = bytes.fromhex("7047")  # BX LR
    data[at(0x1018):at(0x101c)] = struct.pack("<I", event_value)
    data[at(0x1020):at(0x1024)] = bytes.fromhex("01207047")  # MOVS r0,#1; BX LR
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


class PrivateThumbResearchTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.root = Path(self.t.name)
        self.elf = self.root / "synthetic-arm.so"
        self.sha = _synthetic_elf(self.elf)
        self.targets = (("synthetic_transform", 0x1010), ("synthetic_handler", 0x1020))

    def tearDown(self):
        self.t.cleanup()

    def _analyze(self, **kwargs):
        return trace_private_selector_elf(
            self.elf, expected_sha256=self.sha,
            entries=self.targets, max_region_bytes=kwargs.pop("max_region_bytes", 64), **kwargs)

    def test_pinned_official_hash_not_runtime_verified(self):
        self.assertEqual(EXPECTED_LIBOBJ_SHA,
                         "8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a")
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            trace_private_selector_elf(self.elf, entries=self.targets)
        report = self._analyze()
        self.assertFalse(report["selector_helper_semantics_verified"])
        self.assertFalse(report["abi_verified"])
        self.assertFalse(report["device_executed"])
        self.assertFalse(report["event_consumer_identified"])
        self.assertEqual(report["status"], "PRIVATE_ELF_BOUNDED_OPCODE_TRACE_ONLY")

    def test_bounded_thumb_branch_and_literal_are_decoded_from_synthetic_elf(self):
        result = self._analyze()
        a, b = result["function_regions"]
        self.assertEqual(a["research_role_hint"], "synthetic_transform")
        self.assertEqual(a["entry_vma"], "0x1010")
        self.assertEqual(a["decoded_instruction_count"], 3)
        self.assertEqual(a["direct_or_indirect_calls"][0]["target_vma"], "0x1040")
        self.assertIn("0x11004003", [x["u32_le"] for x in a["literal_load_candidates"]])
        self.assertEqual(b["decoded_instruction_count"], 2)
        self.assertFalse(a["whole_function_cfg_verified"])
        self.assertEqual(result["literal_event_word"], "0x11004003")
        self.assertIn("0x1018", [x["vma"] for x in result["unclassified_event_word_occurrences"]])
        self.assertTrue(all(x["classification"] == "RAW_WORD_OCCURRENCE_NOT_XREF_OR_CONSUMER"
                            for x in result["unclassified_event_word_occurrences"]))
        self.assertNotIn("opcode_bytes", json.dumps(result))

    def test_raw_word_only_does_not_categorize_consumer(self):
        self.sha = _synthetic_elf(self.elf, event_value=0x12345678)
        out = self._analyze()
        self.assertEqual(out["unclassified_event_word_occurrences"], [])
        self.assertFalse(out["event_consumer_identified"])
        self.assertEqual(out["function_regions"][0]["literal_load_candidates"][0]["u32_le"],
                         "0x12345678")

    def test_sha_validation_precedes_mapping_or_decoding(self):
        self.sha = _synthetic_elf(self.elf, duplicate_load=True)
        with self.assertRaisesRegex(ValueError, "not uniquely"):
            self._analyze()
        self.sha = _synthetic_elf(self.elf, code_flags=4)
        with self.assertRaisesRegex(ValueError, "not uniquely"):
            self._analyze()

    def test_missing_private_elf_does_not_fabricate_data(self):
        self.elf.unlink()
        with self.assertRaisesRegex(ValueError, "missing"):
            self._analyze()

    def test_bounded_region_and_provenance_guards(self):
        with self.assertRaisesRegex(ValueError, "region"):
            self._analyze(max_region_bytes=20000)
        with self.assertRaisesRegex(ValueError, "digest"):
            trace_private_selector_elf(self.elf, expected_sha256="fake", entries=self.targets)
        with self.assertRaisesRegex(ValueError, "between 1 and 8"):
            trace_private_selector_elf(self.elf, expected_sha256=self.sha, entries=())
        with self.assertRaisesRegex(ValueError, "positive even"):
            trace_private_selector_elf(
                self.elf, expected_sha256=self.sha, entries=(("invalid", 0x1011),),
                max_region_bytes=64)

    def test_cli_with_explicit_synthetic_sha_still_does_not_migrate_sqlite(self):
        nonexisting_db = self.root / "never-create.sqlite"
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = main([
                "--db", str(nonexisting_db), "sdk", "trace-selector",
                "--elf", str(self.elf), "--expected-sha256", self.sha,
                "--region-bytes", "64", "--json",
            ])
        self.assertEqual(rc, 0)
        self.assertFalse(nonexisting_db.exists())
        report = json.loads(out.getvalue())
        self.assertEqual(report["status"], "PRIVATE_ELF_BOUNDED_OPCODE_TRACE_ONLY")
        self.assertEqual(report["input_sha256"], self.sha)
        self.assertFalse(report["selector_helper_semantics_verified"])


if __name__ == "__main__":
    unittest.main()
