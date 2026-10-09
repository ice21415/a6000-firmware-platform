"""Synthetic ELF32 ARM fixtures test exact static instructions without Sony binary."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path

from fwplatform.camera_elf_verify import (
    _thumb_byte_imm, _thumb_imm_branch, verify_camera_elf,
)
from fwplatform.cli import main


def thumb_branch(site: int, target: int, kind: str) -> bytes:
    """Test-only Thumb BL T1 / B.W T4 encoder for small aligned offsets."""
    offset = target - (site + 4)
    if offset % 2 or not -(1 << 24) <= offset < (1 << 24):
        raise ValueError("test offset outside Thumb range")
    word = offset & ((1 << 25) - 1)
    s, i1, i2 = (word >> 24) & 1, (word >> 23) & 1, (word >> 22) & 1
    j1, j2 = 1 ^ (i1 ^ s), 1 ^ (i2 ^ s)
    first = 0xF000 | (s << 10) | ((word >> 12) & 0x3FF)
    second = (0xD000 if kind == "bl" else 0x9000) | (j1 << 13) | (j2 << 11) | ((word >> 1) & 0x7FF)
    return struct.pack("<HH", first, second)


def tiny_arm_elf(path: Path, instruction_overrides=None, *, duplicate_load=False) -> str:
    data = bytearray(0x300)
    ident = b"\x7fELF" + bytes((1, 1, 1, 0)) + bytes(8)
    phnum = 2 if duplicate_load else 1
    data[:52] = struct.pack("<16sHHIIIIIHHHHHH", ident, 3, 40, 1, 0, 52, 0, 0, 52, 32, phnum, 0, 0, 0)
    segment = struct.pack("<IIIIIIII", 1, 0x100, 0x1000, 0x1000, 0x100, 0x100, 5, 0x100)
    data[52:84] = segment
    if duplicate_load:
        data[84:116] = segment
    instructions = {
        0x1010: thumb_branch(0x1010, 0x1040, "bl"),
        0x1020: thumb_branch(0x1020, 0x1000, "b.w"),
        0x1030: struct.pack("<HH", 0xF892, 0x107C),
        0x1034: struct.pack("<HH", 0xF884, 0x3080),
    }
    instructions.update(instruction_overrides or {})
    for addr, op in instructions.items():
        data[0x100 + addr - 0x1000: 0x104 + addr - 0x1000] = op
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


class CameraELFVerifierTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.root = Path(self.t.name)
        self.elf = self.root / "synthetic-arm.so"
        self.sha = tiny_arm_elf(self.elf)
        self.calls = [
            {"caller": "A", "callee": "B", "callsite": "0x1010", "instruction": "bl #0x1040", "kind": "DIRECT_CALL"},
            {"caller": "B", "callee": "A", "callsite": "0x1020", "instruction": "b.w #0x1000", "kind": "TAIL_BRANCH"},
        ]
        self.fields = [
            {"owner": "A", "kind": "FIELD_READ", "instruction_address": "0x1030",
             "instruction_immediate_offset": "0x7c", "object_field_offset": "0x26fc",
             "inferred_base_adjustment": "0x2680", "width_bits": 8},
            {"owner": "B", "kind": "FIELD_WRITE_CONDITIONAL", "instruction_address": "0x1034",
             "instruction_immediate_offset": "0x80", "object_field_offset": "0x80",
             "inferred_base_adjustment": "0x0", "width_bits": 8},
        ]

    def tearDown(self):
        self.t.cleanup()

    def test_exact_sha_thumb_branches_and_raw_byte_field_operands(self):
        r = verify_camera_elf(self.elf, self.sha, self.calls, self.fields)
        self.assertEqual(r["status"], "ELF_INSTRUCTION_CHECKS_PASS")
        self.assertEqual(r["matching_direct_branches"], 2)
        self.assertEqual(r["matching_byte_fields"], 2)
        self.assertFalse(r["abi_verified"])
        self.assertFalse(r["runtime_callable"])
        self.assertTrue(all(not x["object_root_proven_by_opcode_alone"] for x in r["field_checks"]))

    def test_known_thumb_disassembly_vectors_positive_and_negative(self):
        self.assertEqual(_thumb_imm_branch(bytes.fromhex("e2f704f9"), 0x4cf814),
                         ("bl", 0x4b1a20))
        self.assertEqual(_thumb_imm_branch(bytes.fromhex("81f4b6bc"), 0x4b07f0),
                         ("b.w", 0x132160))
        self.assertEqual(_thumb_byte_imm(bytes.fromhex("95f86410")),
                         ("FIELD_READ", 0x64))
        self.assertEqual(_thumb_byte_imm(bytes.fromhex("84f88050")),
                         ("FIELD_WRITE", 0x80))

    def test_exact_digest_and_unique_executable_segment_required(self):
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            verify_camera_elf(self.elf, "0" * 64, self.calls, self.fields)
        self.sha = tiny_arm_elf(self.elf, duplicate_load=True)
        with self.assertRaisesRegex(ValueError, "exactly one"):
            verify_camera_elf(self.elf, self.sha, self.calls, self.fields)
        self.assertFalse((self.root / "new.sqlite").exists())

    def test_wrong_opcode_target_or_byte_immediate_fails_closed(self):
        self.sha = tiny_arm_elf(self.elf, {0x1010: thumb_branch(0x1010, 0x1050, "bl"),
                                           0x1030: struct.pack("<HH", 0xF892, 0x1080)})
        r = verify_camera_elf(self.elf, self.sha, self.calls, self.fields)
        self.assertEqual(r["status"], "ELF_INSTRUCTION_CHECKS_INCOMPLETE")
        self.assertEqual(r["matching_direct_branches"], 1)
        self.assertEqual(r["matching_byte_fields"], 1)
        self.assertIn("MISMATCH", r["branch_checks"][0]["result"])
        self.assertIn("MISMATCH", r["field_checks"][0]["result"])

    def test_conditional_or_nonbranch_opcode_does_not_pass_verification(self):
        self.sha = tiny_arm_elf(self.elf, {0x1020: bytes(4)})
        r = verify_camera_elf(self.elf, self.sha, self.calls, self.fields)
        self.assertEqual(r["matching_direct_branches"], 1)
        self.assertFalse(r["all_checked_instruction_sites_match"])

    def test_cli_exact_synthetic_elf_with_minimal_catalog_no_sqlite(self):
        catalog = {
            "schema_version": 1, "firmware_version": "3.21",
            "verified_static_contract_count": 0, "verified_runtime_count": 0,
            "interfaces": [
                {"name": name, "address": addr, "domain": "Camera",
                 "binary_sha256": self.sha, "abi": None, "calling_convention": None,
                 "parameter_layout": None, "return_semantics": None,
                 "verification_status": "CANDIDATE", "runtime_safety": "DESCRIPTIVE_ONLY",
                 "review": {"runtime_callable_verified": False,
                            "source_artifact_basenames": ["synthetic.txt"]}}
                for name, addr in (("A", "0x1000"), ("B", "0x1040"))
            ],
        }
        graph = {
            "schema_version": 1, "firmware_version": "3.21",
            "binary_sha256": self.sha, "proof_policy": "RESEARCH_REPORT_ONLY",
            "verified_static_api_count": 0, "camera_sdk_callable_count": None,
            "static_calls": [dict(self.calls[0], source_artifact="synthetic.txt")],
            "field_observations": [dict(self.fields[0], source_artifact="synthetic.txt")],
            "normalized_selector_routes": [], "unresolved_external": [],
        }
        catpath, graphpath = self.root / "cat.json", self.root / "graph.json"
        catpath.write_text(json.dumps(catalog))
        graphpath.write_text(json.dumps(graph))
        output = io.StringIO()
        no_db = self.root / "never-created.sqlite"
        with contextlib.redirect_stdout(output):
            code = main(["--db", str(no_db), "sdk", "research", "--catalog",
                         str(catpath), "--graph", str(graphpath),
                         "--verify-elf", str(self.elf), "--json"])
        self.assertEqual(code, 0)
        self.assertFalse(no_db.exists())
        report = json.loads(output.getvalue())
        self.assertTrue(report["independent_elf_check"]["all_checked_instruction_sites_match"])
        self.assertFalse(report["validation"]["independent_abi_verified"])
        self.sha = tiny_arm_elf(self.elf, {0x1010: thumb_branch(0x1010, 0x1050, "bl")})
        catalog["interfaces"][0]["binary_sha256"] = self.sha
        catalog["interfaces"][1]["binary_sha256"] = self.sha
        graph["binary_sha256"] = self.sha
        catpath.write_text(json.dumps(catalog))
        graphpath.write_text(json.dumps(graph))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["--db", str(no_db), "sdk", "research", "--catalog",
                         str(catpath), "--graph", str(graphpath),
                         "--verify-elf", str(self.elf), "--json"])
        self.assertEqual(code, 2)
        self.assertFalse(json.loads(output.getvalue())["independent_elf_check"]["all_checked_instruction_sites_match"])


if __name__ == "__main__":
    unittest.main()
