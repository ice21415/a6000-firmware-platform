"""Only synthetic ELF32 ARM fixtures: local core ABI probe regression tests."""
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
from fwplatform.core_abi_probe import CORE_ABI_TARGETS, probe_private_core_abi
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


def synthetic_arm_elf(path: Path, *, second_result: int = 1,
                      code_flags: int = 5, duplicate: bool = False) -> str:
    """Make tiny ELF with pure synthetic code at two artificial VMAs."""
    data = bytearray(0x400)
    ident = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9)
    nph = 2 if duplicate else 1
    data[:52] = struct.pack("<16sHHIIIIIHHHHHH", ident, 3, 40, 1,
                            0x1010, 52, 0, 0, 52, 32, nph, 0, 0, 0)
    ph = struct.pack("<IIIIIIII", 1, 0x100, 0x1000, 0x1000,
                     0x180, 0x180, code_flags, 0x100)
    data[52:84] = ph
    if duplicate:
        data[84:116] = ph
    at = lambda v: 0x100 + v - 0x1000
    # MOV r0,r1 ; BX LR
    data[at(0x1010):at(0x1014)] = bytes.fromhex("08467047")
    # STR r1,[r2] ; MOVS r0,#N ; BX LR
    data[at(0x1020):at(0x1026)] = bytes([0x11, 0x60, second_result << 0, 0x20, 0x70, 0x47])
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


class CoreABIPrimaryByteProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.elf = self.root / "only-synthetic.so"
        self.sha = synthetic_arm_elf(self.elf)
        self.targets = (
            ("sample_action_payload_getter", 0x1010),
            ("sample_parameter_lookup", 0x1020),
        )

    def tearDown(self):
        self.temp.cleanup()

    def probe(self, **overrides):
        return probe_private_core_abi(
            self.elf,
            expected_sha256=overrides.pop("expected_sha256", self.sha),
            targets=overrides.pop("targets", self.targets),
            region_bytes=overrides.pop("region_bytes", 48),
            **overrides,
        )

    def test_default_pin_denies_non_sony_fixture(self):
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            probe_private_core_abi(self.elf)
        self.assertEqual(CORE_ABI_TARGETS,
                         (("camera_action_payload_getter", 0x13200a),
                          ("camera_parameter_lookup", 0x42ac00)))
        self.assertEqual(len(EXPECTED_LIBOBJ_SHA), 64)

    def test_exact_synthetic_opcodes_and_return_sites(self):
        result = self.probe()
        self.assertEqual(result["status"], "LOCAL_PRIMARY_ELF_BOUNDED_HELPER_EVIDENCE_ONLY")
        self.assertFalse(result["matches_pinned_a6000_libobj_3_21"])
        self.assertFalse(result["authenticated_entire_elf_file"])
        self.assertTrue(result["primary_executable_bytes_were_read"])
        self.assertFalse(result["cpp_type_and_return_contract_verified"])
        self.assertEqual(result["callable_camera_core_api_count"], 0)
        self.assertFalse(result["device_executed"])
        a, b = result["research_targets"]
        self.assertEqual(a["visited_instructions"], 2)
        self.assertEqual(b["visited_instructions"], 3)
        self.assertEqual(a["register_and_return_observations"]["observed_return_sites_capped"],
                         ["0x1012"])
        self.assertEqual(b["register_and_return_observations"]["observed_return_sites_capped"],
                         ["0x1024"])
        self.assertFalse(a["register_and_return_observations"]["return_cpp_type_verified"])
        self.assertFalse(b["function_boundary_proven"])
        self.assertNotIn("raw_opcode_bytes", json.dumps(result))

    def test_reads_before_writes_on_entry_linear_prefix_are_only_hints(self):
        result = self.probe()
        a, b = [x["register_and_return_observations"] for x in result["research_targets"]]
        self.assertIn("0x1010", a["entry_prefix_register_read_before_write_sites"]["r1"])
        self.assertIn("0x1020", b["entry_prefix_register_read_before_write_sites"]["r1"])
        self.assertIn("0x1020", b["entry_prefix_register_read_before_write_sites"]["r2"])
        self.assertFalse(a["register_read_before_write_is_proven_abi"])
        self.assertFalse(b["return_cpp_type_verified"])

    def test_actual_synthetic_memory_store_base_is_reported_but_not_abi(self):
        result = self.probe()
        getter, lookup = [
            item["register_and_return_observations"]
            for item in result["research_targets"]
        ]
        self.assertEqual(getter["r2_based_memory_write_sites_capped"], [])
        self.assertIn("0x1020", lookup["r2_based_memory_write_sites_capped"])
        sites = lookup["visited_memory_access_sites_capped"]
        self.assertTrue(any(
            row["site"] == "0x1020"
            and row["memory_base_register"] == "r2"
            and row["operation_direction_hint"] == "WRITE"
            and row["memory_access_width_cpp_type_verified"] is False
            for row in sites
        ))
        self.assertFalse(lookup["r2_based_store_is_proven_output_parameter"])

    def test_fingerprint_is_stable_and_changes_on_local_opcode_change(self):
        first = self.probe()["research_targets"]
        second = self.probe()["research_targets"]
        self.assertEqual(first[1]["register_and_return_observations"]["visited_instruction_bytes_sha256"],
                         second[1]["register_and_return_observations"]["visited_instruction_bytes_sha256"])
        self.sha = synthetic_arm_elf(self.elf, second_result=2)
        third = self.probe()["research_targets"]
        self.assertNotEqual(first[1]["register_and_return_observations"]["visited_instruction_bytes_sha256"],
                            third[1]["register_and_return_observations"]["visited_instruction_bytes_sha256"])
        self.assertEqual(first[0]["register_and_return_observations"]["visited_instruction_bytes_sha256"],
                         third[0]["register_and_return_observations"]["visited_instruction_bytes_sha256"])

    def test_prohibited_or_ambiguous_code_mapping_is_fail_closed(self):
        self.sha = synthetic_arm_elf(self.elf, duplicate=True)
        with self.assertRaisesRegex(ValueError, "not uniquely"):
            self.probe()
        self.sha = synthetic_arm_elf(self.elf, code_flags=4)
        with self.assertRaisesRegex(ValueError, "not uniquely"):
            self.probe()

    def test_wrong_digest_and_nonexistent_file_fail_before_probing(self):
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.probe(expected_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "digest"):
            self.probe(expected_sha256="fake")
        self.elf.unlink()
        with self.assertRaisesRegex(ValueError, "missing"):
            self.probe()

    def test_target_odd_duplicate_bool_and_budget_guards(self):
        for targets in (
            (), (("bad_odd", 0x1011),),
            (("duplicate-a", 0x1010), ("duplicate-b", 0x1010)),
            (("invalid_bool", True),),
            tuple((f"t{i}", 0x1010 + i * 2) for i in range(7)),
        ):
            with self.subTest(targets=targets), self.assertRaises(ValueError):
                self.probe(targets=targets)
        with self.assertRaisesRegex(ValueError, "region_bytes"):
            self.probe(region_bytes=9000)
        with self.assertRaisesRegex(ValueError, "region_bytes"):
            self.probe(region_bytes=15)

    def test_cli_explicit_synthetic_vma_and_hash_no_sqlite_side_effect(self):
        db = self.root / "never-exist.sqlite"
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main([
                "--db", str(db), "sdk", "probe-core-abi",
                "--elf", str(self.elf),
                "--expected-sha256", self.sha,
                "--entry", "0x1010", "--entry", "0x1020",
                "--region-bytes", "48", "--json",
            ])
        self.assertEqual(code, 0)
        self.assertFalse(db.exists())
        report = json.loads(out.getvalue())
        self.assertEqual(len(report["research_targets"]), 2)
        self.assertFalse(report["authenticated_entire_elf_file"])
        self.assertFalse(report["cpp_type_and_return_contract_verified"])


if __name__ == "__main__":
    unittest.main()
