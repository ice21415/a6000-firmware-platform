"""Self-authored Thumb fixtures for registry-keyflow recon; no firmware bytes."""
import tempfile
import unittest
from pathlib import Path

from fwplatform.camera_registry_keyflow_probe import (
    RECORD_ARG_MARKER, analyze_site, probe_registry_keyflow, summarize_site,
)


def fixture_reader(raw, base=0x1000):
    def read(address, size):
        if base <= address and address + size <= base + len(raw):
            return raw[address - base: address - base + size]
        return None
    return read


class CameraRegistryKeyflowTests(unittest.TestCase):
    def test_record_argument_plus8_store_is_traced(self):
        # mov r4,r1; movs r3,#32; str r3,[r4,#8]; bx lr
        raw = bytes.fromhex("0c462023a3607047")
        result = analyze_site(fixture_reader(raw), "state_machine", 0x1000, len(raw), "r1")
        self.assertEqual(len(result["stores_of_interest"]), 1)
        store = result["stores_of_interest"][0]
        self.assertEqual(store["effective_address"]["values"], [RECORD_ARG_MARKER + 8])
        self.assertEqual(store["written_value"]["values"], [32])
        self.assertEqual(store["argument_alias"], "ENTRY_ARGUMENT_PLUS_8_WHEN_REACHED")
        self.assertEqual(store["status"], "CONDITIONAL_STATIC_OBSERVATION")
        self.assertEqual(result["identity_status"], "INTRA_FUNCTION_ARGUMENT_ALIAS_ONLY")

    def test_same_offset_different_base_is_not_proof(self):
        # movs r3,#32; str r3,[r0,#8]; bx lr
        raw = bytes.fromhex("202383607047")
        result = analyze_site(fixture_reader(raw), "state_machine", 0x1000, len(raw), "r1")
        self.assertEqual(result["stores_of_interest"], [])

    def test_unknown_alias_cannot_be_promoted(self):
        # mov r4,r0; movs r3,#32; str r3,[r4,#8]; bx lr
        raw = bytes.fromhex("04462023a3607047")
        result = analyze_site(fixture_reader(raw), "state_machine", 0x1000, len(raw), "r1")
        self.assertEqual(result["stores_of_interest"], [])

    def test_argument_is_not_a_runtime_pointer(self):
        # Even direct symbolic mapping never changes the unknown identity.
        raw = bytes.fromhex("0c462023a3607047")
        result = analyze_site(fixture_reader(raw), "state_machine", 0x1000, len(raw), "r1")
        self.assertEqual(result["identity_status"], "INTRA_FUNCTION_ARGUMENT_ALIAS_ONLY")
        self.assertNotIn("PRIMARY_ELF_VERIFIED", str(result))

    def test_it_blocks_fail_closed(self):
        # it eq; mov r4,r1; str r3,[r4,#8]; bx lr
        raw = bytes.fromhex("08bf0c46a3607047")
        result = analyze_site(fixture_reader(raw), "state_machine", 0x1000, len(raw), "r1")
        self.assertEqual(result["stores_of_interest"], [])
        self.assertTrue(any(x["reason"] == "IT_BLOCK_UNSUPPORTED" for x in result["unresolved"]))

    def test_bad_bounds_and_arguments_rejected(self):
        read = fixture_reader(bytes.fromhex("7047"))
        for bad_window in (0, 0x801):
            with self.assertRaises(ValueError):
                analyze_site(read, "bad", 0x1000, bad_window, "r1")
        with self.assertRaises(ValueError):
            analyze_site(read, "bad", 0x1000, 2, "r2")
        with self.assertRaises(ValueError):
            analyze_site(read, "bad", 0x1001, 2, "r1")

    def test_private_elf_sha_mismatch_fails_before_decode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.bin"
            path.write_bytes(b"not a private firmware ELF")
            with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
                probe_registry_keyflow(path, expected_sha256="0" * 64)

    def test_no_synthetic_firmware_bytes_in_output(self):
        raw = bytes.fromhex("0c462023a3607047")
        report = analyze_site(fixture_reader(raw), "state_machine", 0x1000, len(raw), "r1")
        self.assertNotIn("raw_bytes", str(report))
        self.assertNotIn("firmware_bytes", str(report))


if __name__ == "__main__":
    unittest.main()
