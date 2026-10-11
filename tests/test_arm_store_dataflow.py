"""Synthetic hand-encoded ARM/Thumb instructions, no firmware fixtures."""
import struct
import unittest
import tempfile
from pathlib import Path

from fwplatform.arm_store_dataflow import Value, analyze_function, recover_provider_writes


class StoreDataflowTests(unittest.TestCase):
    def analyze(self, raw, *, mode="THUMB", target=32, memory=None, initial=None):
        memory = memory or {}
        def read(address, count):
            if 0x1000 <= address and address + count <= 0x1000 + len(raw):
                return raw[address - 0x1000:address - 0x1000 + count]
            value = memory.get(address)
            return value[:count] if value is not None else None
        return analyze_function(read, 0x1000, [(0x1000, 0x1000 + len(raw))], mode=mode, target=target, initial_registers=initial)

    def test_thumb_register_copy_store(self):
        # movs r2,#32; mov r3,r2; str r0,[r3]; bx lr
        result = self.analyze(bytes.fromhex("2022134618607047"))
        self.assertTrue(result["stores"][0]["target_match"])
        self.assertEqual(result["stores"][0]["classification"], "STATICALLY_PROVEN_WRITE")
        self.assertFalse(result["runtime_verified"])

    def test_arm_movw_movt(self):
        raw = struct.pack("<IIII", 0xE3083930, 0xE340310A, 0xE5830000, 0xE12FFF1E)
        result = self.analyze(raw, mode="ARM", target=0x10A8930)
        self.assertEqual(result["stores"][0]["effective_address"]["values"], [0x10A8930])

    def test_literal_and_alias(self):
        # ARM ldr r3,[pc,#4]; ldr r3,[r3]; str r0,[r3]; bx lr
        raw = struct.pack("<IIII", 0xE59F3004, 0xE5933000, 0xE5830000, 0xE12FFF1E)
        # literal intentionally separate from executable bytes
        raw = struct.pack("<IIII", 0xE59F3008, 0xE5933000, 0xE5830000, 0xE12FFF1E) + struct.pack("<I", 0x2000)
        result = self.analyze(raw, mode="ARM", memory={0x2000: struct.pack("<I", 32)})
        self.assertTrue(result["stores"][0]["target_match"])
        self.assertEqual(result["instruction_count"], 4)

    def test_thumb_pc_alignment(self):
        # ldr r3,[pc,#4]; str r0,[r3]; bx lr; nop; literal
        raw = bytes.fromhex("014b1860704700bf") + struct.pack("<I", 32)
        result = self.analyze(raw)
        self.assertTrue(result["stores"][0]["target_match"])
        self.assertEqual(result["instruction_count"], 3)

    def test_cfg_join_multiple_values(self):
        # cmp r0,#0; beq other; movs r3,#32; b store; other: movs r3,#36
        raw = bytes.fromhex("002801d0202300e0242318607047")
        result = self.analyze(raw)
        self.assertEqual(result["stores"][0]["effective_address"]["values"], [32, 36])
        self.assertEqual(result["stores"][0]["classification"], "POSSIBLE_WRITE")

    def test_call_clobber(self):
        raw = struct.pack("<IIII", 0xE3A03020, 0xEB000000, 0xE5830000, 0xE12FFF1E)
        result = self.analyze(raw, mode="ARM")
        self.assertEqual(result["stores"][0]["effective_address"]["kind"], "UNKNOWN")

    def test_unknown_memory(self):
        raw = struct.pack("<IIII", 0xE3A03020, 0xE5933000, 0xE5830000, 0xE12FFF1E)
        result = self.analyze(raw, mode="ARM")
        self.assertEqual(result["stores"][0]["classification"], "UNKNOWN_DESTINATION")

    def test_wrong_address(self):
        result = self.analyze(bytes.fromhex("242318607047"))
        self.assertFalse(result["stores"][0]["target_match"])

    def test_conditional_store(self):
        raw = struct.pack("<III", 0xE3A03020, 0x05830000, 0xE12FFF1E)
        self.assertTrue(self.analyze(raw, mode="ARM")["stores"][0]["conditional"])

    def test_it_fail_closed(self):
        result = self.analyze(bytes.fromhex("08bf202318607047"))
        self.assertFalse(result["stores"])
        self.assertEqual(result["unresolved"][0]["reason"], "IT_BLOCK_UNSUPPORTED")

    def test_function_boundary(self):
        with self.assertRaises(ValueError):
            analyze_function(lambda a, n: b"", 0x2000, [(0x1000, 0x1004)])
        with self.assertRaises(ValueError):
            self.analyze(b"", mode="UNKNOWN")

    def test_unknown_join_dominates(self):
        self.assertIsNone(Value.constant(32).join(Value()).values)

    def test_got_relative_address(self):
        # add r3,r4,r2; ldr r3,[r3]; str r0,[r3]; bx lr
        raw = struct.pack("<IIII", 0xE0843002, 0xE5933000, 0xE5830000, 0xE12FFF1E)
        result = self.analyze(raw, mode="ARM", initial={"r4": 0x2000, "r2": 8}, memory={0x2008: struct.pack("<I", 32)})
        self.assertTrue(result["stores"][0]["target_match"])

    def test_pre_and_post_index(self):
        raw = struct.pack("<IIII", 0xE3A0301C, 0xE5A30004, 0xE4830004, 0xE12FFF1E)
        result = self.analyze(raw, mode="ARM")
        self.assertEqual([s['effective_address']['values'] for s in result['stores']], [[32], [32]])

    def test_alias_unknown_path(self):
        raw = bytes.fromhex("002801d0202300e0134618607047")
        result = self.analyze(raw)
        self.assertEqual(result["stores"][0]["classification"], "UNKNOWN_DESTINATION")

    def test_hash_mismatch_rejected_before_parse(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.bin"
            path.write_bytes(b"synthetic invalid ELF")
            with self.assertRaisesRegex(ValueError, "SHA256"):
                recover_provider_writes(path, "0" * 64)


if __name__ == "__main__":
    unittest.main()
