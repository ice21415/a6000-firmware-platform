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

    def test_pop_unknown_return_origin_forwarded_to_append_argument(self):
        # Self-authored MOV r5,32; BL; MOV r1,r0; MOV r0,r5; BL; BX LR.
        result = self.analyze(bytes.fromhex("202500f000f80146284600f000f87047"))
        args = result["calls"][1]["argument_registers"]
        self.assertEqual(args["r0"]["values"], [32])
        self.assertEqual(args["r1"]["kind"], "UNKNOWN")
        self.assertIn(0x1002, args["r1"]["instruction_origins"])
        self.assertIn(0x1006, args["r1"]["instruction_origins"])

    def test_pointer_overwrite_does_not_retain_return_origin(self):
        result = self.analyze(bytes.fromhex("202500f000f801462021284600f000f87047"))
        argument = result["calls"][1]["argument_registers"]["r1"]
        self.assertEqual(argument["values"], [32])
        self.assertNotIn(0x1002, argument["instruction_origins"])

    def test_unknown_memory(self):
        raw = struct.pack("<IIII", 0xE3A03020, 0xE5933000, 0xE5830000, 0xE12FFF1E)
        result = self.analyze(raw, mode="ARM")
        self.assertEqual(result["stores"][0]["classification"], "UNKNOWN_DESTINATION")

    def test_wrong_address(self):
        result = self.analyze(bytes.fromhex("242318607047"))
        self.assertFalse(result["stores"][0]["target_match"])

    def test_conditional_store(self):
        raw = struct.pack("<III", 0xE3A03020, 0x05830000, 0xE12FFF1E)
        store = self.analyze(raw, mode="ARM")["stores"][0]
        self.assertTrue(store["conditional"])
        self.assertEqual(store["classification"], "CONDITIONAL_WRITE")

    def test_conditional_movt_keeps_both_paths(self):
        # mov r3,#32; movtne r3,#1; str r0,[r3]; bx lr.
        # MOVTNE must update the high half on the true path, not replace r3.
        raw = struct.pack("<IIII", 0xE3A03020, 0x13403001, 0xE5830000, 0xE12FFF1E)
        result = self.analyze(raw, mode="ARM")
        self.assertEqual(result["stores"][0]["effective_address"]["values"], [32, 0x10020])
        self.assertEqual(result["stores"][0]["classification"], "POSSIBLE_WRITE")

    def test_load_writeback_changes_following_store_address(self):
        # mov r3,#28; ldr r2,[r3,#4]!; str r0,[r3]; bx lr.
        raw = struct.pack("<IIII", 0xE3A0301C, 0xE5B32004, 0xE5830000, 0xE12FFF1E)
        self.assertEqual(self.analyze(raw, mode="ARM")["stores"][0]["effective_address"]["values"], [32])

    def test_subtract_post_index_load(self):
        raw = struct.pack("<IIII", 0xE3A03024, 0xE4132004, 0xE5830000, 0xE12FFF1E)
        self.assertEqual(self.analyze(raw, mode="ARM")["stores"][0]["effective_address"]["values"], [32])

    def test_signed_byte_load_is_sign_extended(self):
        # ldrsb r2,[r3]; str r2,[r4]; bx lr.
        raw = struct.pack("<III", 0xE1D320D0, 0xE5842000, 0xE12FFF1E)
        result = self.analyze(raw, mode="ARM", initial={"r3": 0x2000, "r4": 32}, memory={0x2000: b"\xff"})
        self.assertEqual(result["stores"][0]["written_value"]["values"], [0xFFFFFFFF])

    def test_trap_does_not_invent_fallthrough(self):
        result = self.analyze(bytes.fromhex("00be18607047"), initial={"r3": 32})
        self.assertFalse(result["stores"])
        self.assertEqual(result["unresolved"][0]["reason"], "TRAP_CONTROL_FLOW_UNRESOLVED")

    def test_indirect_call_clobbers_alias_but_preserves_callee_saved(self):
        # blx r2; str r0,[r3]; str r0,[r4]; bx lr.
        result = self.analyze(bytes.fromhex("9047186020607047"), initial={"r3": 32, "r4": 36})
        self.assertEqual(result["stores"][0]["effective_address"]["kind"], "UNKNOWN")
        self.assertEqual(result["stores"][1]["effective_address"]["values"], [36])
        self.assertEqual(result["calls"][0]["target_mode"], "UNKNOWN")

    def test_numbered_register_aliases_and_conflicting_inputs(self):
        # str r0,[ip]; bx lr.
        raw = struct.pack("<II", 0xE58C0000, 0xE12FFF1E)
        result = self.analyze(raw, mode="ARM", initial={"r12": 32})
        self.assertEqual(result["stores"][0]["effective_address"]["values"], [32])
        result = self.analyze(raw, mode="ARM", initial={"r12": 32, "ip": 36})
        self.assertEqual(result["stores"][0]["classification"], "POSSIBLE_WRITE")

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
