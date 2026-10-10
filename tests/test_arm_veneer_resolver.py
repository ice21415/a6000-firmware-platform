import unittest
from unittest.mock import patch

from fwplatform.arm_veneer_resolver import _decode


class _Row:
    def __init__(self, address, mnemonic, op_str):
        self.address = address
        self.mnemonic = mnemonic
        self.op_str = op_str


class _Decoder:
    def __init__(self, rows):
        self.rows = rows

    def disasm(self, _code, _entry):
        return iter(self.rows)


class ArmVeneerResolverTests(unittest.TestCase):
    def test_arm_pc_pipeline_and_got_address(self):
        rows = [
            _Row(0x1000, "add", "ip, pc, #0xf00000"),
            _Row(0x1004, "add", "ip, ip, #0x4d000"),
            _Row(0x1008, "ldr", "pc, [ip, #0xb14]!"),
        ]
        with patch("fwplatform.arm_veneer_resolver.Cs", return_value=_Decoder(rows)):
            instructions, got = _decode(b"\0" * 12, 0x1000)
        self.assertEqual(got, 0xf4eb1c)
        self.assertEqual(instructions[0]["instruction_vma"], "0x1000")

    def test_non_veneer_fails_closed(self):
        rows = [_Row(0x1000, "bx", "lr")]
        with patch("fwplatform.arm_veneer_resolver.Cs", return_value=_Decoder(rows)):
            instructions, error = _decode(b"\0" * 12, 0x1000)
        self.assertIsNone(instructions)
        self.assertIn("incomplete", error)

    def test_thumb_like_sequence_is_rejected(self):
        rows = [
            _Row(0x1000, "add", "r0, pc, #1"),
            _Row(0x1004, "add", "r0, r0, #2"),
            _Row(0x1008, "ldr", "r0, [r0]"),
        ]
        with patch("fwplatform.arm_veneer_resolver.Cs", return_value=_Decoder(rows)):
            instructions, error = _decode(b"\0" * 12, 0x1000)
        self.assertIsNone(instructions)
        self.assertIn("unsupported", error)


if __name__ == "__main__":
    unittest.main()
