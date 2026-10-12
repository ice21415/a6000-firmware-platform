import unittest

from fwplatform.elf_plt import arm_plt_slot


class ARMPLTTests(unittest.TestCase):
    def test_arm_slot_and_thumb_interworking_have_correct_pc(self):
        # Self-authored ARM: add ip,pc,#0x100; add ip,ip,#0x20; ldr pc,[ip,#4].
        arm = bytes.fromhex("01cc8fe220c08ce204f09ce5")
        self.assertEqual(arm_plt_slot(arm, 0x1000, thumb_stub=False), 0x112c)
        self.assertEqual(arm_plt_slot(bytes.fromhex("7847c046") + arm, 0x1000, thumb_stub=True), 0x1130)

    def test_truncation_and_wrong_mode_are_not_bindings(self):
        self.assertIsNone(arm_plt_slot(b"\x00" * 16, 0x1000, thumb_stub=True))
        self.assertIsNone(arm_plt_slot(b"\x00" * 4, 0x1000, thumb_stub=False))

    def test_rotated_immediate_is_not_rotation_number(self):
        arm = bytes.fromhex("01cc8fe24cca8ce204f09ce5")
        self.assertEqual(arm_plt_slot(arm, 0x1000, thumb_stub=False), 0x4d10c)
