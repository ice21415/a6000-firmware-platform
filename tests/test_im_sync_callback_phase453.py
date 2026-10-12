"""Offline Phase 4.53 regression tests; no proprietary ELF required in CI."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import verify_im_sync_callback as mod

class CallbackEvidenceTests(unittest.TestCase):
    def test_literal_pool(self):
        self.assertEqual(mod.LITERALS[0x9660], 0xC009)
        self.assertEqual(mod.LITERALS[0x965C], 0x94016A)

    def test_derived_comparisons_exclude_announcement(self):
        values = [0x920143]
        for delta in (0x17,-0xf,2,2,3,0xa):
            values.append(values[-1]+delta)
        self.assertEqual(tuple(values),mod.DERIVED_CODES)
        self.assertNotIn(mod.TARGET,mod.DERIVED_CODES+mod.DIRECT_CODES)

    def test_fail_closed_on_unavailable_binary(self):
        with self.assertRaises(FileNotFoundError):
            mod.verify(Path('__missing_original_im_elf__.elf'))

    def test_no_automatic_runtime_promotion(self):
        self.assertEqual(mod.TARGET,0x94001A)
        self.assertEqual(mod.REQUIRED_INSTRUCTIONS[0x963A],('b.w','#0x8fe0'))

if __name__=='__main__':
    unittest.main()
