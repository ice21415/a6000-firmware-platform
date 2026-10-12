"""Self-authored snapshots exercise inferred layouts; no Sony instructions."""
import struct
import unittest

from fwplatform.paramlist_snapshot import lookup_snapshot


class SnapshotTests(unittest.TestCase):
    def memory(self):
        data = bytearray(256)
        for address, values in ((0x1000, (0x1010, 0x1020)),
                                (0x1010, (0x1030, 0x103c, 0x1040)),
                                (0x1030, (0x1050, 0x1070, 0x1090)),
                                (0x1050, (0x2000, 2, 17, 111)),
                                (0x1070, (0x2000, 1, 17, 222)),
                                (0x1090, (0x2000, 1, 17, 333))):
            struct.pack_into('<' + 'I' * len(values), data, address - 0x1000, *values)
        return data

    def test_first_match_uses_both_fields_without_modifying_snapshot(self):
        memory = self.memory()
        before = bytes(memory)
        result = lookup_snapshot(memory, base=0x1000, list_address=0x1000, key=17)
        self.assertEqual((result.address, result.payload_word), (0x1070, 222))
        self.assertEqual(bytes(memory), before)
        self.assertEqual(lookup_snapshot(memory, base=0x1000, list_address=0x1000,
                                         key=17, discriminator=2).payload_word, 111)

    def test_missing_and_empty_return_none(self):
        memory = self.memory()
        self.assertIsNone(lookup_snapshot(memory, base=0x1000, list_address=0x1000, key=18))
        struct.pack_into('<I', memory, 0x14, 0x1030)
        self.assertIsNone(lookup_snapshot(memory, base=0x1000, list_address=0x1000, key=17))

    def test_corrupt_bounds_and_null_element_fail_closed(self):
        for location, value in ((0x14, 0x1031), (0x14, 0x1020), (0x30, 0)):
            memory = self.memory()
            struct.pack_into('<I', memory, location, value)
            with self.assertRaises(ValueError):
                lookup_snapshot(memory, base=0x1000, list_address=0x1000, key=17)

    def test_budget_and_unsigned_arguments(self):
        for args in ({'max_entries': 2}, {'key': -1}, {'discriminator': 1 << 32}):
            options = dict(base=0x1000, list_address=0x1000, key=17)
            options.update(args)
            with self.assertRaises(ValueError):
                lookup_snapshot(self.memory(), **options)
