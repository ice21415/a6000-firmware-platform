"""Synthetic-only tests for the offline A6000 init-reference scanner."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

p = Path(__file__).resolve().parents[1] / "tools" / "scan_a6000_init_refs.py"
spec = importlib.util.spec_from_file_location("scan_a6000_init_refs", p)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def make_elf(shndx):
    out = bytearray(1024)
    out[:6] = b'\x7fELF\x01\x01'
    struct.pack_into('<I', out, 32, 0x100)
    struct.pack_into('<HH', out, 46, 40, 3)
    strings = b'\0Application_System_Init\0'
    out[0x200:0x200+len(strings)] = strings
    struct.pack_into('<10I', out, 0x100+40, 0, 3, 0, 0, 0x200, len(strings), 0, 0, 1, 0)
    struct.pack_into('<10I', out, 0x100+80, 0, 11, 0, 0, 0x300, 32, 1, 0, 4, 16)
    struct.pack_into('<IIIBBH', out, 0x300+16, 1, 0, 0, 18, 0, shndx)
    return bytes(out)


class ScanApplicationSystemInitTests(unittest.TestCase):
    def test_undefined_import(self):
        self.assertIn('DYNAMIC_IMPORT', mod.elf32_dynsym_class(make_elf(0)))

    def test_defined_export(self):
        self.assertIn('DYNAMIC_EXPORT', mod.elf32_dynsym_class(make_elf(10)))

    def test_literal_not_import(self):
        elf = bytearray(make_elf(10))
        struct.pack_into('<I', elf, 0x300+16, 0)
        self.assertIn('LITERAL_ONLY', mod.elf32_dynsym_class(elf))

    def test_only_elf_scanned(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root/'real.so').write_bytes(make_elf(0))
            (root/'decoy.txt').write_bytes(b'not ELF '+mod.NEEDLE+b'\0'*100)
            (root/'none').write_bytes(make_elf(10).replace(mod.NEEDLE, b'SomethingElseInit___'))
            scanned, large, matches = mod.scan(root)
            self.assertEqual(scanned, 2)
            self.assertEqual(large, 0)
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0][0], 'real.so')
            self.assertIn('IMPORT', matches[0][1])


if __name__ == '__main__':
    unittest.main()
