"""Synthetic regression tests for read-only ELF IMDB consumer scanner."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "scan_a6000_imdb_consumers.py"
spec = importlib.util.spec_from_file_location("imdb_consumer_scan", TOOL)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def fake_elf(symbol="IMDB_find_entry", shndx=0, needed=True):
    blob = bytearray(1024)
    blob[:6] = b"\x7fELF\x01\x01"
    struct.pack_into("<I", blob, 32, 0x100)
    struct.pack_into("<HH", blob, 46, 40, 4)
    strings = b"\0" + symbol.encode() + b"\0libIMDB.so\0"
    blob[0x200:0x200+len(strings)] = strings
    struct.pack_into("<10I", blob, 0x100+40, 0, 3, 0, 0, 0x200, len(strings), 0, 0, 1, 0)
    struct.pack_into("<10I", blob, 0x100+80, 0, 11, 0, 0, 0x300, 32, 1, 0, 4, 16)
    struct.pack_into("<IIIBBH", blob, 0x310, 1, 0, 0, 18, 0, shndx)
    struct.pack_into("<10I", blob, 0x100+120, 0, 6, 0, 0, 0x350, 16, 1, 0, 4, 8)
    struct.pack_into("<II", blob, 0x350, 1, 1+len(symbol)+1 if needed else 999)
    return bytes(blob)


class ImdbConsumerScannerTests(unittest.TestCase):
    def test_import(self):
        self.assertEqual(mod.classify(fake_elf())["imports"], ["IMDB_find_entry"])

    def test_export(self):
        self.assertEqual(mod.classify(fake_elf(shndx=10))["exports"], ["IMDB_find_entry"])

    def test_needed_dependency(self):
        self.assertEqual(mod.classify(fake_elf())["needed"], ["libIMDB.so"])

    def test_unsupported_elf(self):
        self.assertEqual(mod.classify(b"\x7fELF\x01\x01" + bytes(100))["imports"], [])

    def test_scan_ignores_non_elf(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "one.so").write_bytes(fake_elf(symbol="IMDB_get_entries"))
            (root / "decoy.txt").write_bytes(b"text IMDB_find_entry\0")
            checked, _skipped, hits = mod.scan(root)
            self.assertEqual(checked, 1)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0][1]["imports"], ["IMDB_get_entries"])


if __name__ == "__main__":
    unittest.main()
