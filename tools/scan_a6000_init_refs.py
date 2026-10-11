#!/usr/bin/env python3
"""Read-only search for ELF references to Application_System_Init in unpacked A6000 firmware.

Prints only relative paths and symbol classifications; never executes ELF/firmware,
changes files, or outputs unrelated file bytes. A literal is NOT proof of invocation.
"""
from __future__ import annotations

import argparse
import mmap
from pathlib import Path
import struct

NEEDLE = b'Application_System_Init'
MAX_SIZE = 256 * 1024 * 1024


def elf32_dynsym_class(data: bytes | mmap.mmap) -> str:
    """Classify exact ELF32 LE dynamic symbol (if found) as import/export/literal."""
    if len(data) < 52 or data[:6] != b'\x7fELF\x01\x01':
        return 'ELF_LITERAL (not ELF32 LE; no dynamic-symbol classification)'
    try:
        shoff = struct.unpack_from('<I', data, 32)[0]
        shentsize, shnum = struct.unpack_from('<HH', data, 46)
        if shentsize < 40 or shnum > 4096 or shoff > len(data) or shnum * shentsize > len(data) - shoff:
            return 'ELF_LITERAL (section headers unavailable)'
        sections = [struct.unpack_from('<10I', data, shoff + i * shentsize) for i in range(shnum)]
        types = []
        for sec in sections:
            if sec[1] != 11:  # SHT_DYNSYM
                continue
            _, _, _, _, off, size, link, _, _, entsize = sec
            if link >= shnum or entsize < 16 or off > len(data) or size > len(data) - off:
                continue
            string_sec = sections[link]
            soff, ssize = string_sec[4], string_sec[5]
            if soff > len(data) or ssize > len(data) - soff:
                continue
            if size // entsize > 1_000_000:
                continue
            for rel in range(0, size, entsize):
                if rel + 16 > size:
                    break
                name_off, _, _, _, _, shndx = struct.unpack_from('<IIIBBH', data, off + rel)
                if name_off >= ssize or name_off + len(NEEDLE) >= ssize:
                    continue
                pos = soff + name_off
                if data[pos:pos+len(NEEDLE)] == NEEDLE and data[pos+len(NEEDLE)] == 0:
                    types.append('UNDEFINED_IMPORT' if shndx == 0 else 'DEFINED_EXPORT')
        if 'UNDEFINED_IMPORT' in types:
            return 'DYNAMIC_IMPORT (external symbol dependency; runtime call not proven)'
        if 'DEFINED_EXPORT' in types:
            return 'DYNAMIC_EXPORT (defines Application_System_Init)'
        return 'ELF_LITERAL_ONLY (not an exact dynamic import/export)'
    except (IndexError, ValueError, OverflowError, struct.error):
        return 'ELF_LITERAL (malformed/unsupported symbol table)'


def scan(root: Path):
    if not root.is_dir():
        raise ValueError('root must be an existing unpacked firmware directory')
    scanned = 0
    matches = []
    skipped_large = 0
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            size = path.stat().st_size
            if size < 52:
                continue
            if size > MAX_SIZE:
                skipped_large += 1
                continue
            with path.open('rb') as f:
                if f.read(4) != b'\x7fELF':
                    continue
                scanned += 1
                f.seek(0)
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                    if mapped.find(NEEDLE) < 0:
                        continue
                    kind = elf32_dynsym_class(mapped)
                    matches.append((str(path.relative_to(root)), kind))
        except (OSError, ValueError):
            continue
    return scanned, skipped_large, matches


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path, help='unpacked firmware root directory')
    args = parser.parse_args()
    try:
        scanned, large, matches = scan(args.root)
        print('ELF scanned:', scanned, '| skipped >256 MiB:', large)
        for path, kind in matches:
            print(f'  {kind}: {path}')
        print('Matches:', len(matches))
        print('Note: dynamic import or literal occurrence does NOT establish an actual call, argument, or boot-time branch.')
    except (OSError, ValueError) as exc:
        parser.exit(2, f'[ERROR] {exc}\n')


if __name__ == '__main__':
    main()
