#!/usr/bin/env python3
"""Read-only ELF32 ARM scan for candidate UIPC queue-ID announcement participants.

Aligned 32-bit literals + dynsym imports are leads only, never callsite proof.
This tool does not execute ELF files or communicate with hardware.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import struct

WORDS = {
    0x0094001A: 'announce_01a',
    0x00940007: 'state_007',
    0x00940001: 'state_001',
    0x0094016A: 'fixed_dest',
    0x00940036: 'stage_036',
    0x00940037: 'stage_037',
}
IMPORTS = {
    'osal_snd_msg', 'osal_snd_sync_msg', 'osal_dynamic_id',
    'osal_rcv_msg_tmo', 'osal_reg_sync_msg_queue_cb',
}
MAX_FILE = 256 * 1024 * 1024


def cstring(data: bytes, base: int, length: int, index: int) -> str:
    if index < 0 or index >= length:
        return ''
    end = data.find(b'\0', base + index, base + length)
    return data[base + index:end].decode('utf8', 'replace') if end >= 0 else ''


def check_elf(data: bytes):
    if len(data) < 52 or data[:6] != b'\x7fELF\x01\x01':
        return None
    shoff = struct.unpack_from('<I', data, 32)[0]
    entsz, count, nameidx = struct.unpack_from('<HHH', data, 46)
    if not 40 <= entsz <= 1024 or count == 0 or count > 8192 or nameidx >= count:
        return None
    if shoff > len(data) or count * entsz > len(data) - shoff:
        return None
    sections = [struct.unpack_from('<10I', data, shoff + i*entsz) for i in range(count)]
    if any(s[4] > len(data) or (s[1] != 8 and s[5] > len(data) - s[4]) for s in sections):
        return None
    name_strtab = sections[nameidx]
    candidates, imports = [], set()
    for nameid, typ, flags, vma, off, size, link, _, _, entsize in sections:
        name = cstring(data, name_strtab[4], name_strtab[5], nameid)
        if typ == 1 and flags & 2 and size >= 4:
            for val, desc in WORDS.items():
                pat = struct.pack('<I', val)
                pos = off
                while True:
                    pos = data.find(pat, pos, off + size)
                    if pos < 0:
                        break
                    addr = vma + pos - off
                    if addr % 4 == 0:
                        candidates.append((desc, name, addr))
                    pos += 1
        if typ == 11 and link < len(sections) and entsize >= 16:
            strings = sections[link]
            if strings[1] != 3:
                continue
            for i in range(0, size-15, entsize):
                st_name, _, _, _, _, idx = struct.unpack_from('<IIIBBH', data, off+i)
                if idx == 0:
                    symbol = cstring(data, strings[4], strings[5], st_name)
                    if symbol in IMPORTS:
                        imports.add(symbol)
    return {'literals': candidates, 'imports': sorted(imports)}


def scan(root: Path):
    total, skipped, matches = 0, 0, []
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path.is_symlink():
            continue
        try:
            if path.stat().st_size > MAX_FILE:
                skipped += 1
                continue
            with path.open('rb') as f:
                if f.read(6) != b'\x7fELF\x01\x01':
                    continue
                f.seek(0)
                binary = f.read()
            total += 1
            result = check_elf(binary)
            if result and result['literals']:
                labels = {x[0] for x in result['literals']}
                imports = set(result['imports'])
                if 'announce_01a' in labels and imports & {'osal_snd_msg', 'osal_snd_sync_msg', 'osal_rcv_msg_tmo', 'osal_reg_sync_msg_queue_cb'}:
                    rank = 'HIGH'
                elif 'announce_01a' in labels or ('fixed_dest' in labels and imports & {'osal_snd_msg', 'osal_reg_sync_msg_queue_cb'}):
                    rank = 'MEDIUM'
                else:
                    rank = 'LITERAL_ONLY'
                matches.append((rank, path.relative_to(root), result))
        except (OSError, PermissionError):
            continue
    return total, skipped, matches


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path, help='Offline unpacked firmware root')
    args = parser.parse_args()
    if not args.root.is_dir():
        parser.exit(2, 'ERROR: firmware root directory not found\n')
    count, skipped, matches = scan(args.root)
    print(f'ELF read: {count} | >256MiB skipped: {skipped} | literal-bearing ELF: {len(matches)}')
    for rank, path, result in sorted(matches, key=lambda x: {'HIGH':0,'MEDIUM':1,'LITERAL_ONLY':2}[x[0]]):
        print(f'  {rank} | {path} | imports={",".join(result["imports"]) or "none"}')
        for label, section, addr in result['literals'][:20]:
            print(f'    {label} {section}@0x{addr:08x}')
        if len(result['literals']) > 20:
            print(f'    ... {len(result["literals"])-20} more hits')
    print('NOTE: only literal/import candidates, not instruction xrefs or delivery proof.')
    print('NOTE: ET_REL kernel modules typically use .symtab and will be underrated by dynsym checks.')


if __name__ == '__main__':
    main()
