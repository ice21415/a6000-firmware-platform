"""Offline, read-only verification of the A6000 3.21 IM synchronous callback.

Requires pyelftools and capstone. No firmware bytes are emitted or stored.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

PIN = 'f0f181426af4add55a8510c5441ff86c3121678fd1f7e0467152070e870d803a'
LITERALS = {0x9648: 0x9400E1, 0x9650: 0x940021, 0x9654: 0x940022,
            0x9658: 0x920143, 0x965C: 0x94016A, 0x9660: 0xC009}
DIRECT_CODES = (0x9400E1, 0x940021, 0x940022)
DERIVED_CODES = (0x920143, 0x92015A, 0x92014B, 0x92014D,
                 0x92014F, 0x920152, 0x92015C)
TARGET = 0x94001A
REQUIRED_INSTRUCTIONS = {
    0x95BA: ('ldr', 'r1, [r0]'),
    0x95BE: ('bne', '#0x95cc'),
    0x95D8: ('bl', '#0xb530'),
    0x95EA: ('bl', '#0xb740'),
    0x961A: ('bne', '#0x962e'),
    0x9628: ('bl', '#0x91a4'),
    0x962E: ('ldr', 'r0, [pc, #0x30]'),
    0x963A: ('b.w', '#0x8fe0'),
}


def verify(path: Path) -> dict:
    if not path.is_file():
        raise FileNotFoundError(path)
    from elftools.elf.elffile import ELFFile
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

    raw = path.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    if sha != PIN:
        raise ValueError('SHA256 mismatch: refusing to analyze a different ELF')
    with path.open('rb') as handle:
        elf = ELFFile(handle)
        sec = elf.get_section_by_name('.text')
        if sec is None:
            raise ValueError('Missing .text')
        start = sec['sh_addr']
        data = sec.data()
        def bytes_at(vma, size):
            offset = vma-start
            if offset < 0 or offset+size > len(data):
                raise ValueError(f'VMA outside .text: {vma:#x}')
            return data[offset:offset+size]
        for addr, expected in LITERALS.items():
            actual = struct.unpack('<I', bytes_at(addr, 4))[0]
            if actual != expected:
                raise ValueError(f'Literal mismatch at {addr:#x}')
        decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        instructions = {i.address:(i.mnemonic, i.op_str)
                        for i in decoder.disasm(bytes_at(0x95b0,0x96+0x20),0x95b0)
                        if i.address < 0x9646}
        for addr, expect in REQUIRED_INSTRUCTIONS.items():
            if instructions.get(addr) != expect:
                raise ValueError(f'Instruction mismatch at {addr:#x}: {instructions.get(addr)}')
        fmtaddr = LITERALS[0x9660]
        ro = next((s for s in elf.iter_sections()
                   if s['sh_addr'] <= fmtaddr < s['sh_addr']+s['sh_size']),None)
        if ro is None:
            raise ValueError('Format string VMA not mapped')
        fmt = ro.data()[fmtaddr-ro['sh_addr']:].split(b'\0',1)[0]
        if fmt != b'imelf_sync_api_cb: err: cmd:0x%x\n':
            raise ValueError('Unknown default format string')
        imports = [sym.name for s in elf.iter_sections()
                   if s['sh_type'] in ('SHT_SYMTAB','SHT_DYNSYM')
                   for sym in s.iter_symbols()
                   if sym['st_value'] == 0x8fe4]
        if 'printf' not in imports:
            raise ValueError('printf PLT binding not independently confirmed')
    return {
        'phase':'4.53', 'source_sha256':sha,
        'callback_entry':'0x95b0', 'message_code_under_test':'0x94001a',
        'direct_compared_codes':[hex(i) for i in DIRECT_CODES],
        'derived_compared_codes':[hex(i) for i in DERIVED_CODES],
        'default_tailcall':'printf PLT 0x8fe0',
        'default_format':'imelf_sync_api_cb: err: cmd:0x%x\\n',
        'finding':'0x94001a does not match the compared codes; default diagnostic path is selected',
        'scope':'CONDITIONAL_PRIMARY_ELF_STATIC_ONLY',
        'runtime_delivery_verified':False, 'external_consumer_identified':False,
        'callable_apis_verified':0,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--elf',type=Path,required=True)
    args=p.parse_args()
    try:
        print(json.dumps(verify(args.elf),indent=2))
    except (ValueError, OSError, ImportError) as exc:
        p.exit(2, f'FAIL CLOSED: {exc}\n')

if __name__ == '__main__':
    main()
