"""Read-only offline ParamList snapshot model; never invokes firmware APIs.

Layout witnesses are documented in the SDK contract. Parsing a byte snapshot
does not validate object lifetime, runtime ABI or the payload's semantic type.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass


@dataclass(frozen=True)
class ParameterWords:
    address: int
    vptr: int
    discriminator_word: int
    key_word: int
    payload_word: int


def lookup_snapshot(memory: bytes, *, base: int, list_address: int,
                    key: int, discriminator: int = 1,
                    max_entries: int = 4096) -> ParameterWords | None:
    """Return first matching object; malformed snapshots fail, never emulate reads.

    r0=list_address, r1=key, r2=discriminator. r3 is not a semantic argument.
    The caller supplies a self-contained contiguous snapshot, not live memory.
    """
    if not 0 <= key <= 0xffffffff or not 0 <= discriminator <= 0xffffffff:
        raise ValueError("Arguments must be unsigned 32-bit words")
    if not 0 < max_entries <= 1_000_000:
        raise ValueError("Invalid resource budget")

    def word(address: int) -> int:
        offset = address - base
        if address & 3 or offset < 0 or offset + 4 > len(memory):
            raise ValueError("Unaligned or missing snapshot word")
        return struct.unpack_from("<I", memory, offset)[0]

    container = word(list_address)
    begin, end = word(container), word(container + 4)
    if end < begin or (end - begin) & 3 or (end - begin) // 4 > max_entries:
        raise ValueError("Invalid or oversized pointer range")
    for slot in range(begin, end, 4):
        address = word(slot)
        # Firmware dereferences null elements; do not silently skip corruption.
        tag, candidate_key = word(address + 4), word(address + 8)
        if tag == discriminator and candidate_key == key:
            return ParameterWords(address, word(address), tag, candidate_key, word(address + 12))
    return None
