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
        if address == 0:
            raise ValueError("Null element; firmware lookup has no null guard")
        tag, candidate_key = word(address + 4), word(address + 8)
        if tag == discriminator and candidate_key == key:
            return ParameterWords(address, word(address), tag, candidate_key, word(address + 12))
    return None


@dataclass(frozen=True)
class PayloadType:
    name: str
    discriminator: int
    vtable_address_point: int
    width: int
    signed: bool = False


# Primary constructor + RTTI/vtable witnesses; these are ELF VMAs.
KNOWN_PAYLOAD_TYPES = (
    PayloadType("PrmNumber", 1, 0xfe8928, 4, True),
    PayloadType("PrmBool", 5, 0xfe6e08, 1),
)


def decode_payload(parameter: ParameterWords, *, load_bias: int = 0,
                   types: tuple[PayloadType, ...] = KNOWN_PAYLOAD_TYPES) -> dict[str, object]:
    """Decode only an exact unique vptr+discriminator pair in an offline record.

    Unknown/padding/noncanonical bool values remain unknown; neither a tag nor
    an ELF VMA alone proves the dynamic type of an arbitrary runtime object.
    """
    if not 0 <= load_bias <= 0xffffffff:
        raise ValueError("Invalid ARM32 load bias")
    matches = [t for t in types if t.discriminator == parameter.discriminator_word
               and t.vtable_address_point + load_bias <= 0xffffffff
               and t.vtable_address_point + load_bias == parameter.vptr]
    if len(matches) != 1:
        return {"type": "UNKNOWN", "value": None, "raw_word": parameter.payload_word,
                "reason": "No unique vptr and discriminator match"}
    matched = matches[0]
    if matched.width not in (1, 4):
        raise ValueError("Unsupported field width")
    value = parameter.payload_word & ((1 << (8 * matched.width)) - 1)
    if matched.signed and value & (1 << (8 * matched.width - 1)):
        value -= 1 << (8 * matched.width)
    if matched.name == "PrmBool" and value not in (0, 1):
        return {"type": "PrmBool", "value": None, "raw_byte": value,
                "reason": "Noncanonical bool representation"}
    return {"type": matched.name, "value": bool(value) if matched.name == "PrmBool" else value,
            "width": matched.width, "verification": "OFFLINE_SNAPSHOT_DECODED",
            "runtime_verified": False}
