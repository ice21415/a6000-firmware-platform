"""Evidence-gated probe for additional ParamBase-derived classes.

The probe reads a SHA-pinned private ELF and emits only structured metadata:
RTTI/vtable addresses, symbol identities, constructor discriminator stores,
and conservative object-size witnesses.  It never emits instruction bytes,
executes firmware, or turns the observations into live ABI wrappers.
"""
from __future__ import annotations

import hashlib
import re
import struct
from pathlib import Path
from typing import Any, Iterable

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA, MAX_ELF_BYTES


PARAM_FAMILY_TARGETS: tuple[dict[str, Any], ...] = (
    {
        "name": "PrmBool",
        "vtable_vma": 0xFE6E00,
        "constructor_vma": 0xE50E8,
        "constructor_end": 0xE5108,
        "destructor_symbol": "_ZN7PrmBoolD1Ev",
        "destructor_entry": 0xE4750,
        "deleting_destructor_entry": 0xE4840,
        "clone_entry": 0xE5110,
        "discriminator": 5,
        "allocation_size": 0x10,
        "payload_kind": "canonical_bool_byte_at_plus_0x0c",
        "payload_offsets": [0x0C],
        "method_symbols": ["_ZN7PrmBool7setBoolEb"],
    },
    {
        "name": "PrmNumber",
        "vtable_vma": 0xFE8920,
        "constructor_vma": 0xF0FB0,
        "constructor_end": 0xF0FD0,
        "destructor_entry": 0xF0F2C,
        "deleting_destructor_entry": 0xF0F5C,
        "clone_entry": 0xF1034,
        "discriminator": 1,
        "allocation_size": 0x10,
        "payload_kind": "signed_int_word_at_plus_0x0c",
        "payload_offsets": [0x0C],
        "method_symbols": ["_ZN9PrmNumber9setNumberEi"],
    },
    {
        "name": "PrmString",
        "vtable_vma": 0xFE9638,
        "constructor_vma": 0xFF9C8,
        "constructor_end": 0xFFA06,
        "destructor_entry": 0xFF954,
        "deleting_destructor_entry": 0xFF980,
        "clone_entry": 0xFFA18,
        "discriminator": 2,
        "allocation_size": 0x10,
        "payload_kind": "owned_string_pointer_at_plus_0x0c_release_helper_0xdf098",
        "payload_offsets": [0x0C],
        "method_symbols": [],
    },
    {
        "name": "PrmPoint",
        "vtable_vma": 0xFE9610,
        "constructor_vma": 0xFFA3C,
        "constructor_end": 0xFFA66,
        "destructor_entry": 0xFF904,
        "deleting_destructor_entry": 0xFF940,
        "clone_entry": 0xFFA70,
        "discriminator": 3,
        "allocation_size": 0x14,
        "payload_kind": "two_32bit_words_at_plus_0x0c_and_plus_0x10",
        "payload_offsets": [0x0C, 0x10],
        "method_symbols": [],
    },
    {
        "name": "PrmDimension",
        "vtable_vma": 0xFE6E48,
        "constructor_vma": 0xE5128,
        "constructor_end": 0xE5152,
        "destructor_symbol": "_ZN12PrmDimensionD1Ev",
        "destructor_entry": 0xE4774,
        "deleting_destructor_entry": 0xE4868,
        "clone_entry": 0xE515C,
        "discriminator": 4,
        "allocation_size": 0x14,
        "payload_kind": "two_32bit_words_at_plus_0x0c_and_plus_0x10",
        "payload_offsets": [0x0C, 0x10],
        "method_symbols": [],
    },
    {
        "name": "PrmStruct",
        "vtable_vma": 0xFE7400,
        "constructor_vma": 0xE7260,
        "constructor_end": 0xE7296,
        "destructor_entry": 0xE7150,
        "deleting_destructor_entry": 0xE717C,
        "clone_entry": 0xE72A0,
        "discriminator": 6,
        "allocation_size": 0x14,
        "payload_kind": "opaque_pointer_and_word_at_plus_0x0c_and_plus_0x10",
        "payload_offsets": [0x0C, 0x10],
        "method_symbols": [],
    },
    {
        "name": "PrmSet",
        "vtable_vma": 0x1019D18,
        "constructor_vma": 0x7EFB00,
        "constructor_end": 0x7EFB24,
        "destructor_entry": 0x7EFB2C,
        "deleting_destructor_entry": 0x7EFB58,
        "clone_entry": 0x7EFBB4,
        "discriminator": 7,
        "allocation_size": 0x24,
        "payload_kind": "opaque_embedded_24_byte_payload_at_plus_0x0c",
        "payload_offsets": [0x0C],
        "method_symbols": [
            "_ZN6PrmSet6getSetEv",
            "_ZN6PrmSet3GETEPK9ParamListm",
        ],
    },
    {
        "name": "PrmNumberList",
        "vtable_symbol": "_ZTV13PrmNumberList",
        "constructor_symbol": "_ZN13PrmNumberListC1Ev",
        "destructor_entry": 0xECE64,
        "deleting_destructor_entry": 0xECE98,
        "destructor_symbol": "_ZN13PrmNumberListD1Ev",
        "clone_entry": 0xED3A4,
        "initializer_entry": 0xECDA8,
        "discriminator": 10,
        "allocation_size": 0x18,
        "payload_kind": "embedded_vector_uint32_at_plus_0x0c",
        "payload_offsets": [0x0C, 0x10, 0x14],
        "method_symbols": [
            "_ZN13PrmNumberList7getListEv",
            "_ZN13PrmNumberList9getNumberEj",
            "_ZN13PrmNumberList9getLengthEv",
            "_ZN13PrmNumberList9addNumberEj",
            "_ZN13PrmNumberListC1ESt6vectorIjSaIjEE",
        ],
    },
    {
        "name": "PrmCntInfoList",
        "vtable_symbol": "_ZTV14PrmCntInfoList",
        "constructor_symbol": "_ZN14PrmCntInfoListC1Ev",
        "destructor_entry": 0x11D54C,
        "deleting_destructor_entry": 0x11D590,
        "destructor_symbol": "_ZN14PrmCntInfoListD1Ev",
        "clone_entry": 0x11DA18,
        "initializer_entry": 0x11D42C,
        "discriminator": 9,
        "allocation_size": 0x5C,
        "payload_kind": "two_embedded_dynamic_collections_at_plus_0x0c_and_plus_0x34",
        "payload_offsets": [0x0C, 0x34],
        "method_symbols": [
            "_ZN14PrmCntInfoList3GETEPK9ParamListm",
            "_ZN14PrmCntInfoList9getLengthEv",
            "_ZN14PrmCntInfoList7setItemEjj",
            "_ZN14PrmCntInfoList8setGroupEjj",
            "_ZN14PrmCntInfoList7getItemEj",
            "_ZN14PrmCntInfoList8getGroupEj",
            "_ZN14PrmCntInfoList6removeEj",
            "_ZN14PrmCntInfoList3addEjj",
            "_ZN14PrmCntInfoListC1Ejj",
        ],
    },
    {
        "name": "PrmObjMsg",
        "vtable_symbol": None,
        "vtable_vma": 0xFEC498,
        "constructor_symbol": "_ZN9PrmObjMsgC1EPN3MWF6ObjMsgE",
        "destructor_symbol": None,
        "destructor_entry": 0x12C700,
        "deleting_destructor_entry": 0x12C740,
        "clone_entry": 0x12C784,
        "initializer_entry": None,
        "discriminator": 8,
        "allocation_size": 0x10,
        "payload_kind": "pointer_to_MWF_ObjMsg_at_plus_0x0c",
        "payload_offsets": [0x0C],
        "method_symbols": ["_ZNK9PrmObjMsg18getParamTypeObjMsgEv"],
    },
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _section_for(elf: ELFFile, address: int, size: int = 1):
    for section in elf.iter_sections():
        start = int(section["sh_addr"])
        end = start + int(section["sh_size"])
        if start <= address and address + size <= end:
            return section
    return None


def _read_bytes(elf: ELFFile, address: int, size: int) -> bytes:
    section = _section_for(elf, address, size)
    if section is None:
        raise ValueError(f"ELF_VMA 0x{address:x} is not mapped for {size} bytes")
    data = section.data()
    start = address - int(section["sh_addr"])
    return data[start : start + size]


def _read_u32(elf: ELFFile, address: int) -> int:
    return struct.unpack("<I", _read_bytes(elf, address, 4))[0]


def _effective_u32(
    elf: ELFFile,
    relocations: dict[int, dict[str, Any]],
    address: int,
) -> int:
    """Read a file word, falling back to its relocation symbol value."""
    value = _read_u32(elf, address)
    if value:
        return value
    relocation = relocations.get(address)
    return int((relocation or {}).get("symbol_value", 0))


def _symbols(elf: ELFFile) -> dict[str, tuple[int, int]]:
    result: dict[str, tuple[int, int]] = {}
    for section_name in (".dynsym", ".symtab"):
        section = elf.get_section_by_name(section_name)
        if section is None:
            continue
        for symbol in section.iter_symbols():
            name = symbol.name
            value = int(symbol["st_value"])
            if name and value and name not in result:
                result[name] = (value, int(symbol["st_size"]))
    return result


def _relocations(elf: ELFFile) -> dict[int, dict[str, Any]]:
    result: dict[int, dict[str, Any]] = {}
    for section in elf.iter_sections():
        if not isinstance(section, RelocationSection):
            continue
        symbols = elf.get_section(section["sh_link"])
        for relocation in section.iter_relocations():
            symbol = symbols.get_symbol(relocation["r_info_sym"])
            candidate = {
                "type": int(relocation["r_info_type"]),
                "symbol": symbol.name or None,
                "symbol_value": int(symbol["st_value"]),
            }
            offset = int(relocation["r_offset"])
            existing = result.get(offset)
            # RELATIVE relocations are often co-located with a named absolute
            # relocation in partially linked ARM images.  Keep the row that
            # carries an explicit symbol/value instead of silently replacing
            # it with an anonymous zero-symbol record.
            if existing is None or (
                not existing.get("symbol") and candidate.get("symbol")
            ) or (
                not existing.get("symbol_value") and candidate.get("symbol_value")
            ):
                result[offset] = candidate
    return result


def _prel31(place: int, word: int) -> int:
    """Resolve an ARM EHABI PREL31 word without exposing raw bytes."""
    value = word & 0x7FFFFFFF
    if value & 0x40000000:
        value -= 0x80000000
    return (place + value) & 0xFFFFFFFF


def _exception_index_entry(elf: ELFFile, target: int) -> dict[str, Any]:
    """Return sanitized ARM EHABI metadata for one exact function VMA.

    The encoded unwind words are deliberately not returned.  A missing or
    ambiguous entry is an analysis error for the authenticated primary ELF;
    this prevents a nearby function's exception record from being silently
    attached to a family member.
    """
    section = elf.get_section_by_name(".ARM.exidx")
    if section is None:
        raise ValueError("primary ELF has no .ARM.exidx section")
    data = section.data()
    if not data or len(data) % 8:
        raise ValueError("truncated or malformed .ARM.exidx section")
    base = int(section["sh_addr"])
    matches: list[dict[str, Any]] = []
    for offset in range(0, len(data), 8):
        function_vma = _prel31(
            base + offset,
            int.from_bytes(data[offset:offset + 4], "little"),
        )
        if function_vma != (target & ~1):
            continue
        unwind_word = int.from_bytes(data[offset + 4:offset + 8], "little")
        if unwind_word & 0x80000000:
            unwind_kind = "COMPACT"
            extab_vma = None
        else:
            unwind_kind = "EXTAB"
            extab_vma = f"0x{_prel31(base + offset + 4, unwind_word):x}"
        matches.append({
            "section": ".ARM.exidx",
            "entry_vma": f"0x{function_vma:x}",
            "entry_offset": f"0x{base + offset:x}",
            "exidx_entry_vma": f"0x{base + offset:x}",
            "extab_vma": extab_vma,
            "unwind_kind": unwind_kind,
            "status": "PRIMARY_ELF_VERIFIED",
            "address_space": "ELF_VMA",
        })
    if len(matches) != 1:
        raise ValueError(
            f"expected one .ARM.exidx entry for 0x{target:x}, found {len(matches)}"
        )
    return matches[0]


def _discover_parambase_types(
    elf: ELFFile,
    symbols: dict[str, tuple[int, int]],
    relocations: dict[int, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Enumerate RTTI/vtable records whose direct base is ParamBase.

    This is deliberately independent of ``PARAM_FAMILY_TARGETS``.  The
    profile supplies constructor/method hypotheses, while this pass derives
    the class-name, base-relocation and vtable relationship from the ELF.
    """
    base_rtti = _vma_symbol(symbols, "_ZTI9ParamBase")
    if base_rtti is None:
        return []
    typeinfos: set[int] = set()
    for offset, relocation in relocations.items():
        if relocation.get("symbol") == "_ZTI9ParamBase":
            candidate = offset - 8
            if candidate >= 8 and _section_for(elf, candidate + 4, 4):
                typeinfos.add(candidate)

    records: list[dict[str, Any]] = []
    for typeinfo in sorted(typeinfos):
        name_address = _effective_u32(elf, relocations, typeinfo + 4)
        if not name_address:
            continue
        try:
            rtti_name = _read_bytes(elf, name_address, 96).split(b"\0", 1)[0].decode("ascii")
        except (UnicodeDecodeError, ValueError):
            continue
        if not rtti_name or rtti_name == "9ParamBase":
            continue
        try:
            if _read_u32(elf, typeinfo) != 8:
                continue
        except (ValueError, struct.error):
            continue
        vtables = [
            offset - 4
            for offset, relocation in relocations.items()
            if (int(relocation.get("symbol_value", 0)) & ~1) == (typeinfo & ~1)
            and offset >= 4
            and (offset - 4) % 4 == 0
            and _section_for(elf, offset, 4)
            and _section_for(elf, offset + 4, 4)
            and _section_for(elf, offset - 4, 4)
            and _read_u32(elf, offset - 4) == 0
        ]
        vtable = min(vtables) if vtables else None
        records.append({
            "name": rtti_name,
            "rtti": hex(typeinfo),
            "base_rtti": hex(base_rtti),
            "vtable": hex(vtable) if vtable is not None else None,
            "address_space": "ELF_VMA",
            "verification": "PRIMARY_ELF_VERIFIED",
            "evidence_scope": "direct_ParamBase_RTTI_relocation_and_vtable_typeinfo_relocation",
        })
    return records


def _vma_symbol(symbols: dict[str, tuple[int, int]], name: str | None) -> int | None:
    if not name or name not in symbols:
        return None
    return symbols[name][0] & ~1


def _target_symbol(symbols: dict[str, tuple[int, int]], target: int) -> str | None:
    target &= ~1
    matches = [name for name, (value, _size) in symbols.items() if value & ~1 == target]
    return sorted(matches)[0] if len(matches) == 1 else None


def _typeinfo_candidates(elf: ELFFile, name: str) -> list[int]:
    encoded = name.encode("ascii") + b"\0"
    strings: list[int] = []
    for section in elf.iter_sections():
        data = section.data()
        cursor = 0
        while True:
            found = data.find(encoded, cursor)
            if found < 0:
                break
            strings.append(int(section["sh_addr"]) + found)
            cursor = found + 1
    candidates: list[int] = []
    for section in elf.iter_sections():
        data = section.data()
        for name_address in strings:
            needle = struct.pack("<I", name_address)
            cursor = 0
            while True:
                found = data.find(needle, cursor)
                if found < 0:
                    break
                pointer = int(section["sh_addr"]) + found
                if pointer >= 4:
                    candidates.append(pointer - 4)
                cursor = found + 1
    return sorted(set(candidates))


def _find_vtable_for_typeinfo(elf: ELFFile, typeinfo: int) -> int | None:
    needle = struct.pack("<I", typeinfo)
    candidates: list[int] = []
    for section in elf.iter_sections():
        data = section.data()
        cursor = 0
        while True:
            found = data.find(needle, cursor)
            if found < 0:
                break
            pointer = int(section["sh_addr"]) + found
            if pointer >= 4:
                vtable = pointer - 4
                try:
                    if _read_u32(elf, vtable) == 0 and _section_for(elf, vtable + 8, 4):
                        candidates.append(vtable)
                except (ValueError, struct.error):
                    pass
            cursor = found + 1
    return min(candidates) if candidates else None


def _decode_constructor_observations(elf: ELFFile, entry: int, size: int) -> dict[str, Any]:
    from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs

    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    rows = list(decoder.disasm(_read_bytes(elf, entry, min(max(size, 2), 192)), entry))
    immediate_r1: list[int] = []
    stores_plus_0c: list[dict[str, Any]] = []
    key_store = False
    for instruction in rows:
        text = instruction.op_str.lower()
        match = re.match(r"^r1,\s*#(0x[0-9a-f]+|[0-9]+)$", text)
        if match and instruction.mnemonic.lower() in {"mov", "movs", "mov.w"}:
            immediate_r1.append(int(match.group(1), 0))
        # A post-index form such as ``str r3, [r0], #0xc`` writes at the
        # current base (usually the vptr) and then advances the register; it
        # is not evidence of a payload field at +0x0c.
        payload_store = re.search(r"\[[^\]]+,\s*#0xc\]", text)
        if payload_store and instruction.mnemonic.lower().startswith("str"):
            stores_plus_0c.append({
                "instruction_vma": hex(instruction.address),
                "width": "byte" if instruction.mnemonic.lower().startswith("strb") else "word",
                "source_register": text.split(",", 1)[0].strip(),
            })
        if re.search(r"\[[^\]]+,\s*#8\]", text) and instruction.mnemonic.lower().startswith("str"):
            key_store = True
    return {
        "decoded_instruction_count": len(rows),
        "immediate_r1_candidates": sorted(set(immediate_r1)),
        "payload_plus_0c_stores": stores_plus_0c,
        "constructor_writes_key_plus_08": key_store,
        "instruction_bytes_published": False,
    }


def _vtable_record(
    elf: ELFFile,
    symbols: dict[str, tuple[int, int]],
    relocations: dict[int, dict[str, Any]],
    vtable: int,
) -> dict[str, Any]:
    typeinfo = _effective_u32(elf, relocations, vtable + 4)
    slots: list[dict[str, Any]] = []
    for offset in (8, 12, 16):
        relocation = relocations.get(vtable + offset)
        effective_target = _effective_u32(elf, relocations, vtable + offset)
        slots.append({
            "offset": offset,
            "target_vma": hex(effective_target & ~1),
            "thumb_tag": bool(effective_target & 1),
            "target_symbol": _target_symbol(symbols, effective_target)
            or (relocation or {}).get("symbol"),
            "relocation": relocation,
        })
    return {
        "vtable": hex(vtable),
        "vptr_address_point": hex(vtable + 8),
        "typeinfo": hex(typeinfo),
        "slots": slots,
        "address_space": "ELF_VMA",
    }


def probe_param_families(
    elf_path: Path,
    *,
    expected_sha256: str = EXPECTED_LIBOBJ_SHA,
    targets: Iterable[dict[str, Any]] = PARAM_FAMILY_TARGETS,
) -> dict[str, Any]:
    """Extract structured ParamBase family evidence from a private ELF."""
    path = Path(elf_path).resolve()
    if not path.is_file() or path.stat().st_size > MAX_ELF_BYTES:
        raise ValueError("private ELF missing or exceeds analysis limit")
    if not HEX_SHA.fullmatch(expected_sha256):
        raise ValueError("expected_sha256 must be a lowercase SHA-256 digest")
    digest = _sha256(path)
    if digest != expected_sha256:
        raise ValueError("full-file ELF SHA-256 mismatch; refusing analysis")
    records: list[dict[str, Any]] = []
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_ARM":
            raise ValueError("expected ELF32 little-endian ARM")
        symbols = _symbols(elf)
        relocations = _relocations(elf)
        discovered = _discover_parambase_types(elf, symbols, relocations)
        for spec in targets:
            name = str(spec["name"])
            vtable = _vma_symbol(symbols, spec.get("vtable_symbol")) or spec.get("vtable_vma")
            if vtable is None:
                typeinfo_candidates = _typeinfo_candidates(elf, name)
                if not typeinfo_candidates:
                    raise ValueError(f"cannot locate RTTI for {name}")
                vtable = _find_vtable_for_typeinfo(elf, min(typeinfo_candidates))
            if vtable is None:
                raise ValueError(f"cannot locate vtable for {name}")
            constructor_name = spec.get("constructor_symbol")
            constructor = _vma_symbol(symbols, constructor_name)
            if constructor is None and spec.get("constructor_vma") is not None:
                constructor = int(spec["constructor_vma"]) & ~1
            if constructor is None:
                raise ValueError(f"constructor location missing for {name}")
            if constructor_name and constructor_name in symbols:
                constructor_size = symbols[constructor_name][1]
                constructor_boundary = "ELF_SYMBOL_SIZE"
            elif spec.get("constructor_end") is not None:
                constructor_size = int(spec["constructor_end"]) - constructor
                constructor_boundary = "PROFILED_FUNCTION_END"
            else:
                raise ValueError(f"constructor size missing for {name}")
            typeinfo = _effective_u32(elf, relocations, vtable + 4)
            rtti_name_address = _effective_u32(elf, relocations, typeinfo + 4)
            rtti_name = _read_bytes(elf, rtti_name_address, 96).split(b"\0", 1)[0].decode("ascii")
            base_rtti = _effective_u32(elf, relocations, typeinfo + 8)
            base_relocation = relocations.get(typeinfo + 8)
            vtable_record = _vtable_record(elf, symbols, relocations, vtable)
            observations = _decode_constructor_observations(elf, constructor, constructor_size)
            clone = int(spec["clone_entry"])
            lifecycle_entries = {
                "constructor": constructor,
                "clone": clone,
            }
            if spec.get("destructor_entry") is not None:
                lifecycle_entries["nondeleting_destructor"] = int(spec["destructor_entry"])
            if spec.get("deleting_destructor_entry") is not None:
                lifecycle_entries["deleting_destructor"] = int(spec["deleting_destructor_entry"])
            exception_targets = {
                name: _exception_index_entry(elf, entry)
                for name, entry in lifecycle_entries.items()
            }
            records.append({
                "name": name,
                "verification": "PRIMARY_ELF_VERIFIED",
                "rtti": hex(typeinfo),
                "rtti_name": rtti_name,
                "base_rtti": hex(base_rtti),
                "base_rtti_relocation": base_relocation,
                "vtable": vtable_record,
                "constructor": hex(constructor),
                "constructor_symbol": constructor_name,
                "constructor_size": constructor_size,
                "constructor_boundary": constructor_boundary,
                "constructor_observations": observations,
                "discriminator": int(spec["discriminator"]),
                "allocation_size_bytes": int(spec["allocation_size"]),
                "clone_candidate": hex(clone),
                "destructor_entry": hex(int(spec["destructor_entry"]))
                if spec.get("destructor_entry") is not None else None,
                "deleting_destructor_entry": hex(int(spec["deleting_destructor_entry"]))
                if spec.get("deleting_destructor_entry") is not None else None,
                "payload_kind": spec["payload_kind"],
                "payload_offsets": [hex(int(x)) for x in spec["payload_offsets"]],
                "exception_unwind": {
                    "status": "PRIMARY_ELF_VERIFIED",
                    "format": "ARM EHABI .ARM.exidx metadata",
                    "targets": exception_targets,
                    "semantic_limit": (
                        "EHABI records and function-local cleanup metadata do not prove "
                        "every throw edge, exception object, allocator pairing or "
                        "runtime lifetime contract"
                    ),
                },
                "method_symbols": [
                    {"name": symbol, "address": hex(_vma_symbol(symbols, symbol))}
                    for symbol in spec.get("method_symbols", [])
                    if _vma_symbol(symbols, symbol) is not None
                ],
                "evidence_scope": "constructor_vtable_rtti_symbol_table_and_bounded_capstone_metadata",
                "runtime_verified": False,
                "callable": False,
            })
    return {
        "schema_version": 1,
        "firmware_version": "3.21",
        "binary_sha256": digest,
        "address_space": "ELF_VMA",
        "types": records,
        "discovered_parambase_types": discovered,
        "raw_instruction_bytes_published": False,
        "runtime_verified": False,
        "callable": False,
        "limitations": [
            "Constructor field summaries are static observations, not a complete C++ ABI",
            "Runtime load bias, interposition, allocator behavior, locks and exception paths are UNKNOWN",
            "Payload ownership is not inferred from a pointer store alone",
            "No firmware code is executed by this probe",
        ],
    }


def validate_param_family_contract(contract: dict[str, Any]) -> dict[str, Any]:
    """Validate public-safe invariants without validating runtime callability."""
    errors: list[str] = []
    if contract.get("binary_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_sha256_mismatch")
    if contract.get("address_space") != "ELF_VMA":
        errors.append("address_space_mismatch")
    if contract.get("runtime_verified") is not False or contract.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    for item in contract.get("types", []):
        if item.get("verification") not in {"PRIMARY_ELF_VERIFIED", "STATIC_INFERRED", "UNVERIFIED"}:
            errors.append(f"invalid_verification:{item.get('name')}")
        if not item.get("vtable", {}).get("address_space") == "ELF_VMA":
            errors.append(f"missing_vtable_address_space:{item.get('name')}")
        if item.get("runtime_verified") is not False or item.get("callable") is not False:
            errors.append(f"unsafe_type_claim:{item.get('name')}")
        exception_unwind = item.get("exception_unwind")
        if exception_unwind is not None:
            if exception_unwind.get("status") != "PRIMARY_ELF_VERIFIED":
                errors.append(f"exception_unwind_status:{item.get('name')}")
            if exception_unwind.get("format") != "ARM EHABI .ARM.exidx metadata":
                errors.append(f"exception_unwind_format:{item.get('name')}")
            targets = exception_unwind.get("targets")
            if not isinstance(targets, dict) or not targets:
                errors.append(f"exception_unwind_targets:{item.get('name')}")
            else:
                expected_entries = {
                    "constructor": item.get("constructor"),
                    "clone": item.get("clone_candidate"),
                    "nondeleting_destructor": item.get("nondeleting_destructor"),
                    "deleting_destructor": item.get("deleting_destructor"),
                }
                for role, entry in expected_entries.items():
                    if entry is None:
                        continue
                    if isinstance(entry, str):
                        # Existing descriptive contracts may append a prose
                        # explanation after the leading VMA.
                        entry = entry.split(maxsplit=1)[0]
                    row = targets.get(role)
                    if not isinstance(row, dict):
                        errors.append(f"exception_unwind_missing:{item.get('name')}:{role}")
                        continue
                    if row.get("status") != "PRIMARY_ELF_VERIFIED":
                        errors.append(f"exception_unwind_entry_status:{item.get('name')}:{role}")
                    if row.get("address_space") != "ELF_VMA":
                        errors.append(f"exception_unwind_address_space:{item.get('name')}:{role}")
                    if row.get("entry_vma") != str(entry):
                        errors.append(f"exception_unwind_entry:{item.get('name')}:{role}")
    return {"valid": not errors, "errors": errors, "type_count": len(contract.get("types", []))}
