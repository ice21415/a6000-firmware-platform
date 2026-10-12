"""Evidence-gated primary-ELF probe for the ``PrmSet`` family.

The probe records the machine-level shape of the embedded payload used by
``PrmSet``.  It deliberately does not name the payload as ``std::set`` or
claim a source-level return type: the bounded code shows self-linked sentinel
words and copy/destruction helpers, but the complete container ABI is not
available from these regions alone.

Only metadata is emitted.  The private ELF is SHA-pinned, no firmware code is
executed, and no instruction bytes are returned by this module.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from capstone.arm import ARM_OP_IMM
from elftools.elf.elffile import ELFFile

from .elf_plt import resolve_plt_binding
from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA


TARGETS: tuple[dict[str, Any], ...] = (
    {"name": "prmset_get_set", "entry": 0x7EFAE8, "size": 8,
     "symbol": "_ZN6PrmSet6getSetEv"},
    {"name": "prmset_get", "entry": 0x7EFAF0, "size": 14,
     "symbol": "_ZN6PrmSet3GETEPK9ParamListm"},
    {"name": "prmset_constructor", "entry": 0x7EFB00, "size": 0x24},
    # Include the compiler-generated landing-pad-shaped cleanup after the
    # normal copy path.  It is bounded to this primary ELF region and is not
    # treated as a source-level exception contract.
    {"name": "prmset_payload_helper", "entry": 0x7EFB6C, "size": 0x40},
    {"name": "prmset_destructor", "entry": 0x7EFB2C, "size": 0x20},
    {"name": "prmset_deleting_destructor", "entry": 0x7EFB58, "size": 0x14},
    {"name": "prmset_clone", "entry": 0x7EFBB4, "size": 0x24},
    {"name": "payload_default_init", "entry": 0xFFD22, "size": 0x0E},
    {"name": "payload_header_accessors", "entry": 0xFFC40, "size": 0xA0},
    {"name": "payload_init", "entry": 0xFFCF6, "size": 0x30},
    {"name": "payload_sentinel_init", "entry": 0xFFCE4, "size": 0x14},
    {"name": "payload_tree_destroy_recursive", "entry": 0xFFD80, "size": 0x30},
    {"name": "payload_node_size", "entry": 0xFFE1C, "size": 0x1A},
    {"name": "payload_node_construct", "entry": 0xFFE4C, "size": 0x24},
    {"name": "payload_value_copy", "entry": 0xECD7A, "size": 0x0C},
    {"name": "payload_value_compare", "entry": 0xEFE6C, "size": 0x12},
    {"name": "payload_tree_insert", "entry": 0xFFE70, "size": 0x60},
    {"name": "payload_tree_insert_unique", "entry": 0xFFED0, "size": 0xE6},
    {"name": "payload_tree_copy_node", "entry": 0x63E796, "size": 0x1A},
    {"name": "payload_tree_copy", "entry": 0x63E83A, "size": 0x74},
    {"name": "payload_copy_wrapper", "entry": 0x63E8A6, "size": 0x0E},
    {"name": "payload_destroy_wrapper", "entry": 0xFFE0C, "size": 0x0E},
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_exec_range(fp: Any, elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > 0x200:
        raise ValueError("PrmSet read exceeds bounded probe limit")
    offsets: list[int] = []
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD" or not (int(segment["p_flags"]) & 1):
            continue
        base = int(segment["p_vaddr"])
        count = int(segment["p_filesz"])
        if base <= start and start + size <= base + count:
            offsets.append(int(segment["p_offset"]) + start - base)
    if len(offsets) != 1:
        raise ValueError(f"ELF_VMA 0x{start:x} is not uniquely executable")
    fp.seek(offsets[0])
    data = fp.read(size)
    if len(data) != size:
        raise ValueError("truncated executable range")
    return data


def _read_filebacked_u32(fp: Any, elf: ELFFile, address: int) -> int:
    """Read one little-endian word from a unique file-backed PT_LOAD.

    Vtable and RTTI words are data, not executable instructions.  Keeping this
    reader separate from ``_read_exec_range`` prevents a data address from
    being accidentally decoded as Thumb code and rejects ambiguous or
    zero-fill-only mappings instead of guessing a file offset.
    """
    offsets: list[int] = []
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD":
            continue
        base = int(segment["p_vaddr"])
        count = int(segment["p_filesz"])
        if base <= address and address + 4 <= base + count:
            offsets.append(int(segment["p_offset"]) + address - base)
    if len(offsets) != 1:
        raise ValueError(f"ELF_VMA 0x{address:x} is not uniquely file-backed")
    fp.seek(offsets[0])
    data = fp.read(4)
    if len(data) != 4:
        raise ValueError(f"truncated data word at ELF_VMA 0x{address:x}")
    return int.from_bytes(data, "little")


def _decode(fp: Any, elf: ELFFile, entry: int, size: int) -> dict[int, Any]:
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    rows = list(decoder.disasm(_read_exec_range(fp, elf, entry, size), entry))
    if not rows:
        raise ValueError(f"no Thumb instructions at 0x{entry:x}")
    return {int(row.address): row for row in rows}


def _symbols(elf: ELFFile) -> dict[str, tuple[int, int]]:
    result: dict[str, tuple[int, int]] = {}
    for section_name in (".dynsym", ".symtab"):
        section = elf.get_section_by_name(section_name)
        if section is None:
            continue
        for symbol in section.iter_symbols():
            if symbol.name and symbol.name not in result:
                result[symbol.name] = (int(symbol["st_value"]), int(symbol["st_size"]))
    return result


def _immediates(instruction: Any) -> list[int]:
    return [int(operand.imm) for operand in instruction.operands if operand.type == ARM_OP_IMM]


def _require(
    rows: dict[int, Any], address: int, mnemonic: str, *,
    target: int | None = None, operands: str | None = None,
    immediate: int | None = None,
) -> Any:
    instruction = rows.get(address)
    if instruction is None or instruction.mnemonic.lower() != mnemonic.lower():
        raise ValueError(f"unexpected {mnemonic} at 0x{address:x}")
    if target is not None and target not in _immediates(instruction):
        raise ValueError(f"unexpected target at 0x{address:x}")
    if immediate is not None and immediate not in _immediates(instruction):
        raise ValueError(f"unexpected immediate at 0x{address:x}")
    if operands is not None and instruction.op_str.lower() != operands.lower():
        raise ValueError(f"unexpected operands at 0x{address:x}")
    return instruction


def _binding(fp: Any, elf: ELFFile, entry: int, symbol: str) -> dict[str, Any]:
    result = resolve_plt_binding(fp, elf, entry, thumb_stub=False)
    if result.get("status") != "VERIFIED_STATIC":
        raise ValueError(f"PLT binding at 0x{entry:x} is not unique")
    candidates = result.get("candidates", [])
    if len(candidates) != 1 or candidates[0].get("symbol") != symbol:
        raise ValueError(f"unexpected PLT symbol at 0x{entry:x}")
    return result


def _prel31(place: int, word: int) -> int:
    """Resolve an ARM EHABI PREL31 word without exposing raw bytes."""
    value = word & 0x7FFFFFFF
    if value & 0x40000000:
        value -= 0x80000000
    return (place + value) & 0xFFFFFFFF


def _exception_index_entry(elf: ELFFile, target: int) -> dict[str, Any]:
    """Find the exact ``.ARM.exidx`` metadata for one target VMA.

    Only section/address metadata and compact-vs-extab classification are
    returned.  Encoded unwind words and firmware bytes stay private.  A
    missing or ambiguous entry is an error for the SHA-pinned primary ELF,
    rather than a guessed exception relationship.
    """
    section = elf.get_section_by_name(".ARM.exidx")
    if section is None:
        raise ValueError("primary ELF has no .ARM.exidx section")
    data = section.data()
    if len(data) == 0 or len(data) % 8:
        raise ValueError("truncated or malformed .ARM.exidx section")
    base = int(section["sh_addr"])
    matches: list[dict[str, Any]] = []
    for offset in range(0, len(data), 8):
        function_vma = _prel31(
            base + offset,
            int.from_bytes(data[offset:offset + 4], "little"),
        )
        if function_vma != target:
            continue
        unwind_word = int.from_bytes(data[offset + 4:offset + 8], "little")
        if unwind_word & 0x80000000:
            unwind = {"kind": "COMPACT", "extab_vma": None}
        else:
            unwind = {
                "kind": "EXTAB",
                "extab_vma": f"0x{_prel31(base + offset + 4, unwind_word):x}",
            }
        matches.append({
            "section": ".ARM.exidx",
            "entry_vma": f"0x{function_vma:x}",
            "entry_offset": f"0x{base + offset:x}",
            "exidx_entry_vma": f"0x{base + offset:x}",
            "extab_vma": unwind["extab_vma"],
            "unwind_kind": unwind["kind"],
            "unwind": unwind,
            "status": "PRIMARY_ELF_VERIFIED",
            "address_space": "ELF_VMA",
        })
    if len(matches) != 1:
        raise ValueError(
            f"expected one .ARM.exidx entry for 0x{target:x}, found {len(matches)}"
        )
    return matches[0]


def _observe_get_set(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0x7EFAE8, "push")
    _require(rows, 0x7EFAEA, "adds", operands="r0, #0xc")
    _require(rows, 0x7EFAEE, "pop")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "receiver": "PrmSet* candidate in r0",
        "machine_return": "address r0 + 0x0c; no load or allocation in the body",
        "source_return_type": "UNKNOWN; mangled symbol does not encode it",
        "payload_alias": "borrowed address into the receiver's embedded payload",
    }


def _observe_get(rows: dict[int, Any], binding: dict[str, Any]) -> dict[str, Any]:
    _require(rows, 0x7EFAF2, "movs", immediate=7)
    _require(rows, 0x7EFAFA, "b.w", target=0xE2890)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "inputs": {"r0": "const ParamList* candidate", "r1": "unsigned long key candidate"},
        "lookup_discriminator": 7,
        "forwarding": "tail branch through the ParamList::get interworking veneer",
        "target_binding": binding,
        "return": "delegated lookup result; source return and ownership UNKNOWN",
    }


def _observe_prmset_vtable(fp: Any, elf: ELFFile) -> dict[str, Any]:
    """Verify the concrete PrmSet RTTI/vtable words in the primary ELF.

    The slot addresses and Thumb tags are direct file facts.  The labels
    ``clone candidate`` and destructor roles describe the bounded target
    bodies and Itanium-style slot positions; they do not create a callable
    source-level C++ declaration.
    """
    prefix = 0x1019D18
    address_point = 0x1019D20
    rtti = 0x1019D08
    prefix_words = [
        _read_filebacked_u32(fp, elf, prefix),
        _read_filebacked_u32(fp, elf, prefix + 4),
    ]
    if prefix_words != [0, rtti]:
        raise ValueError("PrmSet vtable prefix/RTTI word mismatch")
    expected = (
        (0x00, "clone_candidate", 0x7EFBB4, "bounded clone allocation/copy body"),
        (0x04, "nondeleting_destructor", 0x7EFB2C, "bounded payload-release destructor body"),
        (0x08, "deleting_destructor", 0x7EFB58, "bounded destructor-plus-delete body"),
    )
    slots: dict[str, Any] = {}
    for offset, role, entry, role_evidence in expected:
        raw = _read_filebacked_u32(fp, elf, address_point + offset)
        if (raw & ~1) != entry or (raw & 1) != 1:
            raise ValueError(f"PrmSet vtable slot +0x{offset:x} mismatch")
        slots[f"+0x{offset:02x}"] = {
            "role": role,
            "role_status": "STATIC_INFERRED",
            "entry_vma": f"0x{entry:x}",
            "raw_thumb_value": f"0x{raw:x}",
            "thumb_tag": True,
            "status": "PRIMARY_ELF_VERIFIED",
            "address_space": "ELF_VMA",
            "evidence": role_evidence,
        }
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "address_space": "ELF_VMA",
        "vtable_prefix_vma": f"0x{prefix:x}",
        "address_point_vma": f"0x{address_point:x}",
        "prefix": {
            "offset_to_top": "0x0",
            "typeinfo_pointer": f"0x{prefix_words[1]:x}",
            "status": "PRIMARY_ELF_VERIFIED",
        },
        "slots": slots,
        "source_level_semantics": (
            "slot positions and target bodies are statically observed; exact source "
            "virtual declarations and runtime dispatch remain UNKNOWN"
        ),
    }


def _observe_constructor(rows: dict[int, Any], bindings: dict[str, Any]) -> dict[str, Any]:
    _require(rows, 0x7EFB00, "push")
    _require(rows, 0x7EFB02, "movs", immediate=7)
    _require(rows, 0x7EFB0A, "blx", target=0xE11A4)
    _require(rows, 0x7EFB16, "adds", immediate=8)
    _require(rows, 0x7EFB18, "str")
    _require(rows, 0x7EFB1C, "bl", target=0xFFD22)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "receiver": "PrmSet* candidate in r0",
        "discriminator": 7,
        "allocation_size_bytes": 0x24,
        "vptr": "relocated vtable address point (+8) stored at object +0",
        "payload": "default initialization is called with object +0x0c",
        "key": "object +0x08 is not written in this bounded constructor",
        "bindings": bindings,
    }


def _observe_payload_sentinel(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0xFFCE4, "movs", immediate=0)
    _require(rows, 0xFFCE6, "str", operands="r3, [r0, #4]")
    _require(rows, 0xFFCEC, "str", operands="r3, [r0, #8]")
    _require(rows, 0xFFCEE, "adds", operands="r3, r0, #4")
    _require(rows, 0xFFCF0, "str", operands="r3, [r0, #0xc]")
    _require(rows, 0xFFCF2, "str", operands="r3, [r0, #0x10]")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "relative_layout": {
            "+0x04": "zero",
            "+0x08": "zero",
            "+0x0c": "pointer to payload +0x04",
            "+0x10": "pointer to payload +0x04",
        },
        "payload_plus_0x00": "not written by this helper; UNKNOWN",
    }


def _observe_payload_init(rows: dict[int, Any], memset_binding: dict[str, Any]) -> dict[str, Any]:
    _require(rows, 0xFFCF6, "push")
    _require(rows, 0xFFCFC, "movs", immediate=0)
    _require(rows, 0xFFCFE, "movs", immediate=0x10)
    _require(rows, 0xFFD00, "adds", operands="r0, #4")
    _require(rows, 0xFFD02, "blx", target=0xDE37C)
    _require(rows, 0xFFD0A, "str", operands="r3, [r4, #0x14]")
    _require(rows, 0xFFD0C, "bl", target=0xFFCE4)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "operation": "zero 16 bytes at payload +0x04, clear payload +0x14, then install sentinel links",
        "payload_plus_0x00": "not written by this bounded path; UNKNOWN",
        "memset_binding": memset_binding,
    }


def _observe_payload_default_init(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0xFFD22, "push")
    _require(rows, 0xFFD28, "bl", target=0xFFD14)
    _require(rows, 0xFFD2C, "mov", operands="r0, r4")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "operation": "delegates default payload initialization to 0xffd14",
        "return": "destination payload pointer remains in r0 on the observed path",
    }


def _observe_payload_header_accessors(rows: dict[int, Any]) -> dict[str, Any]:
    """Record direct word/link accessors used by the payload helpers.

    The offsets are machine-level observations.  Their compatibility with a
    libstdc++ tree header is a source-family inference, not a proof of the
    original typedef or element type.
    """
    _require(rows, 0xFFC40, "push")
    _require(rows, 0xFFC44, "ldr", operands="r0, [r0, #8]")
    _require(rows, 0xFFC60, "push")
    _require(rows, 0xFFC64, "ldr", operands="r0, [r0, #0xc]")
    _require(rows, 0xFFC68, "push")
    _require(rows, 0xFFC6C, "ldr", operands="r0, [r0, #8]")
    _require(rows, 0xFFCCC, "push")
    _require(rows, 0xFFCCE, "adds", operands="r0, #0xc")
    _require(rows, 0xFFCD4, "push")
    _require(rows, 0xFFCD6, "adds", operands="r0, #8")
    _require(rows, 0xFFCDC, "push")
    _require(rows, 0xFFCDE, "adds", operands="r0, #0x10")
    _require(rows, 0xFFC70, "push")
    _require(rows, 0xFFC72, "adds", operands="r0, #4")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "payload_root_source": "0xffc40 returns [payload + 0x08]",
        "node_link_accessors": {
            "+0x08": "0xffc68 returns [node + 0x08]",
            "+0x0c": "0xffc60 returns [node + 0x0c]",
        },
        "header_accessors": {
            "+0x04": "0xffc70 returns payload/header base +0x04",
            "+0x08": "0xffcd4 returns payload/header base +0x08",
            "+0x0c": "0xffccc returns payload/header base +0x0c",
            "+0x10": "0xffcdc returns payload/header base +0x10",
        },
        "layout_compatibility": (
            "STATIC_INFERRED; offsets and imported _Rb_tree node-base ABI are "
            "compatible with a libstdc++ _Rb_tree header/node layout"
        ),
    }


def _observe_payload_helper(
    rows: dict[int, Any], bindings: dict[str, Any], exception_index: dict[str, Any]
) -> dict[str, Any]:
    _require(rows, 0x7EFB72, "movs", immediate=7)
    _require(rows, 0x7EFB78, "blx", target=0xE11A4)
    _require(rows, 0x7EFB86, "str")
    _require(rows, 0x7EFB8C, "bl", target=0xFFD22)
    _require(rows, 0x7EFB94, "bl", target=0x63E8A6)
    _require(rows, 0x7EFB9C, "mov")
    _require(rows, 0x7EFB9E, "bl", target=0xFFE0C)
    _require(rows, 0x7EFBA2, "mov")
    _require(rows, 0x7EFBA4, "bl", target=0xE4734)
    _require(rows, 0x7EFBA8, "blx", target=0xDD4F8)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "inputs": {"r0": "destination PrmSet-like object", "r1": "source payload pointer candidate"},
        "operation": "initialize destination base/payload, then copy source payload through 0x63e8a6",
        "payload_source": "source r1 is preserved in the local helper and passed to payload copy",
        "exception_cleanup": {
            "status": "STATIC_INFERRED",
            "landing_pad_candidate": "0x7efb9c",
            "operation": "release partially initialized payload, restore ParamBase destruction path, then end the active EH cleanup",
            "calls": ["0xffe0c", "0xe4734", "0xdd4f8"],
            "end_cleanup_binding": bindings["end_cleanup"],
            "ehabi_index": exception_index,
            "limitation": "direct cleanup calls and EHABI coverage are observed; the complete throw edge and allocation/constructor exception contract remain UNKNOWN",
        },
        "bindings": bindings,
    }


def _observe_copy_wrapper(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0x63E8A6, "push")
    _require(rows, 0x63E8AC, "bl", target=0x63E83A)
    _require(rows, 0x63E8B0, "mov", operands="r0, r4")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "operation": "payload copy wrapper calls local 0x63e83a and returns its destination",
        "self_copy_guard": "implemented in the bounded callee 0x63e83a; complete container semantics UNKNOWN",
    }


def _observe_clone(
    rows: dict[int, Any], delete_binding: dict[str, Any], exception_index: dict[str, Any],
    end_cleanup_binding: dict[str, Any],
) -> dict[str, Any]:
    _require(rows, 0x7EFBB4, "push")
    _require(rows, 0x7EFBBA, "movs", immediate=0x24)
    _require(rows, 0x7EFBBC, "blx", target=0xDC100)
    _require(rows, 0x7EFBC0, "add.w")
    _require(rows, 0x7EFBC6, "bl", target=0x7EFB6C)
    _require(rows, 0x7EFBCA, "mov", operands="r0, r4")
    _require(rows, 0x7EFBCE, "mov")
    _require(rows, 0x7EFBD0, "blx", target=0xDD620)
    _require(rows, 0x7EFBD4, "blx", target=0xDD4F8)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "allocation": "0x24-byte destination allocation through 0xdc100",
        "source_payload": "source receiver +0x0c passed to the helper",
        "return": "destination pointer remains in r0 on the success path; source-level clone return UNKNOWN",
        "exception_cleanup": {
            "status": "STATIC_INFERRED",
            "landing_pad_candidate": "0x7efbce",
            "operation": "release the newly allocated destination through operator-delete, then end the active EH cleanup",
            "calls": ["0xdd620", "0xdd4f8"],
            "delete_binding": delete_binding,
            "end_cleanup_binding": end_cleanup_binding,
            "ehabi_index": exception_index,
            "limitation": "the cleanup is associated with the copy-constructor failure region; exact throw source and exception object semantics remain UNKNOWN",
        },
    }


def _observe_destructor(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0x7EFB3C, "str")
    _require(rows, 0x7EFB40, "bl", target=0xFFE0C)
    _require(rows, 0x7EFB46, "bl", target=0xE4734)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "operation": "restore PrmSet vptr, release payload through 0xffe0c, then call local ParamBase destructor path 0xe4734",
        "payload_release": "non-null guard is not observed in this short wrapper; helper behavior UNKNOWN",
    }


def _observe_deleting_destructor(rows: dict[int, Any], delete_binding: dict[str, Any]) -> dict[str, Any]:
    _require(rows, 0x7EFB5E, "bl", target=0x7EFB2C)
    _require(rows, 0x7EFB64, "blx", target=0xDD620)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "operation": "call non-deleting destructor then operator-delete",
        "delete_binding": delete_binding,
    }


def _observe_payload_destroy(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0xFFE0C, "push")
    _require(rows, 0xFFE12, "bl", target=0xFFDF6)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "operation": "delegates embedded payload release to 0xffdf6",
        "root_source": "0xffdf6 obtains [payload + 0x08] through 0xffc40 before recursive destruction",
        "container_semantics": "UNKNOWN",
    }


def _observe_tree_destroy_recursive(rows: dict[int, Any]) -> dict[str, Any]:
    """Record the bounded recursive tree-node release helper.

    The helper's local names and source container type are unavailable.  The
    probe therefore records only the direct branch/call facts and does not
    turn the routine into a source-level destructor declaration.
    """
    _require(rows, 0xFFD80, "push")
    _require(rows, 0xFFD88, "b", target=0xFFDAA)
    _require(rows, 0xFFD8C, "bl", target=0xFFC60)
    _require(rows, 0xFFD94, "bl", target=0xFFD80)
    _require(rows, 0xFFD9A, "bl", target=0xFFC68)
    _require(rows, 0xFFDA4, "bl", target=0xFFD74)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "operation": "walks a child chain recursively and invokes local node release helpers",
        "recursion": "direct self-call at 0xffd94",
        "node_link_offsets": {
            "+0x08": "followed by 0xffc68 before node release",
            "+0x0c": "followed by 0xffc60 before recursive destruction",
        },
        "termination": "cmp r4, #0; returns when the selected link is null",
        "node_release_path": "0xffd74 -> 0xffd66 -> 0xffd58 -> ARM interworking veneer 0xdd61c/PLT 0xdd620",
        "source_destructor_identity": "UNKNOWN",
    }


def _observe_node_size(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0xFFE1C, "ldr")
    _require(rows, 0xFFE20, "cmp")
    _require(rows, 0xFFE2A, "movs", immediate=0x14)
    _require(rows, 0xFFE2C, "muls", operands="r0, r1, r0")
    _require(rows, 0xFFE32, "b.w", target=0xDC0FC)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "allocation_unit_bytes": 0x14,
        "count_input": "r1",
        "size_expression": "r0 = r1 * 0x14 after the bounded overflow guard",
        "allocator_target": "0xdc0fc; source allocator identity UNKNOWN",
    }


def _observe_node_construct(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0xFFE4C, "push")
    _require(rows, 0xFFE54, "bl", target=0xFFE3C)
    _require(rows, 0xFFE5C, "adds", operands="r0, r7, #4")
    _require(rows, 0xFFE5E, "add.w", operands="r1, r4, #0x10")
    _require(rows, 0xFFE62, "bl", target=0xECD7A)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "node_value_offset": 0x10,
        "value_source": "r1 is retained as r2 and passed to the bounded word-copy helper",
        "word_copy_helper": "0xecd7a; exact source type and copy count semantics UNKNOWN",
        "node_header_size_bytes": 0x10,
    }


def _observe_value_copy(rows: dict[int, Any]) -> dict[str, Any]:
    """Record the helper used to populate a tree-node value slot.

    This is deliberately a word-level fact.  The helper does not carry a
    source-level C++ type, and its null destination branch is not a proof of
    a complete exception-safe copy operation.
    """
    _require(rows, 0xECD7A, "push")
    _require(rows, 0xECD7E, "cbz", target=0xECD84)
    _require(rows, 0xECD80, "ldr", operands="r3, [r2]")
    _require(rows, 0xECD82, "str", operands="r3, [r1]")
    _require(rows, 0xECD84, "pop")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "inputs": {
            "r1": "destination pointer candidate",
            "r2": "source pointer candidate",
        },
        "operation": "if destination is non-null, copy exactly one 32-bit word from [r2] to [r1]",
        "width_bytes": 4,
        "source_type": "UNKNOWN",
    }


def _observe_value_compare(rows: dict[int, Any]) -> dict[str, Any]:
    """Record the local comparator's unsigned word comparison semantics."""
    _require(rows, 0xEFE6C, "ldr", operands="r0, [r2]")
    _require(rows, 0xEFE6E, "ldr", operands="r3, [r1]")
    _require(rows, 0xEFE72, "cmp", operands="r3, r0")
    _require(rows, 0xEFE76, "ite", operands="hs")
    _require(rows, 0xEFE78, "movhs", operands="r0, #0")
    _require(rows, 0xEFE7A, "movlo", operands="r0, #1")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "inputs": {
            "r1": "first value pointer candidate",
            "r2": "second value pointer candidate",
        },
        "operation": "load one word from each pointer and return 1 iff unsigned [r1] < [r2]",
        "width_bytes": 4,
        "ordering": "unsigned word less-than candidate; exact source comparator type UNKNOWN",
    }


def _observe_tree_copy_node(rows: dict[int, Any]) -> dict[str, Any]:
    """Record the bounded node-copy prefix used by the recursive tree copy."""
    _require(rows, 0x63E796, "push")
    _require(rows, 0x63E798, "mov", operands="r4, r1")
    _require(rows, 0x63E79C, "add.w", operands="r1, r1, #0x10")
    _require(rows, 0x63E7A0, "bl", target=0xFFE4C)
    _require(rows, 0x63E7A4, "ldr", operands="r2, [r4]")
    _require(rows, 0x63E7A6, "str", operands="r2, [r0]")
    _require(rows, 0x63E7A8, "movs", immediate=0)
    _require(rows, 0x63E7AA, "str", operands="r2, [r0, #8]")
    _require(rows, 0x63E7AC, "str", operands="r2, [r0, #0xc]")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "operation": "construct a destination node from source value at source node +0x10, then copy the source header word",
        "source_value_offset": 0x10,
        "value_width_bytes": 4,
        "cleared_link_offsets": [0x08, 0x0C],
        "source_type": "UNKNOWN",
    }


def _thumb_bl_callers(fp: Any, elf: ELFFile, target: int) -> list[int]:
    """Find direct Thumb BL encodings to *target* in the executable .text.

    The scanner is intentionally conservative: it only accepts the 32-bit
    Thumb BL encoding and then asks Capstone to decode the candidate.  It does
    not infer a containing function when symbols or a complete function body
    are unavailable.
    """
    return _thumb_bl_callers_many(fp, elf, {target}).get(target, [])


def _thumb_bl_callers_many(
    fp: Any, elf: ELFFile, targets: set[int],
) -> dict[int, list[int]]:
    """Scan one executable ``.text`` image for several direct BL targets."""
    section = elf.get_section_by_name(".text")
    if section is None or not (int(section["sh_flags"]) & 4):
        return {target: [] for target in targets}
    offset = int(section["sh_offset"])
    base = int(section["sh_addr"])
    size = int(section["sh_size"])
    fp.seek(offset)
    data = fp.read(size)
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True

    def sign_extend(value: int, bits: int) -> int:
        return value - (1 << bits) if value & (1 << (bits - 1)) else value

    callers: dict[int, list[int]] = {target: [] for target in targets}
    for index in range(0, max(0, len(data) - 4), 2):
        first = int.from_bytes(data[index:index + 2], "little")
        second = int.from_bytes(data[index + 2:index + 4], "little")
        if (first & 0xF800) != 0xF000 or (second & 0xC000) != 0xC000:
            continue
        sign = (first >> 10) & 1
        j1 = (second >> 13) & 1
        j2 = (second >> 11) & 1
        i1 = (~(j1 ^ sign)) & 1
        i2 = (~(j2 ^ sign)) & 1
        immediate = (
            (sign << 24) | (i1 << 23) | (i2 << 22)
            | ((first & 0x3FF) << 12) | ((second & 0x7FF) << 1)
        )
        caller = base + index
        destination = caller + 4 + sign_extend(immediate, 25)
        rows = list(decoder.disasm(data[index:index + 4], caller, count=1))
        if rows and rows[0].mnemonic.lower() == "bl":
            if destination in callers:
                callers[destination].append(caller)
    return callers


def _observe_tree_insert_callers(fp: Any, elf: ELFFile) -> dict[str, Any]:
    callers = _thumb_bl_callers(fp, elf, 0xFFE70)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "address_space": "ELF_VMA",
        "target": "0xffe70",
        "scan": "executable .text Thumb BL immediate encodings, Capstone-confirmed",
        "direct_callsite_addresses": [f"0x{address:x}" for address in callers],
        "direct_callsite_count": len(callers),
        "prmset_mutator_entry": "UNKNOWN",
        "prmset_relation": "UNKNOWN; no callsite is proven to consume PrmSet::getSet() in this ELF-only scan",
        "function_boundary_resolution": "UNKNOWN; stripped local helper callers are not promoted from nearest-address heuristics",
    }


def _observe_direct_paramset_callers(fp: Any, elf: ELFFile) -> dict[str, Any]:
    """Scan direct Thumb BL references to the named PrmSet lifecycle targets.

    This is deliberately a negative-capability observation: it covers only
    immediate BL encodings in the executable ``.text`` section.  It does not
    claim that an absent direct call rules out BLX/register dispatch, a
    vtable call, or a caller in another ELF.
    """
    targets = {
        "get_set": 0x7EFAE8,
        "get": 0x7EFAF0,
        "constructor": 0x7EFB00,
        "destructor": 0x7EFB2C,
        "deleting_destructor": 0x7EFB58,
        "clone": 0x7EFBB4,
    }
    by_target = _thumb_bl_callers_many(fp, elf, set(targets.values()))
    records: dict[str, Any] = {}
    for name, target in targets.items():
        callsites = by_target.get(target, [])
        records[name] = {
            "target": f"0x{target:x}",
            "direct_callsite_addresses": [f"0x{address:x}" for address in callsites],
            "direct_callsite_count": len(callsites),
            "status": "PRIMARY_ELF_VERIFIED",
            "caller_identity": "UNKNOWN; no nearest-address function attribution",
        }
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "address_space": "ELF_VMA",
        "scan": "executable .text Thumb BL immediate encodings, Capstone-confirmed",
        "targets": records,
        "scope_limit": (
            "absence of a direct BL does not exclude BLX/register/vtable dispatch "
            "or callers in another ELF"
        ),
    }


def _observe_tree_insert(rows: dict[int, Any], insert_binding: dict[str, Any]) -> dict[str, Any]:
    _require(rows, 0xFFE7E, "cbnz", target=0xFFE9C)
    _require(rows, 0xFFE80, "bl", target=0xFFC70)
    _require(rows, 0xFFE94, "bl", target=0xEFE6C)
    _require(rows, 0xFFEA4, "bl", target=0xFFE4C)
    _require(rows, 0xFFEAA, "adds", operands="r3, r4, #4")
    _require(rows, 0xFFEB2, "blx", target=0xDC63C)
    _require(rows, 0xFFEB6, "ldr", operands="r3, [r4, #0x14]")
    _require(rows, 0xFFEBE, "str", operands="r3, [r4, #0x14]")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "header_sentinel_offset": 0x04,
        "node_count_offset": 0x14,
        "node_value_offset": 0x10,
        "operation": "construct a node, call the ELF's comparator, then call libstdc++ tree insertion/rebalance",
        "insert_binding": insert_binding,
        "relation_scope": "generic ELF-local ordered-tree helper; direct PrmSet operation caller is not proven",
    }


def _observe_tree_insert_unique(rows: dict[int, Any]) -> dict[str, Any]:
    """Record the bounded unique-insert wrapper's two insertion paths."""
    _require(rows, 0xFFED0, "push.w")
    _require(rows, 0xFFF4E, "bl", target=0xFFE70)
    _require(rows, 0xFFF86, "bl", target=0xFFE70)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "operation": "walk/compare a tree and dispatch either duplicate or new-node insertion paths",
        "direct_insert_helper": "0xffe70",
        "insertion_paths": ["0xfff4e", "0xfff86"],
        "source_tree_type": "UNKNOWN",
        "caller_function_identity": "UNKNOWN; this helper is itself unnamed in the local symbol table",
    }


def _observe_tree_copy(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0x63E83A, "cmp", operands="r0, r1")
    _require(rows, 0x63E846, "beq", target=0x63E8A0)
    _require(rows, 0x63E848, "bl", target=0xFFDB0)
    _require(rows, 0x63E852, "cbz", target=0x63E8A0)
    _require(rows, 0x63E870, "bl", target=0x63E7B0)
    _require(rows, 0x63E898, "ldr", operands="r3, [r5, #0x14]")
    _require(rows, 0x63E89E, "str", operands="r3, [r4, #0x14]")
    _require(rows, 0x63E8A0, "mov", operands="r0, r4")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "self_copy_guard": "r0 == r1 returns the destination without copying",
        "operation": "copies tree links/node graph through local helpers and copies the source node count",
        "node_count_offset": 0x14,
        "source_type": "UNKNOWN",
    }


def probe_param_set(elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA) -> dict[str, Any]:
    """Read bounded PrmSet methods from the authenticated private ELF."""
    path = Path(elf_path).resolve()
    if not path.is_file():
        raise ValueError("private ELF is missing")
    if not HEX_SHA.fullmatch(expected_sha256):
        raise ValueError("expected_sha256 must be a lowercase full SHA-256 digest")
    digest = _sha256(path)
    if digest != expected_sha256:
        raise ValueError("full-file ELF SHA-256 mismatch; refusing to decode")
    with path.open("rb") as fp:
        elf = ELFFile(fp)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_ARM":
            raise ValueError("probe accepts only ELF32 little-endian ARM")
        symbols = _symbols(elf)
        for target in TARGETS:
            symbol_name = target.get("symbol")
            if not symbol_name:
                continue
            value, size = symbols.get(symbol_name, (0, 0))
            if (value & ~1) != int(target["entry"]) or size != int(target["size"]):
                raise ValueError(f"symbol identity mismatch for {symbol_name}")
        bindings = {
            "param_base_constructor": _binding(fp, elf, 0xE11A4, "_ZN9ParamBaseC2Em"),
            "memset": _binding(fp, elf, 0xDE37C, "memset"),
            "allocator": _binding(fp, elf, 0xDC100, "_Znwj"),
            "delete": _binding(fp, elf, 0xDD620, "_ZdlPv"),
            "end_cleanup": _binding(fp, elf, 0xDD4F8, "__cxa_end_cleanup"),
            "paramlist_get": _binding(fp, elf, 0xE2894, "_ZNK9ParamList3getEmm"),
            "rb_tree_increment_const": _binding(
                fp, elf, 0xDBB6C, "_ZSt18_Rb_tree_incrementPKSt18_Rb_tree_node_base",
            ),
            "rb_tree_insert_rebalance": _binding(
                fp, elf, 0xDC63C,
                "_ZSt29_Rb_tree_insert_and_rebalancebPSt18_Rb_tree_node_baseS0_RS_",
            ),
            "rb_tree_erase_rebalance": _binding(
                fp, elf, 0xDD17C,
                "_ZSt28_Rb_tree_rebalance_for_erasePSt18_Rb_tree_node_baseRS_",
            ),
            "rb_tree_decrement_const": _binding(
                fp, elf, 0xDE038, "_ZSt18_Rb_tree_decrementPKSt18_Rb_tree_node_base",
            ),
            "rb_tree_increment": _binding(
                fp, elf, 0xE0B00, "_ZSt18_Rb_tree_incrementPSt18_Rb_tree_node_base",
            ),
            "rb_tree_decrement": _binding(
                fp, elf, 0xE186C, "_ZSt18_Rb_tree_decrementPSt18_Rb_tree_node_base",
            ),
        }
        observations = {
            "prmset_get_set": _observe_get_set(_decode(fp, elf, 0x7EFAE8, 8)),
            "prmset_get": _observe_get(_decode(fp, elf, 0x7EFAF0, 14), bindings["paramlist_get"]),
            "prmset_constructor": _observe_constructor(
                _decode(fp, elf, 0x7EFB00, 0x24),
                {"param_base_constructor": bindings["param_base_constructor"]},
            ),
            "prmset_payload_helper": _observe_payload_helper(
                _decode(fp, elf, 0x7EFB6C, 0x40),
                {"param_base_constructor": bindings["param_base_constructor"],
                 "end_cleanup": bindings["end_cleanup"]},
                _exception_index_entry(elf, 0x7EFB6C),
            ),
            "prmset_destructor": _observe_destructor(_decode(fp, elf, 0x7EFB2C, 0x20)),
            "prmset_deleting_destructor": _observe_deleting_destructor(
                _decode(fp, elf, 0x7EFB58, 0x14), bindings["delete"],
            ),
            "prmset_clone": _observe_clone(
                _decode(fp, elf, 0x7EFBB4, 0x24),
                bindings["delete"],
                _exception_index_entry(elf, 0x7EFBB4),
                bindings["end_cleanup"],
            ),
            "payload_default_init": _observe_payload_default_init(
                _decode(fp, elf, 0xFFD22, 0x0E),
            ),
            "payload_header_accessors": _observe_payload_header_accessors(
                _decode(fp, elf, 0xFFC40, 0xA0),
            ),
            "payload_init": _observe_payload_init(_decode(fp, elf, 0xFFCF6, 0x30), bindings["memset"]),
            "payload_sentinel_init": _observe_payload_sentinel(_decode(fp, elf, 0xFFCE4, 0x14)),
            "payload_tree_destroy_recursive": _observe_tree_destroy_recursive(
                _decode(fp, elf, 0xFFD80, 0x30),
            ),
            "payload_node_size": _observe_node_size(_decode(fp, elf, 0xFFE1C, 0x1A)),
            "payload_node_construct": _observe_node_construct(
                _decode(fp, elf, 0xFFE4C, 0x24),
            ),
            "payload_value_copy": _observe_value_copy(
                _decode(fp, elf, 0xECD7A, 0x0C),
            ),
            "payload_value_compare": _observe_value_compare(
                _decode(fp, elf, 0xEFE6C, 0x12),
            ),
            "payload_tree_insert": _observe_tree_insert(
                _decode(fp, elf, 0xFFE70, 0x60), bindings["rb_tree_insert_rebalance"],
            ),
            "payload_tree_insert_unique": _observe_tree_insert_unique(
                _decode(fp, elf, 0xFFED0, 0xE6),
            ),
            "payload_tree_copy_node": _observe_tree_copy_node(
                _decode(fp, elf, 0x63E796, 0x1A),
            ),
            "payload_tree_copy": _observe_tree_copy(_decode(fp, elf, 0x63E83A, 0x74)),
            "payload_copy_wrapper": _observe_copy_wrapper(_decode(fp, elf, 0x63E8A6, 0x0E)),
            "payload_destroy_wrapper": _observe_payload_destroy(_decode(fp, elf, 0xFFE0C, 0x0E)),
        }
        prmset_vtable = _observe_prmset_vtable(fp, elf)
        observations["payload_tree_insert_callers"] = _observe_tree_insert_callers(fp, elf)
        observations["direct_paramset_callers"] = _observe_direct_paramset_callers(fp, elf)
    return {
        "status": "LOCAL_PRIMARY_ELF_PRMSET_EVIDENCE_ONLY",
        "binary_file_sha256": digest,
        "address_space": "ELF_VMA",
        "type": "PrmSet",
        "discriminator": 7,
        "allocation_size_bytes": 0x24,
        "exception_unwind": {
            "status": "PRIMARY_ELF_VERIFIED",
            "format": "ARM EHABI .ARM.exidx metadata",
            "targets": {
                "copy_constructor_candidate": observations["prmset_payload_helper"]["exception_cleanup"]["ehabi_index"],
                "clone_candidate": observations["prmset_clone"]["exception_cleanup"]["ehabi_index"],
            },
            "semantic_limit": "EHABI coverage and bounded cleanup calls do not prove every throw edge, exception object type or allocator contract",
        },
        "inheritance": {
            "status": "PRIMARY_ELF_VERIFIED",
            "base_type": "ParamBase",
            "rtti_name": "6PrmSet",
            "rtti_vma": "0x1019d08",
            "vtable_prefix_vma": "0x1019d18",
            "vtable_address_point": "0x1019d20",
            "relation": "direct RTTI +0x08 relocation to _ZTI9ParamBase and vtable typeinfo relation",
            "source": "cross-checked against param_base_3_21.json; source class declaration remains descriptive",
            "vtable_slots": prmset_vtable,
        },
        "payload_layout": {
            "object_base": "+0x0c",
            "size_bytes": 0x18,
            "fields": {
                "+0x00": "not written by the bounded default initializer; UNKNOWN",
                "+0x04": "zeroed payload field",
                "+0x08": "zeroed payload field",
                "+0x0c": "self-linked sentinel pointer to payload +0x04",
                "+0x10": "self-linked sentinel pointer to payload +0x04",
                "+0x14": "zeroed payload field",
            },
            "container_identity": (
                "layout-compatible with a libstdc++ _Rb_tree header/node family; the exact "
                "PrmSet source alias and element type remain UNKNOWN"
            ),
            "header_layout": {
                "status": "PRIMARY_ELF_VERIFIED",
                "base_offset": "+0x04",
                "fields": {
                    "+0x04": "header word; initialized to zero",
                    "+0x08": "root/parent link candidate; initialized to zero",
                    "+0x0c": "header link candidate; initialized to header +0x04",
                    "+0x10": "header link candidate; initialized to header +0x04",
                    "+0x14": "node count candidate; initialized to zero",
                },
                "compatibility": (
                    "STATIC_INFERRED; matches the 20-byte libstdc++ _Rb_tree_node_base "
                    "plus count shape"
                ),
                "evidence": "payload_header_accessors, payload_sentinel_init, payload_tree_destroy_recursive",
            },
            "tree_evidence": {
                "status": "PRIMARY_ELF_VERIFIED",
                "node_size_bytes": 0x14,
                "node_value_offset": 0x10,
                "node_value_width_bytes": 4,
                "header_sentinel_offset": 0x04,
                "node_count_offset": 0x14,
                "node_layout": {
                    "status": "PRIMARY_ELF_VERIFIED",
                    "+0x00": "node header word candidate",
                    "+0x04": "node link candidate",
                    "+0x08": "node link candidate; accessor observed at 0xffc68",
                    "+0x0c": "node link candidate; accessor observed at 0xffc60",
                    "+0x10": "one-word value storage",
                    "compatibility": (
                        "STATIC_INFERRED; compatible with libstdc++ _Rb_tree_node_base "
                        "plus value storage"
                    ),
                },
                "insert_rebalance_binding": bindings["rb_tree_insert_rebalance"],
                "erase_rebalance_binding": bindings["rb_tree_erase_rebalance"],
                "source_type": "UNKNOWN",
                "value_type": "UNKNOWN; one-word storage with an unsigned-order comparator candidate",
                "likely_source_family": "STATIC_INFERRED; libstdc++ _Rb_tree-like ordered container",
                "prmset_operation_path": "UNKNOWN; the bounded PrmSet lifecycle reaches shared helpers, not a named insert method",
                "insert_callers": observations["payload_tree_insert_callers"],
                "value_copy_evidence": observations["payload_value_copy"],
                "value_compare_evidence": observations["payload_value_compare"],
                "node_copy_evidence": observations["payload_tree_copy_node"],
            },
        },
        "bindings": bindings,
        "direct_call_scan": observations["direct_paramset_callers"],
        "observations": observations,
        "ownership": {
            "constructor": "embedded payload initialized in a newly allocated 0x24-byte object",
            "get_set": "returns a borrowed pointer into the object; no retain operation observed",
            "clone": "allocates a separate object and copies payload through 0x63e8a6",
            "destructor": "releases embedded payload then calls ParamBase destruction path",
            "status": "STATIC_INFERRED; container allocator, aliases, exceptions and synchronization UNKNOWN",
        },
        "safety_boundaries": {
            "get_set_null_receiver": {
                "status": "PRIMARY_ELF_VERIFIED",
                "observation": "the bounded 0x7efae8 body has no local null check before adding +0x0c",
                "scope": "bounded body only; caller preconditions and runtime fault behavior UNKNOWN",
            },
            "get_set_lifetime": {
                "status": "STATIC_INFERRED",
                "observation": "the getter returns an interior payload address and performs no retain operation",
                "alias_invalidation": "UNKNOWN",
            },
            "destructor_payload_guard": {
                "status": "PRIMARY_ELF_VERIFIED",
                "observation": "the short 0x7efb2c wrapper has no local null branch before delegating payload release",
                "delegate_semantics": "UNKNOWN",
            },
            "invalid_element": {
                "status": "UNKNOWN",
                "observation": "recursive release observes null child-link termination only; invalid node behavior is not recovered",
            },
            "concurrency": {
                "status": "UNKNOWN",
                "observation": "the bounded PrmSet targets do not prove a lock, atomic counter or scheduler contract",
            },
            "runtime_safe": False,
        },
        "runtime_verified": False,
        "callable": False,
    }


def validate_param_set(report: dict[str, Any]) -> dict[str, Any]:
    """Validate evidence identity and reject runtime/callable promotion."""
    errors: list[str] = []
    if report.get("binary_file_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != "ELF_VMA":
        errors.append("address_space")
    if report.get("type") != "PrmSet" or report.get("discriminator") != 7:
        errors.append("type_identity")
    if report.get("allocation_size_bytes") != 0x24:
        errors.append("allocation_size")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    exception_unwind = report.get("exception_unwind")
    if not isinstance(exception_unwind, dict):
        errors.append("missing_exception_unwind")
    else:
        if exception_unwind.get("status") != "PRIMARY_ELF_VERIFIED":
            errors.append("exception_unwind_status")
        if exception_unwind.get("format") != "ARM EHABI .ARM.exidx metadata":
            errors.append("exception_unwind_format")
        targets = exception_unwind.get("targets")
        if not isinstance(targets, dict):
            errors.append("exception_unwind_targets")
        else:
            expected_unwind = {
                "copy_constructor_candidate": ("0x7efb6c", "0xfb2a74", "0xf19718"),
                "clone_candidate": ("0x7efbb4", "0xfb2a7c", "0xf19730"),
            }
            for name, (entry_vma, exidx_vma, extab_vma) in expected_unwind.items():
                item = targets.get(name)
                if not isinstance(item, dict) or item.get("status") != "PRIMARY_ELF_VERIFIED":
                    errors.append(f"exception_unwind_target:{name}")
                    continue
                if item.get("address_space") != "ELF_VMA":
                    errors.append(f"exception_unwind_space:{name}")
                if item.get("entry_vma") != entry_vma:
                    errors.append(f"exception_unwind_entry:{name}")
                if item.get("exidx_entry_vma") != exidx_vma:
                    errors.append(f"exception_unwind_exidx:{name}")
                if item.get("extab_vma") != extab_vma or item.get("unwind_kind") != "EXTAB":
                    errors.append(f"exception_unwind_extab:{name}")
    bindings = report.get("bindings")
    end_cleanup = bindings.get("end_cleanup") if isinstance(bindings, dict) else None
    if not isinstance(end_cleanup, dict) or end_cleanup.get("status") != "VERIFIED_STATIC":
        errors.append("end_cleanup_binding")
    else:
        if end_cleanup.get("entry_vma") != "0xdd4f8" or end_cleanup.get("got_slot") != "0x102d660":
            errors.append("end_cleanup_locator")
        candidates = end_cleanup.get("candidates")
        if not isinstance(candidates, list) or len(candidates) != 1 or candidates[0].get("symbol") != "__cxa_end_cleanup":
            errors.append("end_cleanup_symbol")
    inheritance = report.get("inheritance")
    if not isinstance(inheritance, dict):
        errors.append("missing_inheritance_evidence")
    else:
        if inheritance.get("status") != "PRIMARY_ELF_VERIFIED":
            errors.append("inheritance_status")
        if inheritance.get("base_type") != "ParamBase" or inheritance.get("rtti_name") != "6PrmSet":
            errors.append("inheritance_identity")
        if inheritance.get("vtable_address_point") != "0x1019d20":
            errors.append("inheritance_vtable")
        slots = inheritance.get("vtable_slots")
        if not isinstance(slots, dict) or slots.get("status") != "PRIMARY_ELF_VERIFIED":
            errors.append("inheritance_vtable_slots")
        else:
            if slots.get("address_space") != "ELF_VMA":
                errors.append("inheritance_vtable_slots_address_space")
            if slots.get("vtable_prefix_vma") != "0x1019d18":
                errors.append("inheritance_vtable_prefix")
            if slots.get("address_point_vma") != "0x1019d20":
                errors.append("inheritance_vtable_address_point")
            prefix = slots.get("prefix")
            if not isinstance(prefix, dict) or prefix.get("offset_to_top") != "0x0" or prefix.get("typeinfo_pointer") != "0x1019d08":
                errors.append("inheritance_vtable_prefix_words")
            expected_slots = {
                "+0x00": ("clone_candidate", "0x7efbb4"),
                "+0x04": ("nondeleting_destructor", "0x7efb2c"),
                "+0x08": ("deleting_destructor", "0x7efb58"),
            }
            actual_slots = slots.get("slots")
            if not isinstance(actual_slots, dict):
                errors.append("inheritance_vtable_slot_map")
            else:
                for offset, (role, entry) in expected_slots.items():
                    slot = actual_slots.get(offset)
                    if not isinstance(slot, dict):
                        errors.append(f"inheritance_vtable_slot:{offset}")
                        continue
                    if slot.get("status") != "PRIMARY_ELF_VERIFIED":
                        errors.append(f"inheritance_vtable_slot_status:{offset}")
                    if slot.get("address_space") != "ELF_VMA":
                        errors.append(f"inheritance_vtable_slot_space:{offset}")
                    if slot.get("role") != role or slot.get("entry_vma") != entry:
                        errors.append(f"inheritance_vtable_slot_target:{offset}")
                    if slot.get("thumb_tag") is not True:
                        errors.append(f"inheritance_vtable_slot_thumb:{offset}")
                    raw = slot.get("raw_thumb_value")
                    try:
                        if int(str(raw), 16) != (int(entry, 16) | 1):
                            errors.append(f"inheritance_vtable_slot_raw:{offset}")
                    except (TypeError, ValueError):
                        errors.append(f"inheritance_vtable_slot_raw:{offset}")
    payload_layout = report.get("payload_layout")
    header = payload_layout.get("header_layout") if isinstance(payload_layout, dict) else None
    if not isinstance(header, dict):
        errors.append("missing_header_layout")
    else:
        if header.get("status") != "PRIMARY_ELF_VERIFIED":
            errors.append("header_layout_status")
        if header.get("base_offset") != "+0x04":
            errors.append("header_layout_base")
        if not str(header.get("compatibility", "")).startswith("STATIC_INFERRED"):
            errors.append("header_layout_compatibility")
    tree = payload_layout.get("tree_evidence") if isinstance(payload_layout, dict) else None
    if not isinstance(tree, dict):
        errors.append("missing_tree_evidence")
    else:
        if tree.get("status") != "PRIMARY_ELF_VERIFIED":
            errors.append("tree_evidence_status")
        if tree.get("node_size_bytes") != 0x14:
            errors.append("tree_node_size")
        if tree.get("node_value_offset") != 0x10:
            errors.append("tree_node_value_offset")
        if tree.get("node_value_width_bytes") != 4:
            errors.append("tree_node_value_width")
        node_layout = tree.get("node_layout")
        if not isinstance(node_layout, dict):
            errors.append("missing_node_layout")
        else:
            if node_layout.get("status") != "PRIMARY_ELF_VERIFIED":
                errors.append("node_layout_status")
            if node_layout.get("+0x10") != "one-word value storage":
                errors.append("node_layout_value_offset")
            if not str(node_layout.get("compatibility", "")).startswith("STATIC_INFERRED"):
                errors.append("node_layout_compatibility")
        if tree.get("header_sentinel_offset") != 0x04:
            errors.append("tree_header_offset")
        if tree.get("node_count_offset") != 0x14:
            errors.append("tree_count_offset")
        if tree.get("source_type") != "UNKNOWN":
            errors.append("tree_source_type_promotion")
        if not str(tree.get("value_type", "")).startswith("UNKNOWN"):
            errors.append("tree_value_type_promotion")
        if not str(tree.get("likely_source_family", "")).startswith("STATIC_INFERRED"):
            errors.append("tree_source_family_status")
        insert = tree.get("insert_rebalance_binding")
        if not isinstance(insert, dict) or insert.get("status") != "VERIFIED_STATIC":
            errors.append("tree_insert_binding")
        else:
            candidates = insert.get("candidates", [])
            if len(candidates) != 1 or candidates[0].get("symbol") != (
                "_ZSt29_Rb_tree_insert_and_rebalancebPSt18_Rb_tree_node_baseS0_RS_"
            ):
                errors.append("tree_insert_symbol")
        callers = tree.get("insert_callers")
        if not isinstance(callers, dict) or callers.get("status") != "PRIMARY_ELF_VERIFIED":
            errors.append("tree_insert_callers")
        elif callers.get("prmset_mutator_entry") != "UNKNOWN":
            errors.append("tree_mutator_promotion")
    safety = report.get("safety_boundaries")
    if not isinstance(safety, dict):
        errors.append("missing_safety_boundaries")
    else:
        if safety.get("runtime_safe") is not False:
            errors.append("safety_runtime_promotion")
        for name, expected_status in (
            ("get_set_null_receiver", "PRIMARY_ELF_VERIFIED"),
            ("get_set_lifetime", "STATIC_INFERRED"),
            ("destructor_payload_guard", "PRIMARY_ELF_VERIFIED"),
            ("invalid_element", "UNKNOWN"),
            ("concurrency", "UNKNOWN"),
        ):
            item = safety.get(name)
            if not isinstance(item, dict) or item.get("status") != expected_status:
                errors.append(f"safety_status:{name}")
    expected = {target["name"] for target in TARGETS}
    observations = report.get("observations")
    if not isinstance(observations, dict) or not expected.issubset(observations):
        errors.append("missing_observations")
    else:
        for name in expected:
            if observations[name].get("status") != "PRIMARY_ELF_VERIFIED":
                errors.append(f"observation:{name}")
        for name in ("prmset_payload_helper", "prmset_clone"):
            cleanup = observations[name].get("exception_cleanup")
            if not isinstance(cleanup, dict) or cleanup.get("status") != "STATIC_INFERRED":
                errors.append(f"exception_cleanup:{name}")
        expected_cleanup = {
            "prmset_payload_helper": ("0x7efb9c", ["0xffe0c", "0xe4734", "0xdd4f8"]),
            "prmset_clone": ("0x7efbce", ["0xdd620", "0xdd4f8"]),
        }
        for name, (landing_pad, calls) in expected_cleanup.items():
            cleanup = observations[name].get("exception_cleanup")
            if isinstance(cleanup, dict):
                if cleanup.get("landing_pad_candidate") != landing_pad:
                    errors.append(f"exception_cleanup_locator:{name}")
                if cleanup.get("calls") != calls:
                    errors.append(f"exception_cleanup_calls:{name}")
    direct_scan = report.get("direct_call_scan")
    if not isinstance(direct_scan, dict):
        errors.append("missing_direct_call_scan")
    else:
        if direct_scan.get("status") != "PRIMARY_ELF_VERIFIED":
            errors.append("direct_call_scan_status")
        if direct_scan.get("address_space") != "ELF_VMA":
            errors.append("direct_call_scan_address_space")
        expected_targets = {
            "get_set": "0x7efae8",
            "get": "0x7efaf0",
            "constructor": "0x7efb00",
            "destructor": "0x7efb2c",
            "deleting_destructor": "0x7efb58",
            "clone": "0x7efbb4",
        }
        rows = direct_scan.get("targets")
        if not isinstance(rows, dict):
            errors.append("direct_call_scan_targets")
        else:
            for name, target in expected_targets.items():
                row = rows.get(name)
                if not isinstance(row, dict):
                    errors.append(f"direct_call_scan_target:{name}")
                    continue
                if row.get("target") != target:
                    errors.append(f"direct_call_scan_locator:{name}")
                if row.get("status") != "PRIMARY_ELF_VERIFIED":
                    errors.append(f"direct_call_scan_target_status:{name}")
                callsites = row.get("direct_callsite_addresses")
                if not isinstance(callsites, list) or row.get("direct_callsite_count") != len(callsites):
                    errors.append(f"direct_call_scan_count:{name}")
    return {"valid": not errors, "errors": sorted(set(errors))}
