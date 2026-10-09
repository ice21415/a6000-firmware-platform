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
    {"name": "prmset_payload_helper", "entry": 0x7EFB6C, "size": 0x30},
    {"name": "prmset_destructor", "entry": 0x7EFB2C, "size": 0x20},
    {"name": "prmset_deleting_destructor", "entry": 0x7EFB58, "size": 0x14},
    {"name": "prmset_clone", "entry": 0x7EFBB4, "size": 0x1C},
    {"name": "payload_default_init", "entry": 0xFFD22, "size": 0x0E},
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


def _observe_payload_helper(rows: dict[int, Any], bindings: dict[str, Any]) -> dict[str, Any]:
    _require(rows, 0x7EFB72, "movs", immediate=7)
    _require(rows, 0x7EFB78, "blx", target=0xE11A4)
    _require(rows, 0x7EFB86, "str")
    _require(rows, 0x7EFB8C, "bl", target=0xFFD22)
    _require(rows, 0x7EFB94, "bl", target=0x63E8A6)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "inputs": {"r0": "destination PrmSet-like object", "r1": "source payload pointer candidate"},
        "operation": "initialize destination base/payload, then copy source payload through 0x63e8a6",
        "payload_source": "source r1 is preserved in the local helper and passed to payload copy",
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


def _observe_clone(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0x7EFBB4, "push")
    _require(rows, 0x7EFBBA, "movs", immediate=0x24)
    _require(rows, 0x7EFBBC, "blx", target=0xDC100)
    _require(rows, 0x7EFBC0, "add.w")
    _require(rows, 0x7EFBC6, "bl", target=0x7EFB6C)
    _require(rows, 0x7EFBCA, "mov", operands="r0, r4")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "allocation": "0x24-byte destination allocation through 0xdc100",
        "source_payload": "source receiver +0x0c passed to the helper",
        "return": "destination pointer remains in r0 on the success path; source-level clone return UNKNOWN",
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
    section = elf.get_section_by_name(".text")
    if section is None or not (int(section["sh_flags"]) & 4):
        return []
    offset = int(section["sh_offset"])
    base = int(section["sh_addr"])
    size = int(section["sh_size"])
    fp.seek(offset)
    data = fp.read(size)
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True

    def sign_extend(value: int, bits: int) -> int:
        return value - (1 << bits) if value & (1 << (bits - 1)) else value

    callers: list[int] = []
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
        if destination != target:
            continue
        rows = list(decoder.disasm(data[index:index + 4], caller, count=1))
        if rows and rows[0].mnemonic.lower() == "bl":
            callers.append(caller)
    return callers


def _observe_tree_insert_callers(fp: Any, elf: ELFFile) -> dict[str, Any]:
    callers = _thumb_bl_callers(fp, elf, 0xFFE70)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "target": "0xffe70",
        "scan": "executable .text Thumb BL immediate encodings, Capstone-confirmed",
        "direct_callsite_addresses": [f"0x{address:x}" for address in callers],
        "direct_callsite_count": len(callers),
        "prmset_mutator_entry": "UNKNOWN",
        "prmset_relation": "UNKNOWN; no callsite is proven to consume PrmSet::getSet() in this ELF-only scan",
        "function_boundary_resolution": "UNKNOWN; stripped local helper callers are not promoted from nearest-address heuristics",
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
                _decode(fp, elf, 0x7EFB6C, 0x30),
                {"param_base_constructor": bindings["param_base_constructor"]},
            ),
            "prmset_destructor": _observe_destructor(_decode(fp, elf, 0x7EFB2C, 0x20)),
            "prmset_deleting_destructor": _observe_deleting_destructor(
                _decode(fp, elf, 0x7EFB58, 0x14), bindings["delete"],
            ),
            "prmset_clone": _observe_clone(_decode(fp, elf, 0x7EFBB4, 0x1C)),
            "payload_default_init": _observe_payload_default_init(
                _decode(fp, elf, 0xFFD22, 0x0E),
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
        observations["payload_tree_insert_callers"] = _observe_tree_insert_callers(fp, elf)
    return {
        "status": "LOCAL_PRIMARY_ELF_PRMSET_EVIDENCE_ONLY",
        "binary_file_sha256": digest,
        "address_space": "ELF_VMA",
        "type": "PrmSet",
        "discriminator": 7,
        "allocation_size_bytes": 0x24,
        "inheritance": {
            "status": "PRIMARY_ELF_VERIFIED",
            "base_type": "ParamBase",
            "rtti_name": "6PrmSet",
            "rtti_vma": "0x1019d08",
            "vtable_prefix_vma": "0x1019d18",
            "vtable_address_point": "0x1019d20",
            "relation": "direct RTTI +0x08 relocation to _ZTI9ParamBase and vtable typeinfo relation",
            "source": "cross-checked against param_base_3_21.json; source class declaration remains descriptive",
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
                "ordered-associative-tree-like payload; ELF-local _Rb_tree ABI evidence is direct, "
                "but the exact PrmSet source alias and element type remain UNKNOWN"
            ),
            "tree_evidence": {
                "status": "PRIMARY_ELF_VERIFIED",
                "node_size_bytes": 0x14,
                "node_value_offset": 0x10,
                "node_value_width_bytes": 4,
                "header_sentinel_offset": 0x04,
                "node_count_offset": 0x14,
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
        "observations": observations,
        "ownership": {
            "constructor": "embedded payload initialized in a newly allocated 0x24-byte object",
            "get_set": "returns a borrowed pointer into the object; no retain operation observed",
            "clone": "allocates a separate object and copies payload through 0x63e8a6",
            "destructor": "releases embedded payload then calls ParamBase destruction path",
            "status": "STATIC_INFERRED; container allocator, aliases, exceptions and synchronization UNKNOWN",
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
    tree = report.get("payload_layout", {}).get("tree_evidence")
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
    expected = {target["name"] for target in TARGETS}
    observations = report.get("observations")
    if not isinstance(observations, dict) or not expected.issubset(observations):
        errors.append("missing_observations")
    else:
        for name in expected:
            if observations[name].get("status") != "PRIMARY_ELF_VERIFIED":
                errors.append(f"observation:{name}")
    return {"valid": not errors, "errors": sorted(set(errors))}
