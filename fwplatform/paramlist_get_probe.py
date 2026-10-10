"""Primary-ELF evidence probe for the ParamList query ABI.

The probe makes the already recovered lookup facts executable and
fail-closed.  It verifies the element-field roles used by the real
``ParamList::get`` body and by the local query forwarders, while keeping the
source-level C++ return type, ownership and runtime safety explicitly
unknown.  It reads only an exact SHA-pinned private ELF and emits metadata;
firmware bytes are never returned.
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


ADDRESS_SPACE = "ELF_VMA"
GET_TARGET = {
    "name": "ParamList::get",
    "entry": 0x7EDACA,
    "symbol_value": 0x7EDACB,
    "size": 0x4C,
    "symbol": "_ZNK9ParamList3getEmm",
}
KEY_ACCESSOR = {"entry": 0x7EDA8C, "size": 0x0C}
DISCRIMINATOR_ACCESSOR = {"entry": 0x7EDA94, "size": 0x0C}
COUNT_HELPER = {"entry": 0x7EDAB0, "size": 0x0E}
ELEMENT_HELPER = {"entry": 0x7EDABE, "size": 0x0C}
PAYLOAD_GETTER = {"entry": 0xE5B18, "size": 0x0C}
GET_FORWARDER = {"entry": 0xE5B20, "size": 0x0E}
GET_PLT = 0xE2890
WORD_WRAPPER = {"entry": 0x42AC00, "size": 0x24}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_exec_range(fp: Any, elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > 0x200:
        raise ValueError("ParamList query read exceeds bounded probe limit")
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


def _decode(fp: Any, elf: ELFFile, entry: int, size: int, label: str) -> dict[int, Any]:
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    rows = list(decoder.disasm(_read_exec_range(fp, elf, entry, size), entry))
    if not rows:
        raise ValueError(f"{label} did not decode")
    return {int(row.address): row for row in rows}


def _symbols(elf: ELFFile) -> dict[str, tuple[int, int]]:
    result: dict[str, tuple[int, int]] = {}
    for section_name in (".dynsym", ".symtab"):
        section = elf.get_section_by_name(section_name)
        if section is None:
            continue
        for symbol in section.iter_symbols():
            if symbol.name and symbol.name not in result:
                result[symbol.name] = (
                    int(symbol["st_value"]), int(symbol["st_size"]),
                )
    return result


def _immediates(instruction: Any) -> list[int]:
    return [int(operand.imm) for operand in instruction.operands
            if operand.type == ARM_OP_IMM]


def _require(
    rows: dict[int, Any], address: int, mnemonic: str, *,
    operands: str | None = None, target: int | None = None,
    immediate: int | None = None,
) -> Any:
    instruction = rows.get(address)
    if instruction is None or instruction.mnemonic.lower() != mnemonic.lower():
        raise ValueError(f"unexpected {mnemonic} at 0x{address:x}")
    if operands is not None and instruction.op_str.lower() != operands.lower():
        raise ValueError(f"unexpected operands at 0x{address:x}")
    if target is not None and target not in _immediates(instruction):
        raise ValueError(f"unexpected branch target at 0x{address:x}")
    if immediate is not None and immediate not in _immediates(instruction):
        raise ValueError(f"unexpected immediate at 0x{address:x}")
    return instruction


def _observe_accessors(fp: Any, elf: ELFFile) -> dict[str, Any]:
    key = _decode(fp, elf, KEY_ACCESSOR["entry"], KEY_ACCESSOR["size"], "key accessor")
    discriminator = _decode(
        fp, elf, DISCRIMINATOR_ACCESSOR["entry"], DISCRIMINATOR_ACCESSOR["size"],
        "discriminator accessor",
    )
    count = _decode(fp, elf, COUNT_HELPER["entry"], COUNT_HELPER["size"], "count helper")
    element = _decode(fp, elf, ELEMENT_HELPER["entry"], ELEMENT_HELPER["size"], "element helper")
    _require(key, 0x7EDA90, "ldr", operands="r0, [r0, #4]")
    _require(discriminator, 0x7EDA98, "ldr", operands="r0, [r0, #8]")
    _require(count, 0x7EDAB0, "ldr", operands="r2, [r0, #4]")
    _require(count, 0x7EDAB2, "ldr", operands="r3, [r0]")
    _require(count, 0x7EDAB6, "subs", operands="r0, r2, r3")
    _require(count, 0x7EDABA, "asrs", operands="r0, r0, #2")
    _require(element, 0x7EDABE, "ldr", operands="r0, [r0]")
    _require(element, 0x7EDAC2, "add.w", operands="r0, r0, r1, lsl #2")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "count": {
            "entry": "0x7edab0",
            "operation": "(storage_end - storage_begin) >> 2",
            "element_width_bytes": 4,
        },
        "element_at": {
            "entry": "0x7edabe",
            "operation": "storage_begin + (index * 4)",
            "return": "address of element pointer slot",
        },
        "fields": {
            "+0x04": {
                "role": "discriminator/value-type word",
                "accessor": "0x7eda8c",
                "status": "PRIMARY_ELF_VERIFIED",
            },
            "+0x08": {
                "role": "lookup key word",
                "accessor": "0x7eda94",
                "status": "PRIMARY_ELF_VERIFIED",
            },
            "+0x0c": {
                "role": "payload word returned by 0xe5b18",
                "getter": "0xe5b18",
                "status": "PRIMARY_ELF_VERIFIED",
            },
        },
        "null_element_guard": "NONE_OBSERVED_IN_BOUNDED_GET_BODY",
    }


def _observe_get(fp: Any, elf: ELFFile) -> dict[str, Any]:
    rows = _decode(fp, elf, GET_TARGET["entry"], GET_TARGET["size"], "ParamList::get")
    checks = (
        (0x7EDACA, "push.w", None, None),
        (0x7EDAD0, "ldr", "r6, [r0]", None),
        (0x7EDAD2, "mov", "r4, r1", None),
        (0x7EDAD4, "mov", "sb, r2", None),
        (0x7EDADA, "bl", None, 0x7EDAB0),
        (0x7EDAE6, "bl", None, 0x7EDABE),
        (0x7EDAEA, "ldr.w", "sl, [r0]", None),
        (0x7EDAF0, "bl", None, 0x7EDA8C),
        (0x7EDAF8, "bl", None, 0x7EDA94),
        (0x7EDAFC, "cmp", None, None),
        (0x7EDB00, "cmp", None, None),
        (0x7EDB0A, "movs", None, None),
        (0x7EDB10, "mov", "r0, sl", None),
    )
    for address, mnemonic, operands, target in checks:
        _require(rows, address, mnemonic, operands=operands, target=target)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "symbol": GET_TARGET["symbol"],
        "symbol_value_thumb": "0x7edacb",
        "entry_vma": "0x7edaca",
        "size_bytes": 0x4C,
        "abi": {
            "r0": "ParamList receiver candidate",
            "r1": "lookup key; copied to r4 and compared with element +0x08",
            "r2": "discriminator; copied to sb and compared with element +0x04",
            "r3": "not observed as an explicit source-level parameter",
            "return": "matching stored element pointer, or zero after exhausting the range",
        },
        "algorithm": {
            "storage": "receiver +0x00 points to contiguous element-pointer storage",
            "count": "(storage +0x04 - storage +0x00) >> 2",
            "iteration": "index starts at zero and increments until count",
            "match": "element +0x04 equals r2 and element +0x08 equals r1",
            "success": "returns the matching element pointer without a local retain",
            "failure": "returns zero",
        },
        "lifetime": {
            "result_kind": "borrowed-pointer candidate; no retain/add-ref instruction observed",
            "invalidation": "UNKNOWN; clear, replacement, shared ownership and concurrency are outside this body",
            "null_element": "UNKNOWN; no element-pointer null guard is present before field reads",
        },
        "return_cpp_type_verified": False,
        "ownership_verified": False,
    }


def _observe_forwarders(fp: Any, elf: ELFFile) -> dict[str, Any]:
    payload = _decode(fp, elf, PAYLOAD_GETTER["entry"], PAYLOAD_GETTER["size"], "payload getter")
    forwarder = _decode(fp, elf, GET_FORWARDER["entry"], GET_FORWARDER["size"], "get forwarder")
    wrapper = _decode(fp, elf, WORD_WRAPPER["entry"], WORD_WRAPPER["size"], "word wrapper")
    _require(payload, 0xE5B1C, "ldr", operands="r0, [r0, #0xc]")
    _require(forwarder, 0xE5B22, "movs", operands="r2, #1")
    _require(forwarder, 0xE5B2A, "b.w", target=GET_PLT)
    _require(wrapper, 0x42AC00, "ldr", operands="r0, [r0, #4]")
    _require(wrapper, 0x42AC02, "push", operands="{r3, r4, r7, lr}")
    _require(wrapper, 0x42AC08, "cbz", target=0x42AC1C)
    _require(wrapper, 0x42AC0A, "cbz", target=0x42AC1C)
    _require(wrapper, 0x42AC0C, "bl", target=GET_FORWARDER["entry"])
    _require(wrapper, 0x42AC10, "cbz", target=0x42AC20)
    _require(wrapper, 0x42AC12, "bl", target=PAYLOAD_GETTER["entry"])
    _require(wrapper, 0x42AC16, "str", operands="r0, [r4]")
    _require(wrapper, 0x42AC18, "movs", operands="r0, #0")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "payload_getter": {
            "entry": "0xe5b18",
            "operation": "reads element +0x0c and returns the word",
        },
        "get_forwarder": {
            "entry": "0xe5b20",
            "operation": "sets discriminator r2=1 and tail-branches to ParamList::get PLT",
            "plt_entry": "0xe2890",
            "plt_binding": resolve_plt_binding(fp, elf, GET_PLT, thumb_stub=True),
        },
        "word_wrapper": {
            "entry": "0x42ac00",
            "inputs": {
                "r0": "wrapper object; [r0+4] is the ParamList pointer candidate",
                "r1": "lookup key",
                "r2": "caller output address; preserved in r4",
            },
            "success": "nonzero element result -> read +0x0c, store one 32-bit word, return 0",
            "failure": "null wrapper/list/output or null lookup result -> return 1",
        },
    }


def probe_paramlist_get(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Validate the primary ParamList query and its local wrappers."""
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
        symbol_value, symbol_size = symbols.get(GET_TARGET["symbol"], (0, 0))
        if symbol_value != GET_TARGET["symbol_value"] or symbol_size != GET_TARGET["size"]:
            raise ValueError("ParamList::get symbol identity/size mismatch")
        accessors = _observe_accessors(fp, elf)
        get_body = _observe_get(fp, elf)
        forwarders = _observe_forwarders(fp, elf)
    return {
        "schema_version": 1,
        "status": "LOCAL_PRIMARY_ELF_PARAMLIST_GET_EVIDENCE_ONLY",
        "firmware_version": "3.21",
        "binary_file_sha256": digest,
        "address_space": ADDRESS_SPACE,
        "target": GET_TARGET,
        "element_layout": {
            "vptr_plus_00": "concrete ParamBase-derived vtable address point",
            "discriminator_plus_04": "constructor-supplied ParamBase family discriminator",
            "key_plus_08": "ParamList lookup key written by the separate key setter",
            "payload_plus_0c": "concrete-family payload word or storage; type depends on discriminator",
            "status": "PRIMARY_ELF_VERIFIED for offsets/accesses; concrete payload type is family-specific",
        },
        "accessors": accessors,
        "get": get_body,
        "forwarders": forwarders,
        "safety": {
            "runtime_verified": False,
            "callable": False,
            "null_receiver": "UNKNOWN; no general runtime guard is established",
            "invalid_index": "UNKNOWN; count/element range is assumed by the bounded loop",
            "shared_container": "UNKNOWN; ParamList shared-counter/lifetime is tracked separately",
            "concurrency": "UNKNOWN; no lock or atomic operation occurs in the bounded get body",
        },
        "limitations": [
            "The concrete C++ return type is not encoded by the symbol and remains unverified",
            "The payload type is selected by the discriminator and is not a universal uint32 ABI",
            "No reference-count increment, lifetime extension or concurrency guarantee is observed",
            "The ELF was not executed and no device was accessed",
        ],
    }


def validate_paramlist_get(report: dict[str, Any]) -> dict[str, Any]:
    """Reject wrong identity and any promotion beyond static evidence."""
    errors: list[str] = []
    if report.get("schema_version") != 1:
        errors.append("schema_version")
    if report.get("status") != "LOCAL_PRIMARY_ELF_PARAMLIST_GET_EVIDENCE_ONLY":
        errors.append("status")
    if report.get("firmware_version") != "3.21":
        errors.append("firmware_version")
    if report.get("binary_file_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != ADDRESS_SPACE:
        errors.append("address_space")
    target = report.get("target") or {}
    if (target.get("entry") != GET_TARGET["entry"]
            or target.get("symbol_value") != GET_TARGET["symbol_value"]
            or target.get("size") != GET_TARGET["size"]
            or target.get("symbol") != GET_TARGET["symbol"]):
        errors.append("target_identity")
    if report.get("element_layout", {}).get("status") != (
        "PRIMARY_ELF_VERIFIED for offsets/accesses; concrete payload type is family-specific"
    ):
        errors.append("element_layout_scope")
    get_body = report.get("get") or {}
    if get_body.get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("get_status")
    if get_body.get("return_cpp_type_verified") is not False:
        errors.append("return_type_promotion")
    if get_body.get("ownership_verified") is not False:
        errors.append("ownership_promotion")
    abi = get_body.get("abi") or {}
    if abi.get("r1") != "lookup key; copied to r4 and compared with element +0x08":
        errors.append("key_role")
    if abi.get("r2") != "discriminator; copied to sb and compared with element +0x04":
        errors.append("discriminator_role")
    lifetime = get_body.get("lifetime") or {}
    if lifetime.get("result_kind") != (
        "borrowed-pointer candidate; no retain/add-ref instruction observed"
    ):
        errors.append("borrowed_scope")
    accessors = report.get("accessors") or {}
    if accessors.get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("accessor_status")
    fields = accessors.get("fields") or {}
    expected_roles = {
        "+0x04": "discriminator/value-type word",
        "+0x08": "lookup key word",
        "+0x0c": "payload word returned by 0xe5b18",
    }
    for offset, role in expected_roles.items():
        if (fields.get(offset) or {}).get("role") != role:
            errors.append(f"field:{offset}")
        if (fields.get(offset) or {}).get("status") != "PRIMARY_ELF_VERIFIED":
            errors.append(f"field_status:{offset}")
    forwarders = report.get("forwarders") or {}
    if forwarders.get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("forwarder_status")
    binding = (forwarders.get("get_forwarder") or {}).get("plt_binding") or {}
    candidates = binding.get("candidates") or []
    if (binding.get("status") != "VERIFIED_STATIC" or len(candidates) != 1
            or candidates[0].get("symbol") != GET_TARGET["symbol"]):
        errors.append("get_plt_binding")
    safety = report.get("safety") or {}
    if safety.get("runtime_verified") is not False or safety.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    return {"valid": not errors, "errors": sorted(set(errors))}
