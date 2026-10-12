"""Evidence-gated owner-constructor candidate for the EventManager layout.

The stripped primary ELF has no exported ``EventManager`` constructor symbol,
but the function-like region at ``0x7ef254`` initializes every field consumed
by the symbol-bound ``EventManager::push`` and ``EventManager::count``
methods.  This probe records that relationship as ``STATIC_INFERRED`` and
keeps the source-level constructor identity, provider type and runtime
ownership unknown.
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
CONSTRUCTOR = {
    "name": "EventManager constructor-like owner initializer",
    "entry": 0x7EF254,
    "bounded_size": 0x128,
    "symbol": None,
}
NAME_HELPER = {"entry": 0x7EF1E4, "bounded_size": 0x5C}
EVENT_MANAGER_INITIALIZER = 0x7EF894
ALLOCATOR_PLT = 0xDC100
PUSH_SYMBOL = {
    "name": "_ZN12EventManager4pushEP5Eventb",
    "entry": 0x7EF960,
    "size": 0x9C,
}
COUNT_SYMBOL = {
    "name": "_ZN12EventManager5countEj",
    "entry": 0x7EF9FC,
    "size": 0x22,
}

# This is sanitized metadata from the private ASCII-path Ghidra run.  It is
# deliberately a *targeted* ``-noanalysis`` export: the script prepared
# bounded regions and decompiled them, so these counts are an independent
# disassembly/CFG cross-check rather than whole-program Auto Analysis or a
# source-level class proof.  No raw instructions, decompiler text or private
# project paths are part of the contract.
GHIDRA_CROSSCHECK = {
    "status": "VERIFIED_STATIC",
    "tool": "Ghidra",
    "version": "12.1.3",
    "profile": "event-manager-constructor",
    "binary_sha256": EXPECTED_LIBOBJ_SHA,
    "program_sha256": EXPECTED_LIBOBJ_SHA,
    "language": "ARM:LE:32:v8",
    "compiler_spec": "default",
    "image_base": "0x10000",
    "address_space": "ram",
    "execution": {
        "exit_code": 0,
        "completion_marker": True,
        "analysis_mode": "targeted_noanalysis_bounded_export",
        "auto_analysis_completed": False,
    },
    "target_count": 5,
    "instruction_count": 260,
    "basic_block_count": 18,
    "cfg_edge_count": 65,
    "target_records": [
        {"elf_vma": "0x7ef1e4", "ghidra_address": "0x7ff1e4", "instruction_count": 38, "basic_block_count": 7, "cfg_edge_count": 14},
        {"elf_vma": "0x7ef254", "ghidra_address": "0x7ff254", "instruction_count": 118, "basic_block_count": 1, "cfg_edge_count": 20},
        {"elf_vma": "0x7ef894", "ghidra_address": "0x7ff894", "instruction_count": 31, "basic_block_count": 1, "cfg_edge_count": 6},
        {"elf_vma": "0x7ef960", "ghidra_address": "0x7ff960", "instruction_count": 60, "basic_block_count": 8, "cfg_edge_count": 22},
        {"elf_vma": "0x7ef9fc", "ghidra_address": "0x7ff9fc", "instruction_count": 13, "basic_block_count": 1, "cfg_edge_count": 3},
    ],
    "raw_export_private": True,
    "runtime_verified": False,
    "callable": False,
    "semantic_names_verified": False,
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_exec_range(fp: Any, elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > 0x240:
        raise ValueError("EventManager constructor read exceeds bounded limit")
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
        raise ValueError(f"unexpected target at 0x{address:x}")
    if immediate is not None and immediate not in _immediates(instruction):
        raise ValueError(f"unexpected immediate at 0x{address:x}")
    return instruction


def _binding(fp: Any, elf: ELFFile, entry: int) -> dict[str, Any]:
    binding = resolve_plt_binding(fp, elf, entry, thumb_stub=False)
    if binding.get("status") != "VERIFIED_STATIC":
        raise ValueError(f"PLT binding at 0x{entry:x} is not unique")
    return binding


def _observe_name_helper(fp: Any, elf: ELFFile) -> dict[str, Any]:
    rows = _decode(fp, elf, NAME_HELPER["entry"], NAME_HELPER["bounded_size"], "name helper")
    _require(rows, 0x7EF1E4, "push")
    _require(rows, 0x7EF1E6, "mov", operands="r6, r0")
    _require(rows, 0x7EF1EA, "mov", operands="r0, r1")
    _require(rows, 0x7EF1EE, "blx", target=0xDD7B8)
    _require(rows, 0x7EF1F8, "cmp", immediate=0x14)
    _require(rows, 0x7EF200, "add.w", operands="r0, r6, #0x2c")
    _require(rows, 0x7EF204, "blx", target=0xDCE00)
    _require(rows, 0x7EF20E, "strb.w", operands="r3, [r6, #0x3f]")
    _require(rows, 0x7EF216, "blx", target=0xDFBB8)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "input": "r0 receiver candidate, r1 pointer-like source used by strlen/strncpy",
        "receiver_name_storage": "+0x2c through bounded strncpy, terminator byte at +0x3f",
        "length_limit": "0x14 bytes",
        "provider_result": "return register from this helper is stored by the owner at +0x14",
        "plt_bindings": {
            "strlen": _binding(fp, elf, 0xDD7B8),
            "strncpy": _binding(fp, elf, 0xDCE00),
            "strncmp": _binding(fp, elf, 0xDFBB8),
        },
    }


def _observe_constructor(fp: Any, elf: ELFFile) -> dict[str, Any]:
    rows = _decode(fp, elf, CONSTRUCTOR["entry"], CONSTRUCTOR["bounded_size"], "owner constructor candidate")
    _require(rows, 0x7EF254, "push.w")
    _require(rows, 0x7EF262, "str", operands="r3, [r0, #0x28]")
    _require(rows, 0x7EF266, "str", operands="r6, [r0, #0x24]")
    _require(rows, 0x7EF268, "bl", target=0x7EF1E4)
    _require(rows, 0x7EF270, "str", operands="r0, [r4, #0x14]")
    _require(rows, 0x7EF2B4, "movs", immediate=0x24)
    _require(rows, 0x7EF2BA, "blx", target=ALLOCATOR_PLT)
    _require(rows, 0x7EF2CA, "bl", target=EVENT_MANAGER_INITIALIZER)
    _require(rows, 0x7EF2D4, "str", operands="r6, [r4, #0x10]")
    _require(rows, 0x7EF2D8, "blx", target=ALLOCATOR_PLT)
    _require(rows, 0x7EF2E0, "bl", target=0x7F4934)
    _require(rows, 0x7EF2E4, "str", operands="r5, [r4, #0xc]")
    _require(rows, 0x7EF2E8, "blx", target=ALLOCATOR_PLT)
    _require(rows, 0x7EF2F0, "bl", target=0x7F4FCC)
    _require(rows, 0x7EF2F4, "str", operands="r5, [r4, #8]")
    _require(rows, 0x7EF2F8, "blx", target=ALLOCATOR_PLT)
    _require(rows, 0x7EF302, "bl", target=0x7EC384)
    _require(rows, 0x7EF306, "str", operands="r5, [r4, #4]")
    _require(rows, 0x7EF30A, "blx", target=ALLOCATOR_PLT)
    _require(rows, 0x7EF31A, "bl", target=0x7F3B00)
    _require(rows, 0x7EF332, "str", operands="r0, [r4, #0x1c]")
    _require(rows, 0x7EF34A, "str", operands="r0, [r4, #0x20]")
    _require(rows, 0x7EF364, "str", operands="r0, [r4, #0x18]")
    _require(rows, 0x7EF372, "pop.w")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "bounded_scope": "0x7ef254..0x7ef373; constructor-like field initialization and cleanup landing pads are not a source-level boundary",
        "input_registers": {
            "r0": "owner receiver candidate",
            "r1": "pointer-like name/source candidate consumed by strlen/strncpy in 0x7ef1e4",
            "r2_r3": "not assigned a source-level constructor meaning",
        },
        "field_initialization": {
            "+0x00": {"allocation_size": "0x7c", "initializer": "0x7f3b00"},
            "+0x04": {"allocation_size": "0xac", "initializer": "0x7ec384"},
            "+0x08": {"allocation_size": "0x38", "initializer": "0x7f4fcc"},
            "+0x0c": {"allocation_size": "0x28", "initializer": "0x7f4934"},
            "+0x10": {"allocation_size": "0x24", "initializer": "0x7ef894"},
            "+0x14": {"initializer": "0x7ef1e4 return value"},
            "+0x18": {"initializer": "0x10afb8 return value"},
            "+0x1c": {"initializer": "virtual call through [owner+0x14] vtable +0x3c"},
            "+0x20": {"initializer": "virtual call through [owner+0x14] vtable +0x2c"},
            "+0x24": {"value": "zero"},
            "+0x28": {"value": "0x80000000 sentinel via MVN"},
        },
        "provider": {
            "field": "+0x14",
            "source": "return register from 0x7ef1e4",
            "type": "UNKNOWN; no RTTI/vtable source-level identity recovered",
        },
        "lifetime": {
            "exception_landing_pads": "present after the bounded normal body; exact EHABI ownership/cleanup semantics remain UNKNOWN",
            "owner_destructor": "UNKNOWN; separate cleanup witness deletes selected subobjects but does not prove this constructor pair",
        },
    }


def _method_identity(elf: ELFFile) -> dict[str, Any]:
    symbols = _symbols(elf)
    for spec in (PUSH_SYMBOL, COUNT_SYMBOL):
        value, size = symbols.get(spec["name"], (0, 0))
        if (value & ~1) != spec["entry"] or size != spec["size"]:
            raise ValueError(f"{spec['name']} symbol identity mismatch")
    constructor_symbols = sorted(
        name for name, (value, size) in symbols.items()
        if name.startswith("_ZN12EventManagerC") and value
    )
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "push": PUSH_SYMBOL,
        "count": COUNT_SYMBOL,
        "constructor_symbol_candidates": constructor_symbols,
        "constructor_identity": "UNKNOWN; no nonzero EventManager constructor symbol in available symbol tables",
        "layout_relation": "STATIC_INFERRED; candidate initializes fields consumed by the symbol-bound push/count methods",
    }


def probe_event_manager_constructor(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Validate the bounded EventManager owner-constructor candidate."""
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
        name_helper = _observe_name_helper(fp, elf)
        constructor = _observe_constructor(fp, elf)
        methods = _method_identity(elf)
        allocator = _binding(fp, elf, ALLOCATOR_PLT)
    return {
        "schema_version": 1,
        "status": "LOCAL_PRIMARY_ELF_EVENT_MANAGER_CONSTRUCTOR_CANDIDATE",
        "firmware_version": "3.21",
        "binary_file_sha256": digest,
        "address_space": ADDRESS_SPACE,
        "target": CONSTRUCTOR,
        "name_helper": name_helper,
        "constructor": constructor,
        "method_identity": methods,
        "allocator_binding": allocator,
        "ghidra_crosscheck": GHIDRA_CROSSCHECK,
        "semantic_status": "STATIC_INFERRED",
        "runtime_verified": False,
        "callable": False,
        "limitations": [
            "No source-level constructor name, RTTI record or EventManager vtable ownership was found",
            "The +0x14 provider type and virtual-call targets remain UNKNOWN",
            "Allocation success, exception cleanup, concurrent access and loader binding remain UNKNOWN",
            "Static layout compatibility is not a proof of C++ class identity or safe invocation",
            "The ELF was not executed and no camera was accessed",
        ],
    }


def validate_event_manager_constructor(report: dict[str, Any]) -> dict[str, Any]:
    """Fail closed on source-identity or runtime/callable promotion."""
    errors: list[str] = []
    if report.get("schema_version") != 1:
        errors.append("schema_version")
    if report.get("status") != "LOCAL_PRIMARY_ELF_EVENT_MANAGER_CONSTRUCTOR_CANDIDATE":
        errors.append("status")
    if report.get("firmware_version") != "3.21":
        errors.append("firmware_version")
    if report.get("binary_file_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != ADDRESS_SPACE:
        errors.append("address_space")
    target = report.get("target") or {}
    if target.get("entry") != CONSTRUCTOR["entry"] or target.get("bounded_size") != CONSTRUCTOR["bounded_size"]:
        errors.append("target_identity")
    if report.get("semantic_status") != "STATIC_INFERRED":
        errors.append("semantic_status")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    if (report.get("name_helper") or {}).get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("name_helper_status")
    constructor = report.get("constructor") or {}
    if constructor.get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("constructor_status")
    if (constructor.get("provider") or {}).get("type") != "UNKNOWN; no RTTI/vtable source-level identity recovered":
        errors.append("provider_type_scope")
    if (report.get("method_identity") or {}).get("constructor_identity") != (
        "UNKNOWN; no nonzero EventManager constructor symbol in available symbol tables"
    ):
        errors.append("constructor_identity_scope")
    if (report.get("method_identity") or {}).get("layout_relation") != (
        "STATIC_INFERRED; candidate initializes fields consumed by the symbol-bound push/count methods"
    ):
        errors.append("layout_relation_scope")
    binding = report.get("allocator_binding") or {}
    candidates = binding.get("candidates") or []
    if binding.get("status") != "VERIFIED_STATIC" or len(candidates) != 1 or candidates[0].get("symbol") != "_Znwj":
        errors.append("allocator_binding")
    crosscheck = report.get("ghidra_crosscheck") or {}
    if crosscheck.get("status") != GHIDRA_CROSSCHECK["status"]:
        errors.append("ghidra_status")
    if crosscheck.get("version") != GHIDRA_CROSSCHECK["version"]:
        errors.append("ghidra_version")
    if crosscheck.get("profile") != GHIDRA_CROSSCHECK["profile"]:
        errors.append("ghidra_profile")
    if crosscheck.get("binary_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("ghidra_binary_identity")
    if crosscheck.get("program_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("ghidra_program_identity")
    if crosscheck.get("language") != GHIDRA_CROSSCHECK["language"]:
        errors.append("ghidra_language")
    if crosscheck.get("compiler_spec") != GHIDRA_CROSSCHECK["compiler_spec"]:
        errors.append("ghidra_compiler_spec")
    if crosscheck.get("image_base") != GHIDRA_CROSSCHECK["image_base"]:
        errors.append("ghidra_image_base")
    if crosscheck.get("address_space") != GHIDRA_CROSSCHECK["address_space"]:
        errors.append("ghidra_address_space")
    execution = crosscheck.get("execution") or {}
    if execution.get("exit_code") != 0 or execution.get("completion_marker") is not True:
        errors.append("ghidra_execution")
    if execution.get("analysis_mode") != GHIDRA_CROSSCHECK["execution"]["analysis_mode"]:
        errors.append("ghidra_analysis_mode")
    if execution.get("auto_analysis_completed") is not False:
        errors.append("ghidra_auto_analysis_scope")
    for field in ("target_count", "instruction_count", "basic_block_count", "cfg_edge_count"):
        if crosscheck.get(field) != GHIDRA_CROSSCHECK[field]:
            errors.append(f"ghidra_{field}")
    if crosscheck.get("raw_export_private") is not True:
        errors.append("ghidra_raw_export_scope")
    if crosscheck.get("runtime_verified") is not False or crosscheck.get("callable") is not False:
        errors.append("ghidra_runtime_or_callable_claim")
    if crosscheck.get("semantic_names_verified") is not False:
        errors.append("ghidra_semantic_name_scope")
    return {"valid": not errors, "errors": sorted(set(errors))}
