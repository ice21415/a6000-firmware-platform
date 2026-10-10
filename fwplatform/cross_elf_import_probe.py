"""Evidence-gated cross-ELF dynamic import recovery.

The analyzer records an exact undefined dynamic symbol, its relocation and the
corresponding ARM PLT stub for each ELF under an explicitly supplied private
firmware root.  It never assumes that a basename or a DT_NEEDED entry proves
the runtime loader route, and it emits no instruction bytes or absolute paths.
Direct BL/BLX callsites are optional corroboration; an absent bounded direct
call is retained as an unresolved dispatch observation.
"""
from __future__ import annotations

import hashlib
import io
from pathlib import Path
from typing import Any, Iterable

from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, Cs
from capstone.arm import ARM_OP_IMM
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from .elf_plt import arm_plt_slot
from .private_thumb_research import HEX_SHA, MAX_ELF_BYTES


SCHEMA_VERSION = 1
DEFAULT_MAX_FILES = 2000
SUPPORTED_SUFFIXES = frozenset({".so", ".elf"})


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _open_elf(path: Path) -> tuple[bytes, ELFFile]:
    data = path.read_bytes()
    if len(data) > MAX_ELF_BYTES:
        raise ValueError("ELF exceeds the bounded analysis limit")
    return data, ELFFile(io.BytesIO(data))


def _symbol_indices(elf: ELFFile, symbol_name: str) -> tuple[dict[int, dict[str, Any]], dict[int, dict[str, Any]]]:
    section = elf.get_section_by_name(".dynsym")
    if not isinstance(section, SymbolTableSection):
        return {}, {}
    defined: dict[int, dict[str, Any]] = {}
    undefined: dict[int, dict[str, Any]] = {}
    for index, symbol in enumerate(section.iter_symbols()):
        if symbol.name != symbol_name:
            continue
        row = {
            "symbol": symbol.name,
            "symbol_index": index,
            "value_vma": hex(int(symbol["st_value"])),
            "size_bytes": int(symbol["st_size"]),
            "type": str(symbol["st_info"]["type"]),
            "binding": str(symbol["st_info"]["bind"]),
            "section_index": str(symbol["st_shndx"]),
        }
        if symbol["st_shndx"] == "SHN_UNDEF":
            undefined[index] = row
        else:
            defined[index] = row
    return defined, undefined


def _all_defined_symbols(elf: ELFFile) -> list[dict[str, Any]]:
    section = elf.get_section_by_name(".dynsym")
    if not isinstance(section, SymbolTableSection):
        return []
    rows: list[dict[str, Any]] = []
    for symbol in section.iter_symbols():
        if symbol["st_shndx"] == "SHN_UNDEF":
            continue
        if symbol["st_info"]["type"] != "STT_FUNC" or int(symbol["st_size"]) <= 0:
            continue
        rows.append({
            "symbol": symbol.name or None,
            "entry_vma": int(symbol["st_value"]) & ~1,
            "size_bytes": int(symbol["st_size"]),
        })
    return rows


def _relocations_for(elf: ELFFile, symbol_indices: set[int]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for section in elf.iter_sections():
        if not hasattr(section, "iter_relocations"):
            continue
        link = int(section["sh_link"])
        symbols = elf.get_section(link) if link else None
        if not isinstance(symbols, SymbolTableSection):
            continue
        for relocation in section.iter_relocations():
            index = int(relocation["r_info_sym"])
            if index not in symbol_indices:
                continue
            rows.append({
                "section": section.name,
                "offset_vma": hex(int(relocation["r_offset"])),
                "relocation_type": int(relocation["r_info_type"]),
                "symbol_index": index,
                "status": "PRIMARY_ELF_VERIFIED",
                "address_space": "ELF_VMA",
            })
    return rows


def _plt_entries(data: bytes, elf: ELFFile, relocation_offsets: set[int]) -> list[dict[str, Any]]:
    section = elf.get_section_by_name(".plt")
    if section is None:
        return []
    base = int(section["sh_addr"])
    offset = int(section["sh_offset"])
    raw = data[offset:offset + int(section["sh_size"])]
    rows: list[dict[str, Any]] = []
    seen: set[tuple[int, int, bool]] = set()
    for local_offset in range(0, max(0, len(raw) - 16), 4):
        entry = base + local_offset
        for thumb_stub in (False, True):
            try:
                got_slot = arm_plt_slot(
                    raw[local_offset:local_offset + 16], entry,
                    thumb_stub=thumb_stub,
                )
            except (IndexError, ValueError):
                got_slot = None
            if got_slot not in relocation_offsets:
                continue
            key = (entry, got_slot, thumb_stub)
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                "entry_vma": hex(entry),
                "got_slot_vma": hex(got_slot),
                "stub_mode": "THUMB_INTERWORK" if thumb_stub else "ARM",
                "status": "VERIFIED_STATIC",
                "address_space": "ELF_VMA",
            })
    return rows


def _direct_calls(
    data: bytes,
    elf: ELFFile,
    plt_entries: Iterable[int],
    symbols: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    targets = {int(entry) & ~1 for entry in plt_entries}
    if not targets:
        return []
    rows: list[dict[str, Any]] = []
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD" or not (int(segment["p_flags"]) & 1):
            continue
        start = int(segment["p_vaddr"])
        raw = data[int(segment["p_offset"]):int(segment["p_offset"]) + int(segment["p_filesz"])]
        for mode, mode_name in ((CS_MODE_THUMB, "THUMB"), (CS_MODE_ARM, "ARM")):
            decoder = Cs(CS_ARCH_ARM, mode)
            decoder.detail = True
            for instruction in decoder.disasm(raw, start):
                if instruction.mnemonic.lower() not in {"bl", "blx"}:
                    continue
                immediate = next(
                    (int(operand.imm) & ~1 for operand in instruction.operands if operand.type == ARM_OP_IMM),
                    None,
                )
                if immediate not in targets:
                    continue
                callers = [
                    symbol for symbol in symbols
                    if symbol["entry_vma"] <= int(instruction.address) < symbol["entry_vma"] + symbol["size_bytes"]
                ]
                rows.append({
                    "callsite_vma": hex(int(instruction.address)),
                    "instruction_mode": mode_name,
                    "target_plt_vma": hex(immediate),
                    "caller_candidates": callers,
                    "status": "PRIMARY_ELF_VERIFIED",
                    "address_space": "ELF_VMA",
                })
    return rows


def _needed(elf: ELFFile) -> list[str]:
    result: list[str] = []
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_DYNAMIC":
            continue
        for tag in segment.iter_tags():
            if tag.entry.d_tag == "DT_NEEDED":
                result.append(str(tag.needed))
    return sorted(set(result))


def _relative_path(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def _scan_one(
    path: Path,
    root: Path,
    symbol_name: str,
    provider_name: str | None,
) -> dict[str, Any] | None:
    data, elf = _open_elf(path)
    _defined, undefined = _symbol_indices(elf, symbol_name)
    if not undefined:
        return None
    relocations = _relocations_for(elf, set(undefined))
    relocation_offsets = {int(row["offset_vma"], 16) for row in relocations}
    plt = _plt_entries(data, elf, relocation_offsets)
    direct_calls = _direct_calls(
        data, elf, (int(row["entry_vma"], 16) for row in plt), _all_defined_symbols(elf),
    )
    needed = _needed(elf)
    return {
        "source_binary": {
            "name": path.name,
            "relative_path": _relative_path(path, root),
            "sha256": _sha256(path),
            "size_bytes": path.stat().st_size,
            "address_space": "ELF_VMA",
        },
        "import": {
            "symbol": symbol_name,
            "undefined_symbols": list(undefined.values()),
            "status": "PRIMARY_ELF_VERIFIED",
        },
        "relocations": relocations,
        "plt": plt,
        "direct_calls": direct_calls,
        "direct_call_scan": {
            "status": "PRIMARY_ELF_VERIFIED" if direct_calls else "UNKNOWN",
            "scope": "executable PT_LOAD segments decoded as ARM and Thumb; direct BL/BLX immediate targets only",
            "unresolved_reason": None if direct_calls else "no direct immediate call to the recovered PLT entry in bounded scan; register/GOT/vtable dispatch remains unresolved",
        },
        "needed": needed,
        "provider_path_in_needed": (
            provider_name is not None
            and any(Path(item).name == provider_name for item in needed)
        ),
        "runtime_loader_binding": "UNKNOWN",
        "runtime_verified": False,
        "callable": False,
    }


def probe_cross_elf_imports(
    root: Path,
    *,
    symbol_name: str,
    provider_elf: Path | None = None,
    provider_sha256: str | None = None,
    max_files: int = DEFAULT_MAX_FILES,
) -> dict[str, Any]:
    """Scan an explicit private root for one exact imported symbol."""
    root = Path(root).resolve()
    if not root.is_dir():
        raise ValueError("firmware root must be an existing directory")
    if not symbol_name or len(symbol_name) > 512:
        raise ValueError("symbol_name must be a bounded non-empty string")
    if max_files <= 0 or max_files > DEFAULT_MAX_FILES:
        raise ValueError("max_files is outside the bounded range")
    provider: dict[str, Any] | None = None
    provider_resolved: Path | None = None
    if provider_elf is not None:
        provider_resolved = Path(provider_elf).resolve()
        if not provider_resolved.is_file():
            raise ValueError("provider ELF does not exist")
        digest = _sha256(provider_resolved)
        if provider_sha256 is not None and (not HEX_SHA.fullmatch(provider_sha256) or digest != provider_sha256):
            raise ValueError("provider ELF SHA-256 mismatch")
        provider_data, provider_parsed = _open_elf(provider_resolved)
        defined, _undefined = _symbol_indices(provider_parsed, symbol_name)
        if len(defined) != 1:
            raise ValueError("provider must expose exactly one matching defined symbol")
        provider_symbol = next(iter(defined.values()))
        provider = {
            "name": provider_resolved.name,
            "sha256": digest,
            "size_bytes": provider_resolved.stat().st_size,
            "export": provider_symbol,
            "export_status": "PRIMARY_ELF_VERIFIED",
            "address_space": "ELF_VMA",
            "runtime_loader_binding": "UNKNOWN",
        }
        del provider_data
    files = [
        path for path in root.rglob("*")
        if path.is_file() and path.suffix.lower() in SUPPORTED_SUFFIXES
        and (provider_resolved is None or path.resolve() != provider_resolved)
    ]
    if len(files) > max_files:
        raise ValueError(f"firmware root contains {len(files)} files; max_files={max_files}")
    observations: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    for path in sorted(files):
        try:
            item = _scan_one(
                path,
                root,
                symbol_name,
                provider_resolved.name if provider_resolved is not None else None,
            )
        except (OSError, ValueError, RuntimeError) as exc:
            failures.append({"relative_path": _relative_path(path, root), "error": str(exc)})
            continue
        if item is None:
            continue
        if provider is not None:
            item["provider"] = {
                "binary_name": provider["name"],
                "binary_sha256": provider["sha256"],
                "symbol": symbol_name,
                "status": "STATIC_INFERRED",
                "reason": "provider exports the exact symbol; runtime loader/search-path binding is not proven",
            }
        observations.append(item)
    return {
        "schema_version": SCHEMA_VERSION,
        "firmware_version": "3.21",
        "symbol": symbol_name,
        "provider": provider,
        "observations": observations,
        "scan": {
            "root_scope": "explicit private root; only .so/.elf files",
            "files_considered": len(files),
            "files_with_import": len(observations),
            "failure_count": len(failures),
            "failures": failures,
        },
        "raw_instruction_bytes_published": False,
        "runtime_verified": False,
        "callable": False,
        "limitations": [
            "An undefined symbol and relocation prove an ELF import, not runtime execution",
            "PLT/GOT resolution does not prove loader search order or provider selection",
            "Direct-call scan excludes register-indirect, GOT-indirect, vtable and cross-process dispatch",
            "No source-level C++ receiver, return type or ParamList ownership is inferred",
            "No firmware code was executed and no device was accessed",
        ],
    }


def validate_cross_elf_import_contract(report: dict[str, Any]) -> dict[str, Any]:
    """Validate sanitized identity/provenance invariants and fail closed."""
    errors: list[str] = []
    if report.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version")
    symbol = report.get("symbol")
    if not isinstance(symbol, str) or not symbol:
        errors.append("symbol")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    provider = report.get("provider")
    if provider is not None:
        if not isinstance(provider, dict) or not HEX_SHA.fullmatch(str(provider.get("sha256", ""))):
            errors.append("provider_identity")
        if provider.get("export_status") != "PRIMARY_ELF_VERIFIED":
            errors.append("provider_export_status")
    observations = report.get("observations")
    if not isinstance(observations, list):
        errors.append("observations")
        observations = []
    seen_sources: set[str] = set()
    for index, item in enumerate(observations):
        source = item.get("source_binary", {}) if isinstance(item, dict) else {}
        digest = source.get("sha256")
        relative = source.get("relative_path")
        if not isinstance(digest, str) or not HEX_SHA.fullmatch(digest):
            errors.append(f"source_identity:{index}")
        if not isinstance(relative, str) or not relative or Path(relative).is_absolute() or "\\" in relative:
            errors.append(f"source_path:{index}")
        if relative in seen_sources:
            errors.append(f"duplicate_source:{index}")
        seen_sources.add(str(relative))
        imported = item.get("import", {})
        if imported.get("symbol") != symbol or imported.get("status") != "PRIMARY_ELF_VERIFIED":
            errors.append(f"import:{index}")
        if not item.get("relocations"):
            errors.append(f"relocations:{index}")
        if not item.get("plt"):
            errors.append(f"plt:{index}")
        for relocation in item.get("relocations", []):
            if relocation.get("status") != "PRIMARY_ELF_VERIFIED" or relocation.get("address_space") != "ELF_VMA":
                errors.append(f"relocation_status:{index}")
        ghidra = item.get("ghidra_crosscheck")
        if ghidra is not None:
            if not isinstance(ghidra, dict):
                errors.append(f"ghidra_crosscheck_type:{index}")
                ghidra = {}
            if ghidra.get("status") != "VERIFIED_STATIC":
                errors.append(f"ghidra_crosscheck_status:{index}")
            if ghidra.get("process_exit") != 0:
                errors.append(f"ghidra_crosscheck_exit:{index}")
            if ghidra.get("binary_sha256") != digest:
                errors.append(f"ghidra_crosscheck_identity:{index}")
            if ghidra.get("address_space") != "ram" or not ghidra.get("image_base"):
                errors.append(f"ghidra_crosscheck_address_space:{index}")
            if ghidra.get("raw_export_private") is not True:
                errors.append(f"ghidra_crosscheck_export_visibility:{index}")
            if ghidra.get("runtime_verified") is not False or ghidra.get("callable") is not False:
                errors.append(f"ghidra_crosscheck_safety:{index}")
            exact = ghidra.get("exact_mangled_symbol_lookup", {})
            if exact.get("status") != "UNRESOLVED":
                errors.append(f"ghidra_exact_lookup_status:{index}")
            imported = ghidra.get("demangled_import_observation", {})
            if imported.get("status") != "PRIMARY_ELF_VERIFIED":
                errors.append(f"ghidra_import_status:{index}")
            if imported.get("plt_reference_status") != "PRIMARY_ELF_VERIFIED":
                errors.append(f"ghidra_plt_reference_status:{index}")
        if item.get("runtime_verified") is not False or item.get("callable") is not False:
            errors.append(f"unsafe_observation:{index}")
    return {"valid": not errors, "errors": sorted(set(errors)), "observation_count": len(observations)}
