"""ParamList cross-ELF evidence profile.

The low-level :mod:`cross_elf_import_probe` is deliberately symbol-agnostic.
This module is a small Sony 3.21 profile that composes it for the three
ParamList ABI symbols needed to connect the primary ``libObj.so`` evidence to
external users.  It records imports, relocations and PLT/GOT metadata only;
an import is not treated as a runtime binding or a callable API.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from .cross_elf_import_probe import (
    DEFAULT_MAX_FILES,
    HEX_SHA,
    _is_absolute_source_path,
    probe_cross_elf_imports,
    validate_cross_elf_import_contract,
)


SCHEMA_VERSION = 1
PROFILE_NAME = "sony-a6000-paramlist-3.21"
PARAMLIST_SYMBOLS: tuple[str, ...] = (
    "_ZN9ParamList3addEmP9ParamBase",
    "_ZNK9ParamList3getEmm",
    "_ZN9ParamListD1Ev",
)


def probe_paramlist_cross_elf(
    root: Path,
    *,
    provider_elf: Path | None = None,
    provider_sha256: str | None = None,
    symbols: Iterable[str] = PARAMLIST_SYMBOLS,
    max_files: int = DEFAULT_MAX_FILES,
) -> dict[str, Any]:
    """Run the generic import probe for a bounded set of symbols.

    ``symbols`` is injectable so the analyzer remains reusable for another
    ABI profile and synthetic tests.  No result is promoted beyond the status
    emitted by the generic probe.
    """
    selected = tuple(dict.fromkeys(str(symbol) for symbol in symbols))
    if not selected or any(not symbol or len(symbol) > 512 for symbol in selected):
        raise ValueError("symbols must contain bounded non-empty names")
    reports: list[dict[str, Any]] = []
    for symbol in selected:
        reports.append(
            probe_cross_elf_imports(
                root,
                symbol_name=symbol,
                provider_elf=provider_elf,
                provider_sha256=provider_sha256,
                max_files=max_files,
            )
        )
    provider = reports[0].get("provider") if reports else None
    return {
        "schema_version": SCHEMA_VERSION,
        "profile": PROFILE_NAME,
        "firmware_version": "3.21",
        "symbols": list(selected),
        "provider": provider,
        "reports": reports,
        "runtime_verified": False,
        "callable": False,
        "raw_instruction_bytes_published": False,
        "limitations": [
            "Each report proves a dynamic import and relocation only",
            "Provider selection remains STATIC_INFERRED unless loader binding is independently observed",
            "No direct BL/BLX result is evidence that indirect/GOT/vtable dispatch is absent",
            "No source-level C++ ownership, return type or runtime ABI is inferred",
            "No firmware code was executed and no device was accessed",
        ],
    }


def validate_paramlist_cross_elf(report: dict[str, Any]) -> dict[str, Any]:
    """Fail closed on profile identity and per-symbol evidence invariants."""
    errors: list[str] = []
    if report.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version")
    if report.get("profile") != PROFILE_NAME:
        errors.append("profile")
    if report.get("firmware_version") != "3.21":
        errors.append("firmware_version")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    symbols = report.get("symbols")
    if not isinstance(symbols, list) or not symbols or len(set(symbols)) != len(symbols):
        errors.append("symbols")
        symbols = []
    reports = report.get("reports")
    if not isinstance(reports, list) or len(reports) != len(symbols):
        errors.append("report_count")
        reports = []
    provider = report.get("provider")
    if provider is not None and (
        not isinstance(provider, dict)
        or not HEX_SHA.fullmatch(str(provider.get("sha256", "")))
    ):
        errors.append("provider_identity")
    ghidra_crosschecks = report.get("ghidra_crosschecks", [])
    if not isinstance(ghidra_crosschecks, list):
        errors.append("ghidra_crosschecks_type")
        ghidra_crosschecks = []
    allowed_hashes = {
        source.get("sha256")
        for item in reports
        if isinstance(item, dict)
        for source_item in item.get("observations", [])
        if isinstance(source_item, dict)
        for source in [source_item.get("source_binary", {})]
        if isinstance(source, dict)
    }
    for index, crosscheck in enumerate(ghidra_crosschecks):
        if not isinstance(crosscheck, dict):
            errors.append(f"ghidra_crosscheck_type:{index}")
            continue
        if crosscheck.get("status") != "VERIFIED_STATIC":
            errors.append(f"ghidra_crosscheck_status:{index}")
        if crosscheck.get("process_exit") != 0:
            errors.append(f"ghidra_crosscheck_exit:{index}")
        if crosscheck.get("binary_sha256") not in allowed_hashes:
            errors.append(f"ghidra_crosscheck_identity:{index}")
        relative = crosscheck.get("source_relative_path")
        if (
            not isinstance(relative, str)
            or not relative
            or _is_absolute_source_path(relative)
            or "\\" in relative
        ):
            errors.append(f"ghidra_crosscheck_path:{index}")
        if crosscheck.get("address_space") != "ram" or not crosscheck.get("image_base"):
            errors.append(f"ghidra_crosscheck_address_space:{index}")
        if crosscheck.get("raw_export_private") is not True:
            errors.append(f"ghidra_crosscheck_visibility:{index}")
        if crosscheck.get("runtime_verified") is not False or crosscheck.get("callable") is not False:
            errors.append(f"ghidra_crosscheck_safety:{index}")
        for observation in crosscheck.get("observations", []):
            if not isinstance(observation, dict):
                errors.append(f"ghidra_crosscheck_observation_type:{index}")
                continue
            if observation.get("symbol") not in symbols:
                errors.append(f"ghidra_crosscheck_symbol:{index}")
            if observation.get("status") not in {
                "PRIMARY_ELF_VERIFIED", "GHIDRA_DERIVED", "UNRESOLVED"
            }:
                errors.append(f"ghidra_crosscheck_observation_status:{index}")
    seen: set[str] = set()
    for index, item in enumerate(reports):
        if not isinstance(item, dict):
            errors.append(f"report_type:{index}")
            continue
        symbol = item.get("symbol")
        if symbol not in symbols:
            errors.append(f"report_symbol:{index}")
        if symbol in seen:
            errors.append(f"duplicate_report_symbol:{index}")
        seen.add(str(symbol))
        result = validate_cross_elf_import_contract(item)
        if not result["valid"]:
            errors.extend(f"{index}:{error}" for error in result["errors"])
        report_provider = item.get("provider")
        if provider is not None and report_provider is not None:
            if report_provider.get("sha256") != provider.get("sha256"):
                errors.append(f"provider_mismatch:{index}")
    return {
        "valid": not errors,
        "errors": sorted(set(errors)),
        "symbol_count": len(symbols),
        "report_count": len(reports),
        "import_observation_count": sum(
            len(item.get("observations", []))
            for item in reports
            if isinstance(item, dict)
        ),
    }
