"""Normalize the private ParamBase constructor-xref Ghidra export.

The Ghidra script intentionally emits only addresses, reference kinds and
function identities.  This adapter keeps that evidence separate from the
family layout probes: a constructor callsite is a usage observation, not a
proof of the caller's source-level type, ownership or runtime safety.
"""
from __future__ import annotations

from collections import Counter, OrderedDict
import hashlib
import logging
from pathlib import Path
import re
from typing import Any, Iterable, Mapping

from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA

LOGGER = logging.getLogger(__name__)

_FIELD_RE = re.compile(r"([A-Z][A-Z0-9_]*)=([^\s]+)")
_XREF_RE = re.compile(r"^XREF\s+FAMILY=([^\s]+)")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fields(line: str) -> dict[str, str]:
    return {key: value for key, value in _FIELD_RE.findall(line)}


def parse_param_family_usage_export(
    path: Path,
    *,
    expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Parse and integrity-check one metadata-only Ghidra export.

    The parser rejects truncated exports and duplicate family target records.
    It does not infer missing callsites and never upgrades a relation to a
    runtime or callable status.
    """
    path = Path(path)
    if not path.is_file():
        raise ValueError(f"Ghidra usage export is missing: {path}")
    if not HEX_SHA.fullmatch(expected_sha256):
        raise ValueError("expected_sha256 must be a lowercase SHA-256 digest")
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[-1].strip() != "COMPLETE_FAMILY_USAGE_EXPORT":
        raise ValueError("Ghidra usage export is truncated or missing completion marker")

    metadata: dict[str, str] = {}
    families: "OrderedDict[str, dict[str, Any]]" = OrderedDict()
    declared_xrefs: int | None = None
    declared_families: int | None = None
    for line in lines:
        if line.startswith("PROGRAM_SHA256="):
            metadata["binary_sha256"] = line.split("=", 1)[1].strip().lower()
        elif line.startswith("IMAGE_BASE="):
            metadata["image_base"] = line.split("=", 1)[1].strip()
        elif line.startswith("LANGUAGE="):
            metadata["language"] = line.split("=", 1)[1].strip()
        elif line.startswith("ADDRESS_SPACE="):
            metadata["address_space"] = line.split("=", 1)[1].strip()
        elif line.startswith("ANALYSIS_SCOPE="):
            metadata["analysis_scope"] = line.split("=", 1)[1].strip()
        elif line.startswith("FAMILY="):
            fields = _fields(line)
            family = fields.get("FAMILY")
            if not family:
                raise ValueError(f"family record has no name: {line}")
            if family in families:
                raise ValueError(f"duplicate family record: {family}")
            record: dict[str, Any] = {
                "name": family,
                "target": fields.get("TARGET"),
                "locator": fields.get("LOCATOR"),
                "symbol": fields.get("SYMBOL", ""),
                "status": "RESOLVED" if fields.get("TARGET") else fields.get("STATUS", "UNKNOWN"),
                "xrefs": [],
            }
            if fields.get("STATUS") == "UNRESOLVED":
                record["status"] = "UNRESOLVED"
            families[family] = record
        elif line.startswith("XREF "):
            fields = _fields(line)
            family_match = _XREF_RE.match(line)
            family = family_match.group(1) if family_match else None
            if not family or family not in families:
                raise ValueError(f"xref refers to unknown family: {line}")
            required = ("TARGET", "FROM_ELF_VMA", "FROM_GHIDRA", "TYPE", "ADDRESS_SPACE")
            if any(not fields.get(key) for key in required):
                raise ValueError(f"xref lacks address-space-aware locator: {line}")
            families[family]["xrefs"].append({
                "target": fields["TARGET"],
                "from_elf_vma": fields["FROM_ELF_VMA"],
                "from_ghidra": fields["FROM_GHIDRA"],
                "caller_entry_elf_vma": fields.get("CALLER_ENTRY_ELF_VMA", "UNKNOWN"),
                "caller_entry_ghidra": fields.get("CALLER_ENTRY_GHIDRA", "UNKNOWN"),
                "caller_name": fields.get("CALLER", "UNKNOWN"),
                "address_space": fields["ADDRESS_SPACE"],
                "reference_type": fields["TYPE"],
            })
        elif line.startswith("FAMILY_COUNT="):
            declared_families = int(line.split("=", 1)[1])
        elif line.startswith("XREF_COUNT="):
            declared_xrefs = int(line.split("=", 1)[1])

    if metadata.get("binary_sha256") != expected_sha256:
        raise ValueError("Ghidra export binary SHA-256 does not match the pinned ELF")
    if metadata.get("address_space", "").upper() not in {"", "RAM"}:
        raise ValueError(f"unexpected Ghidra address space: {metadata['address_space']}")
    actual_xrefs = sum(len(item["xrefs"]) for item in families.values())
    if declared_families != len(families):
        raise ValueError("family count does not match export records")
    if declared_xrefs != actual_xrefs:
        raise ValueError("xref count does not match export records")
    for item in families.values():
        if item["status"] == "RESOLVED" and not item["target"]:
            raise ValueError(f"resolved family lacks target: {item['name']}")
    LOGGER.info("parsed %d ParamBase family records and %d xrefs from %s", len(families), actual_xrefs, path)
    return {
        "schema_version": 1,
        "binary_sha256": expected_sha256,
        "address_space": "ELF_VMA",
        "ghidra_address_space": metadata.get("address_space", "UNKNOWN"),
        "image_base": metadata.get("image_base", "UNKNOWN"),
        "language": metadata.get("language", "UNKNOWN"),
        "analysis_scope": metadata.get("analysis_scope", "UNKNOWN"),
        "families": list(families.values()),
        "family_count": len(families),
        "xref_count": actual_xrefs,
        "runtime_verified": False,
        "callable": False,
        "raw_export_private": True,
    }


def summarize_param_family_usage(
    parsed: Mapping[str, Any],
    *,
    analysis_status: str,
    analyzer_version: str,
    timeout_seconds: int | None = None,
    sample_limit: int = 4,
) -> dict[str, Any]:
    """Create a public-safe count/index contract from a parsed export."""
    if analysis_status not in {"COMPLETE", "PARTIAL_TIMEOUT", "PARTIAL_ERROR"}:
        raise ValueError("analysis_status must state whether the export is complete")
    if sample_limit < 0 or sample_limit > 32:
        raise ValueError("sample_limit must be between 0 and 32")
    public_families: list[dict[str, Any]] = []
    for item in parsed.get("families", []):
        xrefs = list(item.get("xrefs", []))
        relation_counts = Counter(str(xref["reference_type"]) for xref in xrefs)
        call_xrefs = [
            xref for xref in xrefs
            if str(xref["reference_type"]).endswith("CALL")
        ]
        known_callers = {
            xref["caller_entry_elf_vma"] for xref in call_xrefs
            if xref.get("caller_entry_elf_vma") not in {None, "UNKNOWN"}
        }
        unresolved_callers = sum(
            1 for xref in call_xrefs
            if xref.get("caller_entry_elf_vma") in {None, "UNKNOWN"}
        )
        public_families.append({
            "name": item["name"],
            "target": item.get("target"),
            "locator": item.get("locator"),
            "symbol": item.get("symbol", ""),
            "status": item.get("status", "UNKNOWN"),
            "xref_count": len(xrefs),
            "relation_counts": dict(sorted(relation_counts.items())),
            "call_xref_count": len(call_xrefs),
            "unique_callers": len(known_callers),
            "unresolved_caller_count": unresolved_callers,
            "callsite_examples": [
                {
                    "callsite_elf_vma": xref["from_elf_vma"],
                    "callsite_ghidra": xref["from_ghidra"],
                    "caller_entry_elf_vma": xref.get("caller_entry_elf_vma", "UNKNOWN"),
                    "caller_entry_ghidra": xref.get("caller_entry_ghidra", "UNKNOWN"),
                    "address_space": xref.get("address_space", "UNKNOWN"),
                    "reference_type": xref["reference_type"],
                }
                for xref in call_xrefs[:sample_limit]
            ],
        })
    result: dict[str, Any] = {
        "schema_version": 1,
        "firmware_version": "3.21",
        "binary_sha256": parsed["binary_sha256"],
        "address_space": "ELF_VMA",
        "analyzer": {
            "name": "ParamFamilyUsage.java",
            "version": analyzer_version,
            "analysis_status": analysis_status,
            "scope": parsed.get("analysis_scope", "UNKNOWN"),
            "ghidra_language": parsed.get("language", "UNKNOWN"),
            "ghidra_image_base": parsed.get("image_base", "UNKNOWN"),
            "timeout_seconds": timeout_seconds,
            "raw_export_private": True,
        },
        "families": public_families,
        "family_count": len(public_families),
        "xref_count": sum(item["xref_count"] for item in public_families),
        "runtime_verified": False,
        "callable": False,
        "limitations": [
            "Constructor xrefs are metadata observations, not proof of source-level caller types",
            "Generated Ghidra labels are not semantic function names",
            "PARTIAL_TIMEOUT exports are not exhaustive whole-firmware usage graphs",
            "Computed calls, external references and data references remain distinct from direct calls",
            "No ownership, lifetime extension, locking, runtime binding or callable safety is inferred",
        ],
    }
    return result


def validate_param_family_usage(
    contract: Mapping[str, Any],
    *,
    expected_families: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Validate fail-closed invariants for the public usage contract."""
    errors: list[str] = []
    if contract.get("binary_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if contract.get("address_space") != "ELF_VMA":
        errors.append("address_space")
    if contract.get("runtime_verified") is not False or contract.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    families = contract.get("families")
    if not isinstance(families, list):
        errors.append("families_missing")
        families = []
    names = [item.get("name") for item in families if isinstance(item, Mapping)]
    if len(names) != len(set(names)):
        errors.append("duplicate_family")
    if expected_families is not None:
        missing = set(expected_families) - set(names)
        if missing:
            errors.append("missing_family:" + ",".join(sorted(missing)))
    counted = 0
    for item in families:
        if not isinstance(item, Mapping):
            errors.append("invalid_family_record")
            continue
        if item.get("xref_count", -1) < 0 or item.get("call_xref_count", -1) < 0:
            errors.append(f"negative_count:{item.get('name')}")
        counted += int(item.get("xref_count", 0))
    if counted != contract.get("xref_count"):
        errors.append("xref_count_mismatch")
    return {"valid": not errors, "errors": errors, "family_count": len(names), "xref_count": counted}
