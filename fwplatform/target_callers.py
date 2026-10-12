"""Parse and bind metadata-only Ghidra caller exports.

The companion Ghidra script intentionally exports addresses and function-body
ranges, never firmware bytes or decompiler text.  This adapter keeps the
Ghidra address space separate from ELF VMA and only promotes a callsite when a
second, exact Capstone scan agrees.  A generated Ghidra label is retained as a
locator; it is never treated as a semantic function name.
"""
from __future__ import annotations

from collections import OrderedDict
import hashlib
import re
from pathlib import Path
from typing import Any, Iterable, Mapping

from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA


_BODY_RE = re.compile(
    r"^\[\s*(?:\[\s*([0-9A-Fa-f]+)\s*,\s*([0-9A-Fa-f]+)\s*\]\s*,?\s*)+\]$"
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _number(value: str, field: str) -> int:
    text = value.strip()
    if not text or text.upper() == "UNKNOWN":
        raise ValueError(f"{field} is unknown")
    try:
        return int(text, 0 if text.lower().startswith("0x") else 16)
    except ValueError as exc:
        raise ValueError(f"invalid {field}: {value!r}") from exc


def _optional_number(value: str, field: str) -> int | None:
    if value.upper() == "UNKNOWN":
        return None
    return _number(value, field)


def _fields(line: str) -> dict[str, str]:
    payload = line.split(" ", 1)[1] if " " in line else ""
    fields: dict[str, str] = {}
    pattern = re.compile(
        r"(?:^|\s)([A-Z][A-Z0-9_]*)=(.*?)(?=\s+[A-Z][A-Z0-9_]*=|$)"
    )
    matches = list(pattern.finditer(payload))
    if not matches or matches[0].start() != 0:
        raise ValueError(f"malformed field in export line: {line}")
    for match in matches:
        key, value = match.group(1), match.group(2).strip()
        if not value or key in fields:
            raise ValueError(f"duplicate or empty field in export line: {line}")
        fields[key] = value
    if matches[-1].end() != len(payload):
        raise ValueError(f"unparsed field in export line: {line}")
    return fields


def _body_ranges(raw: str, *, image_base: int, field: str) -> list[dict[str, str]] | None:
    if raw.upper() == "UNKNOWN":
        return None
    if not _BODY_RE.fullmatch(raw):
        raise ValueError(f"malformed {field}: {raw!r}")
    ranges: list[dict[str, str]] = []
    for start_text, end_text in re.findall(r"\[\s*([0-9A-Fa-f]+)\s*,\s*([0-9A-Fa-f]+)\s*\]", raw):
        start = int(start_text, 16)
        end = int(end_text, 16)
        if start > end:
            raise ValueError(f"descending {field} range")
        ranges.append({
            "start_ghidra": f"0x{start:x}",
            "end_ghidra": f"0x{end:x}",
            "start_elf_vma": f"0x{start - image_base:x}",
            "end_elf_vma": f"0x{end - image_base:x}",
        })
    if not ranges:
        raise ValueError(f"empty {field}")
    return ranges


def _contains(ranges: Iterable[Mapping[str, str]] | None, value: int) -> bool:
    if not ranges:
        return False
    return any(
        int(item["start_elf_vma"], 16) <= value <= int(item["end_elf_vma"], 16)
        for item in ranges
    )


def parse_target_callers_export(
    path: Path,
    *,
    expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Parse a complete TargetCallers export and validate all address mappings.

    The export is private metadata.  The returned object is safe to summarize,
    but callers must not publish the raw text because it is tied to private
    analysis state.  Missing containing functions remain ``UNKNOWN``.
    """
    path = Path(path)
    if not path.is_file():
        raise ValueError(f"Ghidra caller export is missing: {path}")
    expected = expected_sha256.lower()
    if not HEX_SHA.fullmatch(expected):
        raise ValueError("expected_sha256 must be a lowercase SHA-256 digest")
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[-1].strip() != "COMPLETE_TARGET_CALLER_EXPORT":
        raise ValueError("Ghidra caller export is truncated or missing completion marker")

    metadata: dict[str, str] = {}
    targets: "OrderedDict[int, dict[str, Any]]" = OrderedDict()
    declared_targets: int | None = None
    declared_references: int | None = None
    image_base: int | None = None
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("PROGRAM_SHA256="):
            metadata["binary_sha256"] = stripped.split("=", 1)[1].lower()
        elif stripped.startswith("IMAGE_BASE="):
            metadata["image_base"] = stripped.split("=", 1)[1]
            image_base = _number(metadata["image_base"], "IMAGE_BASE")
        elif stripped.startswith("LANGUAGE="):
            metadata["language"] = stripped.split("=", 1)[1]
        elif stripped.startswith("ADDRESS_SPACE="):
            metadata["address_space"] = stripped.split("=", 1)[1]
        elif stripped.startswith("ANALYSIS_SCOPE="):
            metadata["analysis_scope"] = stripped.split("=", 1)[1]
        elif stripped.startswith("ANALYZER_VERSION="):
            metadata["analyzer_version"] = stripped.split("=", 1)[1]
        elif stripped.startswith("TARGET="):
            # The target record has no command word; prepend a synthetic one
            # so the common key/value parser treats TARGET like other fields.
            fields = _fields("TARGET_RECORD " + stripped)
            target_text = fields.get("TARGET")
            ghidra_text = fields.get("GHIDRA")
            if target_text is None or ghidra_text is None:
                raise ValueError(f"target lacks address fields: {line}")
            target = _number(target_text, "TARGET")
            if target in targets:
                raise ValueError(f"duplicate target: {target_text}")
            targets[target] = {
                "target_vma": f"0x{target:x}",
                "target_ghidra": ghidra_text,
                "symbol": fields.get("SYMBOL", "UNKNOWN"),
                "xrefs": [],
            }
        elif stripped.startswith("XREF "):
            if image_base is None:
                raise ValueError("XREF appeared before IMAGE_BASE")
            fields = _fields(stripped)
            required = (
                "TARGET", "FROM_GHIDRA", "FROM_ELF_VMA", "CALLER_ENTRY_GHIDRA",
                "CALLER_ENTRY_ELF_VMA", "CALLER_BODY", "ADDRESS_SPACE", "TYPE",
            )
            if any(not fields.get(key) for key in required):
                raise ValueError(f"xref lacks address-space-aware locator: {line}")
            target = _number(fields["TARGET"], "XREF TARGET")
            record = targets.get(target)
            if record is None:
                raise ValueError(f"xref refers to unknown target: {fields['TARGET']}")
            from_ghidra = _number(fields["FROM_GHIDRA"], "FROM_GHIDRA")
            from_vma = _number(fields["FROM_ELF_VMA"], "FROM_ELF_VMA")
            if from_ghidra - image_base != from_vma:
                raise ValueError("FROM_GHIDRA does not map to FROM_ELF_VMA")
            target_ghidra = _number(record["target_ghidra"], "TARGET GHIDRA")
            if target_ghidra - image_base != target:
                raise ValueError("TARGET GHIDRA does not map to TARGET ELF VMA")
            caller_ghidra = _optional_number(fields["CALLER_ENTRY_GHIDRA"], "CALLER_ENTRY_GHIDRA")
            caller_vma = _optional_number(fields["CALLER_ENTRY_ELF_VMA"], "CALLER_ENTRY_ELF_VMA")
            body = _body_ranges(fields["CALLER_BODY"], image_base=image_base, field="CALLER_BODY")
            if (caller_ghidra is None) != (caller_vma is None) or (caller_ghidra is not None and caller_ghidra - image_base != caller_vma):
                raise ValueError("caller entry address spaces do not agree")
            if caller_ghidra is None and body is not None:
                raise ValueError("unknown caller cannot have a body")
            if caller_ghidra is not None and body is None:
                raise ValueError("resolved caller lacks a body range")
            if body is not None and not _contains(body, from_vma):
                raise ValueError("callsite is outside the reported caller body")
            key = (target, from_vma, fields["TYPE"], caller_vma)
            if any(item["identity_key"] == key for item in record["xrefs"]):
                raise ValueError("duplicate caller reference")
            record["xrefs"].append({
                "identity_key": key,
                "target_vma": f"0x{target:x}",
                "from_ghidra": f"0x{from_ghidra:x}",
                "from_elf_vma": f"0x{from_vma:x}",
                "caller_name": fields.get("CALLER", "UNKNOWN"),
                "caller_entry_ghidra": (
                    "UNKNOWN" if caller_ghidra is None else f"0x{caller_ghidra:x}"
                ),
                "caller_entry_elf_vma": (
                    "UNKNOWN" if caller_vma is None else f"0x{caller_vma:x}"
                ),
                "caller_body_ranges": body,
                "ghidra_address_space": fields["ADDRESS_SPACE"],
                "reference_type": fields["TYPE"],
            })
        elif stripped.startswith("TARGET_COUNT="):
            declared_targets = int(stripped.split("=", 1)[1])
        elif stripped.startswith("REFERENCE_COUNT="):
            declared_references = int(stripped.split("=", 1)[1])

    if metadata.get("binary_sha256") != expected:
        raise ValueError("Ghidra caller export binary SHA-256 does not match the pinned ELF")
    if image_base is None or not metadata.get("language") or not metadata.get("address_space"):
        raise ValueError("Ghidra caller export lacks program identity metadata")
    if metadata["address_space"].lower() != "ram":
        raise ValueError(f"unexpected Ghidra address space: {metadata['address_space']}")
    actual_references = sum(len(item["xrefs"]) for item in targets.values())
    if declared_targets != len(targets):
        raise ValueError("target count does not match export records")
    if declared_references != actual_references:
        raise ValueError("reference count does not match export records")
    for item in targets.values():
        for xref in item["xrefs"]:
            xref.pop("identity_key", None)
    return {
        "schema_version": 1,
        "binary_sha256": expected,
        "address_space": "ELF_VMA",
        "ghidra_image_base": f"0x{image_base:x}",
        "ghidra_address_space": metadata["address_space"],
        "language": metadata["language"],
        "analysis_scope": metadata.get("analysis_scope", "UNKNOWN"),
        "analyzer_version": metadata.get("analyzer_version", "UNKNOWN"),
        "targets": list(targets.values()),
        "target_count": len(targets),
        "reference_count": actual_references,
        "source_export_sha256": _sha256(path),
        "raw_export_private": True,
        "runtime_verified": False,
        "callable": False,
    }


def _callsite_map(values: Mapping[Any, Iterable[Any]] | Iterable[tuple[Any, Any]]) -> dict[int, set[int]]:
    if isinstance(values, Mapping):
        rows = values.items()
    else:
        grouped: dict[Any, list[Any]] = {}
        for target, callsite in values:
            grouped.setdefault(target, []).append(callsite)
        rows = grouped.items()
    result: dict[int, set[int]] = {}
    for target, callsites in rows:
        target_number = _number(str(target), "Capstone target") if not isinstance(target, int) else target
        result[target_number] = {
            _number(str(item), "Capstone callsite") if not isinstance(item, int) else item
            for item in callsites
        }
    return result


def summarize_target_callers(
    parsed: Mapping[str, Any],
    *,
    capstone_callsites: Mapping[Any, Iterable[Any]] | Iterable[tuple[Any, Any]] | None = None,
    capstone_version: str = "UNKNOWN",
) -> dict[str, Any]:
    """Create a public-safe caller contract with conservative promotion.

    ``PRIMARY_ELF_VERIFIED`` is assigned only to an exact callsite present in
    both the metadata export and the independent Capstone scan.  The containing
    function identity/body remains ``GHIDRA_DERIVED`` even when the callsite is
    primary verified.  Capstone-only references are retained as unresolved
    coverage gaps instead of being silently attached to a nearby function.
    """
    if parsed.get("address_space") != "ELF_VMA":
        raise ValueError("parsed caller export must use ELF_VMA normalization")
    exact = _callsite_map(capstone_callsites or {})
    targets: list[dict[str, Any]] = []
    observed: dict[int, set[int]] = {}
    for target in parsed.get("targets", []):
        target_vma = _number(str(target["target_vma"]), "target_vma")
        observed[target_vma] = set()
        xrefs: list[dict[str, Any]] = []
        for xref in target.get("xrefs", []):
            callsite = _number(str(xref["from_elf_vma"]), "from_elf_vma")
            observed[target_vma].add(callsite)
            direct = callsite in exact.get(target_vma, set())
            body_status = "GHIDRA_DERIVED" if xref.get("caller_body_ranges") else "UNKNOWN"
            xrefs.append({
                "callsite_elf_vma": xref["from_elf_vma"],
                "callsite_ghidra": xref["from_ghidra"],
                "caller_name": xref.get("caller_name", "UNKNOWN"),
                "caller_name_semantic": False,
                "caller_entry_elf_vma": xref.get("caller_entry_elf_vma", "UNKNOWN"),
                "caller_body_ranges": xref.get("caller_body_ranges"),
                "caller_identity_status": body_status,
                "reference_type": xref["reference_type"],
                "ghidra_address_space": xref["ghidra_address_space"],
                "callsite_status": "PRIMARY_ELF_VERIFIED" if direct else "GHIDRA_DERIVED",
                "evidence_method": "GHIDRA_DERIVED+CAPSTONE" if direct else "GHIDRA_DERIVED",
            })
        targets.append({
            "target_vma": target["target_vma"],
            "target_ghidra": target["target_ghidra"],
            "symbol": target.get("symbol", "UNKNOWN"),
            "symbol_semantic": False,
            "xrefs": xrefs,
        })
    capstone_only: list[dict[str, str]] = []
    for target, callsites in exact.items():
        for callsite in sorted(callsites - observed.get(target, set())):
            capstone_only.append({
                "target_vma": f"0x{target:x}",
                "callsite_elf_vma": f"0x{callsite:x}",
                "caller_entry_elf_vma": "UNKNOWN",
                "status": "PRIMARY_ELF_VERIFIED_CALLSITE_UNRESOLVED_CALLER",
                "evidence_method": "DIRECT_CALL_CAPSTONE_ONLY",
            })
    return {
        "schema_version": "param-set-tree-callers-1",
        "firmware_version": "3.21",
        "binary_sha256": parsed["binary_sha256"],
        "address_space": "ELF_VMA",
        "ghidra": {
            "image_base": parsed.get("ghidra_image_base", "UNKNOWN"),
            "address_space": parsed.get("ghidra_address_space", "UNKNOWN"),
            "language": parsed.get("language", "UNKNOWN"),
            "analysis_scope": parsed.get("analysis_scope", "UNKNOWN"),
            "analyzer_version": parsed.get("analyzer_version", "UNKNOWN"),
            "source_export_sha256": parsed.get("source_export_sha256", "UNKNOWN"),
            "raw_export_private": True,
        },
        "capstone_crosscheck": {
            "analyzer": "Capstone",
            "version": capstone_version,
            "mode": "ARM_THUMB",
            "method": "exact Thumb BL immediate target scan",
        },
        "targets": targets,
        "capstone_only_callsites": capstone_only,
        "counts": {
            "ghidra_targets": len(targets),
            "ghidra_references": sum(len(item["xrefs"]) for item in targets),
            "primary_verified_callsites": sum(
                1 for item in targets for xref in item["xrefs"]
                if xref["callsite_status"] == "PRIMARY_ELF_VERIFIED"
            ),
            "unresolved_caller_count": sum(
                1 for item in targets for xref in item["xrefs"]
                if xref["caller_identity_status"] == "UNKNOWN"
            ) + len(capstone_only),
            "capstone_only_callsites": len(capstone_only),
        },
        "prmset_mutator_entry": "UNKNOWN",
        "prmset_relation": "UNKNOWN; generic ordered-tree helper identity is not proven",
        "runtime_verified": False,
        "callable": False,
        "limitations": [
            "Generated Ghidra labels are locators, not confirmed semantic names",
            "Ghidra caller ranges are not proof that the helper belongs to PrmSet",
            "Capstone-only callsites retain UNKNOWN caller identity",
            "No runtime ownership, exception, locking or callable safety is inferred",
        ],
    }


def validate_target_callers_contract(
    contract: Mapping[str, Any],
    *,
    expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    errors: list[str] = []
    if contract.get("schema_version") != "param-set-tree-callers-1":
        errors.append("schema_version")
    if contract.get("binary_sha256") != expected_sha256:
        errors.append("binary_identity")
    if contract.get("address_space") != "ELF_VMA":
        errors.append("address_space")
    if contract.get("runtime_verified") is not False or contract.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    ghidra = contract.get("ghidra")
    if not isinstance(ghidra, Mapping) or ghidra.get("raw_export_private") is not True:
        errors.append("ghidra_provenance")
    capstone = contract.get("capstone_crosscheck")
    if (
        not isinstance(capstone, Mapping)
        or capstone.get("analyzer") != "Capstone"
        or capstone.get("mode") != "ARM_THUMB"
        or not capstone.get("version")
    ):
        errors.append("capstone_provenance")
    targets = contract.get("targets")
    if not isinstance(targets, list) or not targets:
        errors.append("targets_missing")
        targets = []
    ghidra_target_count = len(targets)
    ghidra_reference_count = 0
    primary_count = 0
    unresolved_count = 0
    seen: set[tuple[str, str]] = set()
    for target in targets:
        if not isinstance(target, Mapping):
            errors.append("invalid_target")
            continue
        if target.get("symbol_semantic") is not False:
            errors.append("symbol_semantic_promotion")
        for xref in target.get("xrefs", []):
            ghidra_reference_count += 1
            key = (str(target.get("target_vma")), str(xref.get("callsite_elf_vma")))
            if key in seen:
                errors.append("duplicate_xref")
            seen.add(key)
            if xref.get("caller_name_semantic") is not False:
                errors.append("caller_name_semantic_promotion")
            if xref.get("callsite_status") == "PRIMARY_ELF_VERIFIED" and xref.get("evidence_method") != "GHIDRA_DERIVED+CAPSTONE":
                errors.append("primary_evidence_method")
            if xref.get("caller_identity_status") not in {"GHIDRA_DERIVED", "UNKNOWN"}:
                errors.append("caller_identity_status")
            if xref.get("callsite_status") == "PRIMARY_ELF_VERIFIED":
                primary_count += 1
            elif xref.get("callsite_status") != "GHIDRA_DERIVED":
                errors.append("callsite_status")
            if xref.get("caller_identity_status") == "UNKNOWN":
                unresolved_count += 1
    capstone_only = contract.get("capstone_only_callsites", [])
    if not isinstance(capstone_only, list):
        errors.append("capstone_only_callsites")
        capstone_only = []
    unresolved_count += len(capstone_only)
    if contract.get("prmset_mutator_entry") != "UNKNOWN":
        errors.append("mutator_promotion")
    counts = contract.get("counts")
    if not isinstance(counts, Mapping):
        errors.append("counts_missing")
    else:
        if counts.get("ghidra_targets") != ghidra_target_count:
            errors.append("target_count")
        if counts.get("ghidra_references") != ghidra_reference_count:
            errors.append("reference_count")
        if counts.get("primary_verified_callsites") != primary_count:
            errors.append("primary_count")
        if counts.get("unresolved_caller_count") != unresolved_count:
            errors.append("unresolved_count")
        if counts.get("capstone_only_callsites") != len(capstone_only):
            errors.append("capstone_only_count")
    return {"valid": not errors, "errors": sorted(set(errors))}
