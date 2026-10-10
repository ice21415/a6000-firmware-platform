"""Address-aware callsite indexing for the ParamList query helpers.

The primary ELF contains mixed ARM/Thumb code and large executable segments.
Decoding one continuous stream from a segment start can skip valid Thumb
instructions after an ARM/Thumb boundary.  This module therefore scans
instruction-aligned Thumb candidates, validates each candidate with Capstone,
and only then records a direct branch target.  It never assigns a caller by
nearest address: a caller is reported only when one ELF symbol range contains
the callsite.

The result is metadata only.  It contains no firmware bytes, does not execute
the ELF and never turns a callsite into a runtime-safe C++ API.
"""
from __future__ import annotations

from collections import OrderedDict
import hashlib
from pathlib import Path
import struct
from typing import Any, Iterable, Mapping, Sequence

from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, Cs
from capstone.arm import ARM_OP_IMM
from elftools.elf.elffile import ELFFile

from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA, MAX_ELF_BYTES


SCHEMA_VERSION = 1
ADDRESS_SPACE = "ELF_VMA"
ANALYZER_VERSION = "param-query-callers-1"
MAX_EXAMPLES = 16

# These are evidence targets, not hard-coded answers in the scanner.  The
# public API accepts arbitrary target maps for synthetic and future profiles.
QUERY_TARGETS: "OrderedDict[str, int]" = OrderedDict((
    ("lookup_view_initializer", 0x42ABCC),
    ("adjacent_parameter_word_lookup", 0x42ABDC),
    ("opaque_parameter_word_lookup", 0x42AC00),
    ("paramlist_get_forwarder", 0xE5B20),
    ("param_payload_getter", 0xE5B18),
    ("bool_get_forwarder", 0x120970),
    ("point_get_forwarder", 0xFE9BE),
))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return value - (1 << bits) if value & sign else value


def decode_thumb_branch_target(data: bytes, base_vma: int, offset: int) -> int | None:
    """Return the raw Thumb-2 BL/BLX target candidate, if the encoding fits.

    Capstone is still required to validate the final instruction.  This cheap
    encoding filter lets the full ELF be scanned without decoding every byte
    offset as a separate Capstone stream.
    """
    if offset < 0 or offset + 4 > len(data) or offset & 1:
        return None
    first, second = struct.unpack_from("<HH", data, offset)
    if (first & 0xF800) != 0xF000:
        return None
    # BL uses 11xxxx; BLX immediate uses 10xxxx.  Other second-halfword
    # encodings are not calls and are intentionally ignored.
    if (second & 0xC000) not in (0xC000, 0x8000):
        return None
    sign = (first >> 10) & 1
    j1 = (second >> 13) & 1
    j2 = (second >> 11) & 1
    i1 = (~(j1 ^ sign)) & 1
    i2 = (~(j2 ^ sign)) & 1
    immediate = (
        (sign << 24) | (i1 << 23) | (i2 << 22)
        | ((first & 0x03FF) << 12) | ((second & 0x07FF) << 1)
    )
    return (base_vma + offset + 4 + _sign_extend(immediate, 25)) & 0xFFFFFFFF


def _symbol_ranges(elf: ELFFile) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[int, int, str]] = set()
    for section_name in (".dynsym", ".symtab"):
        section = elf.get_section_by_name(section_name)
        if section is None:
            continue
        for symbol in section.iter_symbols():
            if symbol["st_info"]["type"] != "STT_FUNC":
                continue
            value = int(symbol["st_value"]) & ~1
            size = int(symbol["st_size"])
            name = str(symbol.name)
            if not name or size <= 0:
                continue
            identity = (value, size, name)
            if identity in seen:
                continue
            seen.add(identity)
            result.append({
                "entry_vma": value,
                "size_bytes": size,
                "symbol": name,
                "address_space": ADDRESS_SPACE,
            })
    return sorted(result, key=lambda item: (item["entry_vma"], item["size_bytes"], item["symbol"]))


def _caller_candidates(address: int, symbols: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Use exact symbol ranges only; never choose the nearest lower address."""
    candidates = []
    for symbol in symbols:
        entry = int(symbol["entry_vma"])
        size = int(symbol["size_bytes"])
        if entry <= address < entry + size:
            candidates.append({
                "entry_vma": hex(entry),
                "size_bytes": size,
                "symbol": str(symbol["symbol"]),
                "address_space": str(symbol.get("address_space", ADDRESS_SPACE)),
            })
    return candidates


def _validate_branch_instruction(data: bytes, base_vma: int, offset: int, target: int) -> tuple[str, int] | None:
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    instruction = next(decoder.disasm(data[offset : offset + 4], base_vma + offset, count=1), None)
    if instruction is None or instruction.mnemonic.lower() not in {"bl", "blx"}:
        return None
    immediate = next(
        (int(operand.imm) & ~1 for operand in instruction.operands if operand.type == ARM_OP_IMM),
        None,
    )
    if immediate != (target & ~1):
        return None
    return instruction.mnemonic.lower(), int(instruction.address)


def scan_thumb_calls(
    data: bytes,
    *,
    base_vma: int,
    targets: Mapping[str, int],
    symbols: Sequence[Mapping[str, Any]] = (),
    section_name: str = ".text",
) -> list[dict[str, Any]]:
    """Find Capstone-validated direct Thumb BL/BLX callsites.

    ``data`` is an internal caller-owned buffer.  The return value includes
    only addresses, modes, symbol-range identities and status fields.
    """
    target_by_address = {int(value) & ~1: str(name) for name, value in targets.items()}
    if not target_by_address or len(target_by_address) != len(targets):
        raise ValueError("targets must have unique normalized VMAs")
    rows: list[dict[str, Any]] = []
    for offset in range(0, max(0, len(data) - 3), 2):
        candidate = decode_thumb_branch_target(data, base_vma, offset)
        if candidate is None or (candidate & ~1) not in target_by_address:
            continue
        target = candidate & ~1
        validated = _validate_branch_instruction(data, base_vma, offset, target)
        if validated is None:
            continue
        mnemonic, callsite = validated
        callers = _caller_candidates(callsite, symbols)
        rows.append({
            "target_name": target_by_address[target],
            "target_vma": hex(target),
            "callsite_vma": hex(callsite),
            "instruction_mode": "THUMB",
            "branch_mnemonic": mnemonic,
            "section": section_name,
            "address_space": ADDRESS_SPACE,
            "caller_candidates": callers,
            "caller_status": "PRIMARY_ELF_VERIFIED" if len(callers) == 1 else "UNRESOLVED",
            "callsite_status": "PRIMARY_ELF_VERIFIED",
        })
    return rows


def _executable_sections(elf: ELFFile) -> Iterable[tuple[str, int, bytes]]:
    for section in elf.iter_sections():
        if int(section["sh_flags"]) & 0x4 and int(section["sh_size"]):
            yield str(section.name), int(section["sh_addr"]), section.data()


def _canonical_rows(rows: Iterable[Mapping[str, Any]]) -> str:
    values = []
    for row in rows:
        caller = row.get("caller_candidates", [])
        caller_id = ",".join(
            f"{item.get('entry_vma')}:{item.get('size_bytes')}:{item.get('symbol')}"
            for item in caller if isinstance(item, Mapping)
        )
        values.append("|".join((
            str(row.get("target_vma")), str(row.get("callsite_vma")),
            str(row.get("instruction_mode")), str(row.get("branch_mnemonic")), caller_id,
        )))
    return "\n".join(sorted(values))


def _summarize_rows(rows: Sequence[Mapping[str, Any]], target_name: str, target_vma: int) -> dict[str, Any]:
    selected = [row for row in rows if row.get("target_name") == target_name]
    known = [row for row in selected if row.get("caller_status") == "PRIMARY_ELF_VERIFIED"]
    return {
        "target_name": target_name,
        "target_vma": hex(target_vma),
        "address_space": ADDRESS_SPACE,
        "callsite_count": len(selected),
        "symbol_resolved_caller_count": len(known),
        "unresolved_caller_count": len(selected) - len(known),
        "examples": [dict(row) for row in selected[:MAX_EXAMPLES]],
        "scan_status": "STATIC_INFERRED",
        "scope": "executable sections; instruction-aligned Thumb candidates validated by Capstone; exact symbol ranges only",
        "limitation": "No function-boundary recovery is claimed for callsites with no unique ELF symbol range; register/GOT/vtable dispatch is outside this index",
    }


def _verified_helper_chain(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Return only the four known local edges that are present in ``rows``.

    The source wrapper VMAs are part of this probe's evidence profile, but the
    edge is emitted only after the corresponding Capstone-validated callsite
    was found in the current primary ELF.  This keeps the profile fail-closed
    if a target map or input changes.
    """
    expected = (
        ("0x42ac00", "0x42ac0c", "0xe5b20"),
        ("0x42ac00", "0x42ac12", "0xe5b18"),
        ("0x42abdc", "0x42abe8", "0xe5b20"),
        ("0x42abdc", "0x42abee", "0xe5b18"),
    )
    result: list[dict[str, Any]] = []
    for source_vma, callsite_vma, target_vma in expected:
        if not any(
            str(row.get("callsite_vma")) == callsite_vma
            and str(row.get("target_vma")) == target_vma
            and row.get("callsite_status") == "PRIMARY_ELF_VERIFIED"
            for row in rows
        ):
            continue
        result.append({
            "source_vma": source_vma,
            "callsite_vma": callsite_vma,
            "target_vma": target_vma,
            "relation": "DIRECT_CALLS",
            "address_space": ADDRESS_SPACE,
            "status": "PRIMARY_ELF_VERIFIED",
        })
    return result


def probe_param_query_callers(
    elf_path: Path,
    *,
    expected_sha256: str = EXPECTED_LIBOBJ_SHA,
    targets: Mapping[str, int] = QUERY_TARGETS,
) -> dict[str, Any]:
    """Build the deterministic direct-call index for the pinned primary ELF."""
    path = Path(elf_path).resolve()
    if not path.is_file() or path.stat().st_size > MAX_ELF_BYTES:
        raise ValueError("private ELF missing or exceeds analysis limit")
    if not HEX_SHA.fullmatch(expected_sha256):
        raise ValueError("expected_sha256 must be a lowercase full SHA-256 digest")
    digest = _sha256(path)
    if digest != expected_sha256:
        raise ValueError("full-file ELF SHA-256 mismatch; refusing to decode")
    normalized_targets = OrderedDict((str(name), int(value) & ~1) for name, value in targets.items())
    if not normalized_targets or len(normalized_targets) != len(set(normalized_targets.values())):
        raise ValueError("targets must be a non-empty map of unique VMAs")
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_ARM":
            raise ValueError("probe accepts ELF32 little-endian ARM")
        symbols = _symbol_ranges(elf)
        rows: list[dict[str, Any]] = []
        section_counts: dict[str, int] = {}
        for section_name, base_vma, data in _executable_sections(elf):
            section_rows = scan_thumb_calls(
                data, base_vma=base_vma, targets=normalized_targets,
                symbols=symbols, section_name=section_name,
            )
            rows.extend(section_rows)
            section_counts[section_name] = len(section_rows)
    rows.sort(key=lambda row: (int(row["callsite_vma"], 16), int(row["target_vma"], 16)))
    canonical = _canonical_rows(rows).encode("utf-8")
    summaries = OrderedDict(
        (name, _summarize_rows(rows, name, value))
        for name, value in normalized_targets.items()
    )
    chain = _verified_helper_chain(rows)
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "LOCAL_PRIMARY_ELF_PARAM_QUERY_CALLSITE_INDEX",
        "firmware_version": "3.21",
        "binary_file_sha256": digest,
        "address_space": ADDRESS_SPACE,
        "analyzer": {"name": "fwplatform.param_query_callers", "version": ANALYZER_VERSION},
        "targets": summaries,
        "direct_call_rows": len(rows),
        "section_counts": dict(sorted(section_counts.items())),
        "callsite_set_sha256": hashlib.sha256(canonical).hexdigest(),
        "known_helper_chain": chain,
        "runtime_verified": False,
        "callable": False,
        "raw_instruction_bytes_published": False,
        "limitations": [
            "Thumb direct-branch instruction facts do not prove that every candidate lies on an executable path",
            "Caller identity is emitted only for one exact ELF symbol range; no nearest-function fallback is used",
            "ARM direct calls, register/GOT/vtable dispatch, external loader binding and complete CFG reachability are outside this index",
            "The helper chain confirms local branch/callsite facts, not C++ return types, ownership, locking or runtime safety",
            "No firmware code was executed and no device was accessed",
        ],
    }


def validate_param_query_callers(report: Mapping[str, Any]) -> dict[str, Any]:
    """Fail closed on identity, target uniqueness and unsafe promotion."""
    errors: list[str] = []
    if report.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version")
    if report.get("binary_file_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != ADDRESS_SPACE:
        errors.append("address_space")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    targets = report.get("targets")
    if not isinstance(targets, Mapping) or not targets:
        errors.append("targets_missing")
    else:
        seen_vmas: set[str] = set()
        for name, item in targets.items():
            if not isinstance(item, Mapping):
                errors.append(f"target:{name}:invalid")
                continue
            vma = item.get("target_vma")
            if not isinstance(vma, str) or vma in seen_vmas:
                errors.append(f"target:{name}:duplicate_or_missing_vma")
            seen_vmas.add(str(vma))
            for key in ("callsite_count", "symbol_resolved_caller_count", "unresolved_caller_count"):
                if not isinstance(item.get(key), int) or item[key] < 0:
                    errors.append(f"target:{name}:{key}")
            if item.get("scan_status") != "STATIC_INFERRED":
                errors.append(f"target:{name}:scan_status")
            for row in item.get("examples", []) if isinstance(item.get("examples"), list) else []:
                if row.get("caller_status") == "PRIMARY_ELF_VERIFIED" and len(row.get("caller_candidates", [])) != 1:
                    errors.append(f"target:{name}:caller_cardinality")
                if row.get("address_space") != ADDRESS_SPACE or row.get("callsite_status") != "PRIMARY_ELF_VERIFIED":
                    errors.append(f"target:{name}:evidence_locator")
    chain = report.get("known_helper_chain")
    expected_chain = (
        ("0x42ac00", "0x42ac0c", "0xe5b20"),
        ("0x42ac00", "0x42ac12", "0xe5b18"),
        ("0x42abdc", "0x42abe8", "0xe5b20"),
        ("0x42abdc", "0x42abee", "0xe5b18"),
    )
    if not isinstance(chain, list) or len(chain) != len(expected_chain):
        errors.append("helper_chain")
    else:
        for edge, expected in zip(chain, expected_chain):
            if edge.get("address_space") != ADDRESS_SPACE or edge.get("status") != "PRIMARY_ELF_VERIFIED":
                errors.append("helper_chain_status")
            if tuple(edge.get(key) for key in ("source_vma", "callsite_vma", "target_vma")) != expected:
                errors.append("helper_chain_identity")
            if edge.get("relation") != "DIRECT_CALLS":
                errors.append("helper_chain_relation")
    if not isinstance(report.get("callsite_set_sha256"), str) or not HEX_SHA.fullmatch(report["callsite_set_sha256"]):
        errors.append("callsite_set_hash")
    return {
        "valid": not errors,
        "errors": sorted(set(errors)),
        "target_count": len(targets) if isinstance(targets, Mapping) else 0,
        "direct_call_rows": int(report.get("direct_call_rows", 0) or 0),
    }
