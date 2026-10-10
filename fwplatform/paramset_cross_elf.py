"""Evidence-gated cross-ELF usage recovery for the ParamSet helpers.

The generic part of this module consumes a metadata-only Ghidra JSONL export
and resolves imported ARM PLT symbols by relocation identity.  The optional
Capstone pass validates the referenced call instructions and a small,
branch-local register shape.  It never executes firmware and never emits
instruction bytes or decompiler text.
"""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

import capstone
from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, Cs
from capstone.arm import ARM_OP_IMM
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from .elf_plt import arm_plt_slot


GET_SET = "_ZN6PrmSet6getSetEv"
GET = "_ZN6PrmSet3GETEPK9ParamListm"
EXPECTED_LIBOBJ_SHA = "8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_hex(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a hexadecimal address")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as exc:
            raise ValueError(f"{field} is not a hexadecimal address") from exc
    raise ValueError(f"{field} is missing")


def _address(record: dict[str, Any], prefix: str, image_base: int) -> tuple[int, int]:
    """Return (Ghidra address, ELF VMA), accepting old exporter field names."""
    ghidra_key = f"{prefix}_ghidra"
    vma_key = f"{prefix}_elf_vma"
    if prefix == "address" and "ghidra_address" in record:
        ghidra_key = "ghidra_address"
    if ghidra_key in record:
        ghidra = _parse_hex(record[ghidra_key], ghidra_key)
    elif prefix in record:
        ghidra = _parse_hex(record[prefix], prefix)
    else:
        ghidra = None
    if vma_key in record and record[vma_key] is not None:
        vma = _parse_hex(record[vma_key], vma_key)
    elif ghidra is not None:
        vma = ghidra - image_base
    else:
        raise ValueError(f"{prefix} address is missing")
    return (ghidra if ghidra is not None else vma + image_base, vma)


def load_imported_symbol_export(
    path: Path, *, expected_binary_sha256: str | None = None,
) -> dict[str, Any]:
    """Load and normalize a complete metadata-only Ghidra export.

    A complete marker and exact record count are mandatory.  The parser
    accepts the pre-normalization ``address`` fields emitted by older local
    scripts but always returns separate Ghidra and ELF-VMA fields.
    """
    if not path.is_file():
        raise ValueError(f"Ghidra export not found: {path}")
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(lines) < 2:
        raise ValueError("Ghidra export is empty or truncated")
    try:
        records = [json.loads(line) for line in lines]
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid Ghidra JSONL: {exc}") from exc
    metadata = records[0]
    complete = records[-1]
    if metadata.get("kind") != "metadata" or complete.get("kind") != "complete":
        raise ValueError("Ghidra export is missing metadata or complete marker")
    if complete.get("export_status") != "complete":
        raise ValueError("Ghidra export is not complete")
    if int(complete.get("record_count", -1)) != len(records) - 1:
        raise ValueError("Ghidra record count does not match JSONL length")
    digest = str(metadata.get("binary_sha256") or complete.get("binary_sha256") or "").lower()
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("Ghidra export has no valid binary SHA-256")
    if str(complete.get("binary_sha256", "")).lower() != digest:
        raise ValueError("metadata and complete-marker binary hashes differ")
    if expected_binary_sha256 and digest != expected_binary_sha256.lower():
        raise ValueError("Ghidra export binary identity mismatch")
    image_base = _parse_hex(metadata.get("image_base"), "image_base")
    normalized: list[dict[str, Any]] = []
    for record in records[1:-1]:
        if not isinstance(record, dict):
            raise ValueError("Ghidra record is not an object")
        if str(record.get("binary_sha256", digest)).lower() != digest:
            raise ValueError("Ghidra record binary identity mismatch")
        item = dict(record)
        if item.get("kind") == "symbol":
            ghidra, vma = _address(item, "address", image_base)
            item["ghidra_address"] = hex(ghidra)
            item["elf_vma"] = hex(vma) if vma >= 0 else None
            if vma < 0:
                item["address_space"] = "EXTERNAL"
        elif item.get("kind") == "reference":
            for prefix in ("target_address", "from_address"):
                ghidra, vma = _address(item, prefix, image_base)
                item[f"{prefix}_ghidra"] = hex(ghidra)
                item[f"{prefix}_elf_vma"] = hex(vma)
            for prefix in ("caller_entry",):
                key = f"{prefix}_elf_vma"
                if item.get(key) is not None or item.get(prefix) is not None:
                    ghidra, vma = _address(item, prefix, image_base)
                    item[f"{prefix}_ghidra"] = hex(ghidra)
                    item[key] = hex(vma)
        normalized.append(item)
    return {
        "metadata": metadata,
        "records": normalized,
        "binary_sha256": digest,
        "ghidra_image_base": hex(image_base),
        "source_export_sha256": _sha256(path),
    }


def _symbol_imports(elf: ELFFile, requested: Iterable[str]) -> dict[str, dict[str, Any]]:
    wanted = set(requested)
    result: dict[str, dict[str, Any]] = {}
    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym is None:
        return result
    for index, symbol in enumerate(dynsym.iter_symbols()):
        if symbol.name not in wanted:
            continue
        result[symbol.name] = {
            "dynsym_index": index,
            "value": int(symbol["st_value"]),
            "size": int(symbol["st_size"]),
            "section": str(symbol["st_shndx"]),
            "binding": str(symbol["st_info"]["bind"]),
        }
    return result


def _plt_bindings(fp: Any, elf: ELFFile, requested: Iterable[str]) -> dict[str, dict[str, Any]]:
    """Resolve ARM PLT slots from actual instructions and relocations."""
    wanted = set(requested)
    plt = elf.get_section_by_name(".plt")
    if plt is None:
        return {}
    raw = plt.data()
    base = int(plt["sh_addr"])
    slot_to_symbol: dict[int, dict[str, Any]] = {}
    for section in elf.iter_sections():
        if not hasattr(section, "iter_relocations"):
            continue
        symbols = elf.get_section(section["sh_link"])
        if not isinstance(symbols, SymbolTableSection):
            continue
        for relocation in section.iter_relocations():
            if not relocation["r_info_sym"]:
                continue
            symbol = symbols.get_symbol(relocation["r_info_sym"])
            if symbol.name in wanted:
                slot_to_symbol[int(relocation["r_offset"])] = {
                    "symbol": symbol.name,
                    "relocation_type": int(relocation["r_info_type"]),
                    "section": section.name,
                    "got_slot": hex(int(relocation["r_offset"])),
                }
    result: dict[str, dict[str, Any]] = {}
    # PLT entries are 4-byte aligned; scanning all aligned offsets also works
    # for linkers that place a non-entry padding word between entry groups.
    for offset in range(0, max(0, len(raw) - 11), 4):
        vma = base + offset
        try:
            slot = arm_plt_slot(raw[offset:offset + 12], vma, thumb_stub=False)
        except Exception:
            continue
        if slot not in slot_to_symbol:
            continue
        binding = dict(slot_to_symbol[slot])
        binding.update({"plt_vma": hex(vma), "address_space": "ELF_VMA", "status": "PRIMARY_ELF_VERIFIED"})
        result[binding["symbol"]] = binding
    return result


def _exec_bytes(fp: Any, elf: ELFFile, address: int, size: int) -> bytes:
    matches: list[int] = []
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD" or not (int(segment["p_flags"]) & 1):
            continue
        start = int(segment["p_vaddr"])
        end = start + int(segment["p_filesz"])
        if start <= address and address + size <= end:
            matches.append(int(segment["p_offset"]) + address - start)
    if len(matches) != 1:
        raise ValueError(f"ELF_VMA 0x{address:x} is not uniquely executable")
    fp.seek(matches[0])
    data = fp.read(size)
    if len(data) != size:
        raise ValueError("truncated executable range")
    return data


def _decode_at(fp: Any, elf: ELFFile, address: int, target: int) -> dict[str, Any]:
    raw = _exec_bytes(fp, elf, address, 8)
    matches: list[dict[str, Any]] = []
    for mode, name in ((CS_MODE_THUMB, "Thumb"), (CS_MODE_ARM, "ARM")):
        decoder = Cs(CS_ARCH_ARM, mode)
        decoder.detail = True
        rows = list(decoder.disasm(raw, address))
        if not rows:
            continue
        instruction = rows[0]
        immediate_targets = [int(op.imm) & 0xffffffff for op in instruction.operands if op.type == ARM_OP_IMM]
        if instruction.mnemonic.lower() in ("bl", "blx") and target in immediate_targets:
            matches.append({"mode": name, "mnemonic": instruction.mnemonic.lower(), "target": hex(target)})
    if len(matches) != 1:
        return {"status": "UNRESOLVED", "candidate_modes": matches}
    return {"status": "PRIMARY_ELF_VERIFIED", **matches[0]}


def _decode_window(fp: Any, elf: ELFFile, start: int, size: int) -> dict[int, Any]:
    raw = _exec_bytes(fp, elf, start, size)
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    return {int(row.address): row for row in decoder.disasm(raw, start)}


def _caller_symbol(elf: ELFFile, entry: int) -> dict[str, Any] | None:
    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym is None:
        return None
    candidates = []
    for symbol in dynsym.iter_symbols():
        value = int(symbol["st_value"]) & ~1
        if value == entry and symbol.name:
            candidates.append({"name": symbol.name, "value": hex(int(symbol["st_value"])), "size": int(symbol["st_size"]), "binding": str(symbol["st_info"]["bind"])})
    return candidates[0] if candidates else None


def _chain_observation(fp: Any, elf: ELFFile, refs: list[dict[str, Any]], get_binding: dict[str, Any], set_binding: dict[str, Any]) -> dict[str, Any]:
    by_caller: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ref in refs:
        caller = ref.get("caller_entry_elf_vma")
        if caller:
            by_caller[str(caller)].append(ref)
    chains: list[dict[str, Any]] = []
    for caller_text, rows in by_caller.items():
        caller = _parse_hex(caller_text, "caller_entry_elf_vma")
        get_rows = [row for row in rows if row.get("target_symbol") == GET]
        set_rows = [row for row in rows if row.get("target_symbol") == GET_SET]
        for get_row in get_rows:
            for set_row in set_rows:
                get_call = _parse_hex(get_row["from_address_elf_vma"], "from_address_elf_vma")
                set_call = _parse_hex(set_row["from_address_elf_vma"], "from_address_elf_vma")
                try:
                    window = _decode_window(fp, elf, get_call - 0x0a, 0x12)
                except ValueError:
                    continue
                mov_r1 = window.get(get_call - 4)
                mov_r4 = window.get(get_call - 2)
                guard = window.get(get_call + 4)
                adjacent = set_call == get_call + 6
                parameter_id = None
                if mov_r1 and mov_r1.mnemonic.lower() == "movs" and "r1, #0x19" == mov_r1.op_str.lower():
                    parameter_id = 0x19
                copy_shape = bool(mov_r4 and mov_r4.mnemonic.lower() == "mov" and mov_r4.op_str.lower() == "r4, r0")
                guard_shape = bool(guard and guard.mnemonic.lower() == "cbz" and guard.op_str.lower().startswith("r0,"))
                if not (adjacent and parameter_id == 0x19 and copy_shape and guard_shape):
                    continue
                caller_info = _caller_symbol(elf, caller)
                chains.append({
                    # The instruction/control-flow shape is directly
                    # observed.  The C++ meaning of the returned pointers is
                    # a separate, lower-confidence interpretation.
                    "status": "PRIMARY_ELF_VERIFIED",
                    "semantic_status": "STATIC_INFERRED",
                    "caller_entry_elf_vma": hex(caller),
                    "caller_symbol": caller_info,
                    "event_parameter_lookup": {
                        "target_symbol": GET,
                        "callsite_elf_vma": hex(get_call),
                        "r0_source": "result of preceding Event/ParamList helper, copied through r4 before this call",
                        "r1_source": "immediate constant 0x19",
                        "r1_value": "0x19",
                        "return_guard": "cbz r0 before getSet call",
                        "plt": get_binding,
                    },
                    "set_payload_lookup": {
                        "target_symbol": GET_SET,
                        "callsite_elf_vma": hex(set_call),
                        "receiver_source": "r0 is the non-null return from PrmSet::GET",
                        "return": "borrowed payload pointer candidate from PrmSet::getSet",
                        "plt": set_binding,
                    },
                    "control_flow": "GET result is null-checked, then immediately used as getSet receiver",
                })
    return {"status": "PRIMARY_ELF_VERIFIED" if chains else "UNKNOWN", "chains": chains}


def probe_paramset_cross_elf(
    dependent_elf: Path, ghidra_export: Path, *,
    expected_dependent_sha256: str | None = None,
    provider_elf: Path | None = None,
    expected_provider_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Recover imported ``PrmSet`` callsites from one dependent ELF."""
    dependent_elf = dependent_elf.resolve()
    actual_sha = _sha256(dependent_elf)
    if expected_dependent_sha256 and actual_sha.lower() != expected_dependent_sha256.lower():
        raise ValueError("dependent ELF SHA-256 mismatch")
    export = load_imported_symbol_export(ghidra_export, expected_binary_sha256=actual_sha)
    requested = (GET_SET, GET)
    with dependent_elf.open("rb") as fp:
        elf = ELFFile(fp)
        imports = _symbol_imports(elf, requested)
        if set(imports) != set(requested):
            missing = sorted(set(requested) - set(imports))
            raise ValueError("dependent ELF is missing requested imports: " + ",".join(missing))
        bindings = _plt_bindings(fp, elf, requested)
        if set(bindings) != set(requested):
            missing = sorted(set(requested) - set(bindings))
            raise ValueError("could not resolve requested ARM PLT entries: " + ",".join(missing))
        records = export["records"]
        # Ghidra commonly emits a demangled local name such as ``GET`` for
        # several ParamBase classes.  Names alone are therefore ambiguous.
        # Resolve only when the reference's exact ELF VMA equals the unique
        # PLT VMA established from the dependent ELF's relocation table.
        binding_by_target_vma = {
            _parse_hex(binding["plt_vma"], "plt_vma"): target
            for target, binding in bindings.items()
        }
        normalized_refs: list[dict[str, Any]] = []
        excluded_refs: list[dict[str, Any]] = []
        for record in records:
            if record.get("kind") != "reference" or not record.get("is_call"):
                continue
            target_vma = _parse_hex(record["target_address_elf_vma"], "target_address_elf_vma")
            caller_vma_text = record.get("caller_entry_elf_vma")
            caller_vma = (
                _parse_hex(caller_vma_text, "caller_entry_elf_vma")
                if caller_vma_text is not None else None
            )
            # Some Ghidra programs model a PLT's computed branch through an
            # external pointer instead of using the PLT entry as target.  A
            # caller entry that is itself the uniquely resolved PLT is still
            # a linker self-reference and never an application caller.
            self_target = binding_by_target_vma.get(caller_vma)
            if self_target is not None:
                excluded_refs.append({
                    "target_symbol": self_target,
                    "from_address_elf_vma": hex(_parse_hex(record["from_address_elf_vma"], "from_address_elf_vma")),
                    "reason": "PLT_SELF_REFERENCE",
                })
                continue
            target_symbol = binding_by_target_vma.get(target_vma)
            if target_symbol is None:
                continue
            from_vma = _parse_hex(record["from_address_elf_vma"], "from_address_elf_vma")
            # Ghidra also reports the relocation/data reference inside the
            # imported PLT stub itself.  It is a linker implementation detail,
            # not an application caller, so retain it separately instead of
            # presenting it as a second semantic use.
            plt_vma = _parse_hex(bindings[target_symbol]["plt_vma"], "plt_vma")
            if caller_vma == plt_vma:
                excluded_refs.append({
                    "target_symbol": target_symbol,
                    "from_address_elf_vma": hex(from_vma),
                    "reason": "PLT_SELF_REFERENCE",
                })
                continue
            item = dict(record)
            item["target_symbol"] = target_symbol
            item["target_plt_vma"] = hex(target_vma)
            item["callsite_elf_vma"] = hex(from_vma)
            item["capstone"] = _decode_at(fp, elf, from_vma, _parse_hex(bindings[target_symbol]["plt_vma"], "plt_vma"))
            item["status"] = "PRIMARY_ELF_VERIFIED" if item["capstone"].get("status") == "PRIMARY_ELF_VERIFIED" else "UNRESOLVED"
            item["evidence_method"] = "GHIDRA_DERIVED+CAPSTONE"
            normalized_refs.append(item)
        chain = _chain_observation(fp, elf, normalized_refs, bindings[GET], bindings[GET_SET])
        provider = None
        if provider_elf is not None:
            provider_elf = provider_elf.resolve()
            provider_sha = _sha256(provider_elf)
            if provider_sha.lower() != expected_provider_sha256.lower():
                raise ValueError("provider ELF SHA-256 mismatch")
            with provider_elf.open("rb") as provider_stream:
                provider = _symbol_imports(ELFFile(provider_stream), requested)
            provider = {
                "path_basename": provider_elf.name,
                "sha256": provider_sha,
                "symbols": provider,
                "status": "PRIMARY_ELF_VERIFIED",
            }
        return {
            "schema_version": "paramset-cross-elf-1",
            "firmware_version": "3.21",
            "dependent_binary": {
                "path_basename": dependent_elf.name,
                "sha256": actual_sha,
                "address_space": "ELF_VMA",
                "ghidra_image_base": export["ghidra_image_base"],
                "ghidra_export_sha256": export["source_export_sha256"],
                "language": export["metadata"].get("language", "UNKNOWN"),
            },
            "provider_binary": provider,
            "imports": imports,
            "plt_bindings": bindings,
            "relations": normalized_refs,
            "excluded_references": excluded_refs,
            "chains": chain["chains"],
            "chain_status": chain["status"],
            "chain_semantic_status": "STATIC_INFERRED" if chain["chains"] else "UNKNOWN",
            "runtime_verified": False,
            "callable": False,
            "verification_boundary": "Static import relocation, Ghidra reference and Capstone callsite evidence; loader binding, ownership and runtime safety remain UNKNOWN",
            "analyzer_versions": {
                "ghidra": export["metadata"].get("ghidra_version", "UNKNOWN"),
                "capstone": getattr(capstone, "__version__", "UNKNOWN"),
                "platform_probe": "paramset-cross-elf-1",
            },
            "evidence_scope": {
                "import_relocations": "PRIMARY_ELF_VERIFIED; .dynsym undefined imports and unique .rel.plt R_ARM_JUMP_SLOT entries",
                "plt_targets": "PRIMARY_ELF_VERIFIED; ARM PLT instruction pattern resolves each GOT slot",
                "callers": "PRIMARY_ELF_VERIFIED; Ghidra reference plus Capstone callsite instruction at the exact ELF VMA",
                "query_chain": "STATIC_INFERRED; local register/control-flow shape supports GET result as getSet receiver, but C++ source types and runtime ownership are not proven",
            },
            "runtime_constraints": {
                "runtime_verified": False,
                "callable": False,
                "loader_binding": "UNKNOWN; static provider export and dependent relocation agree, dynamic loader behavior was not exercised",
                "ownership": "UNKNOWN; GET/getSet return ownership and concurrent validity are not established",
                "provider_load_bias": "UNKNOWN; all recorded addresses are file ELF_VMA, not runtime virtual addresses",
            },
        }


def validate_paramset_cross_elf(contract: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    if contract.get("schema_version") != "paramset-cross-elf-1": errors.append("schema_version")
    dependent = contract.get("dependent_binary") or {}
    if len(str(dependent.get("sha256", ""))) != 64: errors.append("dependent_identity")
    if dependent.get("address_space") != "ELF_VMA": errors.append("address_space")
    imports = contract.get("imports") or {}
    if set(imports) != {GET_SET, GET}: errors.append("imports")
    bindings = contract.get("plt_bindings") or {}
    if set(bindings) != {GET_SET, GET}: errors.append("plt_bindings")
    for name, binding in bindings.items():
        if binding.get("status") != "PRIMARY_ELF_VERIFIED": errors.append(f"binding:{name}")
        if binding.get("address_space") != "ELF_VMA": errors.append(f"binding_space:{name}")
    relations = contract.get("relations") or []
    if not relations: errors.append("relations")
    for relation in relations:
        target_symbol = relation.get("target_symbol")
        if target_symbol not in {GET_SET, GET}:
            errors.append("relation_target_symbol")
            continue
        if relation.get("binary_sha256") != dependent.get("sha256"):
            errors.append("relation_binary_identity")
        expected_plt = bindings.get(target_symbol, {}).get("plt_vma")
        if relation.get("target_address_elf_vma") != expected_plt:
            errors.append("relation_target_address")
        if relation.get("status") not in {"PRIMARY_ELF_VERIFIED", "UNRESOLVED"}:
            errors.append("relation_status")
        if relation.get("evidence_method") != "GHIDRA_DERIVED+CAPSTONE": errors.append("relation_evidence")
        if relation.get("status") == "PRIMARY_ELF_VERIFIED" and relation.get("capstone", {}).get("status") != "PRIMARY_ELF_VERIFIED":
            errors.append("relation_capstone")
    if contract.get("runtime_verified") is not False or contract.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    chains = contract.get("chains") or []
    if chains:
        chain = chains[0]
        if chain.get("status") != "PRIMARY_ELF_VERIFIED": errors.append("chain_status")
        if chain.get("semantic_status") != "STATIC_INFERRED": errors.append("chain_semantic_status")
        if chain.get("event_parameter_lookup", {}).get("r1_value") != "0x19": errors.append("parameter_value")
        if chain.get("set_payload_lookup", {}).get("receiver_source") != "r0 is the non-null return from PrmSet::GET": errors.append("receiver_flow")
    if chains and contract.get("chain_semantic_status") != "STATIC_INFERRED":
        errors.append("contract_chain_semantic_status")
    return {"valid": not errors, "errors": sorted(set(errors))}
