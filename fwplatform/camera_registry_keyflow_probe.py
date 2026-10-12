"""Read-only, SHA-pinned *intra-function* Registry identity reconnaissance.

The marker in r1 is symbolic, not a fabricated camera pointer.  Its purpose is
to distinguish stores to the state machine's *argument record* from unrelated
objects sharing the +8 offset.  No cross-function registration-to-lookup,
runtime instance, or loader identity is inferred from this probe.

Runs only on an explicitly supplied, locally accessible PRIVATE ELF.  Output
contains curated VMAs, counts and value provenance; never firmware bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

from .arm_store_dataflow import analyze_function
from .private_thumb_research import EXPECTED_LIBOBJ_SHA

RECORD_ARG_MARKER = 0x40000000  # analysis-only symbolic address, NOT camera VMA
MAX_ELF_SIZE = 128 * 1024 * 1024

# Targeted bounded windows are *not* proven function extents.  ELF symbols or
# EHABI ranges must independently establish exact boundaries if needed.
SITES = (
    ("camera_config_register", 0x401F78, 0x180, None),
    ("idso_add", 0x7F08A0, 0x180, None),
    ("tree_key_lookup", 0x7F063C, 0x120, None),
    ("registry_registration", 0x7EC8A4, 0x130, None),
    ("registry_lookup", 0x7EB8FA, 0x100, None),
    ("consumer", 0x7ED49C, 0x480, None),
    ("record_state_machine", 0x7EAC60, 0x420, "r1"),
    ("record_loader", 0x7F11CA, 0x90, "r0"),
    ("record_forwarder", 0x7F124A, 0x20, "r0"),
)
WATCH_CALLS = frozenset({
    0x402090, 0x4020A0, 0x7EC91C, 0x7EC954,
    0x7ED5FC, 0x7ED71E, 0x7ED72E,
    0x7EAF8E, 0x7F11D8, 0x7F11E6, 0x7F11F2,
    0x7F1252,
})
WATCH_STORES = frozenset({0x7EAF4A, 0x7EAFCE, 0x7EB016, 0x7EC874, 0x7F11F4})
ANALYZER_VERSION = "camera-registry-keyflow-recon-1"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def summarize_site(result: dict[str, Any], name: str, *, marker: int | None) -> dict[str, Any]:
    """Summarize dataflow without upgrading any end-to-end identity proof."""
    stores = []
    target = (marker + 8) if marker is not None else None
    for store in result["stores"]:
        vma = store["instruction_vma"]
        if vma not in WATCH_STORES and (target is None or target not in store["effective_address"]["values"]):
            continue
        address = store["effective_address"]
        is_unique = (target is not None and result["converged"]
                     and address["values"] == [target])
        stores.append({
            "vma": hex(vma),
            "size": store["size"],
            "effective_address": address,
            "written_value": store["written_value"],
            "conditional_instruction": store["conditional"],
            "cfg_predecessors": [hex(x) for x in store["cfg_predecessors"]],
            "argument_alias": (
                "ENTRY_ARGUMENT_PLUS_8_WHEN_REACHED" if is_unique
                else "MAY_ALIAS_ENTRY_ARGUMENT_PLUS_8" if target is not None and target in address["values"]
                else "NOT_ESTABLISHED"
            ),
            "status": "CONDITIONAL_STATIC_OBSERVATION",
        })
    calls = []
    for call in result["calls"]:
        if call["callsite"] not in WATCH_CALLS:
            continue
        calls.append({
            "callsite": hex(call["callsite"]),
            "target": hex(call["target"]) if call["target"] is not None else None,
            "kind": call["kind"],
            "args": call["argument_registers"],
        })
    return {
        "name": name,
        "entry": hex(result["function_vma"]),
        "mode": result["mode"],
        "range_type": "BOUNDED_WINDOW_NOT_A_PROVEN_FUNCTION_BOUNDARY",
        "reachable_instruction_count": result["instruction_count"],
        "converged": result["converged"],
        "cfg_edge_count": len(result["cfg_edges"]),
        "calls_of_interest": calls,
        "stores_of_interest": stores,
        "unresolved": [
            {"vma": hex(x["address"]) if "address" in x else None, "reason": x["reason"]}
            for x in result["unresolved"]
        ],
        "identity_status": "INTRA_FUNCTION_ARGUMENT_ALIAS_ONLY",
    }


def analyze_site(
    read: Callable[[int, int], bytes | None],
    name: str,
    entry: int,
    window: int,
    argument_register: str | None,
    *,
    marker: int = RECORD_ARG_MARKER,
) -> dict[str, Any]:
    """Run the real CFG engine; never infer external caller/record identity."""
    if window <= 0 or window > 0x800 or entry < 0 or entry & 1:
        raise ValueError("invalid bounded Thumb region")
    if argument_register not in (None, "r0", "r1"):
        raise ValueError("unsupported argument register")
    init = {argument_register: marker} if argument_register else None
    report = analyze_function(
        read, entry, [(entry, entry + window)], mode="THUMB",
        initial_registers=init, max_instructions=2048, max_iterations=16384,
    )
    return summarize_site(report, name, marker=marker if argument_register else None)


def probe_registry_keyflow(path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA) -> dict[str, Any]:
    """Targeted ELF scan. No implicit network, device access, or SDK promotion."""
    from elftools.elf.elffile import ELFFile

    path = Path(path).resolve()
    if not path.is_file() or path.stat().st_size > MAX_ELF_SIZE:
        raise ValueError("missing or oversized private ELF")
    digest = sha256_file(path)
    if digest != expected_sha256:
        raise ValueError("ELF SHA256 mismatch")
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_ARM":
            raise ValueError("requires ELF32 little-endian ARM")
        segments = [s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
        dynamic_slots = {
            int(rel["r_offset"])
            for section in elf.iter_sections()
            if section["sh_type"] in ("SHT_REL", "SHT_RELA")
            for rel in section.iter_relocations()
        }

        def read(address: int, size: int) -> bytes | None:
            if not 0 < size <= 4:
                return None
            if any(address <= slot < address + size for slot in dynamic_slots):
                return None
            choices = [s for s in segments
                       if int(s["p_vaddr"]) <= address
                       and address + size <= int(s["p_vaddr"]) + int(s["p_filesz"])]
            if len(choices) != 1:
                return None
            segment = choices[0]
            # Mutable memory, including .data, must not be treated as immutable.
            if int(segment["p_flags"]) & 2:
                return None
            stream.seek(int(segment["p_offset"]) + address - int(segment["p_vaddr"]))
            return stream.read(size)

        output = []
        for name, entry, window, arg in SITES:
            report = analyze_site(read, name, entry, window, arg)
            output.append(report)
    return {
        "schema_version": 1,
        "analyzer_version": ANALYZER_VERSION,
        "binary_sha256": digest,
        "address_space": "ELF_VMA",
        "sites": output,
        "registration_lookup_identity": "UNKNOWN",
        "record_instance_identity": "UNKNOWN",
        "runtime_dso_identity": "UNKNOWN",
        "runtime_verified": False,
        "safe_to_invoke": False,
        "proof_scope": "TARGETED_ELF_CFG_AND_SYMBOLIC_ARGUMENT_ALIAS_ONLY",
        "limitations": [
            "bounded windows are not complete function extents",
            "unknown stack/heap, IT blocks and indirect branches fail closed",
            "symbolic marker does not establish caller object identity",
            "record insertion and lookup equivalence remains unverified",
            "no runtime loader resolution or firmware bytes exported",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline private-ELF Registry pointer reconnaissance")
    parser.add_argument("--elf", required=True, type=Path, help="locally held private libObj.so")
    parser.add_argument("--sha256", default=EXPECTED_LIBOBJ_SHA)
    args = parser.parse_args()
    print(json.dumps(probe_registry_keyflow(args.elf, expected_sha256=args.sha256), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
