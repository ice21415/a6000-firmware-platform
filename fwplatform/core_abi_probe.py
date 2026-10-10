"""Bounded *primary ELF byte* ABI probe for two core Sony Camera helpers.

This is a LOCAL diagnostic tool, not a camera API or an implementation
of Sony's private library. It never executes firmware, changes any file,
or claims a C++ prototype from a Capstone mnemonic alone.

Evidence tiers:
* the pinned full-file SHA authenticates the original private libObj.so;
* each reviewed instruction is loaded from the exact executable PT_LOAD VMA;
* a region fingerprint covers observed VMA/bytes but proves no function extent;
* register READ_BEFORE_WRITE is only an entry-block heuristic, not ABI proof.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile

from .private_thumb_research import (
    EXPECTED_LIBOBJ_SHA, MAX_ELF_BYTES, MAX_REGION_BYTES,
    _read_vma, _sha256, _trace_thumb,
)

CORE_ABI_TARGETS: tuple[tuple[str, int], ...] = (
    ("camera_action_payload_getter", 0x13200A),
    ("camera_parameter_lookup", 0x42AC00),
)
MAX_TARGETS = 6
DEFAULT_REGION_BYTES = 384
MAX_RETURN_SITES = 32
MAX_SAMPLED_ROWS = 96
MAX_REGISTER_SITES = 64
MAX_MEMORY_SITES = 96
ARG_REGISTERS = ("r0", "r1", "r2", "r3")


def _reg_observations(fp: Any, elf: ELFFile, region: dict[str, Any]) -> dict[str, Any]:
    """Inspect only locally reached instructions, not static symbol contracts."""
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_AC_READ, CS_AC_WRITE
    from capstone.arm import ARM_OP_MEM

    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    rows = region["instruction_observations"]
    raw_hash = hashlib.sha256()
    reads_before_writes: dict[str, list[str]] = {reg: [] for reg in ARG_REGISTERS}
    writes_seen: set[str] = set()
    prefix_rows: list[dict[str, Any]] = []
    r0_writes: list[str] = []
    return_sites: list[str] = []
    memory_accesses: list[dict[str, Any]] = []
    fingerprints = 0
    decoded: dict[int, Any] = {}

    for row in rows:
        address = int(row["vma"], 16)
        raw = _read_vma(fp, elf, address, row["size"], executable=True)
        ins_list = list(decoder.disasm(raw, address, count=1))
        if len(ins_list) != 1 or ins_list[0].size != row["size"]:
            raise ValueError(f"ELF probe failed byte/decoder consistency at {row['vma']}")
        ins = ins_list[0]
        # This represents a canonical sorted list of *visited instruction bytes*
        # rather than a claim to have obtained the entire function.
        raw_hash.update(struct.pack("<I", address))
        raw_hash.update(bytes([row["size"]]))
        raw_hash.update(raw)
        fingerprints += 1
        decoded[address] = ins
        read_regs, write_regs = ins.regs_access()
        read = {ins.reg_name(x) for x in read_regs}
        write = {ins.reg_name(x) for x in write_regs}
        if "r0" in write and len(r0_writes) < MAX_REGISTER_SITES:
            r0_writes.append(row["vma"])
        # Only actual decoded memory operands count. A base of 'r2'
        # is a promising out-pointer use, but r2 might have been
        # redefined since entry, so never promote this to ABI proof.
        if len(memory_accesses) < MAX_MEMORY_SITES:
            for operand in ins.operands:
                if operand.type != ARM_OP_MEM:
                    continue
                access = getattr(operand, "access", 0)
                if not access:
                    # Capstone ARM operand metadata may omit access flags
                    # for some encodings, so use mnemonic only as a
                    # conservative local load/store direction hint.
                    mnemonic = ins.mnemonic.lower()
                    if mnemonic.startswith(("str", "stm", "push")):
                        access = CS_AC_WRITE
                    elif mnemonic.startswith(("ldr", "ldm", "pop")):
                        access = CS_AC_READ
                direction = ("READ_WRITE" if access & CS_AC_READ and access & CS_AC_WRITE
                             else "WRITE" if access & CS_AC_WRITE
                             else "READ" if access & CS_AC_READ
                             else "UNKNOWN")
                memory_accesses.append({
                    "site": row["vma"],
                    "mnemonic": ins.mnemonic,
                    "memory_base_register": ins.reg_name(operand.mem.base),
                    "memory_index_register": (
                        ins.reg_name(operand.mem.index) if operand.mem.index else None
                    ),
                    "displacement": int(operand.mem.disp),
                    "operation_direction_hint": direction,
                    "memory_access_width_cpp_type_verified": False,
                })
        # Returns may be "bx lr", "pop {...,pc}", or a Capstone RET group.
        if (ins.group(CS_GRP_RET)
            or (ins.mnemonic.lower() in ("bx", "bx.w") and ins.op_str.strip() == "lr")
            or (ins.mnemonic.lower() in ("pop", "pop.w") and "pc" in ins.op_str)):
            if len(return_sites) < MAX_RETURN_SITES:
                return_sites.append(row["vma"])

    # Prefix walks only the linear instruction stream from the entry until
    # its first branch, call, return or gap. It is a useful set of ABI *leads*
    # but neither follows control flow nor proves parameter types.
    address = int(region["entry_vma"], 16)
    while address in decoded and len(prefix_rows) < MAX_REGISTER_SITES:
        ins = decoded[address]
        reads_raw, writes_raw = ins.regs_access()
        read = {ins.reg_name(x) for x in reads_raw}
        write = {ins.reg_name(x) for x in writes_raw}
        for reg in ARG_REGISTERS:
            if reg in read and reg not in writes_seen:
                reads_before_writes[reg].append(hex(address))
        writes_seen |= (write & set(ARG_REGISTERS))
        prefix_rows.append({
            "vma": hex(address), "mnemonic": ins.mnemonic,
            "operands": ins.op_str,
        })
        if (ins.group(CS_GRP_JUMP) or ins.group(CS_GRP_CALL)
            or ins.group(CS_GRP_RET)
            or ins.mnemonic.lower() in ("cbz", "cbnz", "bx", "tbh", "tbb")
            or "pc" in ins.op_str and ins.mnemonic.lower().startswith("pop")):
            break
        address += ins.size

    return {
        "visited_instruction_bytes_sha256": raw_hash.hexdigest(),
        "fingerprinted_instruction_count": fingerprints,
        "prefix_end_reason": (
            "CONTROL_TRANSFER_OR_RETURN" if prefix_rows and prefix_rows[-1]["vma"] == hex(address)
            and (decoded.get(address) is not None)
            else "NONLINEAR_OR_REGION_LIMIT"
        ),
        "entry_linear_prefix": prefix_rows,
        "entry_prefix_register_read_before_write_sites": reads_before_writes,
        "entry_prefix_register_initially_written": sorted(writes_seen),
        "visited_r0_write_sites_capped": r0_writes,
        "visited_memory_access_sites_capped": memory_accesses,
        "r2_based_memory_write_sites_capped": [
            item["site"] for item in memory_accesses
            if item["memory_base_register"] == "r2"
            and item["operation_direction_hint"] in ("WRITE", "READ_WRITE")
        ],
        "r2_based_store_is_proven_output_parameter": False,
        "observed_return_sites_capped": sorted(return_sites, key=lambda x: int(x, 16)),
        "register_read_before_write_is_proven_abi": False,
        "return_cpp_type_verified": False,
        "entire_function_covered": False,
    }


def probe_private_core_abi(
    elf_path: Path, *,
    expected_sha256: str = EXPECTED_LIBOBJ_SHA,
    targets: tuple[tuple[str, int], ...] = CORE_ABI_TARGETS,
    region_bytes: int = DEFAULT_REGION_BYTES,
) -> dict[str, Any]:
    """Offline exact-sha Thumb probe; returns evidence, never a callable ABI."""
    from .private_thumb_research import HEX_SHA

    path = Path(elf_path).resolve()
    if not path.is_file() or not 0 < path.stat().st_size <= MAX_ELF_BYTES:
        raise ValueError("private ELF missing or exceeds 128 MiB")
    if not isinstance(expected_sha256, str) or not HEX_SHA.fullmatch(expected_sha256):
        raise ValueError("expected_sha256 must be a lowercase full SHA-256 digest")
    if not 16 <= region_bytes <= MAX_REGION_BYTES or region_bytes & 1:
        raise ValueError("region_bytes must be an even number between 16 and 8192")
    if not targets or len(targets) > MAX_TARGETS:
        raise ValueError("must supply 1 to 6 target entries")
    if (len({vma for _, vma in targets}) != len(targets)
        or any(not isinstance(label, str) or not label.strip()
               or not isinstance(vma, int) or isinstance(vma, bool)
               or vma <= 0 or vma & 1 for label, vma in targets)):
        raise ValueError("target names must be nonempty and VMAs distinct/even/positive")
    digest = _sha256(path)
    if digest != expected_sha256:
        raise ValueError("full-file ELF SHA-256 mismatch; refusing to decode")
    reports = []
    with path.open("rb") as fp:
        elf = ELFFile(fp)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_ARM":
            raise ValueError("core ABI probe accepts ELF32 little-endian ARM only")
        if elf["e_type"] not in ("ET_EXEC", "ET_DYN"):
            raise ValueError("core ABI probe requires executable/shared-library ELF")
        for label, entry in targets:
            # Fail closed on non-code entries, ambiguous PT_LOAD mappings.
            _read_vma(fp, elf, entry, 2, executable=True)
            region = _trace_thumb(fp, elf, entry, region_bytes)
            observations = _reg_observations(fp, elf, region)
            from .elf_plt import resolve_plt_binding
            bindings = []
            plt = elf.get_section_by_name(".plt")
            if plt is not None:
                for branch in region["branch_observations"]:
                    target = branch.get("target_vma")
                    if target is None:
                        continue
                    target_address = int(target, 16)
                    if plt["sh_addr"] <= target_address < plt["sh_addr"] + plt["sh_size"]:
                        bindings.append(resolve_plt_binding(fp, elf, target_address, thumb_stub=True))
            reports.append({
                "research_target": label, "entry_vma": hex(entry),
                "bounded_region_bytes": region_bytes,
                "visited_instructions": region["decoded_instruction_count"],
                "call_targets_and_sites": region["direct_or_indirect_calls"],
                "branches_within_or_outside_region": region["branch_observations"],
                "literal_load_candidates": region["literal_load_candidates"],
                "incompleteness_reasons": region["incompleteness_reasons"],
                "sampled_instruction_rows": region["instruction_observations"][:MAX_SAMPLED_ROWS],
                "register_and_return_observations": observations,
                "relocation_bound_tail_targets": bindings,
                "complete_cpp_abi_proven": False,
                "function_boundary_proven": False,
            })
    return {
        "status": "LOCAL_PRIMARY_ELF_BOUNDED_HELPER_EVIDENCE_ONLY",
        "binary_file_sha256": digest,
        "matches_pinned_a6000_libobj_3_21": digest == EXPECTED_LIBOBJ_SHA,
        "authenticated_entire_elf_file": digest == EXPECTED_LIBOBJ_SHA,
        "primary_executable_bytes_were_read": True,
        "research_targets": reports,
        "callable_camera_core_api_count": 0,
        "cpp_type_and_return_contract_verified": False,
        "control_flow_completeness_verified": False,
        "device_executed": False,
        "note": (
            "The command reads private ELF bytes locally without publishing raw "
            "instruction bytes or running firmware. Mnemonics, register heuristics "
            "and fingerprints cover only visited paths and cannot prove a whole "
            "C++ ABI, exception contract, lifetime, or safe device callability."
        ),
    }
