"""Bounded ARM32 CFG constant/alias propagation over Capstone operands.

This module proves effective addresses, not execution or callback identity.
Memory readers must return None for mutable/unresolved memory. Function ranges
are supplied by the caller; bytes outside them are never decoded as code.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct
from typing import Callable, Iterable

from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, Cs
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_CC_AL, ARM_CC_INVALID, ARM_INS_BL, ARM_INS_BLX


@dataclass(frozen=True)
class Value:
    """None is lattice top (UNKNOWN), finite sets are possible values."""
    values: frozenset[int] | None = None
    origins: frozenset[int] = frozenset()

    @classmethod
    def constant(cls, value: int, address: int = 0) -> Value:
        return cls(frozenset({value & 0xFFFFFFFF}), frozenset({address}))

    def join(self, other: Value, limit: int = 8) -> Value:
        origins = self.origins | other.origins
        if self.values is None or other.values is None:
            return Value(None, origins)
        values = self.values | other.values
        return Value(values if len(values) <= limit else None, origins)

    def combine(self, other: Value, operation: Callable[[int, int], int], address: int) -> Value:
        origins = self.origins | other.origins | {address}
        if self.values is None or other.values is None:
            return Value(None, frozenset(origins))
        result = frozenset(operation(a, b) & 0xFFFFFFFF for a in self.values for b in other.values)
        return Value(result if len(result) <= 8 else None, frozenset(origins))

    def as_dict(self) -> dict:
        return {"kind": "UNKNOWN" if self.values is None else ("CONSTANT" if len(self.values) == 1 else "MULTIPLE_CANDIDATES"),
                "values": sorted(self.values) if self.values is not None else [], "instruction_origins": sorted(self.origins)}


UNKNOWN = Value()


def analyze_function(
    read_memory: Callable[[int, int], bytes | None], entry: int,
    ranges: Iterable[tuple[int, int]], *, mode: str = "THUMB",
    target: int | None = None, initial_registers: dict[str, int] | None = None,
    max_instructions: int = 4096, max_iterations: int = 32768,
) -> dict:
    """Recover reachable instruction CFG and memory-store effective addresses.

    Range ends are exclusive. Conditional paths are joined conservatively;
    calls are recorded and clobber AAPCS caller-saved registers. No callee is
    guessed or executed. Store proofs are emitted only after fixed-point.
    """
    if mode not in {"ARM", "THUMB"}:
        raise ValueError("mode must be ARM or THUMB")
    entry &= ~1
    bounds = tuple(ranges)
    if not any(start <= entry < end for start, end in bounds):
        raise ValueError("entry outside function ranges")
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB if mode == "THUMB" else CS_MODE_ARM)
    decoder.detail = True
    instructions: dict[int, object] = {}
    edges: dict[int, list[tuple[int, str]]] = {}
    unresolved: list[dict] = []
    calls: list[dict] = []
    pending = deque([entry])
    visited: set[int] = set()

    def inside(address: int) -> bool:
        return any(start <= address < end for start, end in bounds)

    # Recursive traversal decodes only reachable instructions, never literal pools.
    while pending and len(instructions) < max_instructions:
        address = pending.popleft()
        if address in visited:
            continue
        visited.add(address)
        if not inside(address):
            unresolved.append({"address": address, "reason": "OUTSIDE_FUNCTION_RANGE"})
            continue
        available = min(4, max(end - address for start, end in bounds if start <= address < end))
        raw = read_memory(address, available)
        decoded = list(decoder.disasm(raw or b"", address, count=1))
        if not decoded:
            unresolved.append({"address": address, "reason": "DECODE_FAILURE"})
            continue
        insn = decoded[0]
        instructions[address] = insn
        name = insn.mnemonic.split(".")[0]
        next_address = address + insn.size
        successors: list[tuple[int, str]] = []
        conditional = insn.cc not in (ARM_CC_AL, ARM_CC_INVALID)
        is_call = insn.id in {ARM_INS_BL, ARM_INS_BLX}
        if name == "it" or name.startswith("it"):
            unresolved.append({"address": address, "reason": "IT_BLOCK_UNSUPPORTED"})
            edges[address] = []
            continue
        if is_call:
            direct = insn.operands[0].imm if insn.operands and insn.operands[0].type == ARM_OP_IMM else None
            calls.append({"callsite": address, "target": direct, "kind": "DIRECT" if direct is not None else "INDIRECT",
                          "target_mode": "ARM" if name == "blx" and direct is not None and mode == "THUMB" else mode})
            successors.append((next_address, "CALL_RETURN"))
        elif name.startswith("b") or name in {"cbz", "cbnz"}:
            if name in {"bic", "bics", "bfi", "bfc"}:
                successors.append((next_address, "FALLTHROUGH"))
            elif insn.operands and insn.operands[-1].type == ARM_OP_IMM:
                successors.append((insn.operands[-1].imm & ~1, "BRANCH"))
                if conditional or name in {"cbz", "cbnz"}:
                    successors.append((next_address, "CONDITION_FALSE"))
            else:
                unresolved.append({"address": address, "reason": "INDIRECT_BRANCH_OR_RETURN"})
                if conditional:
                    successors.append((next_address, "CONDITION_FALSE"))
        else:
            _, writes = insn.regs_access()
            if any(insn.reg_name(reg) == "pc" for reg in writes):
                unresolved.append({"address": address, "reason": "PC_WRITE_OR_RETURN"})
                if conditional:
                    successors.append((next_address, "CONDITION_FALSE"))
            else:
                successors.append((next_address, "FALLTHROUGH"))
        edges[address] = successors
        for destination, _ in successors:
            if inside(destination):
                pending.append(destination)
            else:
                unresolved.append({"address": address, "target": destination, "reason": "CFG_BOUNDARY"})
    if pending:
        unresolved.append({"reason": "INSTRUCTION_BUDGET"})

    def register(insn: object, reg: int, state: dict[str, Value]) -> Value:
        name = insn.reg_name(reg)
        if name == "pc":
            return Value.constant(insn.address + (4 if mode == "THUMB" else 8), insn.address)
        return state.get(name, UNKNOWN)

    def operand(insn: object, op: object, state: dict[str, Value]) -> Value:
        if op.type == ARM_OP_IMM:
            return Value.constant(op.imm, insn.address)
        if op.type != ARM_OP_REG:
            return UNKNOWN
        value = register(insn, op.reg, state)
        if op.shift.type:
            # Capstone ARM_SFT_LSL=2, LSR=3, ASR=1. Register shifts unknown.
            if op.shift.type == 2:
                return value.combine(Value.constant(op.shift.value), lambda a, b: a << b, insn.address)
            if op.shift.type == 3:
                return value.combine(Value.constant(op.shift.value), lambda a, b: a >> b, insn.address)
            return UNKNOWN
        return value

    def effective(insn: object, op: object, state: dict[str, Value]) -> Value:
        value = register(insn, op.mem.base, state)
        if insn.reg_name(op.mem.base) == "pc" and mode == "THUMB":
            value = Value.constant((insn.address + 4) & ~3, insn.address)
        offset = Value.constant(op.mem.disp, insn.address)
        if op.mem.index:
            index = register(insn, op.mem.index, state)
            if op.shift.type == 2:
                index = index.combine(Value.constant(op.shift.value), lambda a, b: a << b, insn.address)
            elif op.shift.type:
                index = UNKNOWN
            scale = -(op.mem.scale or 1) if op.subtracted else (op.mem.scale or 1)
            offset = offset.combine(index, lambda a, b: a + b * scale, insn.address)
        return value.combine(offset, lambda a, b: a + b, insn.address)

    def transfer(insn: object, state: dict[str, Value]) -> tuple[dict[str, Value], list[dict]]:
        result = dict(state)
        stores: list[dict] = []
        ops = insn.operands
        name = insn.mnemonic.split(".")[0]
        _, written = insn.regs_access()
        for reg in written:
            result[insn.reg_name(reg)] = UNKNOWN
        destination = insn.reg_name(ops[0].reg) if ops and ops[0].type == ARM_OP_REG else None
        if name.startswith("mov") and destination and len(ops) >= 2:
            value = operand(insn, ops[1], state)
            if name == "movt":
                value = state.get(destination, UNKNOWN).combine(value, lambda a, b: (a & 0xFFFF) | (b << 16), insn.address)
            result[destination] = value
        elif name.startswith(("add", "sub")) and destination and len(ops) >= 2:
            left = operand(insn, ops[1], state) if len(ops) >= 3 else state.get(destination, UNKNOWN)
            right = operand(insn, ops[2] if len(ops) >= 3 else ops[1], state)
            result[destination] = left.combine(right, (lambda a, b: a - b) if name.startswith("sub") else (lambda a, b: a + b), insn.address)
        elif name == "adr" and destination and len(ops) >= 2:
            result[destination] = Value.constant(((insn.address + 4) & ~3) if mode == "THUMB" else insn.address + 8, insn.address).combine(operand(insn, ops[1], state), lambda a, b: a + b, insn.address)
        elif name.startswith("ldr") and destination and len(ops) >= 2 and ops[1].type == ARM_OP_MEM:
            address = effective(insn, ops[1], state)
            size = 1 if name.startswith("ldrb") else 2 if name.startswith("ldrh") else 4
            values: Value | None = None
            if address.values is not None:
                for location in address.values:
                    data = read_memory(location, size)
                    loaded = Value.constant(int.from_bytes(data, "little"), insn.address) if data is not None and len(data) == size else UNKNOWN
                    loaded = Value(loaded.values, loaded.origins | address.origins)
                    values = loaded if values is None else values.join(loaded)
            result[destination] = values or UNKNOWN
        elif name.startswith("str") and len(ops) >= 2 and ops[1].type == ARM_OP_MEM:
            address = effective(insn, ops[1], state)
            stores.append({"instruction_vma": insn.address, "effective_address": address.as_dict(),
                           "written_value": operand(insn, ops[0], state).as_dict(),
                           "size": 1 if name.startswith("strb") else 2 if name.startswith("strh") else 4})
            if insn.writeback:
                base = insn.reg_name(ops[1].mem.base)
                result[base] = address
                if len(ops) > 2:  # post-index update, address is original base
                    result[base] = state.get(base, UNKNOWN).combine(operand(insn, ops[2], state), lambda a, b: a + b, insn.address)
        elif name.startswith("stm") and len(ops) > 1:
            base = operand(insn, ops[0], state)
            count = len(ops) - 1
            start = -4 * count if name.startswith("stmdb") else 4 if name.startswith("stmib") else -4 * (count - 1) if name.startswith("stmda") else 0
            for index, op in enumerate(ops[1:]):
                address = base.combine(Value.constant(start + 4 * index), lambda a, b: a + b, insn.address)
                stores.append({"instruction_vma": insn.address, "effective_address": address.as_dict(), "written_value": operand(insn, op, state).as_dict(), "size": 4})
            if insn.writeback:
                result[destination] = base.combine(Value.constant(-4 * count if "d" in name[3:] else 4 * count), lambda a, b: a + b, insn.address)
        if insn.id in {ARM_INS_BL, ARM_INS_BLX}:
            for reg in ("r0", "r1", "r2", "r3", "ip", "lr"):
                result[reg] = UNKNOWN
        if insn.cc not in (ARM_CC_AL, ARM_CC_INVALID):
            for key in set(result) | set(state):
                result[key] = result.get(key, UNKNOWN).join(state.get(key, UNKNOWN))
        for store in stores:
            store["conditional"] = insn.cc not in (ARM_CC_AL, ARM_CC_INVALID)
        return result, stores

    states: dict[int, dict[str, Value]] = {entry: {key: Value.constant(value) for key, value in (initial_registers or {}).items()}}
    work = deque([entry])
    iterations = 0
    while work and iterations < max_iterations:
        address = work.popleft()
        iterations += 1
        if address not in instructions:
            continue
        output, _ = transfer(instructions[address], states[address])
        for successor, _ in edges[address]:
            if successor not in instructions:
                continue
            old = states.get(successor)
            merged = output if old is None else {key: old.get(key, UNKNOWN).join(output.get(key, UNKNOWN)) for key in set(old) | set(output)}
            if old != merged:
                states[successor] = dict(merged)
                work.append(successor)
    stores = []
    converged = not work
    for address, state in states.items():
        if address not in instructions:
            continue
        _, observations = transfer(instructions[address], state)
        for observation in observations:
            values = observation["effective_address"]["values"]
            observation.update({"function_vma": entry, "mode": mode,
                "target_match": target is not None and target in values,
                "classification": "STATICALLY_PROVEN_WRITE" if converged and len(values) == 1 else "POSSIBLE_WRITE" if values else "UNKNOWN_DESTINATION",
                "cfg_predecessors": [source for source, rows in edges.items() if any(dest == address for dest, _ in rows)]})
            stores.append(observation)
    return {"function_vma": entry, "mode": mode, "instruction_count": len(instructions), "iterations": iterations,
            "converged": converged, "stores": stores, "calls": calls,
            "cfg_edges": [{"source": source, "target": destination, "kind": kind} for source, rows in edges.items() for destination, kind in rows],
            "unresolved": unresolved, "runtime_verified": False, "safe_to_invoke": False,
            "limitations": ["bounded intraprocedural value sets; flags not evaluated", "mutable memory must be unknown in reader", "stack memory and indirect branch targets unresolved"]}


def recover_provider_writes(path: Path, expected_sha256: str, *, target: int = 0x10A8930,
                            additional_entries: Iterable[int] = (), max_window: int = 512,
                            max_functions: int = 300, max_instructions: int = 512) -> dict:
    """Reproduce bounded constructor EA recovery directly from a hash-pinned ELF.

    Dynamic symbol relocations and BSS memory are unknown. RELATIVE addends
    describe original ELF VMA only; runtime load bias is never fabricated.
    Entries lacking symbols receive explicit bounded windows, not invented
    function boundaries. This helper does not infer external writer absence.
    """
    from elftools.elf.elffile import ELFFile
    path = Path(path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if not expected_sha256 or digest != expected_sha256:
        raise ValueError("ELF SHA256 mismatch")
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 32 or not elf.little_endian or elf['e_machine'] != 'EM_ARM':
            raise ValueError("requires little-endian ARM32 ELF")
        segments = [seg for seg in elf.iter_segments() if seg['p_type'] == 'PT_LOAD']
        dynamic_locations = {int(rel['r_offset']) for section in elf.iter_sections()
                             if section['sh_type'] in ('SHT_REL', 'SHT_RELA')
                             for rel in section.iter_relocations() if int(rel['r_info_type']) != 23}
        relative_locations = {int(rel['r_offset']) for section in elf.iter_sections()
                              if section['sh_type'] in ('SHT_REL', 'SHT_RELA')
                              for rel in section.iter_relocations() if int(rel['r_info_type']) == 23}
        def read(address: int, size: int) -> bytes | None:
            if any(address <= slot < address + size for slot in dynamic_locations):
                return None
            for segment in segments:
                if int(segment['p_vaddr']) <= address and address + size <= int(segment['p_vaddr']) + int(segment['p_filesz']):
                    if int(segment['p_flags']) & 2 and not (size == 4 and address in relative_locations):
                        return None
                    stream.seek(int(segment['p_offset']) + address - int(segment['p_vaddr']))
                    return stream.read(size)
            return None
        symbols: dict[int, int] = {}
        for section in elf.iter_sections():
            if section['sh_type'] not in ('SHT_DYNSYM', 'SHT_SYMTAB'):
                continue
            for symbol in section.iter_symbols():
                if symbol['st_info']['type'] == 'STT_FUNC' and int(symbol['st_size']):
                    symbols[int(symbol['st_value']) & ~1] = int(symbol['st_size'])
        section = elf.get_section_by_name('.init_array')
        raw = section.data() if section is not None else b''
        if len(raw) % 4:
            raise ValueError("misaligned init_array")
        entries = [struct.unpack_from('<I', raw, index)[0] for index in range(0, len(raw), 4)]
        selected = list(dict.fromkeys(entries + list(additional_entries)))[:max_functions]
        results: list[dict] = []
        hits: list[dict] = []
        errors: list[dict] = []
        for pointer in selected:
            entry = pointer & ~1
            segment = next((s for s in segments if int(s['p_flags']) & 1 and int(s['p_vaddr']) <= entry < int(s['p_vaddr']) + int(s['p_filesz'])), None)
            if segment is None:
                errors.append({"entry": entry, "reason": "ENTRY_OUTSIDE_EXECUTABLE_FILE_MAPPING"})
                continue
            boundary = "SYMBOL_SIZE" if entry in symbols else "BOUNDED_WINDOW_NOT_FUNCTION_BOUNDARY"
            end = min(entry + min(symbols.get(entry, max_window), max_window), int(segment['p_vaddr']) + int(segment['p_filesz']))
            result = analyze_function(read, entry, [(entry, end)], mode='THUMB' if pointer & 1 else 'ARM',
                                      target=target, max_instructions=max_instructions, max_iterations=4096)
            results.append({"entry": entry, "mode": result['mode'], "boundary": boundary,
                            "range_end": end, "instructions": result['instruction_count'],
                            "stores": len(result['stores']), "converged": result['converged'],
                            "unresolved": result['unresolved'], "calls": result['calls']})
            for store in result['stores']:
                if store['target_match']:
                    hits.append({**store, "binary_sha256": digest, "address_space": "ELF_VMA",
                                 "boundary_confidence": boundary})
        return {"schema_version": 1, "analyzer_version": "arm-store-dataflow-1", "binary_sha256": digest,
                "address_space": "ELF_VMA", "target": target, "init_array_entry_count": len(entries),
                "functions_analyzed": len(results), "instruction_count": sum(row['instructions'] for row in results),
                "store_count": sum(row['stores'] for row in results), "writer_observations": hits,
                "function_coverage": results, "errors": errors,
                "budgets": {"max_window": max_window, "max_functions": max_functions, "max_instructions": max_instructions},
                "runtime_verified": False, "safe_to_invoke": False,
                "limitations": ["no interprocedural argument propagation", "non-RELATIVE relocation and BSS reads unknown",
                                "writable file data unknown except RELATIVE addends under static ELF VMA assumption",
                                "IT blocks fail closed", "missing symbol sizes use bounded windows", "no external writer absence claim"]}
