"""Evidence-gated primary-ELF probe for the Appframework event handoff.

The probe authenticates the private A6000 3.21 ``libObj.so`` before reading
small Thumb regions around the two semaphore-gated helpers at ``0x7f21e8``
and ``0x7f2210``.  It records the direct handoff from ``0x7eecac`` and the
guarded helper at ``0x7f099c`` without claiming an event consumer or runtime
Camera behavior.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM
from elftools.elf.elffile import ELFFile

from .elf_plt import resolve_plt_binding
from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA


TARGETS: tuple[dict[str, Any], ...] = (
    {"name": "dispatch_tail", "entry": 0x7EECAC, "size": 0x10},
    {"name": "semaphore_dispatch_gate", "entry": 0x7F21E8, "size": 0x28},
    {"name": "semaphore_application_gate", "entry": 0x7F2210, "size": 0x24},
    {"name": "callback_application_gate", "entry": 0x7F2238, "size": 0x28},
    {"name": "guarded_application_helper", "entry": 0x7F099C, "size": 0x22},
    {"name": "dispatch_count_thunk", "entry": 0x7F0AA0, "size": 0x0C},
    {"name": "callback_application_helper", "entry": 0x7F0AAC, "size": 0x20},
)

SEMAPHORE_LITERAL = 0x830451
SEMAPHORE_DISPATCH_ENTRY = 0x7F21E8
SEMAPHORE_APPLICATION_ENTRY = 0x7F2210
CALLBACK_APPLICATION_ENTRY = 0x7F2238
WAIT_PLT = 0xE0E38
SIGNAL_PLT = 0xE1C4C


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_vma(fp: Any, elf: ELFFile, start: int, size: int) -> bytes:
    if size <= 0 or size > 0x300:
        raise ValueError("Appframework primary probe exceeds bounded read limit")
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


def _read_load_word(fp: Any, elf: ELFFile, address: int) -> int:
    offsets: list[int] = []
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD":
            continue
        base = int(segment["p_vaddr"])
        count = int(segment["p_filesz"])
        if base <= address and address + 4 <= base + count:
            offsets.append(int(segment["p_offset"]) + address - base)
    if len(offsets) != 1:
        raise ValueError(f"ELF_VMA 0x{address:x} is not uniquely load-backed")
    fp.seek(offsets[0])
    data = fp.read(4)
    if len(data) != 4:
        raise ValueError("truncated literal word")
    return int.from_bytes(data, "little")


def _decode(fp: Any, elf: ELFFile, entry: int, size: int) -> dict[int, Any]:
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    rows = list(decoder.disasm(_read_vma(fp, elf, entry, size), entry))
    if not rows:
        raise ValueError(f"no Thumb instructions at 0x{entry:x}")
    return {int(row.address): row for row in rows}


def _immediates(instruction: Any) -> list[int]:
    return [int(operand.imm) for operand in instruction.operands if operand.type == ARM_OP_IMM]


def _require(
    rows: dict[int, Any], address: int, mnemonic: str, *,
    target: int | None = None, operands: str | None = None,
    immediate: int | None = None,
) -> Any:
    instruction = rows.get(address)
    if instruction is None or instruction.mnemonic.lower() != mnemonic.lower():
        raise ValueError(f"unexpected {mnemonic} at 0x{address:x}")
    if target is not None and target not in _immediates(instruction):
        raise ValueError(f"unexpected branch target at 0x{address:x}")
    if immediate is not None and immediate not in _immediates(instruction):
        raise ValueError(f"unexpected immediate at 0x{address:x}")
    if operands is not None and instruction.op_str.lower() != operands.lower():
        raise ValueError(f"unexpected operands at 0x{address:x}")
    return instruction


def _thumb_literal_address(instruction: Any) -> int:
    if len(instruction.operands) != 2 or instruction.operands[1].type != ARM_OP_MEM:
        raise ValueError(f"instruction at 0x{instruction.address:x} is not a literal load")
    memory = instruction.operands[1].mem
    if instruction.reg_name(memory.base) != "pc" or memory.index:
        raise ValueError(f"instruction at 0x{instruction.address:x} is not PC-relative")
    return ((int(instruction.address) + 4) & ~3) + int(memory.disp)


def _binding(fp: Any, elf: ELFFile, entry: int) -> dict[str, Any]:
    result = resolve_plt_binding(fp, elf, entry, thumb_stub=False)
    if result.get("status") != "VERIFIED_STATIC":
        raise ValueError(f"PLT binding at 0x{entry:x} is not unique")
    return result


def _observe_literal(
    fp: Any, elf: ELFFile, rows: dict[int, Any], address: int,
) -> dict[str, Any]:
    instruction = _require(rows, address, "ldr")
    literal_vma = _thumb_literal_address(instruction)
    value = _read_load_word(fp, elf, literal_vma)
    if value != SEMAPHORE_LITERAL:
        raise ValueError(f"unexpected semaphore literal at 0x{literal_vma:x}")
    return {
        "instruction": f"0x{address:x}",
        "literal_vma": f"0x{literal_vma:x}",
        "value": hex(value),
        "status": "PRIMARY_ELF_VERIFIED",
    }


def _observe_gate(
    fp: Any, elf: ELFFile, rows: dict[int, Any], *, entry: int,
    helper_target: int, wait: dict[str, Any], signal: dict[str, Any],
    literal_loads: tuple[int, int],
) -> dict[str, Any]:
    _require(rows, entry, "push")
    _require(rows, entry + 2, "mov.w", immediate=-1)
    _require(rows, entry + 8, "mov")
    _require(rows, entry + 10, "ldr")
    _require(rows, entry + 12, "blx", target=WAIT_PLT)
    _require(rows, entry + 16, "adds", operands="r0, r4, #4")
    _require(rows, entry + 18, "bl", target=helper_target)
    _require(rows, entry + 22, "mov")
    _require(rows, entry + 24, "ldr")
    _require(rows, entry + 26, "blx", target=SIGNAL_PLT)
    _require(rows, entry + 30, "mov")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "receiver": "incoming r0 preserved in r4",
        "wait_timeout_argument": "r1 = -1 at the OSAL wait call; blocking/error meaning UNKNOWN",
        "wait_binding": wait,
        "signal_binding": signal,
        "semaphore_literals": [
            _observe_literal(fp, elf, rows, literal_loads[0]),
            _observe_literal(fp, elf, rows, literal_loads[1]),
        ],
        "helper_call": {
            "target": f"0x{helper_target:x}",
            "relation": "DIRECT_CALL",
            "argument": "receiver + 4",
            "return": "saved in r4 and returned after OSAL signal",
            "status": "PRIMARY_ELF_VERIFIED",
        },
        "synchronization": "wait -> helper -> signal sequence is instruction-verified; lock ownership and event semantics UNKNOWN",
    }


def _observe_dispatch_tail(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0x7EECAC, "push")
    _require(rows, 0x7EECB0, "ldr", operands="r0, [r0, #0x18]")
    _require(rows, 0x7EECB6, "b.w", target=SEMAPHORE_DISPATCH_ENTRY)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "receiver_field": "loads incoming object +0x18 into r0",
        "tail_target": f"0x{SEMAPHORE_DISPATCH_ENTRY:x}",
        "relation": "DIRECT_TAIL_BRANCH",
        "target_semantics": "semaphore-gated helper; event ID and consumer remain UNKNOWN",
    }


def _observe_guarded_helper(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0x7F099C, "push")
    _require(rows, 0x7F09A2, "bl", target=0x11113E)
    _require(rows, 0x7F09A6, "cbnz", target=0x7F09B8)
    _require(rows, 0x7F09AA, "bl", target=0x11127E)
    _require(rows, 0x7F09AE, "ldr", operands="r4, [r0]")
    _require(rows, 0x7F09B2, "bl", target=0x1114DE)
    _require(rows, 0x7F09B8, "movs", operands="r4, #0")
    _require(rows, 0x7F09BA, "mov", operands="r0, r4")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "input": "opaque pointer in r0 preserved in r5",
        "guard": "local call 0x11113e; nonzero result returns zero",
        "zero_path": "calls 0x11127e, loads one word from its result, then calls 0x1114de",
        "return": "word loaded into r4 on the guarded path, otherwise zero",
        "helper_identities": "0x11113e/0x11127e/0x1114de source semantics UNKNOWN",
    }


def _observe_count_thunk(rows: dict[int, Any]) -> dict[str, Any]:
    _require(rows, 0x7F0AA0, "push")
    _require(rows, 0x7F0AA4, "pop.w")
    _require(rows, 0x7F0AA8, "b.w", target=0x7F0A84)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "operation": "tail wrapper to local helper 0x7f0a84",
        "source_semantics": "UNKNOWN",
    }


def _observe_callback_helper(rows: dict[int, Any]) -> dict[str, Any]:
    """Record the callback-registration helper without naming its container."""
    _require(rows, 0x7F0AAC, "push")
    _require(rows, 0x7F0AB2, "mov", operands="r4, r0")
    _require(rows, 0x7F0AB4, "str", operands="r1, [r7, #4]")
    _require(rows, 0x7F0AB6, "bl", target=0x7F0916)
    _require(rows, 0x7F0ABA, "cbz", target=0x7F0AC4)
    _require(rows, 0x7F0ABC, "mov", operands="r0, r4")
    _require(rows, 0x7F0ABE, "adds", operands="r1, r7, #4")
    _require(rows, 0x7F0AC0, "bl", target=0x1116DE)
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "receiver": "incoming r0 preserved in r4",
        "argument": "incoming r1 saved at local [r7,#4] and passed to 0x7f0916",
        "guard": "zero result from 0x7f0916 skips the 0x1116de call",
        "registration_call": {
            "target": "0x1116de",
            "receiver": "original r0",
            "argument": "address of saved r1 local",
            "status": "PRIMARY_ELF_VERIFIED",
        },
        "helper_identities": "0x7f0916 and 0x1116de container/registration semantics UNKNOWN",
    }


def _observe_callback_gate(
    fp: Any, elf: ELFFile, rows: dict[int, Any], *,
    wait: dict[str, Any], signal: dict[str, Any],
) -> dict[str, Any]:
    """Record the wait/helper/signal gate and its unresolved callback target."""
    _require(rows, CALLBACK_APPLICATION_ENTRY, "push")
    _require(rows, CALLBACK_APPLICATION_ENTRY + 2, "mov", operands="r4, r0")
    _require(rows, CALLBACK_APPLICATION_ENTRY + 6, "mov", operands="r5, r1")
    _require(rows, CALLBACK_APPLICATION_ENTRY + 8, "ldr")
    _require(rows, CALLBACK_APPLICATION_ENTRY + 10, "mov.w", immediate=-1)
    _require(rows, CALLBACK_APPLICATION_ENTRY + 14, "blx", target=WAIT_PLT)
    _require(rows, CALLBACK_APPLICATION_ENTRY + 18, "adds", operands="r0, r4, #4")
    _require(rows, CALLBACK_APPLICATION_ENTRY + 20, "mov", operands="r1, r5")
    _require(rows, CALLBACK_APPLICATION_ENTRY + 22, "bl", target=0x7F0AAC)
    _require(rows, CALLBACK_APPLICATION_ENTRY + 26, "ldr")
    _require(rows, CALLBACK_APPLICATION_ENTRY + 28, "blx", target=SIGNAL_PLT)
    _require(rows, CALLBACK_APPLICATION_ENTRY + 32, "ldr", operands="r3, [r4]")
    _require(rows, CALLBACK_APPLICATION_ENTRY + 34, "cbz", target=CALLBACK_APPLICATION_ENTRY + 38)
    _require(rows, CALLBACK_APPLICATION_ENTRY + 36, "blx", operands="r3")
    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "receiver": "incoming r0 preserved in r4; incoming r1 preserved in r5",
        "wait_timeout_argument": "r1 = -1 at the OSAL wait call; blocking/error meaning UNKNOWN",
        "wait_binding": wait,
        "signal_binding": signal,
        "semaphore_literals": [
            _observe_literal(fp, elf, rows, CALLBACK_APPLICATION_ENTRY + 8),
            _observe_literal(fp, elf, rows, CALLBACK_APPLICATION_ENTRY + 26),
        ],
        "helper_call": {
            "target": "0x7f0aac",
            "relation": "DIRECT_CALL",
            "arguments": "r0 = receiver + 4; r1 = original incoming r1",
            "status": "PRIMARY_ELF_VERIFIED",
        },
        "callback_dispatch": {
            "load": "ldr r3, [r4]",
            "guard": "cbz skips the call when the loaded word is zero",
            "call": "blx r3",
            "target": "UNRESOLVED_INDIRECT_CALL",
            "argument_state": "not independently established after osal_sig_sem",
            "status": "CANDIDATE",
        },
        "synchronization": "wait -> helper -> signal -> guarded indirect call is instruction-verified; callback ownership and event semantics UNKNOWN",
    }


def probe_app_event_primary(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Read and validate bounded Appframework regions from the private ELF."""
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
        rows = {
            target["name"]: _decode(fp, elf, int(target["entry"]), int(target["size"]))
            for target in TARGETS
        }
        wait = _binding(fp, elf, WAIT_PLT)
        signal = _binding(fp, elf, SIGNAL_PLT)
        observation = {
            "dispatch_tail": _observe_dispatch_tail(rows["dispatch_tail"]),
            "semaphore_dispatch_gate": _observe_gate(
                fp, elf, rows["semaphore_dispatch_gate"], entry=SEMAPHORE_DISPATCH_ENTRY,
                helper_target=0x7F0AA0, wait=wait, signal=signal,
                literal_loads=(0x7F21F2, 0x7F2200),
            ),
            "semaphore_application_gate": _observe_gate(
                fp, elf, rows["semaphore_application_gate"], entry=SEMAPHORE_APPLICATION_ENTRY,
                helper_target=0x7F099C, wait=wait, signal=signal,
                literal_loads=(0x7F221A, 0x7F2228),
            ),
            "callback_application_gate": _observe_callback_gate(
                fp, elf, rows["callback_application_gate"], wait=wait, signal=signal,
            ),
            "guarded_application_helper": _observe_guarded_helper(rows["guarded_application_helper"]),
            "dispatch_count_thunk": _observe_count_thunk(rows["dispatch_count_thunk"]),
            "callback_application_helper": _observe_callback_helper(rows["callback_application_helper"]),
        }
    return {
        "status": "LOCAL_PRIMARY_ELF_APP_EVENT_EVIDENCE_ONLY",
        "firmware_version": "3.21",
        "binary": {"name": "libObj.so", "sha256": digest},
        "address_space": "ELF_VMA",
        "observation": observation,
        "event_id_under_investigation": "0x11004003",
        "event_id_consumer_verified": False,
        "parameter_keys_7_8_decoded": False,
        "model_camera_consumer_verified": False,
        "runtime_verified": False,
        "callable": False,
        "limitations": [
            "OSAL wait/signal bindings are static relocation facts; runtime semaphore behavior is UNKNOWN",
            "The gate/helper chain does not prove that event 0x11004003 reaches these sites",
            "Event consumer, parameter keys 7/8 and ModelCamera dispatch remain UNKNOWN",
            "No firmware execution or device interaction",
        ],
    }


def validate_app_event_primary(report: dict[str, Any]) -> dict[str, Any]:
    """Reject identity mismatches and unsafe promotion of the evidence."""
    errors: list[str] = []
    if report.get("status") != "LOCAL_PRIMARY_ELF_APP_EVENT_EVIDENCE_ONLY":
        errors.append("report_status")
    if report.get("firmware_version") != "3.21":
        errors.append("firmware_version")
    binary = report.get("binary", {})
    if not isinstance(binary, dict) or binary.get("name") != "libObj.so" or binary.get("sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != "ELF_VMA":
        errors.append("address_space")
    if any(report.get(key) is not False for key in (
        "event_id_consumer_verified", "parameter_keys_7_8_decoded",
        "model_camera_consumer_verified", "runtime_verified", "callable",
    )):
        errors.append("unsafe_promotion")
    observation = report.get("observation", {})
    for name in (
        "dispatch_tail", "semaphore_dispatch_gate", "semaphore_application_gate",
        "callback_application_gate", "guarded_application_helper", "dispatch_count_thunk",
        "callback_application_helper",
    ):
        if not isinstance(observation.get(name), dict) or observation[name].get("status") != "PRIMARY_ELF_VERIFIED":
            errors.append(f"observation_{name}")
    for name in ("semaphore_dispatch_gate", "semaphore_application_gate"):
        gate = observation.get(name, {})
        if gate.get("wait_binding", {}).get("status") != "VERIFIED_STATIC":
            errors.append(f"{name}_wait_binding")
        if gate.get("signal_binding", {}).get("status") != "VERIFIED_STATIC":
            errors.append(f"{name}_signal_binding")
        literals = gate.get("semaphore_literals", [])
        if len(literals) != 2 or any(item.get("value") != hex(SEMAPHORE_LITERAL) for item in literals):
            errors.append(f"{name}_literal")
    callback_gate = observation.get("callback_application_gate", {})
    callback = callback_gate.get("callback_dispatch", {})
    if callback.get("target") != "UNRESOLVED_INDIRECT_CALL" or callback.get("status") != "CANDIDATE":
        errors.append("callback_target_promotion")
    literals = callback_gate.get("semaphore_literals", [])
    if len(literals) != 2 or any(item.get("value") != hex(SEMAPHORE_LITERAL) for item in literals):
        errors.append("callback_application_gate_literal")
    return {"valid": not errors, "errors": sorted(set(errors))}
