"""Evidence-gated ParamList construction/use witness.

The primary ELF contains one useful external owner/use boundary in
``InputService::getInputEventStatus``.  This probe verifies that bounded
function body and records only normalized instruction and relocation facts:
two local ParamList constructor/destructor pairs, one ParamList::add path,
two lookup/getter paths, and the guarded shared-rebind call.  It deliberately
does not assign a source-level static/member form, ownership transfer or
runtime-safe ABI to the function.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM
from elftools.elf.elffile import ELFFile

from .elf_plt import resolve_plt_binding
from .private_thumb_research import EXPECTED_LIBOBJ_SHA, HEX_SHA, MAX_ELF_BYTES


INPUT_STATUS_ENTRY = 0x114104
INPUT_STATUS_SIZE = 0x164
INPUT_STATUS_SYMBOL = "_ZN12InputService19getInputEventStatusEP9ParamListPKS0_"

PARAMLIST_GET_FORWARDER = 0xE5B20
PARAMLIST_PAYLOAD_GETTER = 0xE5B18
PARAMLIST_REBIND_CANDIDATE = 0x7EDCC6
PARAMLIST_CONSTRUCTOR_PLT = 0xDF894
PARAMLIST_ADD_PLT = 0xDFDC0
PARAMLIST_DESTRUCTOR_PLT = 0xE0080
ALLOCATOR_PLT = 0xDC100
PRM_NUMBER_CONSTRUCTOR = 0xF0FB0

FIRST_LOOKUP_KEY = 0x17005003
SECOND_LOOKUP_KEY = 0x17005008
LOCAL_LIST_ONE_OFFSET = 0x18
LOCAL_LIST_TWO_OFFSET = 0x20
MAX_READ_BYTES = 0x400


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _segment_offset(elf: ELFFile, start: int, size: int, *, executable: bool) -> int:
    if size <= 0 or size > MAX_READ_BYTES:
        raise ValueError("ParamList owner/use read exceeds bounded limit")
    offsets: list[int] = []
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_LOAD":
            continue
        if executable and not (int(segment["p_flags"]) & 1):
            continue
        base = int(segment["p_vaddr"])
        filesz = int(segment["p_filesz"])
        if base <= start and start + size <= base + filesz:
            offsets.append(int(segment["p_offset"]) + start - base)
    if len(offsets) != 1:
        raise ValueError(f"ELF_VMA 0x{start:x} is not uniquely mapped")
    return offsets[0]


def _read_vma(stream: Any, elf: ELFFile, start: int, size: int, *, executable: bool = False) -> bytes:
    stream.seek(_segment_offset(elf, start, size, executable=executable))
    data = stream.read(size)
    if len(data) != size:
        raise ValueError("truncated ELF VMA range")
    return data


def _decode(stream: Any, elf: ELFFile, start: int, size: int) -> dict[int, Any]:
    decoder = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    decoder.detail = True
    rows = list(decoder.disasm(_read_vma(stream, elf, start, size, executable=True), start))
    if not rows:
        raise ValueError(f"no Thumb instructions at 0x{start:x}")
    return {int(row.address): row for row in rows}


def _symbols(elf: ELFFile) -> dict[str, tuple[int, int]]:
    result: dict[str, tuple[int, int]] = {}
    for section_name in (".dynsym", ".symtab"):
        section = elf.get_section_by_name(section_name)
        if section is None:
            continue
        for symbol in section.iter_symbols():
            if symbol.name and symbol.name not in result:
                result[symbol.name] = (int(symbol["st_value"]), int(symbol["st_size"]))
    return result


def _immediates(instruction: Any) -> list[int]:
    return [int(operand.imm) for operand in instruction.operands if operand.type == ARM_OP_IMM]


def _require(
    rows: dict[int, Any], address: int, mnemonic: str, *,
    operands: str | None = None, target: int | None = None,
) -> Any:
    instruction = rows.get(address)
    if instruction is None or instruction.mnemonic.lower() != mnemonic.lower():
        raise ValueError(f"unexpected {mnemonic} at 0x{address:x}")
    if operands is not None and instruction.op_str.lower() != operands.lower():
        raise ValueError(f"unexpected operands at 0x{address:x}")
    if target is not None and (target & ~1) not in {value & ~1 for value in _immediates(instruction)}:
        raise ValueError(f"unexpected target at 0x{address:x}")
    return instruction


def _symbol_identity(
    symbols: dict[str, tuple[int, int]], name: str, entry: int, size: int,
) -> dict[str, Any]:
    value, actual_size = symbols.get(name, (0, 0))
    if (value & ~1) != entry or actual_size != size:
        raise ValueError(f"symbol identity mismatch for {name}")
    return {
        "symbol": name,
        "entry_vma": hex(entry),
        "thumb_value": hex(value),
        "size_bytes": size,
        "address_space": "ELF_VMA",
        "status": "PRIMARY_ELF_VERIFIED",
    }


def _literal_witness(
    stream: Any, elf: ELFFile, rows: dict[int, Any], address: int, expected: int,
) -> dict[str, Any]:
    instruction = rows.get(address)
    if instruction is None or instruction.mnemonic.lower() != "ldr":
        raise ValueError(f"expected literal ldr at 0x{address:x}")
    if len(instruction.operands) < 2 or instruction.operands[1].type != ARM_OP_MEM:
        raise ValueError(f"literal load at 0x{address:x} is not PC-relative")
    memory = instruction.operands[1].mem
    if instruction.reg_name(memory.base).lower() != "pc":
        raise ValueError(f"literal load at 0x{address:x} is not PC-relative")
    literal_vma = ((address + 4) & ~3) + int(memory.disp)
    actual = int.from_bytes(_read_vma(stream, elf, literal_vma, 4), "little")
    if actual != expected:
        raise ValueError(
            f"unexpected literal at 0x{address:x}: 0x{actual:x} != 0x{expected:x}"
        )
    return {
        "load_vma": hex(address),
        "literal_vma": hex(literal_vma),
        "value": hex(actual),
        "status": "PRIMARY_ELF_VERIFIED",
        "address_space": "ELF_VMA",
    }


def _binding(stream: Any, elf: ELFFile, entry: int, symbol: str) -> dict[str, Any]:
    result = resolve_plt_binding(stream, elf, entry, thumb_stub=False)
    candidates = result.get("candidates", [])
    if result.get("status") != "VERIFIED_STATIC" or len(candidates) != 1:
        raise ValueError(f"PLT binding at 0x{entry:x} is not unique")
    if candidates[0].get("symbol") != symbol:
        raise ValueError(f"unexpected PLT symbol at 0x{entry:x}")
    return result


def _observe_function(
    stream: Any,
    elf: ELFFile,
    rows: dict[int, Any],
    symbols: dict[str, tuple[int, int]],
    bindings: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    function = _symbol_identity(symbols, INPUT_STATUS_SYMBOL, INPUT_STATUS_ENTRY, INPUT_STATUS_SIZE)

    # The original r0/r1 values are preserved before the first lookup.  The
    # C++ static/member form is intentionally left unresolved; these are only
    # register-flow observations.
    _require(rows, 0x11410A, "mov", operands="r6, r0")
    _require(rows, 0x11410E, "mov", operands="r0, r1")
    first_key = _literal_witness(stream, elf, rows, 0x114112, FIRST_LOOKUP_KEY)
    _require(rows, 0x114114, "bl", target=PARAMLIST_GET_FORWARDER)
    _require(rows, 0x11411E, "mov", operands="r4, r0")
    _require(rows, 0x114122, "beq.w", target=0x11422C)
    _require(rows, 0x11413E, "mov", operands="r0, r4")
    _require(rows, 0x114140, "bl", target=PARAMLIST_PAYLOAD_GETTER)

    _require(rows, 0x11416A, "add.w", operands="r0, r7, #0x20")
    _require(rows, 0x11416E, "blx", target=PARAMLIST_CONSTRUCTOR_PLT)
    _require(rows, 0x114172, "add.w", operands="r0, r7, #0x18")
    _require(rows, 0x114176, "blx", target=PARAMLIST_CONSTRUCTOR_PLT)

    _require(rows, 0x114184, "movs")
    if 0x10 not in _immediates(rows[0x114184]):
        raise ValueError("local PrmNumber allocation size is not 0x10")
    _require(rows, 0x114186, "blx", target=ALLOCATOR_PLT)
    _require(rows, 0x11418A, "mov", operands="r8, r0")
    _require(rows, 0x11418C, "mov", operands="r1, r5")
    _require(rows, 0x11418E, "bl", target=PRM_NUMBER_CONSTRUCTOR)

    add_key = _literal_witness(stream, elf, rows, 0x114196, FIRST_LOOKUP_KEY)
    _require(rows, 0x114192, "add.w", operands="r0, r7, #0x18")
    _require(rows, 0x114198, "mov", operands="r2, r8")
    _require(rows, 0x11419A, "blx", target=PARAMLIST_ADD_PLT)

    second_key = _literal_witness(stream, elf, rows, 0x1141B0, SECOND_LOOKUP_KEY)
    _require(rows, 0x1141AC, "add.w", operands="r0, r7, #0x20")
    _require(rows, 0x1141B2, "bl", target=PARAMLIST_GET_FORWARDER)
    _require(rows, 0x1141B8, "bl", target=PARAMLIST_PAYLOAD_GETTER)

    _require(rows, 0x1141DC, "mov", operands="r0, r6")
    _require(rows, 0x1141DE, "add.w", operands="r1, r7, #0x20")
    _require(rows, 0x1141E2, "bl", target=PARAMLIST_REBIND_CANDIDATE)
    _require(rows, 0x1141F2, "add.w", operands="r0, r7, #0x18")
    _require(rows, 0x1141F6, "blx", target=PARAMLIST_DESTRUCTOR_PLT)
    _require(rows, 0x1141FA, "add.w", operands="r0, r7, #0x20")
    _require(rows, 0x1141FE, "blx", target=PARAMLIST_DESTRUCTOR_PLT)
    _require(rows, 0x11422C, "mov", operands="r0, r4")

    return {
        "status": "PRIMARY_ELF_VERIFIED",
        "symbol_identity": function,
        "register_flow": {
            "r0": "incoming ParamList-shaped destination candidate preserved in r6; exact static/member form UNKNOWN",
            "r1": "incoming ParamList-shaped source candidate used for first lookup",
            "r2": "not assigned a confirmed semantic role in this bounded body",
            "r3": "used by an indirect virtual call; target unresolved",
        },
        "first_lookup": {
            "receiver_source": "original r1",
            "forwarder_vma": hex(PARAMLIST_GET_FORWARDER),
            "key": first_key,
            "result_saved_to": "r4",
            "null_branch": "zero result branches to function return/cleanup path at 0x11422c",
            "payload_getter_vma": hex(PARAMLIST_PAYLOAD_GETTER),
        },
        "local_paramlists": {
            "list_one": {
                "stack_offset": hex(LOCAL_LIST_ONE_OFFSET),
                "constructor_callsite": hex(0x114176),
                "destructor_callsite": hex(0x1141F6),
                "lifetime": "constructed before the add path and destroyed after the loop",
            },
            "list_two": {
                "stack_offset": hex(LOCAL_LIST_TWO_OFFSET),
                "constructor_callsite": hex(0x11416E),
                "destructor_callsite": hex(0x1141FE),
                "lifetime": "constructed before the add path and destroyed after the loop",
            },
        },
        "number_element": {
            "allocator_callsite": hex(0x114186),
            "allocation_size_bytes": 0x10,
            "constructor_callsite": hex(0x11418E),
            "constructor_vma": hex(PRM_NUMBER_CONSTRUCTOR),
            "value_source": "r5 at callsite; r5 is populated by an earlier helper and remains dynamic",
            "payload_type": "PrmNumber word payload remains governed by its separate scalar contract",
        },
        "add": {
            "callsite": hex(0x11419A),
            "receiver": "stack +0x18 local ParamList",
            "key": add_key,
            "element": "r8 local PrmNumber allocation",
            "binding": bindings["add"],
        },
        "second_lookup": {
            "receiver": "stack +0x20 local ParamList",
            "key": second_key,
            "forwarder_vma": hex(PARAMLIST_GET_FORWARDER),
            "payload_getter_vma": hex(PARAMLIST_PAYLOAD_GETTER),
        },
        "rebind": {
            "callsite": hex(0x1141E2),
            "destination_register": "r0 from preserved original input",
            "source_register": "r1 = stack +0x20 local ParamList",
            "target_vma": hex(PARAMLIST_REBIND_CANDIDATE),
            "guard": "conditional key/value comparisons reach this call only on selected branches",
            "source_level_identity": "UNKNOWN",
        },
        "destruction": {
            "callsite_one": hex(0x1141F6),
            "callsite_two": hex(0x1141FE),
            "binding": bindings["destructor"],
            "stack_objects_are_destroyed_after_use": True,
        },
        "return": {
            "return_register": "r0",
            "last_local_assignment": "r4 at 0x11422c",
            "source_level_return_type": "UNKNOWN",
        },
        "address_space": "ELF_VMA",
    }


def probe_paramlist_owner_use(
    elf_path: Path, *, expected_sha256: str = EXPECTED_LIBOBJ_SHA,
) -> dict[str, Any]:
    """Verify the bounded InputService ParamList owner/use path."""
    path = Path(elf_path).resolve()
    if not path.is_file() or path.stat().st_size > MAX_ELF_BYTES:
        raise ValueError("private ELF missing or exceeds analysis limit")
    if not isinstance(expected_sha256, str) or not HEX_SHA.fullmatch(expected_sha256):
        raise ValueError("expected_sha256 must be a lowercase full SHA-256 digest")
    digest = _sha256(path)
    if digest != expected_sha256:
        raise ValueError("full-file ELF SHA-256 mismatch; refusing to decode")
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 32 or not elf.little_endian or elf["e_machine"] != "EM_ARM":
            raise ValueError("probe accepts only ELF32 little-endian ARM")
        symbols = _symbols(elf)
        bindings = {
            "constructor": _binding(stream, elf, PARAMLIST_CONSTRUCTOR_PLT, "_ZN9ParamListC1Ev"),
            "add": _binding(stream, elf, PARAMLIST_ADD_PLT, "_ZN9ParamList3addEmP9ParamBase"),
            "destructor": _binding(stream, elf, PARAMLIST_DESTRUCTOR_PLT, "_ZN9ParamListD1Ev"),
            "allocator": _binding(stream, elf, ALLOCATOR_PLT, "_Znwj"),
        }
        function = _observe_function(
            stream, elf, _decode(stream, elf, INPUT_STATUS_ENTRY, INPUT_STATUS_SIZE), symbols, bindings,
        )
    return {
        "schema_version": 1,
        "firmware_version": "3.21",
        "status": "LOCAL_PRIMARY_ELF_PARAMLIST_OWNER_USE_EVIDENCE_ONLY",
        "binary_file_sha256": digest,
        "address_space": "ELF_VMA",
        "abi": "ARM AAPCS32, Thumb, little endian; static/member form, ownership and runtime ABI UNKNOWN",
        "bindings": bindings,
        "observations": {"input_service_owner_use": function},
        "lifetime": {
            "local_paramlists": "PRIMARY_ELF_VERIFIED constructor/destructor callsite pairing within the symbol-bounded body",
            "shared_rebind": "STATIC_INFERRED from guarded call with original input as destination and local list as source",
            "element_ownership": "UNKNOWN; allocation and ParamList::add are observed, but transfer/destruction ownership is not proven",
            "source_level_static_member_form": "UNKNOWN",
            "concurrency_verified": False,
            "runtime_verified": False,
            "callable": False,
        },
        "raw_instruction_bytes_published": False,
        "runtime_verified": False,
        "callable": False,
        "limitations": [
            "The InputService symbol does not independently prove a C++ static/member form",
            "The function has no direct caller in the bounded direct-BL scan; dispatch/registration context is UNKNOWN",
            "PrmNumber value source is dynamic and its exact semantic domain remains UNKNOWN",
            "ParamList::add ownership transfer, exception cleanup, locking and runtime binding remain UNKNOWN",
            "No firmware code was executed and no device was accessed",
        ],
    }


def validate_paramlist_owner_use(report: dict[str, Any]) -> dict[str, Any]:
    """Fail closed on identity and attempts to promote the owner/use witness."""
    errors: list[str] = []
    if report.get("schema_version") != 1:
        errors.append("schema_version")
    if report.get("binary_file_sha256") != EXPECTED_LIBOBJ_SHA:
        errors.append("binary_identity")
    if report.get("address_space") != "ELF_VMA":
        errors.append("address_space")
    if report.get("runtime_verified") is not False or report.get("callable") is not False:
        errors.append("runtime_or_callable_claim")
    observations = report.get("observations")
    function = observations.get("input_service_owner_use") if isinstance(observations, dict) else None
    if not isinstance(function, dict) or function.get("status") != "PRIMARY_ELF_VERIFIED":
        errors.append("function_observation")
    else:
        identity = function.get("symbol_identity")
        if (
            not isinstance(identity, dict)
            or identity.get("symbol") != INPUT_STATUS_SYMBOL
            or identity.get("entry_vma") != hex(INPUT_STATUS_ENTRY)
            or identity.get("size_bytes") != INPUT_STATUS_SIZE
            or identity.get("address_space") != "ELF_VMA"
        ):
            errors.append("symbol_identity")
        first_key = function.get("first_lookup", {}).get("key", {})
        second_key = function.get("second_lookup", {}).get("key", {})
        if first_key.get("value") != hex(FIRST_LOOKUP_KEY) or second_key.get("value") != hex(SECOND_LOOKUP_KEY):
            errors.append("lookup_key_evidence")
        locals_ = function.get("local_paramlists", {})
        if (
            locals_.get("list_one", {}).get("stack_offset") != hex(LOCAL_LIST_ONE_OFFSET)
            or locals_.get("list_two", {}).get("stack_offset") != hex(LOCAL_LIST_TWO_OFFSET)
            or function.get("add", {}).get("callsite") != hex(0x11419A)
            or function.get("rebind", {}).get("callsite") != hex(0x1141E2)
        ):
            errors.append("owner_use_callsite_evidence")
        if function.get("rebind", {}).get("source_level_identity") != "UNKNOWN":
            errors.append("rebind_identity_promotion")
        if function.get("return", {}).get("source_level_return_type") != "UNKNOWN":
            errors.append("return_type_promotion")
    bindings = report.get("bindings")
    expected_bindings = {
        "constructor": "_ZN9ParamListC1Ev",
        "add": "_ZN9ParamList3addEmP9ParamBase",
        "destructor": "_ZN9ParamListD1Ev",
        "allocator": "_Znwj",
    }
    if not isinstance(bindings, dict):
        errors.append("bindings")
    else:
        for name, symbol in expected_bindings.items():
            item = bindings.get(name)
            candidates = item.get("candidates", []) if isinstance(item, dict) else []
            if (
                not isinstance(item, dict)
                or item.get("status") != "VERIFIED_STATIC"
                or len(candidates) != 1
                or candidates[0].get("symbol") != symbol
            ):
                errors.append(f"binding:{name}")
    lifetime = report.get("lifetime")
    if not isinstance(lifetime, dict):
        errors.append("lifetime")
    else:
        if lifetime.get("source_level_static_member_form") != "UNKNOWN":
            errors.append("static_member_form_promotion")
        if lifetime.get("concurrency_verified") is not False:
            errors.append("concurrency_claim")
    return {
        "valid": not errors,
        "errors": sorted(set(errors)),
        "observation_count": len(observations) if isinstance(observations, dict) else 0,
    }
