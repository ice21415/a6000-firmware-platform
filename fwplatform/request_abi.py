"""Evidence-gated AAPCS32 parameter prototypes for Sony A6000 request APIs.

The Itanium _ZN...E mangling records explicit parameter *types* but
not ordinary function return types, nor static-vs-instance membership.
Both questions require register and data-flow evidence. This module
keeps a proof ledger for those distinctions without generating any
callable device wrapper or pretending that the selector helper is known.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .event_envelope import _entry_instructions

MAX_FIXTURE = 192 * 1024
MAX_DISASSEMBLY = 2 * 1024 * 1024
LIBOBJ_SHA = "8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a"
VIEW_SHA = "7fbfa8539717ba3dca0cb5a82cf976b50a2b97443972fe321a064cbb09a75588"

# All site checks are deliberate, narrow register-source observations.
# The same mangled suffix for a static and an instance method can
# produce different physical AAPCS32 argument registers.
REGISTER_SITES: dict[str, tuple[tuple[str, str], ...]] = {
    "0x12106e": (
        ("0x121072", "mov      r4, r0"),
        ("0x121076", "ldr.w    sb, [r0, #0x7c]"),
        ("0x12107a", "mov      r0, r1"),
        ("0x12107c", "mov      sl, r2"),
        ("0x12107e", "mov      r5, r1"),
        ("0x121080", "mov      r6, r3"),
        ("0x121082", "blx      #0xdffb8 ; _ZN11IdGenerator3GetEPKc"),
        ("0x121086", "mov      r1, sl"),
        ("0x121088", "mov      r8, r0"),
        ("0x12108a", "mov      r0, r5"),
        ("0x12108c", "bl       #0x12d780"),
        ("0x121090", "mov      r1, r8"),
        ("0x121092", "mov      r3, r6"),
        ("0x121094", "mov      r2, r0"),
        ("0x121096", "mov      r0, sb"),
        ("0x121098", "blx      #0xdfbdc ; _ZN22AbstractUtilityManager30createRequestModelExecuteEventEimP9ParamList"),
        ("0x12109c", "mov      r1, r0"),
        ("0x12109e", "mov      r0, r4"),
        ("0x1210a4", "b.w      #0xdb578 ; _ZN4View25requestApplicationExecuteEP5Event"),
    ),
    "0x1250c0": (
        ("0x1250c0", "ldr      r3, [pc, #0x38]"),
        ("0x1250c6", "mov      r4, r2"),
        ("0x1250ce", "mov      r5, r0"),
        ("0x1250d0", "mov      sb, r1"),
        ("0x1250d4", "ldr.w    r8, [r3]"),
        ("0x1250d8", "blx      #0xdffb8 ; _ZN11IdGenerator3GetEPKc"),
        ("0x1250dc", "mov      r1, sb"),
        ("0x1250de", "mov      r6, r0"),
        ("0x1250e0", "mov      r0, r5"),
        ("0x1250e2", "bl       #0x12d780"),
        ("0x1250e6", "mov      r1, r6"),
        ("0x1250e8", "mov      r3, r4"),
        ("0x1250ea", "mov      r2, r0"),
        ("0x1250ec", "mov      r0, r8"),
        ("0x1250ee", "blx      #0xdfbdc ; _ZN22AbstractUtilityManager30createRequestModelExecuteEventEimP9ParamList"),
        ("0x1250f6", "b.w      #0x125084"),
    ),
    "0x7f0b0c": (
        ("0x7f0b10", "movs     r0, #0x10"),
        ("0x7f0b14", "mov      r6, r1"),
        ("0x7f0b16", "mov      r8, r2"),
        ("0x7f0b18", "mov      r5, r3"),
        ("0x7f0b1a", "blx      #0xdc100 ; _Znwj"),
        ("0x7f0b1e", "literal 0x11004003"),
        ("0x7f0b24", "mov      r4, r0"),
        ("0x7f0b26", "blx      #0xdb66c ; _ZN5EventC1Emhh"),
        ("0x7f0b2a", "cbz      r5, #0x7f0b34"),
        ("0x7f0b2e", "mov      r1, r5"),
        ("0x7f0b30", "blx      #0xde3a4 ; _ZN5Event12setParamListEP9ParamList"),
        ("0x7f0b3a", "mov      r1, r6"),
        ("0x7f0b3e", "bl       #0xf0fb0"),
        ("0x7f0b44", "movs     r1, #7"),
        ("0x7f0b48", "blx      #0xdd194 ; _ZN5Event12addParameterEmP9ParamBase"),
        ("0x7f0b52", "mov      r1, r8"),
        ("0x7f0b56", "bl       #0xf0fb0"),
        ("0x7f0b5c", "movs     r1, #8"),
        ("0x7f0b60", "blx      #0xdd194 ; _ZN5Event12addParameterEmP9ParamBase"),
        ("0x7f0b64", "mov      r0, r4"),
        ("0x7f0b66", "pop.w    {r4, r5, r6, r7, r8, pc}"),
    ),
}
UI_SITES = (
    ("0x1a26dc", "mov      r0, r5"),
    ("0x1a26de", "movw     r2, #0xf01"),
    ("0x1a26e2", "model/CAMERA"),
    ("0x1a26e4", "mov      r3, sb"),
    ("0x1a26e6", "blx      #0xeb610 ; _ZN8ViewBase19requestModelExecuteEPKcmP9ParamList"),
)

EXPECTED_ABI = {
    "0x12106e": (
        "ViewBase::requestModelExecute",
        ("char const*", "unsigned long", "ParamList*"),
        "INSTANCE_METHOD_CANDIDATE",
        {"r0": "ViewBase* this", "r1": "char const* model_name",
         "r2": "unsigned long selector", "r3": "ParamList* params"},
    ),
    "0x1250c0": (
        "viewManagerIf::requestModelExecute",
        ("char const*", "unsigned long", "ParamList*"),
        "STATIC_METHOD_CANDIDATE",
        {"r0": "char const* model_name", "r1": "unsigned long selector",
         "r2": "ParamList* params"},
    ),
    "0x7f0b0c": (
        "AbstractUtilityManager::createRequestModelExecuteEvent",
        ("int", "unsigned long", "ParamList*"),
        "INSTANCE_METHOD_CANDIDATE",
        {"r0": "AbstractUtilityManager* context", "r1": "int model_id",
         "r2": "unsigned long transformed_selector", "r3": "ParamList* params"},
    ),
}


def demangle_aapcs_parameter_types(mangled: str) -> tuple[str, tuple[str, ...]]:
    """Deliberately bounded Itanium *subset*, never guesses return type.

    Supports exactly nested length-prefixed method names and primitive
    i/m or PKc/P<length>Class parameters seen in this scoped analysis.
    Any unexpected code raises rather than claiming a reconstructed ABI.
    """
    if not isinstance(mangled, str) or not mangled.startswith("_ZN") or len(mangled) > 160:
        raise ValueError("expected length-prefixed Itanium nested function symbol")
    pos = 3
    names = []
    while pos < len(mangled) and mangled[pos] != "E":
        match = re.match(r"[1-9][0-9]{0,2}", mangled[pos:])
        if match is None:
            raise ValueError("unsupported nested Itanium component")
        count = int(match.group())
        pos += len(match.group())
        if count > 80 or pos + count > len(mangled):
            raise ValueError("malformed nested Itanium identifier length")
        names.append(mangled[pos:pos + count])
        pos += count
    if len(names) != 2 or pos >= len(mangled) or mangled[pos] != "E":
        raise ValueError("Itanium symbol must have class and method identifier")
    pos += 1
    types: list[str] = []
    while pos < len(mangled):
        if mangled.startswith("PKc", pos):
            types.append("char const*")
            pos += 3
        elif mangled[pos] == "m":
            types.append("unsigned long")
            pos += 1
        elif mangled[pos] == "i":
            types.append("int")
            pos += 1
        elif mangled[pos] == "P":
            pos += 1
            match = re.match(r"[1-9][0-9]{0,2}", mangled[pos:])
            if match is None:
                raise ValueError("unsupported pointer pointee type")
            count = int(match.group())
            pos += len(match.group())
            if count > 80 or pos + count > len(mangled):
                raise ValueError("malformed pointed-to class name")
            pointee = mangled[pos:pos + count]
            if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", pointee):
                raise ValueError("unsupported pointer pointee identifier")
            types.append(pointee + "*")
            pos += count
        else:
            raise ValueError("unsupported Itanium parameter code")
    if not types:
        raise ValueError("prototype requires explicit known arguments")
    return "::".join(names), tuple(types)


def _check_sites(rows: dict[int, str], expected: tuple[tuple[str, str], ...], kind: str) -> int:
    for address, snippet in expected:
        opcode = rows.get(int(address, 16))
        if opcode is None or snippet not in opcode:
            raise ValueError(f"{kind} mismatch at {address}")
    return len(expected)


def _unique_scanned_opcode_lines(report: str, sites: tuple[tuple[str, str], ...]) -> int:
    """For the different UI ELF saved report, require one exact-address match."""
    parsed: dict[int, str] = {}
    for line in report.splitlines():
        match = re.match(r"^(0x[0-9a-fA-F]+):\s+(.+)$", line)
        if match is None:
            continue
        address = int(match.group(1), 16)
        if any(address == int(x[0], 16) for x in sites):
            if address in parsed:
                raise ValueError("ambiguous UI saved disassembly VMA")
            parsed[address] = match.group(2)
    return _check_sites(parsed, sites, "UI cross-ELF source")


def audit_request_abi(
    fixture: Path, *, saved_libobj: Path | None = None,
    saved_view: Path | None = None,
) -> dict[str, Any]:
    path = Path(fixture)
    if not path.is_file() or not 0 < path.stat().st_size <= MAX_FIXTURE:
        raise ValueError("request ABI fixture missing or oversized")
    obj = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(obj, dict) or obj.get("schema_version") != 1
        or obj.get("status") != "STATIC_ARGUMENT_ABI_INFERRED_RETURN_AND_RUNTIME_UNVERIFIED"
        or obj.get("callable_camera_api_count") != 0):
        raise ValueError("request ABI fixture must be a noncallable research lead")
    bins = obj.get("binaries")
    if not isinstance(bins, list) or len(bins) != 2 or [
        (x.get("library"), x.get("sha256")) for x in bins if isinstance(x, dict)
    ] != [("libObj.so", LIBOBJ_SHA), ("viewUnified2.so", VIEW_SHA)]:
        raise ValueError("request ABI requires two separately identified ELF sources")
    candidates = obj.get("entrypoints")
    if not isinstance(candidates, list) or len(candidates) != len(EXPECTED_ABI):
        raise ValueError("request ABI candidate entries missing")
    by_addr = {}
    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise ValueError("invalid candidate")
        addr = candidate.get("entry_vma")
        if addr in by_addr or addr not in EXPECTED_ABI:
            raise ValueError("unexpected or duplicate ABI candidate")
        name, params, method_form, regs = EXPECTED_ABI[addr]
        decoded_name, decoded_params = demangle_aapcs_parameter_types(candidate.get("symbol"))
        if (decoded_name != name or decoded_params != params
            or candidate.get("method_form") != method_form
            or candidate.get("aapcs32_input_registers") != regs
            or candidate.get("abi_verified") is not False
            or candidate.get("return_type_verified") is not False
            or candidate.get("usable_on_device") is not False):
            raise ValueError("parameter ABI evidence must preserve types, method form and incomplete status")
        by_addr[addr] = candidate
    if set(by_addr) != set(EXPECTED_ABI):
        raise ValueError("request ABI missing an entry")
    vb, vm, factory = (by_addr[x] for x in ("0x12106e", "0x1250c0", "0x7f0b0c"))
    for source, helper_inputs, factory_r3 in (
        (vb, {"r0": "original r1 (model_name)", "r1": "original r2 (selector)"},
         "original r3 (ParamList*)"),
        (vm, {"r0": "original r0 (model_name)", "r1": "original r1 (selector)"},
         "original r2 (ParamList*)"),
    ):
        if (source.get("helper_target") != "0x12d780"
            or source.get("factory_stub") != "0xdfbdc"
            or source.get("helper_inputs") != helper_inputs
            or source.get("factory_inputs", {}).get("r3") != factory_r3
            or source.get("factory_inputs", {}).get("r2") != "0x12d780 result"):
            raise ValueError("caller register dataflow to common helper/factory differs")
    if (vm.get("ignored_incoming_register") !=
        "r3 is overwritten by an ELF-relative literal/GOT lookup before use; not proof of fourth argument"
        or vb.get("observable_return") != "UNKNOWN_TAIL_TO_View_requestApplicationExecute"
        or vm.get("observable_return") != "UNKNOWN_TAIL_TO_0x125084"
        or factory.get("observed_return") != "Event* STATIC_INFERRED_NOT_TYPE_SIGNATURE_ENCODED"
        or factory.get("returned_value_observed") !=
        "allocation pointer copied to r4 after Event constructor; r0 restored from r4 at 0x7f0b64 prior to return 0x7f0b66"
        or factory.get("new_allocation_arg") != "0x10"
        or factory.get("constructor_event_id") != "0x11004003"):
        raise ValueError("return and allocation observations must remain source-scoped")
    ui = obj.get("ui_crosscheck")
    if (not isinstance(ui, dict) or ui.get("library") != "viewUnified2.so"
        or ui.get("callsite_vma") != "0x1a26e6"
        or ui.get("import_target") != "0xeb610"
        or ui.get("symbol") != vb.get("symbol")
        or ui.get("requested_destination") != "model/CAMERA"
        or ui.get("requested_selector") != "0x0f01"
        or ui.get("dynamic_plt_resolution_verified") is not False
        or ui.get("called_runtime_path_verified") is not False):
        raise ValueError("UI caller evidence or cross-ELF boundary inaccurate")
    if not isinstance(obj.get("unresolved"), list) or len(obj["unresolved"]) < 5:
        raise ValueError("prototype still has critical unresolved ABI dependencies")
    libobj_count = None
    if saved_libobj is not None:
        p = Path(saved_libobj)
        if not p.is_file() or not 0 < p.stat().st_size <= MAX_DISASSEMBLY:
            raise ValueError("saved ModelCamera instruction report unavailable or oversized")
        source = p.read_text(encoding="utf-8")
        libobj_count = 0
        for addr, expected in REGISTER_SITES.items():
            method_name = by_addr[addr]["symbol"]
            rows = _entry_instructions(source, int(addr, 16), method_name)
            libobj_count += _check_sites(rows, expected, method_name)
    view_count = None
    if saved_view is not None:
        p = Path(saved_view)
        if not p.is_file() or not 0 < p.stat().st_size <= MAX_DISASSEMBLY:
            raise ValueError("saved UI ELF disassembly unavailable or oversized")
        view_count = _unique_scanned_opcode_lines(p.read_text(encoding="utf-8"), UI_SITES)
    return {
        "status": ("TWO_SAVED_ELF_TEXT_CHECKS_MATCH" if libobj_count is not None and view_count is not None
                   else "ONE_SAVED_ELF_TEXT_CHECK_MATCH" if libobj_count is not None or view_count is not None
                   else "STATIC_PROTOTYPE_CANDIDATES_ONLY"),
        "abi_platform": obj["abi_platform"],
        "entrypoint_parameter_prototypes": [
            {"entry_vma": addr,
             "qualified_name": EXPECTED_ABI[addr][0],
             "named_input_types": list(EXPECTED_ABI[addr][1]),
             "method_form": EXPECTED_ABI[addr][2],
             "register_mapping": EXPECTED_ABI[addr][3],
             "return_type_verified": False,
             "runtime_callable": False} for addr in EXPECTED_ABI
        ],
        "factory_event_pointer_return_static_inference": "Event* allocation/constructor/r0 return",
        "factory_return_abi_verified": False,
        "saved_libobj_register_sites_checked": libobj_count,
        "saved_view_ui_sites_checked": view_count,
        "selector_transform_0x12d780_verified": False,
        "actual_elf_bytes_redecoded": False,
        "sony_camera_core_api_abi_completed": 0,
        "remaining_evidence": obj["unresolved"],
    }
