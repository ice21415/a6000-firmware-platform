"""Read-only bridge audit for preserved REA UI and Camera ELF research.

This never runs REA/Ghidra, executes firmware, reads hardware, or creates an
SDK callable interface. It checks per-ELF address-space normalization,
saved decompiler request expressions, and independently decodes a bounded
saved raw-ELF instruction slice at the Camera dispatch boundary. Saving
a byte slice is not equivalent to checking a new original full ELF.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .camera_elf_verify import _thumb_imm_branch


SHA = re.compile(r"[a-f0-9]{64}\Z")
EVIDENCE = re.compile(r"ev_[a-f0-9]{64}\Z")
UI_REQUEST = re.compile(
    r"requestModelExecuteEPKcmP9ParamList\s*\([^;]{0,250}?"
    r'"(?P<destination>model/CAMERA|model/STILL_REC)"\s*,\s*'
    r"(?P<selector>0x[0-9a-fA-F]+|[0-9]+)\s*,", re.S,
)
MAX_TEXT_BYTES = 2 * 1024 * 1024
MAX_AUDIT_BYTES = 2 * 1024 * 1024


def _number(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"{what}: invalid numeric value")
    try:
        number = int(str(value).strip(), 0)
    except ValueError as exc:
        raise ValueError(f"{what}: invalid numeric value") from exc
    if number < 0:
        raise ValueError(f"{what}: negative value")
    return number


def _verify_saved_movw(raw: bytes, immediate: int) -> bool:
    """Only Thumb MOVW T3 imm16, little-endian (not MOVT or synthetic ABI)."""
    if len(raw) != 4:
        return False
    h1 = int.from_bytes(raw[:2], "little")
    h2 = int.from_bytes(raw[2:4], "little")
    if (h1 & 0xFBF0) != 0xF240 or (h2 & 0x8000):
        return False
    imm16 = ((h1 & 15) << 12) | (((h1 >> 10) & 1) << 11) | (
        ((h2 >> 12) & 7) << 8) | (h2 & 255)
    return imm16 == immediate


def _load_object(path: Path, max_size: int) -> dict[str, Any]:
    if not path.is_file() or not 0 < path.stat().st_size <= max_size:
        raise ValueError(f"research artifact missing or exceeds {max_size} bytes")
    content = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(content, dict):
        raise ValueError("research artifact must be an object")
    return content


def audit_rea_ui_camera_bridge(
    fixture: Path,
    *, ui_decompile: Path | None = None,
    camera_audit: Path | None = None,
) -> dict[str, Any]:
    """Require unique ELF identity and never infer the missing event route."""
    record = _load_object(Path(fixture), MAX_AUDIT_BYTES)
    if record.get("schema_version") != 1 or record.get("status") != "ENDPOINTS_OBSERVED_MESSAGE_ROUTE_UNRESOLVED":
        raise ValueError("invalid report-only REA bridge record")
    ui, camera, boundary = (record.get(k) for k in ("ui", "camera", "boundary"))
    if not all(isinstance(k, dict) for k in (ui, camera, boundary)):
        raise ValueError("REA bridge requires UI, Camera and unresolved boundary")
    for x in (ui, camera):
        if not SHA.fullmatch(str(x.get("sha256") or "")):
            raise ValueError("REA bridge missing ELF SHA-256 provenance")
    if ui["sha256"] == camera["sha256"] or ui.get("binary") == camera.get("binary"):
        raise ValueError("UI and Camera are independent ELF binaries")
    for k, x in (("ui.selector", ui.get("selector")),
                 ("camera.selector", camera.get("selector"))):
        if _number(x, k) != _number(ui["selector"], "ui.selector"):
            raise ValueError("UI and Camera selectors differ")
    selector = _number(ui["selector"], "ui.selector")
    if not 0 <= selector <= 0xFFFFFFFF:
        raise ValueError("selector exceeds 32-bit event namespace")
    ghidra = _number(ui.get("ghidra_vma"), "ui.ghidra_vma")
    elf_vma = _number(ui.get("elf_vma"), "ui.elf_vma")
    bias = _number(ui.get("ghidra_image_bias"), "ui.ghidra_image_bias")
    if bias > 0x10000000 or ghidra - bias != elf_vma:
        raise ValueError("UI Ghidra-to-ELF address mapping mismatch")
    if _number(camera.get("dispatcher_elf_vma"), "camera.dispatcher") <= 0:
        raise ValueError("invalid Camera dispatcher VMA")
    if _number(camera.get("branch_instruction_elf_vma"), "camera.branch") < _number(
            camera.get("dispatcher_elf_vma"), "camera.dispatcher"):
        raise ValueError("Camera dispatch branch precedes dispatcher entry")
    if not EVIDENCE.fullmatch(str(ui.get("rea_evidence_id") or "")):
        raise ValueError("missing saved REA evidence identity")
    if ui.get("destination") != "model/CAMERA" or ui.get("also_observed_destination") != "model/STILL_REC":
        raise ValueError("unexpected UI model request namespace")
    if not (boundary.get("proven_end_to_end") is False
            and boundary.get("abi_verified") is False
            and boundary.get("runtime_callable") is False
            and boundary.get("ui_ghidra_bias_applies_to_camera_binary") is False):
        raise ValueError("REA report cannot claim a verified firmware message route or ABI")
    gaps = boundary.get("unverified")
    if not isinstance(gaps, list) or len(gaps) < 3 or not all(isinstance(x, str) and x for x in gaps):
        raise ValueError("boundary must preserve unresolved message routing gaps")
    checks = {"ui_saved_pseudocode": "NOT_PROVIDED",
              "camera_saved_raw_instruction_slice": "NOT_PROVIDED"}
    counts: dict[str, int | None] = {"ui_camera_selector_request_sites": None,
                                    "ui_still_selector_request_sites": None}
    if ui_decompile is not None:
        ui_path = Path(ui_decompile)
        if not ui_path.is_file() or not 0 < ui_path.stat().st_size <= MAX_TEXT_BYTES:
            raise ValueError("saved REA UI pseudocode is missing or exceeds 2 MiB")
        text = ui_path.read_text(encoding="utf-8")
        if "CmnViewBigModelUtil13setInitForRec" not in text:
            raise ValueError("REA saved UI pseudocode does not identify expected function")
        requests = list(UI_REQUEST.finditer(text))
        c = sum(x.group("destination") == "model/CAMERA"
                and _number(x.group("selector"), "UI request selector") == selector for x in requests)
        s = sum(x.group("destination") == "model/STILL_REC"
                and _number(x.group("selector"), "UI request selector") == selector for x in requests)
        if c != ui.get("observed_call_sites_in_saved_decompile") or s != ui.get(
                "other_destination_call_sites_in_saved_decompile"):
            raise ValueError("saved REA UI model request site count differs from reported finding")
        checks["ui_saved_pseudocode"] = "EXACT_REQUEST_TEXT_AND_COUNT_MATCH"
        counts["ui_camera_selector_request_sites"] = c
        counts["ui_still_selector_request_sites"] = s
    if camera_audit is not None:
        audit = _load_object(Path(camera_audit), MAX_AUDIT_BYTES)
        if audit.get("source_sha256") != camera["sha256"] or audit.get("evidence_type") != "raw-ELF-Capstone-static-audit-not-REA":
            raise ValueError("saved raw Camera audit source or evidence class mismatch")
        ranges = audit.get("ranges")
        if not isinstance(ranges, list) or len(ranges) > 100:
            raise ValueError("Camera audit ranges invalid or unbounded")
        start = _number(camera.get("source_bytes_elf_vma"), "camera.source_bytes")
        hits = [x for x in ranges if isinstance(x, dict) and _number(
            x.get("ELF_address"), "audit.ELF_address") == start]
        if len(hits) != 1:
            raise ValueError("Camera raw selector disassembly span is absent or ambiguous")
        item = hits[0]
        hex_bytes = item.get("bytes")
        if not isinstance(hex_bytes, str) or not re.fullmatch(r"(?:[a-fA-F0-9]{2}){1,2048}", hex_bytes):
            raise ValueError("Camera raw audit hex bytes invalid")
        raw = bytes.fromhex(hex_bytes)
        movw_vma = _number(camera["compare_selector_instruction_elf_vma"], "selector instruction")
        branch_vma = _number(camera["branch_instruction_elf_vma"], "branch instruction")
        mi, bi = movw_vma - start, branch_vma - start
        if mi < 0 or bi < 0 or mi + 4 > len(raw) or bi + 4 > len(raw):
            raise ValueError("reported Camera opcode sites outside saved byte slice")
        if not _verify_saved_movw(raw[mi:mi + 4], selector):
            raise ValueError("Camera raw Thumb MOVW selector operand differs")
        call = _thumb_imm_branch(raw[bi:bi + 4], branch_vma)
        target = _number(camera.get("callee_elf_vma"), "Camera callee")
        if call != ("bl", target):
            raise ValueError("Camera raw Thumb BL target differs")
        # Cross-check the saved disassembler text without trusting it as an opcode decoder.
        instructions = item.get("instructions")
        if not isinstance(instructions, list):
            raise ValueError("Camera audit instructions missing")
        pairs = {(str(x.get("address")), str(x.get("mnemonic")), str(x.get("operands")))
                 for x in instructions if isinstance(x, dict)}
        if ((hex(movw_vma), "movw", f"r3, #{hex(selector)}") not in pairs
                or (hex(branch_vma), "bl", f"#{hex(target)}") not in pairs):
            raise ValueError("saved Capstone metadata does not agree with raw byte decoder")
        checks["camera_saved_raw_instruction_slice"] = "THUMB_MOVW_SELECTOR_AND_BL_TARGET_MATCH"
    status = ("BOTH_SAVED_ENDPOINTS_RECHECKED_MESSAGE_ROUTE_UNVERIFIED"
              if all(v != "NOT_PROVIDED" for v in checks.values())
              else "SAVED_ENDPOINTS_PARTIALLY_RECHECKED_MESSAGE_ROUTE_UNVERIFIED")
    return {
        "status": status, "firmware_version": record["firmware_version"],
        "ui": {"binary": ui["binary"], "sha256": ui["sha256"],
               "ghidra_vma": hex(ghidra), "elf_vma": hex(elf_vma),
               "per_binary_image_bias": hex(bias),
               "rea_evidence_id": ui["rea_evidence_id"]},
        "camera": {"binary": camera["binary"], "sha256": camera["sha256"],
                   "dispatcher_elf_vma": camera["dispatcher_elf_vma"],
                   "callee_elf_vma": camera["callee_elf_vma"]},
        "selector": hex(selector), "saved_artifact_checks": checks,
        "saved_ui_callsite_counts": counts,
        "end_to_end_message_delivery_verified": False,
        "independent_full_original_elf_checked_now": False,
        "sony_abi_verified": False, "device_callability_verified": False,
        "next_evidence": gaps,
        "evidence_limit": "Saved Ghidra pseudocode and saved raw-ELF slice are separately scoped; same selector is not proof of a transmitted, accepted message or of a callable SDK.",
    }
