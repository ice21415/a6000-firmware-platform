"""Non-invasive host-side USB validation helpers.

This module deliberately stops at OS device enumeration.  It does not open a
camera, send PTP/vendor commands, mount storage, or alter device state.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import platform
import re
import subprocess
from typing import Callable, Iterable


STATUS_NOT_CONNECTED = "NOT_CONNECTED"
STATUS_USB_NOT_ACCESSIBLE = "USB_NOT_ACCESSIBLE"
STATUS_UNSUPPORTED_MODE = "UNSUPPORTED_MODE"
STATUS_READ_ONLY_VERIFIED = "READ_ONLY_VERIFIED"
STATUS_INCONCLUSIVE = "INCONCLUSIVE"
STATUS_ERROR = "ERROR"

_SONY_VIDS = {"054C"}
_CAMERA_WORDS = re.compile(r"sony|ilce|a6000|mtp|ptp", re.I)
_VID_PID = re.compile(r"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", re.I)


@dataclass(frozen=True)
class UsbDevice:
    vendor_id: str | None
    product_id: str | None
    description: str
    manufacturer: str
    status: str


@dataclass(frozen=True)
class HardwareValidation:
    status: str
    host: str
    platform: str
    enumeration_command: str
    access_error: str | None
    devices: tuple[UsbDevice, ...]
    sony_candidates: tuple[UsbDevice, ...]
    ptp_queried: bool
    runtime_verified: bool = False
    safe_to_invoke: bool = False

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["devices"] = [asdict(item) for item in self.devices]
        data["sony_candidates"] = [asdict(item) for item in self.sony_candidates]
        return data


def _run_pnputil(command: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15)
    return proc.returncode, proc.stdout, proc.stderr


def parse_pnputil(text: str) -> tuple[UsbDevice, ...]:
    """Parse pnputil output while intentionally discarding instance IDs."""
    devices: list[UsbDevice] = []
    block: dict[str, str] = {}
    for line in text.splitlines() + [""]:
        if not line.strip():
            if block:
                match = _VID_PID.search(block.get("Instance ID", ""))
                devices.append(UsbDevice(
                    vendor_id=match.group(1).upper() if match else None,
                    product_id=match.group(2).upper() if match else None,
                    description=block.get("Device Description", ""),
                    manufacturer=block.get("Manufacturer Name", ""),
                    status=block.get("Status", ""),
                ))
                block = {}
            continue
        if ":" in line:
            key, value = line.strip().split(":", 1)
            block[key.strip()] = value.strip()
    return tuple(devices)


def enumerate_usb(*, runner: Callable[[list[str]], tuple[int, str, str]] | None = None) -> HardwareValidation:
    """Enumerate USB devices using the OS tool; no device handle is opened."""
    synthetic_runner = runner is not None
    runner = runner or _run_pnputil
    if not synthetic_runner and platform.system().lower() != "windows":
        return HardwareValidation(STATUS_USB_NOT_ACCESSIBLE, platform.node(), platform.system(), "pnputil", "Windows pnputil unavailable", (), (), False)
    command = ["pnputil", "/enum-devices", "/connected", "/class", "USB"]
    try:
        code, stdout, stderr = runner(command)
    except (OSError, subprocess.SubprocessError) as exc:
        return HardwareValidation(STATUS_USB_NOT_ACCESSIBLE, platform.node(), platform.system(), " ".join(command), str(exc), (), (), False)
    if code != 0:
        return HardwareValidation(STATUS_USB_NOT_ACCESSIBLE, platform.node(), platform.system(), " ".join(command), stderr.strip() or f"exit {code}", (), (), False)
    devices = parse_pnputil(stdout)
    candidates = tuple(d for d in devices if (d.vendor_id in _SONY_VIDS) or _CAMERA_WORDS.search(d.description + " " + d.manufacturer))
    status = STATUS_READ_ONLY_VERIFIED if candidates else STATUS_NOT_CONNECTED
    return HardwareValidation(status, platform.node(), platform.system(), " ".join(command), None, devices, candidates, False)


def evidence_digest(result: HardwareValidation) -> str:
    """Stable digest of redacted enumeration facts, suitable for a report."""
    text = repr(result.to_dict()).encode("utf-8")
    return hashlib.sha256(text).hexdigest()


__all__ = ["HardwareValidation", "UsbDevice", "enumerate_usb", "parse_pnputil", "evidence_digest"]
