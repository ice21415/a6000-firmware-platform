"""Evidence model for the legacy libusb-win32 0.1 ABI.

This module intentionally does not load a DLL or open a USB device. It records
what can be checked offline and keeps unresolved calling-convention/layout
questions explicit.
"""
from __future__ import annotations

import ctypes
from pathlib import Path
from typing import Any

REQUIRED_SYMBOLS = ("usb_init", "usb_find_busses", "usb_find_devices", "usb_get_busses",
                    "usb_open", "usb_control_msg", "usb_close")


def validate_libusb_abi(*, dll_path: str | Path | None = None,
                        header_path: str | Path | None = None) -> dict[str, Any]:
    issues = [
        {"kind": "UNKNOWN", "item": "calling_convention", "message": "legacy 32-bit export convention needs an authoritative header or vendor ABI record"},
        {"kind": "UNKNOWN", "item": "device_bus_layout", "message": "ctypes layout has not been independently checked against installed libusb headers"},
    ]
    if dll_path and not Path(dll_path).exists():
        issues.append({"kind": "MISSING_EVIDENCE", "item": "dll", "message": "specified DLL path does not exist"})
    if header_path and not Path(header_path).exists():
        issues.append({"kind": "MISSING_EVIDENCE", "item": "header", "message": "specified header path does not exist"})
    return {"architecture": f"host-pointer-{ctypes.sizeof(ctypes.c_void_p) * 8}",
            "library_identity": "libusb-win32 0.1 (requested; not loaded)",
            "checked_symbols": list(REQUIRED_SYMBOLS),
            "layout_verification": "HOST_CTYPES_ONLY",
            "pointer_width": ctypes.sizeof(ctypes.c_void_p),
            "evidence_source": "offline ABI review; no DLL/device access",
            "verification_status": "ABI_UNVERIFIED",
            "issues": issues,
            "transfer_authorized": False}


__all__ = ["REQUIRED_SYMBOLS", "validate_libusb_abi"]
