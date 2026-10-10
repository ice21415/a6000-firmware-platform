"""Conservative offline readiness checks for a future standard PTP review."""
from __future__ import annotations

from typing import Any

from .usb_descriptor_probe import DescriptorResult

NOT_READY = "NOT_READY"
INCOMPATIBLE_INTERFACE = "INCOMPATIBLE_INTERFACE"
ABI_UNVERIFIED = "ABI_UNVERIFIED"
DESCRIPTOR_INCOMPLETE = "DESCRIPTOR_INCOMPLETE"
READY_FOR_REVIEW = "READY_FOR_REVIEW"


def assess_ptp_readiness(result: DescriptorResult, *, transport_abi_verified: bool = False) -> dict[str, Any]:
    """Assess only preconditions; this function never authorizes a transfer."""
    blockers: list[str] = []
    if result.status != "READ_ONLY_VERIFIED":
        blockers.append("descriptor observation is not complete and verified")
    if not result.vendor_id or not result.product_id:
        blockers.append("device identity is missing")
    candidates = [item for item in result.interfaces
                  if (item.interface_class, item.subclass, item.protocol) == (0x06, 0x01, 0x01)]
    if not candidates:
        blockers.append("no PTP Still Image interface candidate was observed")
    candidate_scopes = {(item.configuration, item.number, item.alternate) for item in candidates}
    for scope in candidate_scopes:
        endpoints = [item for item in result.endpoints
                     if (item.configuration, item.interface_number, item.alternate) == scope]
        if not any(item.direction == "IN" and item.transfer_type == "BULK" for item in endpoints):
            blockers.append(f"PTP candidate {scope} has no bulk IN endpoint")
        if not any(item.direction == "OUT" and item.transfer_type == "BULK" for item in endpoints):
            blockers.append(f"PTP candidate {scope} has no bulk OUT endpoint")
    if not transport_abi_verified:
        blockers.append("libusb transport ABI has not been independently verified")
    if result.limitations:
        blockers.append("descriptor limitations remain applicable")
    if result.status != "READ_ONLY_VERIFIED":
        status = DESCRIPTOR_INCOMPLETE
    elif not candidates:
        status = INCOMPATIBLE_INTERFACE
    elif not transport_abi_verified:
        status = ABI_UNVERIFIED
    elif blockers:
        status = NOT_READY
    else:
        status = READY_FOR_REVIEW
    return {"status": status, "ptp_interface_candidates": [
        {"configuration": item.configuration, "interface": item.number, "alternate": item.alternate}
        for item in candidates], "blockers": blockers,
            "transfer_authorized": False,
            "verification_level": "OFFLINE_READINESS_REVIEW"}


__all__ = ["assess_ptp_readiness", "NOT_READY", "INCOMPATIBLE_INTERFACE",
           "ABI_UNVERIFIED", "DESCRIPTOR_INCOMPLETE", "READY_FOR_REVIEW"]
