"""Conservative offline readiness checks for a future standard PTP review."""
from __future__ import annotations

from typing import Any
from .usb_descriptor_probe import DescriptorResult

NOT_READY = "NOT_READY"
INCOMPATIBLE_INTERFACE = "INCOMPATIBLE_INTERFACE"
ABI_UNVERIFIED = "ABI_UNVERIFIED"
DESCRIPTOR_INCOMPLETE = "DESCRIPTOR_INCOMPLETE"
READY_FOR_REVIEW = "READY_FOR_REVIEW"

INFORMATIONAL = "INFORMATIONAL"
MISSING_EVIDENCE = "MISSING_EVIDENCE"
INTERFACE_INCOMPATIBLE = "INTERFACE_INCOMPATIBLE"
ENDPOINT_INVALID = "ENDPOINT_INVALID"
ABI_UNVERIFIED_KIND = "ABI_UNVERIFIED"
DESCRIPTOR_INCOMPLETE_KIND = "DESCRIPTOR_INCOMPLETE"


def _issue(kind: str, message: str) -> dict[str, str]:
    return {"kind": kind, "message": message}


def assess_ptp_readiness(result: DescriptorResult, *, transport_abi: dict[str, Any] | None = None,
                         transport_abi_verified: bool | None = None) -> dict[str, Any]:
    """Assess offline prerequisites; never authorizes a transfer.

    ``transport_abi_verified`` is retained for compatibility but is deliberately
    treated as an untrusted hint. A structured ABI report with status
    ``ABI_VERIFIED`` and an evidence source is required for review readiness.
    """
    issues: list[dict[str, str]] = []
    if result.status != "READ_ONLY_VERIFIED":
        issues.append(_issue(DESCRIPTOR_INCOMPLETE_KIND, "descriptor observation is incomplete or unverified"))
    if result.vendor_id is None or result.product_id is None:
        issues.append(_issue(MISSING_EVIDENCE, "device identity is missing"))
    if result.limitations:
        issues.append(_issue(INFORMATIONAL, "descriptor limitations remain applicable"))

    candidates = [item for item in result.interfaces
                  if (item.interface_class, item.subclass, item.protocol) == (0x06, 0x01, 0x01)]
    candidate_reports: list[dict[str, Any]] = []
    complete_candidates = 0
    for item in candidates:
        scope = (item.configuration, item.number, item.alternate)
        endpoints = [endpoint for endpoint in result.endpoints
                     if (endpoint.configuration, endpoint.interface_number, endpoint.alternate) == scope]
        missing: list[str] = []
        if not any(endpoint.direction == "IN" and endpoint.transfer_type == "BULK" for endpoint in endpoints):
            missing.append("bulk IN endpoint")
        if not any(endpoint.direction == "OUT" and endpoint.transfer_type == "BULK" for endpoint in endpoints):
            missing.append("bulk OUT endpoint")
        if missing:
            issues.append(_issue(ENDPOINT_INVALID, f"PTP candidate {scope} lacks {', '.join(missing)}"))
        else:
            complete_candidates += 1
        candidate_reports.append({"configuration": item.configuration, "interface": item.number,
                                 "alternate": item.alternate, "missing_endpoints": missing})
    if not candidates:
        issues.append(_issue(INTERFACE_INCOMPATIBLE, "no PTP Still Image interface candidate was observed"))

    abi_verified = bool(transport_abi and transport_abi.get("status") == "ABI_VERIFIED"
                        and transport_abi.get("evidence_source"))
    if not abi_verified:
        issues.append(_issue(ABI_UNVERIFIED_KIND, "libusb transport ABI lacks independent structured evidence"))

    if any(item["kind"] == DESCRIPTOR_INCOMPLETE_KIND for item in issues):
        status = DESCRIPTOR_INCOMPLETE
    elif not candidates:
        status = INCOMPATIBLE_INTERFACE
    elif complete_candidates == 0:
        status = NOT_READY
    elif not abi_verified:
        status = ABI_UNVERIFIED
    else:
        status = READY_FOR_REVIEW
    return {"status": status, "ptp_interface_candidates": candidate_reports,
            "issues": issues, "blockers": [item["message"] for item in issues if item["kind"] != INFORMATIONAL],
            "transfer_authorized": False, "verification_level": "OFFLINE_READINESS_REVIEW"}


__all__ = ["assess_ptp_readiness", "NOT_READY", "INCOMPATIBLE_INTERFACE",
           "ABI_UNVERIFIED", "DESCRIPTOR_INCOMPLETE", "READY_FOR_REVIEW",
           "INFORMATIONAL", "MISSING_EVIDENCE", "INTERFACE_INCOMPATIBLE",
           "ENDPOINT_INVALID", "ABI_UNVERIFIED_KIND", "DESCRIPTOR_INCOMPLETE_KIND"]
