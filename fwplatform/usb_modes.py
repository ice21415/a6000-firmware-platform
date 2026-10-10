"""Conservative USB interface mode classification and offline comparison."""
from __future__ import annotations

from dataclasses import asdict
from typing import Any

from .usb_descriptor_probe import DescriptorResult, UsbEndpoint, UsbInterface


def result_from_observation(data: dict[str, Any]) -> DescriptorResult:
    """Load a sanitized descriptor observation; no device access occurs."""
    return DescriptorResult(
        data.get("status", "INCONCLUSIVE"), data.get("evidence_source", "offline observation"),
        data.get("verification_level", "UNVERIFIED"), data.get("timestamp_utc", "unknown"),
        data.get("vendor_id"), data.get("product_id"), data.get("usb_version_bcd"),
        data.get("device_class"), data.get("configurations", 0),
        tuple(UsbInterface(**item) for item in data.get("interfaces", [])),
        tuple(UsbEndpoint(**item) for item in data.get("endpoints", [])),
        data.get("error"), tuple(data.get("limitations", [])),
    )


def classify_descriptor(result: DescriptorResult) -> dict[str, Any]:
    modes: list[str] = []
    evidence: list[dict[str, Any]] = []
    for interface in result.interfaces:
        key = (interface.interface_class, interface.subclass, interface.protocol)
        if key == (0x08, 0x06, 0x50):
            mode = "USB_MASS_STORAGE"
        elif key == (0x06, 0x01, 0x01):
            # The USB class tuple is shared by PTP Still Image and MTP
            # implementations; it cannot distinguish the higher protocol.
            mode = "PTP_STILL_IMAGE_CANDIDATE"
            modes.append("MTP_COMPATIBLE_CANDIDATE")
        elif interface.interface_class == 0xFF:
            mode = "VENDOR_SPECIFIC"
        else:
            mode = "UNKNOWN"
        modes.append(mode)
        evidence.append({"configuration": interface.configuration, "interface": interface.number,
                         "alternate": interface.alternate, "class": interface.interface_class,
                         "subclass": interface.subclass, "protocol": interface.protocol,
                         "mode": mode, "status": "STATIC_DESCRIPTOR_CANDIDATE"})
    unique = list(dict.fromkeys(modes))
    return {"status": result.status, "modes": unique or ["UNKNOWN"],
            "evidence": evidence,
            "limitations": ["Classification uses USB interface descriptors only.",
                            "PTP and MTP cannot be distinguished from this class tuple alone.",
                            "No USB mode was changed and no protocol command was sent."]}


def compare_descriptor_results(before: DescriptorResult, after: DescriptorResult) -> dict[str, Any]:
    def signature(result: DescriptorResult) -> set[tuple[Any, ...]]:
        return {(i.configuration, i.number, i.alternate, i.interface_class, i.subclass, i.protocol)
                for i in result.interfaces}
    def endpoint_signature(result: DescriptorResult) -> set[tuple[Any, ...]]:
        return {(e.configuration, e.interface_number, e.alternate, e.address, e.direction, e.transfer_type, e.max_packet_size)
                for e in result.endpoints}
    old_i, new_i = signature(before), signature(after)
    old_e, new_e = endpoint_signature(before), endpoint_signature(after)
    return {"interface_added": sorted(new_i - old_i), "interface_removed": sorted(old_i - new_i),
            "endpoint_added": sorted(new_e - old_e), "endpoint_removed": sorted(old_e - new_e),
            "before_mode": classify_descriptor(before)["modes"],
            "after_mode": classify_descriptor(after)["modes"],
            "missing_evidence": ["PTP/MTP protocol exchange", "firmware version over USB",
                                 "Camera Core runtime/API correspondence"],
            "status": "OFFLINE_COMPARISON"}


def validate_endpoint_evidence(result: DescriptorResult) -> dict[str, Any]:
    """Report endpoint ownership and completeness without inferring protocol."""
    reports: list[dict[str, Any]] = []
    scopes = {(item.configuration, item.number, item.alternate) for item in result.interfaces}
    for scope in sorted(scopes):
        endpoints = [item for item in result.endpoints
                     if (item.configuration, item.interface_number, item.alternate) == scope]
        addresses = [item.address for item in endpoints]
        issues = []
        if len(addresses) != len(set(addresses)):
            issues.append("duplicate endpoint address")
        if not endpoints:
            issues.append("no endpoints associated with interface")
        reports.append({"scope": {"configuration": scope[0], "interface": scope[1], "alternate": scope[2]},
                        "endpoints": [asdict(item) for item in endpoints], "issues": issues,
                        "valid": not issues})
    return {"status": "OFFLINE_ENDPOINT_REVIEW", "interfaces": reports,
            "verification_level": result.verification_level,
            "limitations": ["Endpoint evidence does not prove PTP or Camera Core capability."]}


__all__ = ["classify_descriptor", "compare_descriptor_results", "result_from_observation",
           "validate_endpoint_evidence"]
