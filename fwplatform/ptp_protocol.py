"""Strict, offline-only PTP container and DeviceInfo parsing."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
import struct
from typing import Any

PTP_HEADER_SIZE = 12
PTP_MAX_CONTAINER = 1024 * 1024
PTP_MAX_STREAM_CONTAINERS = 256
PTP_MAX_DEVICE_INFO_BYTES = 65536
PTP_MAX_ARRAY_ITEMS = 4096
PTP_MAX_STRING_CHARS = 1024
PTP_TYPES = {1: "COMMAND", 2: "DATA", 3: "RESPONSE", 4: "EVENT"}
PTP_OPERATIONS = {0x1001: "GetDeviceInfo", 0x1002: "OpenSession", 0x1003: "CloseSession", 0x1004: "GetStorageIDs", 0x1005: "GetStorageInfo", 0x1007: "GetObjectHandles", 0x1008: "GetObjectInfo", 0x1009: "GetObject", 0x100B: "DeleteObject", 0x100E: "InitiateCapture", 0x1014: "GetDevicePropDesc", 0x1015: "GetDevicePropValue", 0x1016: "SetDevicePropValue"}
PTP_RESPONSES = {0x2001: "OK", 0x2002: "GeneralError", 0x2003: "SessionNotOpen", 0x2005: "OperationNotSupported", 0x2006: "ParameterNotSupported", 0x2009: "InvalidTransactionID", 0x2019: "DeviceBusy"}
PTP_EVENTS = {0x4001: "Undefined", 0x4002: "CancelTransaction", 0x4003: "ObjectAdded", 0x4004: "ObjectRemoved", 0x4005: "StoreAdded", 0x4006: "StoreRemoved", 0x4007: "DevicePropChanged", 0x4008: "ObjectInfoChanged", 0x4009: "DeviceInfoChanged", 0x400A: "RequestObjectTransfer", 0x400B: "StoreFull", 0x400C: "DeviceReset", 0x400D: "StorageInfoChanged", 0x400E: "CaptureComplete", 0x400F: "UnreportedStatus"}

@dataclass(frozen=True)
class PtpContainer:
    length: int; container_type: int; container_type_name: str; code: int; code_name: str | None; transaction_id: int; payload: bytes
    def to_dict(self) -> dict[str, Any]:
        return {"length": self.length, "container_type": self.container_type, "container_type_name": self.container_type_name, "code": self.code, "code_name": self.code_name, "transaction_id": self.transaction_id, "payload_length": len(self.payload), "raw_payload_exposed": False, "verification_level": "OFFLINE_SYNTHETIC_OR_CAPTURED_BYTES"}

@dataclass(frozen=True)
class ProtocolEvidence:
    source_type: str; firmware_scope: str; device_identity: str | None; usb_interface_identity: str | None; container_type: str; code: int; evidence_level: str; timestamp_utc: str; verification_status: str; limitations: tuple[str, ...]
    def to_dict(self) -> dict[str, Any]:
        value = dict(self.__dict__); value["limitations"] = list(self.limitations); return value

def evidence_for_container(container: PtpContainer, *, source_type: str = "SYNTHETIC_TESTED", firmware_scope: str = "UNKNOWN", device_identity: str | None = None, usb_interface_identity: str | None = None) -> ProtocolEvidence:
    if source_type not in {"SYNTHETIC_TESTED", "OFFLINE_CAPTURE_PARSED"}: raise ValueError("live protocol evidence requires an explicit external verifier")
    return ProtocolEvidence(source_type, firmware_scope, device_identity, usb_interface_identity, container.container_type_name, container.code, source_type, datetime.now(timezone.utc).isoformat(), "NOT_RUNTIME_VERIFIED", ("No USB command was sent by this parser.", "Code names are descriptive standard-table lookups only."))

def parse_container(data: bytes, *, max_length: int = PTP_MAX_CONTAINER) -> PtpContainer:
    if len(data) < PTP_HEADER_SIZE: raise ValueError("truncated PTP container header")
    length, kind, code, transaction = struct.unpack_from("<IHHI", data, 0)
    if length < PTP_HEADER_SIZE or length > max_length or length > len(data): raise ValueError("invalid PTP container length")
    if kind not in PTP_TYPES: raise ValueError("unknown PTP container type")
    table = PTP_OPERATIONS if kind in (1, 2) else PTP_RESPONSES if kind == 3 else PTP_EVENTS
    if len(data) != length:
        raise ValueError("container has trailing bytes")
    return PtpContainer(length, kind, PTP_TYPES[kind], code, table.get(code), transaction, data[PTP_HEADER_SIZE:length])

def parse_stream(data: bytes, *, max_containers: int = PTP_MAX_STREAM_CONTAINERS, max_total_bytes: int = PTP_MAX_CONTAINER * 4) -> list[PtpContainer]:
    if len(data) > max_total_bytes: raise ValueError("PTP stream exceeds safety bound")
    result: list[PtpContainer] = []; offset = 0
    while offset < len(data):
        if len(result) >= max_containers: raise ValueError("too many PTP containers")
        if len(data) - offset < PTP_HEADER_SIZE: raise ValueError("truncated PTP stream container")
        length = struct.unpack_from("<I", data, offset)[0]
        if length < PTP_HEADER_SIZE or offset + length > len(data): raise ValueError("invalid PTP stream boundary")
        result.append(parse_container(data[offset:offset + length])); offset += length
    return result

def _ptp_string(data: bytes, offset: int) -> tuple[str, int]:
    if offset >= len(data): raise ValueError("truncated PTP string length")
    count = data[offset]
    if count > PTP_MAX_STRING_CHARS:
        raise ValueError("PTP string exceeds safety bound")
    end = offset + 1 + count * 2
    if end > len(data): raise ValueError("truncated PTP string")
    raw = data[offset + 1:end]
    if count and raw[-2:] != b"\x00\x00": raise ValueError("PTP string is not terminated")
    return (raw[:-2].decode("utf-16le", errors="strict") if count else ""), end

def _u16_array(data: bytes, offset: int) -> tuple[list[int], int]:
    if offset + 4 > len(data): raise ValueError("truncated PTP array count")
    count = struct.unpack_from("<I", data, offset)[0]; end = offset + 4 + count * 2
    if count > PTP_MAX_ARRAY_ITEMS or end > len(data): raise ValueError("invalid PTP array")
    return (list(struct.unpack_from("<" + "H" * count, data, offset + 4)) if count else []), end

def parse_device_info_dataset(data: bytes) -> dict[str, Any]:
    if len(data) < 8 or len(data) > PTP_MAX_DEVICE_INFO_BYTES: raise ValueError("invalid DeviceInfo dataset size")
    standard_version, vendor_id, vendor_version = struct.unpack_from("<HIH", data, 0); offset = 8
    vendor_description, offset = _ptp_string(data, offset)
    if offset + 2 > len(data): raise ValueError("truncated DeviceInfo functional mode")
    functional_mode = struct.unpack_from("<H", data, offset)[0]; offset += 2
    operations, offset = _u16_array(data, offset); events, offset = _u16_array(data, offset); properties, offset = _u16_array(data, offset); capture_formats, offset = _u16_array(data, offset); image_formats, offset = _u16_array(data, offset)
    manufacturer, offset = _ptp_string(data, offset)
    model, offset = _ptp_string(data, offset)
    device_version, offset = _ptp_string(data, offset)
    serial_number, offset = _ptp_string(data, offset)
    if offset != len(data): raise ValueError("unexpected trailing DeviceInfo bytes")
    return {"standard_version": standard_version, "vendor_extension_id": vendor_id, "vendor_extension_version": vendor_version, "vendor_extension_description": vendor_description, "functional_mode": functional_mode, "operations": operations, "events": events, "device_properties": properties, "capture_formats": capture_formats, "image_formats": image_formats, "manufacturer": manufacturer, "model": model, "device_version": device_version, "serial_number_present": bool(serial_number), "serial_number_redacted": True, "verification_level": "OFFLINE_DATASET_PARSED"}

__all__ = ["PtpContainer", "ProtocolEvidence", "parse_container", "parse_stream", "parse_device_info_dataset", "evidence_for_container", "PTP_OPERATIONS", "PTP_RESPONSES", "PTP_EVENTS"]
