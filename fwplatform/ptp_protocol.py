"""Offline PTP container parsing and standard-code descriptions only."""
from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Any

PTP_HEADER_SIZE = 12
PTP_MAX_CONTAINER = 1024 * 1024
PTP_TYPES = {1: "COMMAND", 2: "DATA", 3: "RESPONSE", 4: "EVENT"}
PTP_OPERATIONS = {0x1001: "GetDeviceInfo", 0x1002: "OpenSession", 0x1003: "CloseSession",
                  0x1004: "GetStorageIDs", 0x1005: "GetStorageInfo", 0x1007: "GetObjectHandles",
                  0x1008: "GetObjectInfo", 0x1009: "GetObject", 0x100B: "DeleteObject",
                  0x100E: "InitiateCapture", 0x1014: "GetDevicePropDesc", 0x1015: "GetDevicePropValue",
                  0x1016: "SetDevicePropValue"}
PTP_RESPONSES = {0x2001: "OK", 0x2002: "GeneralError", 0x2003: "SessionNotOpen",
                 0x2005: "OperationNotSupported", 0x2006: "ParameterNotSupported",
                 0x2009: "InvalidTransactionID", 0x2019: "DeviceBusy"}


@dataclass(frozen=True)
class PtpContainer:
    length: int
    container_type: int
    container_type_name: str
    code: int
    code_name: str | None
    transaction_id: int
    payload: bytes

    def to_dict(self) -> dict[str, Any]:
        value = {"length": self.length, "container_type": self.container_type,
                 "container_type_name": self.container_type_name, "code": self.code,
                 "code_name": self.code_name, "transaction_id": self.transaction_id,
                 "payload_length": len(self.payload), "raw_payload_exposed": False,
                 "verification_level": "OFFLINE_SYNTHETIC_OR_CAPTURED_BYTES"}
        return value


def parse_container(data: bytes, *, max_length: int = PTP_MAX_CONTAINER) -> PtpContainer:
    if len(data) < PTP_HEADER_SIZE:
        raise ValueError("truncated PTP container header")
    length, kind, code, transaction = struct.unpack_from("<IHHI", data, 0)
    if length < PTP_HEADER_SIZE or length > max_length or length > len(data):
        raise ValueError("invalid PTP container length")
    if kind not in PTP_TYPES:
        raise ValueError("unknown PTP container type")
    name = (PTP_OPERATIONS if kind in (1, 2) else PTP_RESPONSES).get(code)
    return PtpContainer(length, kind, PTP_TYPES[kind], code, name, transaction, data[PTP_HEADER_SIZE:length])


__all__ = ["PtpContainer", "parse_container", "PTP_OPERATIONS", "PTP_RESPONSES"]
