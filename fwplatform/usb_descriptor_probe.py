"""Bounded, read-only USB descriptor probing.

Only standard control-transfer GET_DESCRIPTOR requests are issued.  The
libusb-win32 backend never claims an interface, changes configuration, resets,
or sends a vendor/PTP request.  The default entry point is a dry-run.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import ctypes
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from .hardware_validation import STATUS_INCONCLUSIVE, STATUS_READ_ONLY_VERIFIED, STATUS_USB_NOT_ACCESSIBLE

MAX_DESCRIPTOR_BYTES = 4096
DEFAULT_TIMEOUT_MS = 1000
USB_DT_DEVICE = 1
USB_DT_CONFIG = 2
USB_REQ_GET_DESCRIPTOR = 6
USB_DIR_IN = 0x80
USB_TYPE_STANDARD = 0x00
USB_RECIP_DEVICE = 0x00


class DescriptorTransport(Protocol):
    def get_descriptor(self, descriptor_type: int, index: int, length: int, timeout_ms: int) -> bytes: ...

    def close(self) -> None: ...


@dataclass(frozen=True)
class UsbInterface:
    configuration: int
    number: int
    alternate: int
    interface_class: int
    subclass: int
    protocol: int
    ptp_compatible: bool


@dataclass(frozen=True)
class UsbEndpoint:
    configuration: int
    interface_number: int
    alternate: int
    address: int
    direction: str
    transfer_type: str
    max_packet_size: int


@dataclass(frozen=True)
class DescriptorResult:
    status: str
    evidence_source: str
    verification_level: str
    timestamp_utc: str
    vendor_id: int | None
    product_id: int | None
    usb_version_bcd: int | None
    device_class: int | None
    configurations: int
    interfaces: tuple[UsbInterface, ...]
    endpoints: tuple[UsbEndpoint, ...]
    error: str | None
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["interfaces"] = [asdict(item) for item in self.interfaces]
        value["endpoints"] = [asdict(item) for item in self.endpoints]
        return value


def _result(status: str, source: str, level: str, error: str | None = None, **kwargs: object) -> DescriptorResult:
    return DescriptorResult(status, source, level, datetime.now(timezone.utc).isoformat(),
                            kwargs.pop("vendor_id", None), kwargs.pop("product_id", None),
                            kwargs.pop("usb_version_bcd", None), kwargs.pop("device_class", None),
                            kwargs.pop("configurations", 0), tuple(kwargs.pop("interfaces", ())),
                            tuple(kwargs.pop("endpoints", ())), error,
                            ("No USB serial, instance ID, string descriptor, firmware bytes, or PTP command was read.",
                             "Interface class is only static compatibility evidence; it does not prove PTP communication.",))


def parse_device_descriptor(data: bytes) -> dict[str, int]:
    if len(data) < 18 or data[0] < 18 or data[1] != USB_DT_DEVICE:
        raise ValueError("truncated or invalid device descriptor")
    fields = struct.unpack_from("<BBHBBBBHHHBBBB", data, 0)
    return {"usb_version_bcd": fields[2], "device_class": fields[3], "vendor_id": fields[7],
            "product_id": fields[8], "configurations": fields[13]}


def parse_configuration_descriptor(data: bytes, configuration_index: int = 0) -> tuple[tuple[UsbInterface, ...], tuple[UsbEndpoint, ...]]:
    if len(data) < 9 or data[0] < 9 or data[1] != USB_DT_CONFIG:
        raise ValueError("truncated or invalid configuration descriptor")
    total = struct.unpack_from("<H", data, 2)[0]
    if total < 9 or total > MAX_DESCRIPTOR_BYTES or len(data) < total:
        raise ValueError("invalid configuration total length")
    interfaces: list[UsbInterface] = []
    endpoints: list[UsbEndpoint] = []
    current_interface: tuple[int, int] | None = None
    endpoint_counts: dict[tuple[int, int], int] = {}
    offset = 0
    while offset < total:
        length = data[offset]
        if length < 2 or offset + length > total:
            raise ValueError("invalid descriptor length")
        kind = data[offset + 1]
        if kind == 4 and length >= 9:
            cls, sub, proto = data[offset + 5], data[offset + 6], data[offset + 7]
            current_interface = (data[offset + 2], data[offset + 3])
            endpoint_counts[current_interface] = data[offset + 4]
            interfaces.append(UsbInterface(configuration_index, data[offset + 2], data[offset + 3], cls, sub, proto,
                                           cls == 6 and sub == 1 and proto == 1))
        elif kind == 5 and length >= 7:
            if current_interface is None:
                raise ValueError("endpoint is not associated with an interface")
            address, attrs, packet = data[offset + 2], data[offset + 3], struct.unpack_from("<H", data, offset + 4)[0]
            endpoint_counts[current_interface] -= 1
            if endpoint_counts[current_interface] < 0:
                raise ValueError("too many endpoints for interface")
            endpoints.append(UsbEndpoint(configuration_index, current_interface[0], current_interface[1], address, "IN" if address & 0x80 else "OUT",
                                          ("CONTROL", "ISOCHRONOUS", "BULK", "INTERRUPT")[attrs & 3], packet))
        offset += length
    if len({(item.number, item.alternate) for item in interfaces}) != len(interfaces):
        raise ValueError("duplicate interface alternate descriptor")
    if any(count != 0 for count in endpoint_counts.values()):
        raise ValueError("interface endpoint count does not match descriptors")
    if len({item.number for item in interfaces}) != data[4]:
        raise ValueError("bNumInterfaces does not match interface descriptors")
    return tuple(interfaces), tuple(endpoints)


def probe_descriptors(transport: DescriptorTransport, *, expected_vid: int = 0x054C,
                      expected_pid: int = 0x07C4, timeout_ms: int = DEFAULT_TIMEOUT_MS,
                      source: str = "libusb-win32 read-only GET_DESCRIPTOR") -> DescriptorResult:
    try:
        if timeout_ms <= 0 or timeout_ms > 10000:
            return _result(STATUS_INCONCLUSIVE, source, "UNVERIFIED", "invalid timeout")
        device = transport.get_descriptor(USB_DT_DEVICE, 0, 18, timeout_ms)
        identity = parse_device_descriptor(device)
        if identity["vendor_id"] != expected_vid or identity["product_id"] != expected_pid:
            return _result(STATUS_INCONCLUSIVE, source, "PRIMARY_DESCRIPTOR_VERIFIED", "VID/PID mismatch", **identity)
        all_interfaces: list[UsbInterface] = []
        all_endpoints: list[UsbEndpoint] = []
        for configuration_index in range(identity["configurations"]):
            header = transport.get_descriptor(USB_DT_CONFIG, configuration_index, 9, timeout_ms)
            if len(header) < 9 or header[0] < 9:
                raise ValueError("truncated configuration header")
            total = struct.unpack_from("<H", header, 2)[0]
            if total < 9 or total > MAX_DESCRIPTOR_BYTES:
                raise ValueError("configuration length outside safety bound")
            config = transport.get_descriptor(USB_DT_CONFIG, configuration_index, total, timeout_ms)
            interfaces, endpoints = parse_configuration_descriptor(config, configuration_index)
            all_interfaces.extend(interfaces)
            all_endpoints.extend(endpoints)
        return _result(STATUS_READ_ONLY_VERIFIED, source, "PRIMARY_DESCRIPTOR_VERIFIED",
                       interfaces=tuple(all_interfaces), endpoints=tuple(all_endpoints), **identity)
    except TimeoutError as exc:
        return _result(STATUS_INCONCLUSIVE, source, "UNVERIFIED", str(exc))
    except PermissionError as exc:
        return _result(STATUS_USB_NOT_ACCESSIBLE, source, "UNVERIFIED", str(exc))
    except (OSError, ValueError, struct.error) as exc:
        return _result(STATUS_INCONCLUSIVE, source, "UNVERIFIED", str(exc))
    finally:
        transport.close()


class LibusbWin32Transport:
    """Minimal libusb-0.1 ABI wrapper; only used after explicit opt-in."""
    def __init__(self, vid: int, pid: int, dll_path: Path = Path(r"C:\Windows\System32\libusb0.dll")) -> None:
        self._dll = ctypes.WinDLL(str(dll_path))
        required = ("usb_init", "usb_find_busses", "usb_find_devices", "usb_get_busses", "usb_open", "usb_control_msg", "usb_close")
        if any(not hasattr(self._dll, name) for name in required):
            raise OSError("libusb-win32 required API is incomplete")
        self._handle = None
        self._vid, self._pid = vid, pid
        # The legacy structures are used only to locate the matching device;
        # no descriptor strings or serial fields are read.
        class DeviceDesc(ctypes.Structure):
            _fields_ = [("length", ctypes.c_ubyte), ("dtype", ctypes.c_ubyte), ("usb", ctypes.c_ushort),
                        ("devclass", ctypes.c_ubyte), ("subclass", ctypes.c_ubyte), ("protocol", ctypes.c_ubyte),
                        ("max_packet", ctypes.c_ubyte), ("vendor", ctypes.c_ushort), ("product", ctypes.c_ushort),
                        ("release", ctypes.c_ushort), ("imanufacturer", ctypes.c_ubyte), ("iproduct", ctypes.c_ubyte),
                        ("iserial", ctypes.c_ubyte), ("configs", ctypes.c_ubyte)]
        class Device(ctypes.Structure): pass
        DevicePtr = ctypes.POINTER(Device)
        Device._fields_ = [("next", DevicePtr), ("prev", DevicePtr), ("filename", ctypes.c_char * 512),
                           ("bus", ctypes.c_void_p), ("descriptor", DeviceDesc), ("config", ctypes.c_void_p),
                           ("dev", ctypes.c_void_p), ("busnum", ctypes.c_ubyte), ("devnum", ctypes.c_ubyte)]
        class Bus(ctypes.Structure):
            pass
        BusPtr = ctypes.POINTER(Bus)
        Bus._fields_ = [("next", BusPtr), ("prev", BusPtr), ("dirname", ctypes.c_char * 512),
                        ("devices", DevicePtr), ("location", ctypes.c_ulong), ("root_dev", DevicePtr)]
        dll = self._dll
        dll.usb_init(); dll.usb_find_busses(); dll.usb_find_devices()
        dll.usb_get_busses.restype = ctypes.c_void_p
        bus = dll.usb_get_busses()
        while bus:
            bus_obj = ctypes.cast(bus, BusPtr).contents
            device = ctypes.cast(bus_obj.devices, ctypes.c_void_p).value
            while device:
                item = ctypes.cast(device, DevicePtr).contents
                if item.descriptor.vendor == vid and item.descriptor.product == pid:
                    dll.usb_open.restype = ctypes.c_void_p
                    dll.usb_open.argtypes = [ctypes.c_void_p]
                    self._handle = dll.usb_open(ctypes.c_void_p(device))
                    break
                device = ctypes.cast(item.next, ctypes.c_void_p).value
            if self._handle:
                break
            bus = ctypes.cast(bus_obj.next, ctypes.c_void_p).value
        if not self._handle:
            raise OSError("matching libusb device was not opened")
        dll.usb_control_msg.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
        dll.usb_control_msg.restype = ctypes.c_int
        dll.usb_close.argtypes = [ctypes.c_void_p]

    def get_descriptor(self, descriptor_type: int, index: int, length: int, timeout_ms: int) -> bytes:
        if descriptor_type not in (USB_DT_DEVICE, USB_DT_CONFIG) or length <= 0 or length > MAX_DESCRIPTOR_BYTES:
            raise ValueError("descriptor request outside allowlist")
        buf = ctypes.create_string_buffer(length)
        value = (descriptor_type << 8) | index
        read = self._dll.usb_control_msg(self._handle, USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_DEVICE,
                                         USB_REQ_GET_DESCRIPTOR, value, 0, buf, length, timeout_ms)
        if read < 0:
            raise PermissionError(f"libusb control transfer failed ({read})")
        return bytes(buf.raw[:read])

    def close(self) -> None:
        if self._handle:
            self._dll.usb_close(self._handle)
            self._handle = None


__all__ = ["DescriptorResult", "LibusbWin32Transport", "parse_device_descriptor", "parse_configuration_descriptor", "probe_descriptors", "MAX_DESCRIPTOR_BYTES"]
