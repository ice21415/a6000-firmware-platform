# Hardware validation status

Date: 2026-10-10

The validation run was performed from the Windows Codex workspace using the
read-only `pnputil /enum-devices /connected` command. No camera
handle was opened and no PTP, PC Remote, vendor-specific, storage, or write
operation was sent.

Result: **READ_ONLY_VERIFIED (device identity only)**. The full connected-device
enumeration found `VID_054C`, `PID_07C4`, description `ILCE-6000`, status
`Started`, and class `libusb-win32 devices`. The earlier USB-class-only query
missed it because this driver class is not `USB`, `WPD`, or `Camera`. A separate
WPD/Camera class query was denied by Windows (`HRESULT 0x80041003`), so camera
capabilities, USB protocol mode, and firmware version remain **UNKNOWN**.

The device properties show `libusb-win32` 1.4.0.0 (`libusb0` service,
`oem132.inf`) as the installed best-ranked driver. Windows also reports a
matching `USBSTOR` bulk-only-storage driver, but it is outranked. Therefore the
current setup is not a normal Windows MTP/PTP or mass-storage session, and the
platform's standard camera query tools cannot be assumed to work.

This is device identity enumeration only, not a firmware compatibility test.
No firmware version, USB mode, operation list, response status, or packet trace
was obtained. No Camera Core relation was promoted to `RUNTIME_VERIFIED`;
runtime-verified and safe-to-invoke counts remain zero.

The reusable parser and status model are in
[`fwplatform/hardware_validation.py`](../fwplatform/hardware_validation.py).
It redacts instance IDs and supports synthetic tests without requiring a
camera. PTP querying is intentionally not implemented until a real camera is
visible through the host USB boundary and a documented read-only capability
operation is selected.

The next safe step is either a read-only descriptor query through the already
installed libusb interface, or an explicitly approved driver change to the
camera's documented PC Remote/MTP mode. Do not send arbitrary PTP or Sony
vendor commands and do not replace the driver without explicit approval.

## Phase 4.1 descriptor result

On 2026-10-10, the explicit `hardware descriptors --execute-readonly` probe
successfully opened the existing libusb-win32 handle and issued only standard
control `GET_DESCRIPTOR` requests for the device and configuration descriptors.
The sanitized result was:

| Field | Result |
|---|---|
| VID/PID | `054C:07C4` |
| USB version | `0x0200` |
| Device class | `0x00` (interface-defined) |
| Configurations | `1` |
| Interface | class `0x08`, subclass `0x06`, protocol `0x50` (USB mass-storage bulk-only) |
| Endpoints | `0x81 IN BULK`, `0x02 OUT BULK`, 512-byte max packet |
| PTP-compatible interface | **not observed** |

This is `PRIMARY_DESCRIPTOR_VERIFIED` USB evidence only. It confirms a
mass-storage-class interface through the currently installed driver; it does
not prove PTP support, camera protocol success, firmware 3.21, or any Camera
Core callback/API behavior. No string descriptor, serial number, storage
mount, or file operation was requested.

## Phase 4.2 mode classification and offline PTP research

`python -m fwplatform.cli hardware modes --json` classifies the sanitized
observation as `USB_MASS_STORAGE`, based on interface class `08/06/50` and its
bulk endpoints. No PTP Still Image interface was observed. The classifier keeps
the PTP/MTP class tuple as a candidate only when a future descriptor contains
`06/01/01`; it cannot distinguish PTP from MTP by descriptors alone.

`fwplatform/ptp_protocol.py` parses synthetic PTP container headers, validates
lengths and standard container types, and provides descriptive standard
operation/response names. It has no device transport and does not contain Sony
vendor operation codes. No PTP packet was sent to the camera.

## Phase 4.3 hardening

Descriptor parsing is now fail-closed for zero configurations, duplicate
interfaces/endpoints, endpoints before an interface, inconsistent configuration
headers, short descriptors, and bounded transfer budgets. Alternate settings
and endpoint ownership retain configuration/interface scope. PTP parsing keeps
EVENT codes separate from RESPONSE codes, supports bounded offline streams and
synthetic DeviceInfo datasets, and records non-escalating protocol evidence.

See [`PTP_PROTOCOL_RESEARCH.md`](PTP_PROTOCOL_RESEARCH.md),
[`USB_MODE_RESEARCH.md`](USB_MODE_RESEARCH.md), and
[`USB_CAMERA_CORE_BOUNDARY.md`](USB_CAMERA_CORE_BOUNDARY.md). These changes do
 not add runtime or safe-to-invoke Camera Core evidence.

## Phase 4.4 readiness

The offline DeviceInfo parser consumes all standard fields and redacts serial
content. `ptp_readiness` reports the current Mass Storage observation as
`INCOMPATIBLE_INTERFACE`; no status authorizes PTP transfer. The legacy
libusb-win32 transport remains host-dependent and is not independently
ABI-verified. Firmware version, PTP/MTP capability, and Camera Core runtime ABI
remain UNKNOWN.
