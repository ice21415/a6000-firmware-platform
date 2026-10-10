# Hardware validation status

Date: 2026-10-10

The validation run was performed from the Windows Codex workspace using the
read-only `pnputil /enum-devices /connected /class USB` command. No camera
handle was opened and no PTP, PC Remote, vendor-specific, storage, or write
operation was sent.

Result: **NOT_CONNECTED**. The host USB bus was enumerable and showed ordinary
USB composite devices, hubs, and AMD USB controllers. No Sony vendor device,
ILCE/A6000 descriptor, MTP interface, or PTP interface was present in the
enumeration output. A separate WPD/Camera class query was denied by Windows
(`HRESULT 0x80041003`), so camera capability and firmware queries are
**USB_NOT_ACCESSIBLE / UNKNOWN**, rather than failed camera operations.

The result is not a firmware compatibility test. No model, firmware version,
USB mode, operation list, response status, or packet trace was obtained. No
Camera Core relation was promoted to `RUNTIME_VERIFIED`; runtime-verified and
safe-to-invoke counts remain zero.

The reusable parser and status model are in
[`fwplatform/hardware_validation.py`](../fwplatform/hardware_validation.py).
It redacts instance IDs and supports synthetic tests without requiring a
camera. PTP querying is intentionally not implemented until a real camera is
visible through the host USB boundary and a documented read-only capability
operation is selected.

Required minimum condition for the next run: connect the camera directly to
this Windows host with a data-capable USB cable, select an official PC Remote
or MTP mode, and ensure the device appears in Windows Device Manager. No
manual shooting benchmark is required.
