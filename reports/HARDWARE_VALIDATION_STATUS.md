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

The next safe step is to identify which already-installed `libusb-win32`
interface owns the device, then use only a documented read-only operation. Do
not send arbitrary PTP or Sony vendor commands and do not replace the driver
without explicit approval.
