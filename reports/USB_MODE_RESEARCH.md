# A6000 USB mode research (Phase 4.3)

The sanitized descriptor observation `sdk/usb_descriptor_observation_2026-10-10.json`
records VID `054C`, PID `07C4`, one configuration, and interface
`08/06/50` with bulk endpoints. The classifier therefore reports
`USB_MASS_STORAGE` only. No PTP Still Image interface was observed.

`fwplatform.usb_modes` can compare two offline observations while preserving
configuration, interface alternate setting, and endpoint scope. A descriptor
class tuple `06/01/01` is reported only as a PTP/MTP compatibility candidate;
it cannot distinguish those protocols. Official documentation, a future
user-selected camera mode, and a new sanitized descriptor observation are
required before comparing another mode. Automatic mode changes, driver changes,
USB reset, and PTP commands remain outside this phase.
