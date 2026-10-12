# USB/PTP to Camera Core evidence boundary

USB descriptor evidence establishes host-visible identity and interface
structure. Offline PTP parsing establishes only that supplied bytes conform to
the standard container and dataset grammar. Neither result proves a Sony
firmware event, ModelCamera object identity, callback address, or safe C++ ABI
call.

The current A6000 observation is `PRIMARY_DESCRIPTOR_VERIFIED` for
`054C:07C4` and Mass Storage class. PTP communication, firmware version over
USB, and Camera Core runtime API correspondence remain `UNKNOWN`. Static
Camera Core relations continue to use their own ELF evidence and are not
promoted by USB observations. Runtime-verified and safe-to-invoke SDK counts
remain zero.

The offline readiness validator reports the current Mass Storage observation as
`INCOMPATIBLE_INTERFACE`. A future PTP-class descriptor can at most reach
`ABI_UNVERIFIED` until the legacy libusb transport ABI is independently
reviewed; `READY_FOR_REVIEW` never authorizes a transfer.

Serialized descriptor observations are now treated as untrusted by default;
their status strings cannot self-attest primary hardware provenance. An
independent caller must explicitly provide the provenance decision.

The USB mode matrix in `A6000_USB_MODE_MATRIX.md` keeps Sony documentation,
primary descriptor observations and unknown future observations separate.
