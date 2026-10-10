# Phase 4.4 PTP readiness

`fwplatform/ptp_readiness.py` checks only offline prerequisites: complete
descriptor status, device identity, a PTP Still Image class candidate, bulk IN
and OUT endpoints, and an independently supplied transport ABI decision.

For the sanitized observation (`054C:07C4`, interface `08/06/50`) the result is
`INCOMPATIBLE_INTERFACE`. A candidate descriptor without ABI evidence is
`ABI_UNVERIFIED`. No state permits automatic commands; `transfer_authorized`
is always false.

Phase 4.5 classifies issues as `INFORMATIONAL`, `MISSING_EVIDENCE`,
`INTERFACE_INCOMPATIBLE`, `ENDPOINT_INVALID`, `ABI_UNVERIFIED` or
`DESCRIPTOR_INCOMPLETE`. Informational limitations no longer force `NOT_READY`.
Each candidate alternate setting is evaluated independently.

The preflight command reads serialized observations as untrusted by default.
`READ_ONLY_VERIFIED` in JSON is not sufficient to pass the descriptor gate.
