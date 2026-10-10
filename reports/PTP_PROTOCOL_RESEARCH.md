# PTP protocol research (Phase 4.3)

The PTP implementation in `fwplatform/ptp_protocol.py` is an offline parser.
It accepts synthetic bytes or an explicitly supplied, authorised capture and
never opens a device or sends a command.

It now separates COMMAND/DATA operation codes, RESPONSE codes, and EVENT codes,
validates little-endian container length and transaction fields, parses bounded
concatenated streams, and provides a strict synthetic DeviceInfo dataset
parser. Unknown vendor codes remain unnamed. `ProtocolEvidence` records source
and limitations; parser success is never promoted to runtime verification.

No PTP packet has been sent to the A6000. The observed USB configuration is
Mass Storage bulk-only, so it is not treated as a PTP endpoint.
