# Unofficial A6000 SDK — offline, evidence-gated contracts

This is a **descriptive reverse-engineering evidence model**, not an official Sony SDK,
an executable firmware interface, or a hardware patching library. Symbol names, DEX
method references, ABI guesses, and speculative OSAL messages are not proven APIs.

## SDK domain coverage

Domains are Camera, Lens, Sensor, Media, UI, OSAL, Android, Networking, and Other.
Coverage is reported as an evidence/readiness matrix, never a firmware-completion
percentage: the total number of required camera APIs is not established.

## Import, review and export

Work only with a backed-up, **private** SQLite copy and a local fixture:

```powershell
python -m fwplatform.cli --db database/private-copy.sqlite sdk import --fixture sdk/contracts.example.json --json
python -m fwplatform.cli --db database/private-copy.sqlite sdk audit --json
python -m fwplatform.cli --db database/private-copy.sqlite sdk coverage --json
python -m fwplatform.cli --db database/private-copy.sqlite sdk build --output sdk/private-sdk-index.json --json
```

Fixture schema version 1 includes firmware_version and interfaces. An interface
requires name and domain. Optional fields include binary_sha256, address,
source_evidence_id (an existing independent evidence row), abi,
calling_convention, parameter_layout, return_semantics, preconditions,
thread_context, state_requirements, side_effects, and event_dependencies.

An exact binary SHA-256 and unambiguous function address, backed by a separate
VERIFIED_STATIC source evidence row, are required before a claimed
VERIFIED_STATIC contract may keep that status. Incomplete claims are
downgraded to CANDIDATE. Imported fixtures never authorize VERIFIED_RUNTIME
or CALLABLE_VALIDATED.

The audit identifies missing primary evidence, binary and function ambiguity,
inconsistent addresses, ABI gaps and incomplete return/parameter layouts.
The domain matrix has UNKNOWN API denominators and UNKNOWN callable counts.

## Phase 3.5: pure offline protocol mock

A deterministic, explicitly defined mock transition table is available.
It **does not** encode verified camera behavior or communicate with a camera.

```powershell
python -m fwplatform.cli --db database/private-copy.sqlite sdk mock --scenario sdk/mock_scenario.example.json --json
```

Each JSON scenario contains `schema_version: 1`, `initial_state`,
`transitions` (each with `from`, `to`, `namespace`, `command`, optional
`reply`), and `steps` (each with `namespace`, `command`, optional
`expect_state`/`expect_reply`). Unrecognized transitions are reported as
`UNRESOLVED_TRANSITION`, and failed assertions return nonzero exit status.
The provided scenario uses explicit synthetic UI-ready and camera-ready
states to keep them conceptually distinct.

Static SDK contract verification also requires the *primary* evidence
excerpt to identify the exact ELF SHA-256, function address, ABI, parameter
layout, and return semantics. A function location alone cannot prove a
callable signature. JNI and OSAL fixtures are all-or-nothing SQLite imports;
function links require a binary fingerprint, not a name or virtual address
without a known ELF identity.

The pure mock runner opens no SQLite database; it reads only the supplied
local JSON scenario. SDK index export also sanitizes legacy status flags:
`verification_status` is downgraded if the contract is not audited,
`runtime_safety` is always `DESCRIPTIVE_ONLY`, and the original database
values appear separately as `reported_verification_status` and
`reported_runtime_safety` for transparency. Mock tests and status flags are
never evidence of live device compatibility.

## Device safety boundaries

SDK exports and mock contracts do not authorize executing functions on a camera.
Even an imported legacy row marked CALLABLE_VALIDATED cannot bypass audit.
No NAND, WBI, bootloader, selector, or camera-runtime memory writes are exposed.
No Sony firmware binaries or populated private evidence databases are shipped.
Real firmware semantics and physical-device safety require independent evidence.
