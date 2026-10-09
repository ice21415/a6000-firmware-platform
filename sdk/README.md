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

## Phase 3.6: reverse-engineering candidate review queue

To review functions exported by the actual inventoried ELF binaries, run:

```powershell
python -m fwplatform.cli --db C:\private\firmware-copy.db sdk discover --domain Camera --limit 100 --json
python -m fwplatform.cli --db C:\private\firmware-copy.db sdk discover --name Lens --include-internal --limit 100 --json
python -m fwplatform.cli --db C:\private\firmware-copy.db sdk draft --name Camera --output C:\private\camera-review.json --json
python -m fwplatform.cli --db C:\private\firmware-copy.db sdk import --fixture C:\private\camera-review.json --json
```

Discovery defaults to **exported, nongenerated functions**; internal functions
and generated names must be explicitly opted in. The `--binary-sha256`
argument scopes candidates to one exact ELF identity. Lexical domain matches
are search hints, not confirmed camera semantics. The output separates a
verified function **location** from UNKNOWN function behavior, ABI, arguments,
JNI/OSAL protocol, and runtime callability.

The draft always uses `domain=Other`, `verification_status=CANDIDATE`,
`runtime_safety=DESCRIPTIVE_ONLY`, and NULL ABI/parameter/return layouts.
It is structurally importable but never verified without independent
semantic/ABI evidence; review metadata records lexical suggestions and raw
Ghidra prototype text. Keep generated review JSON and any populated SQLite
database **private**. Per-function Ghidra evidence is created only from a
validated JSONL input and proves an address/location, *not* the function ABI.

## Controlled multi-ELF coverage expansion

The offline Ghidra batch planner consumes inventoried ELF hashes and skips
successfully completed identical binaries. Plan mode is read-only apart from
the CLI's normal database migration:

```powershell
python -m fwplatform.cli --db C:\private\firmware-copy.db analyze ghidra-batch --root C:\private\firmware --limit 5 --json
```

With a local Ghidra installation, explicitly use `--execute` along with
`--ghidra-root`, `--project-dir` and `--output-dir` (both outputs outside
the firmware input root). The batch executes at most 30 local files per call,
checks file hashes before and after analysis, discards stale JSONL, imports
only completed validated exports, and reports failures without skipping the
other selected binaries. Real Ghidra execution requires user-provided local
inputs and is **not** exercised by public CI. Never place generated JSONL,
SQLite databases or Ghidra projects in the public repository.

## Phase 3.8: address-exact SDK identity hardening

An ELF export name alone does not establish an exported API candidate.
Discovery requires a matching numeric export VMA in the same binary. For
example, `0x100` and `0x0100` compare equally, but another entry with the
same name at a different address is not treated as exported. The discovery
result exposes `unique_function_entry`; a collision between numeric entry
addresses makes location evidence insufficient for identification.

Contract import also requires a unique binary SHA-256 row and a unique
numeric entry address. Subsequent alias collisions are reported by SDK audit
as `AMBIGUOUS_FUNCTION_ADDRESS`; legacy static status is automatically
downgraded in a descriptive SDK export. These checks strengthen the review
queue but do not verify an API ABI, semantics, or runtime callability.
If two inventoried paths have the same ELF SHA-256, discovery reports
`unique_binary_identity=false` and cannot claim a uniquely resolved entry.
The review draft keeps candidate source paths together and collapses duplicate
contract identities, remaining importable as unverified hypotheses.

## Device safety boundaries

SDK exports and mock contracts do not authorize executing functions on a camera.
Even an imported legacy row marked CALLABLE_VALIDATED cannot bypass audit.
No NAND, WBI, bootloader, selector, or camera-runtime memory writes are exposed.
No Sony firmware binaries or populated private evidence databases are shipped.
Real firmware semantics and physical-device safety require independent evidence.
