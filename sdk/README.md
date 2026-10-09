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

An SDK contract fixture is never its own independent ABI proof, even if a
legacy evidence row labels that fixture `VERIFIED_STATIC`. The audit reports
`SELF_ATTESTED_SDK_FIXTURE` for any such claim.

Contract import also requires a unique binary SHA-256 row and a unique
numeric entry address. Subsequent alias collisions are reported by SDK audit
as `AMBIGUOUS_FUNCTION_ADDRESS`; legacy static status is automatically
downgraded in a descriptive SDK export. These checks strengthen the review
queue but do not verify an API ABI, semantics, or runtime callability.
If two inventoried paths have the same ELF SHA-256, discovery reports
`unique_binary_identity=false` and cannot claim a uniquely resolved entry.
The review draft keeps candidate source paths together and collapses duplicate
contract identities, remaining importable as unverified hypotheses.

## Phase 3.9: conservative cross-ELF import/provider candidates

`analyze linkage` now restricts imported-symbol provider candidates to
binaries uniquely resolved through `DT_NEEDED`. Unrelated global names,
unknown/missing dependencies, incompatible symbol versions and multiple
distinct provider VMAs remain unresolved or ambiguous. Even a single
matched export yields only a `CANDIDATE` cross-reference: loader binding,
symbol interposition, PLT/GOT behavior and ABI remain unverified.

SDK candidate discovery also reports `incoming_static_import_candidates`,
`incoming_importing_binary_count` and source evidence IDs based only on
`elf_dynamic`-backed cross-reference records. Review drafts preserve these
counts for prioritizing manual disassembly. These counts never prove
a successful runtime import binding, ABI signature or callable API.

The linkage analyzer fingerprints binary/SONAME/search metadata and the
import/export catalog, so newly indexed providers trigger a conservative
recheck. Stale automated dependency/symbol assertions are swept and one
binary's failed import is rolled back without altering the next binary.
This remains read-only with respect to hardware and cannot produce a
callable firmware SDK without further independent evidence.

## Phase 3.11: static ModelCamera reverse-engineering bundle (no device access)

The private Sony ILCE-6000 3.21 ELF was located in the connected research
workspace. Previously saved disassembly reports identify a conservative set of
**14** `libObj.so` Camera function-entry candidates including
`ActionGpSetSetting`, `pvt_ActionSetInit`, `pvt_ExeEENeutralCmd`,
`PrepChk`, `PrepON`, `PrepOFF`, the common prepare setter, ACTIVE
completion helper and state selector dispatch. The candidate review fixture
`sdk/camera_3_21_static_candidates.json` is importable into a **private
copied** SQLite database and intentionally leaves ABI/arguments/returns NULL.

`sdk/camera_3_21_static_callgraph.json` records nine *reported* static
call/tail branches, six model byte-field observations, four bounded normalized
selector transitions and one unresolved indirect dispatch. It is a manually
transcribed summary of saved, private instruction-level research, **not**
primary instruction or ABI evidence redistributed in this repository.

Review it without opening SQLite, executing an ELF or contacting hardware:

```powershell
python -m fwplatform.cli sdk research --json
python -m fwplatform.cli sdk research --focus "ModelCamera::ActionGpSetSetting" --json
python -m fwplatform.cli sdk research --compare-db C:\private\firmware-copy.db --json
python -m fwplatform.cli --db C:\private\firmware-copy.db sdk import --fixture sdk/camera_3_21_static_candidates.json --json
python -m fwplatform.cli --db C:\private\firmware-copy.db sdk audit --json
```

`sdk research` verifies *internal consistency* of ELF digests, candidate
entry ownership, reported direct-branch targets, field observation and
selector metadata. It rejects forged VERIFIED_STATIC/runtime/ABI assertions,
numeric entry alias collisions and raw private source paths. It **cannot**
revalidate instruction bytes without the private original ELF, prove ABI,
trace runtime execution or authorize callable Camera APIs. The private
`libObj.so` reverse-engineering results were generated before this PR and
their detailed provenance remains in local research artifacts.

Known blockers include the asynchronous EE-neutral command's concrete
implementation and completion producer, EventFilter normalization, complete
state/action coverage, calling conventions/return layouts, and physical
first-shot readiness. Static `camera-ready` labels are not interchangeable
with hardware ready. Lens/Sensor/Media analysis still requires separate
direct ELF/ABI evidence.

## Phase 3.10: inspect Camera, Lens, Sensor and adjacent core API candidates

For a generated or stripped entry whose name does not contain a domain keyword,
use `sdk inspect --function-id <id> --json`. This follows the exact function
foreign key, exposes the unverified raw prototype, CFG/callsites, protocol
roles, unresolved edges, and module-level state-machine context without
claiming the function performs any camera state transition. The function ID
is local to the research database, not a firmware address or runtime handle.

Use `sdk investigate --domain Camera --json` or select Lens, Sensor,
Media, UI, OSAL, Android or Networking. Add `--include-internal` to include
non-exported named functions, `--binary-sha256` to scope one ELF and
`--relation-limit` to bound detailed evidence per function.

The read-only investigation joins **explicit function foreign keys** from
Ghidra callsites, OSAL message flows, JNI native bridges and lifecycle
callbacks. It reports body ranges and basic blocks separately from any claim
of ABI or function semantics. It never matches function/message IDs across
binaries just because their values or names coincide. Camera-named state
machines are presented as lexical context **only**, not function-to-state
links or camera/first-shot readiness proof.

All investigated interfaces remain **unverified** for real device ABI,
side effects, runtime callability and safety. The generated queue is for
manual disassembly and independent evidence review; no firmware executable,
patch or hardware interface is produced.

## Device safety boundaries

SDK exports and mock contracts do not authorize executing functions on a camera.
Even an imported legacy row marked CALLABLE_VALIDATED cannot bypass audit.
No NAND, WBI, bootloader, selector, or camera-runtime memory writes are exposed.
No Sony firmware binaries or populated private evidence databases are shipped.
Real firmware semantics and physical-device safety require independent evidence.
