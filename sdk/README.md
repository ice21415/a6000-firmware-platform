# Unofficial A6000 SDK — offline, evidence-gated contracts

This is a **descriptive reverse-engineering evidence model**, not an official Sony SDK,
an executable firmware interface, or a hardware patching library. Symbol names, DEX
method references, ABI guesses, and speculative OSAL messages are not proven APIs.

The private-only family probe can summarize additional `ParamBase` RTTI/vtable
and constructor evidence without publishing firmware bytes:

```powershell
python -m fwplatform.cli sdk parameter-family-probe --elf C:\private\libObj.so --json
```

The factory-caller probe records only bounded argument provenance, result
guards and relocation identity for the four known `0x42acd4` callsites:

```powershell
python -m fwplatform.cli sdk parameter-factory --elf C:\private\libObj.so --json
```

Its `PRIMARY_ELF_VERIFIED` fields identify decoded instruction sites and PLT
relocations. Register values loaded from dynamic tables are
`STATIC_INFERRED`; no result is runtime-callable and no ownership or locking
guarantee is implied.

The container lifetime probe separately checks clear/destruction and the
unnamed shared-assignment body:

```powershell
python -m fwplatform.cli sdk parameter-mutation --elf C:\private\libObj.so --json
```

The bounded `parameter-numberlist` probe records primary-ELF evidence for
`PrmNumberList`'s uint32 vector layout, indexed access, length calculation,
append path and constructors/destructors:

```powershell
python -m fwplatform.cli sdk parameter-numberlist --elf C:\private\libObj.so --json
```

Its output is descriptive only (`safe_to_call=false`, with runtime and
allocator behavior unknown); it must not be used as a live camera wrapper.

The `parameter-cntinfolist` probe independently checks the two collection
regions, accessors, append path, constructors and destruction path of
`PrmCntInfoList`:

```powershell
python -m fwplatform.cli sdk parameter-cntinfolist --elf C:\private\libObj.so --json
```

Collection element types, bounds, allocator and synchronization behavior stay
unknown, and the output is never a callable firmware interface.

The `camera-selector` probe is a separate primary-ELF check for the bounded
model/name selector helper at `ELF_VMA 0x12d780`:

```powershell
python -m fwplatform.cli sdk camera-selector --elf C:\private\libObj.so --json
```

It verifies the visible `0x40` branch, the `M`/`V` base constants, the
relocation-bound `IdGenerator::Get` call and the normal branch's guarded
virtual dispatch. The transformation at `0x120168`, the helper identities,
the C++ return type and the relation to `ModelCamera` remain UNKNOWN.
`runtime_verified=false` and `callable=false` are enforced by the probe.

It reports element deletion, counter-zero cleanup and allocator relocation
evidence. The assignment identity, copy-on-write behavior, locking and
exception contract remain unknown by design.

It currently discovers ten direct 3.21 `ParamBase`-derived RTTI/vtable records
and profiles `PrmBool`, `PrmNumber`, `PrmString`, `PrmPoint`, `PrmDimension`,
`PrmStruct`, `PrmSet`, `PrmNumberList`, `PrmCntInfoList` and `PrmObjMsg`. The
output remains `runtime_verified=false` and
`callable=false`; pointer ownership, allocator behavior and live ABI safety
remain unknown. Keep the resulting JSON outside the public checkout.

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

## Phase 3.22 — primary-byte probe correctness / output-register evidence

The core helper ELF probe was tightened specifically for
`0x13200a` and `0x42ac00`. Its exact-byte decoder now also
records a bounded list of Capstone **memory operands**
(load/store direction hint, base/index registers, displacement,
instruction VMA), together with highlighted **`r2`-based
memory stores**. A store using a base register `r2`
is a useful check against the `r2=output pointer`
caller ABI lead, but **is not proof** that this register
still holds the original argument or that the stored
value has a specific C++ type. For that reason the
report deliberately sets
`r2_based_store_is_proven_output_parameter=false`.

The shared Thumb decoder also accepts a complete
2-byte instruction at the **end of an executable PT_LOAD**
without incorrectly requiring 4 bytes of mapped code.
This matters when a function ends with `BX LR`
on the last executable halfword; it is covered by
a synthetic ARM ELF boundary regression.

**Both improvements passed CI with synthetic ELF input,
not an extracted Sony `libObj.so`.** The local private
probe command and hard SHA-256 pin remain the same.
Please inspect its `research_targets` section for
visited memory access sites; only outputs from an
exact-sha private Sony run constitute new primary
machine-code evidence.

## Phase 3.21 — targeted primary-byte ABI probe (Core: 0x13200a / 0x42ac00)

To stop accumulating speculative static reports, the first priority
is **reading original private `libObj.so` bytes for the two core
function bodies**. Use the already existing, now more focused
read-only local command:

```powershell
python -m fwplatform.cli sdk probe-core-abi --elf "C:\private\firmware\libObj.so" --json > "C:\private\core-abi-evidence.json"
```

This probes just `0x13200a` (action-payload accessor)
and `0x42ac00` (parameter-query helper) by default,
with a maximum of 384 bytes per function entry.
It refuses a different ELF SHA-256; the default pin is
`8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`.
It additionally requires uniquely mapped executable PT_LOAD
bytes. Each result provides locally decoded reachable Thumb
instructions, call and branch targets, return-site candidates,
entry-block register read-before-write *heuristics*, and a SHA-256
of the observed instruction bytes with their ELF VMAs.
It does not assert whole-function coverage, C++ return type,
a proven fourth argument, safe callability or device behavior.
It never executes the firmware, touches SQLite or changes source.

To investigate related helpers individually:

```powershell
python -m fwplatform.cli sdk probe-core-abi --elf "C:\private\firmware\libObj.so" --entry 0x42abcc --entry 0x42abdc --region-bytes 384 --json
```

**Access limitation:** the connected workspace's file interface
only exposes prior text disassembly; it cannot stream the proprietary
original `libObj.so` file. Consequently, this new primary-byte
probe has **passed synthetic ELF32 ARM tests** but has **not
been run against the real Sony binary within this interaction**.
Keep private ELF and any detailed local trace private; do not
commit them to a public repository. A completed primary-ELF
probe output is the exact missing input for concluding the
real implementation and ABI of these two functions.

## Phase 3.20: query output-pointer ABI shape for Camera payload reads

A *new, caller-grounded register constraint* is recovered for
`libObj.so` function `0x42ac00` from two different
`ModelCamera` action entries. Under ARM AAPCS32, immediately
before this call the saved instructions consistently show:

| Register | Observed role | Proof boundary |
|---|---|---|
| `r0` | pointer to a stack-local payload view initialized by `0x42abcc` | observed in both action sources |
| `r1` | numeric parameter identifier | `0x3fe` / `0x3ff` and `0x1b8` / `0x1b9` |
| `r2` | address of a caller-allocated output slot | stack addresses `[r7+0x34]`, `[r7+0x30]`, `[r7+0x14]` |
| `r3` | **UNKNOWN** | cannot establish a stable semantic input |

The `ActionExeAfRangeLimitDrive` caller branches around
**`Invalid ParamList`** when the lookup returns zero,
then loads the previously supplied output slot.
The `ActionObjectFocusPosDisplayEvent` caller also
reads a four-byte output slot only on the zero-result
branch and stores the result to its own Camera field
(`+0x200`, `+0x204`). Thus we can now infer a
**query-with-output-pointer and zero-accepted-result
register convention**; we still cannot assert its
complete C++ prototype, type encoding, exception behavior,
or lifetime.

`pvt_ActionSetInit` separately calls **`0x42abdc`**,
not `0x42ac00`, with a `0x12000005` key and a
separate stack output address. The zero-result branch reads
the output and logs `EasyMode ON` when it equals one.
These are useful converging observations, **not proof
that the two nearby functions are identical or
interchangeable APIs**.

```powershell
python -m fwplatform.cli sdk param-lookup --json
python -m fwplatform.cli sdk param-lookup --saved-libobj C:\private\boot-static-analysis\model-camera-methods.txt --json
```

The source-gated report requires 39 exact opcode-text
observations across these three caller regions, and returns
CANDIDATE_ONLY if private source is absent. The linked
workspace's previously saved text matched **39/39** requested
sites. Synthetic tests enforce branch/argument provenance
and reject hypothetical `r3` or callable ABI claims.
No new primary proprietary ELF bytes were disassembled
or executed in this session.

## Phase 3.19: constrain the Camera action payload ABI at `0x13200a`

The next core ABI analysis traced the **same** opaque
`libObj.so` helper `0x13200a` through **five distinct
saved instruction entry regions**, instead of simply listing its
addresses. Its `r0` result is forwarded as `r1` to
the common `0x42abcc` wrapper from three
actions (`0x4aea00`, `0x4bac78`, `0x4afc9c`).
The `0x4bac78` path then queries the constructed
wrapper via `0x42ac00` with key IDs **`0x3fe`**
and **`0x3ff`** and has explicit **`Invalid
ParamList`** branches on lookup errors. A separate
action `0x4ae930` forwards the helper result to a
message-construction function `0x44a284`. The
`pvt_ActionSetInit=0x4cf7a8` function takes the
opaque `r1` value from its caller, passes it into
the very **same `0x42abcc` wrapper**, and
calls the EE-neutral/prepare helpers.

This adds a **structural type constraint** beyond
"an untyped `r1` register": the action payload
is used by ParamList-like lookup logic. But an
argument consumed by that wrapper is **not proof**
that `0x13200a` itself has the declared C++
return type `ParamList*`; the wrapper may adapt
another type. The implementations of `0x13200a`,
`0x42abcc`, and `0x42ac00`, event ownership,
lifetime and error ABI are still unknown.

```powershell
python -m fwplatform.cli sdk action-payload --json
python -m fwplatform.cli sdk action-payload --saved-libobj C:\private\boot-static-analysis\model-camera-methods.txt --json
```

A read-only source-gated validator with **36 targeted instruction
snippets from five independently labeled action entries**,
synthetic mismatch tests and zero verified callable API assertions
is committed. Original private ELF opcode bytes remain
unavailable to the connected read-only workspace interface;
this is **saved ARM text verification**, not a new binary decode.

## Phase 3.18: first typed *argument* ABI leads (no callable Camera ABI yet)

This phase deliberately stops producing broad inventories and instead
recovers specific AAPCS32 register arguments for the
`requestModelExecute` bridge and the ModelCamera `0x0f01`
dispatch to `pvt_ActionSetInit`. The Itanium C++ symbols preserve
parameter **types** but do **not** encode ordinary return type or
whether a method is static. The saved Thumb register flows let us
distinguish the two identically parameter-mangled entry points:

| Candidate entry | Mangled explicit arguments | Saved AAPCS32 register lead |
|---|---|---|
| `ViewBase::requestModelExecute` `0x12106e` | `char const*, unsigned long, ParamList*` | instance-like: `r0=this`, `r1=name`, `r2=selector`, `r3=ParamList*` |
| `viewManagerIf::requestModelExecute` `0x1250c0` | identical | static-like: `r0=name`, `r1=selector`, `r2=ParamList*`; incoming `r3` overwritten during GOT setup |
| `AbstractUtilityManager::createRequestModelExecuteEvent` `0x7f0b0c` | `int, unsigned long, ParamList*` | instance/context-like: `r0=context`, `r1=model ID`, `r2=transformed selector`, `r3=ParamList*` |

The `ViewBase` caller uses a context pointer loaded from
`[this+0x7c]`, whereas `viewManagerIf` fetches the context
through the GOT. In *both* cases, `IdGenerator::Get` receives
the original **model name** and helper `0x12d780` receives
the **original model name and selector**, then the event factory
receives the helper's unknown transformed selector. The different
physical input registers are therefore explained by the static-vs-
instance calling convention, *not* evidence that the helper
has different APIs.

The factory saves `operator new(0x10)`'s return in `r4`,
constructs `Event` there, then returns `r4` in `r0`
at `0x7f0b64–66`. `Event*` is a **strong static
return-object inference**; the C++ declared return type,
return/error ownership semantics and calling safety remain unverified.

The cross-ELF saved `viewUnified2.so` call at
`0x1a26e6` independently shows `model/CAMERA`, explicit
selector `0x0f01` placed into `r2`, and candidate
`ParamList*` in `r3`. **It does not by itself prove
dynamic linker binding or event consumption.**

For the Camera internals, the `ActionGpSetSetting`
selector check `0x4cfe8a–90` gates an action call
`0x4cfe98→0x4cf7a8` with `r0` sourced from the
saved Camera instance and `r1` sourced from helper
`0x13200a`. The callee preserves these in `r4/sl`
and forwards `sl` to `0x42abcc`. The exact **C++ type
of the second Camera argument is UNKNOWN**: this is an
internal two-register argument *shape*, not a complete Camera
ABI. Its downstream `0x4b1a20` and `0x4b096c`
calls are consistent with previous static EE/prepare research.

The new command enforces this evidence hierarchy and never calls
firmware:

```powershell
python -m fwplatform.cli sdk request-abi --json
python -m fwplatform.cli sdk request-abi --saved-libobj C:\private\boot-static-analysis\model-camera-methods.txt --saved-view C:\private\boot-static-analysis\view-boot-methods.txt --json
```

Without saved source, the command only reports ABI candidates.
When given both private saved reports, it checks exact address and
register-site observations, including the original `0x0f01`
UI and ModelCamera dispatch. A direct reread of the connected private
saved disassembly text matched **80/80 selected instruction-address
fingerprints** across the two ELF reports (56 request/factory,
19 internal Camera, 5 UI caller). These are source-text checks,
not 80 completed APIs. Current source reports are **text**
extractions, not freshly SHA-verified original ELF bytes.
CI uses synthetic data, rejects wrong registers/prototypes,
and asserts **zero completed callable core Camera APIs**.

## Phase 3.17: ModelManager status gate and shared semaphore boundaries

Existing **private saved** `libObj.so` ARM disassembly and the older
separate Appframework wait-chain JSON now identify a more exact
application-queue **Boolean status gate**, not a Camera ready API.

The saved `0x7eaa14` status-reader entry loads a word at
`[r0+0xa4]` and normalizes its nonzero test to 0 or 1.
The upstream `0x7eeec8` queue-state helper has an earlier
guard `0x7f29ec`: a nonzero guard result returns 0. When that
guard does not short circuit, it calls `0x7eaa14`, XORs the
result with 1, and zero-extends it. Consequently, **only under
the guard-passed path**:

| Word at ModelManager candidate `+0xa4` | Local `0x7eaa14` result | `0x7eeec8` return |
|---|---:|---:|
| Zero | 0 | 1 |
| Nonzero | 1 | 0 |

The caller `application_thread_body` branches to its sleep
path `0x7eeefa` when that gate result is zero (callsite
`0x7ef180` and conditional branch `0x7ef188`).
This is local assembly control flow only: **do not infer a
global Camera-ready predicate or the runtime cause of a delay**.
The adjacent scan at `0x7eaa68` compares status
`0x50000`, `0x70000`, `0x40000`, but this is **not
proven to be the same C++ function** as the `0x7eaa14`
Boolean reader.

The separate `app-status-wait-chain.json` preserves three
reported semaphore `0x830451` wrappers: `0x7f21e8`
(completion helper `0x7f0aa0`), `0x7f2210` (`0x7f099c`)
and `0x7f2238` (`0x7f0aac`). It also reports five
callsite/state pairs for the `0x7eb118` status setter.
These are **secondary static research claims**, not fresh
opcode proofs for `0x7f21e8` or `0x7f2238`.
The earlier `0x7f2210` branch does have an independently
saved instruction region.

Run independent, opt-in source-tier crosschecks:

```powershell
python -m fwplatform.cli sdk app-sync --json
python -m fwplatform.cli sdk app-sync --saved-disassembly C:\private\boot-static-analysis\app-event-functions.txt --saved-status-chain C:\private\boot-static-analysis\app-status-wait-chain.json --json
```

With no private source files, the output is CANDIDATE_FIXTURE_ONLY.
With saved files, the validator separately verifies 18 selected
ARM instruction-text locations (rechecked in the connected workspace)
and three reported semaphore wrappers / five status-transition
callsites. No SQLite, device access, Sony bytecode distribution, or
ABI/run-time proof is involved. CI uses synthetic saved inputs.

**Remaining critical links:** the `0x11004003` event's real
consumer, any decoding of keys 7/8, exact `0x12d780`
selector semantics and actual original-ELF disassembly of the
`0x7f21e8` wait body. Do not patch a wait, change `+0xa4`
or claim any completed Camera SDK ABI from this data.

## Phase 3.16: Appframework event-queue and dispatch boundary

A saved original-firmware `libObj.so` disassembly identifies
`application_thread_body=0x7eeee8`, which calls a queue state/guard
`0x7eeec8` and the candidate dispatch thunk `0x7eecac`
(at `0x7ef0d4` and `0x7ef16e`). The dispatch thunk loads
from object offset `+0x18` and tail-branches to
**unresolved** `0x7f21e8`. A separate cleanup path at
`0x7eecec` also calls the dispatch candidate. A related
helper at `0x7f2210` uses semaphore ID `0x830451`
around `0x7f099c`.

The saved report contains **overlapping bounded disassembly windows**
for `app_event_pop`, `app_event_dispatch` and
`app_event_cleanup`. These are not interchangeable full-function
bodies. `sdk event-loop` audits **26 exact saved opcode-text sites**
across **six named function windows** and rejects altered branches,
missing function labels and fabricated event-consumer/ABI assertions:

```powershell
python -m fwplatform.cli sdk event-loop --json
python -m fwplatform.cli sdk event-loop --saved-disassembly C:\private\boot-static-analysis\app-event-functions.txt --json
```

The first invocation returns candidate status only; the second
checks previously saved textual evidence, **not** original ELF
instruction bytes. The connected workspace interface cannot read
the private binary stream, so no fresh Sony opcode scan or firmware
execution happened in this session. To examine still-unknown
`0x7f21e8`/`0x7f099c` locally, the existing SHA-pinned
`sdk trace-selector --elf <private-libObj.so> --entry 0x7f21e8
--entry 0x7f099c --json` is read-only and bounded.

**Critical gap:** the `0x11004003` event factory has not been
linked to this particular queue or consumer; the loop is not
proven to decode event keys 7/8 or invoke ModelCamera.
Do not treat this evidence as a callable camera API.

## Phase 3.15: two shared model-request frontends, separate dispatch boundaries

The preserved private `libObj.so` instruction report additionally records a
second, distinct frontend `viewManagerIf::requestModelExecute` at
ELF VMA `0x1250c0`, compared with the previously documented
`ViewBase::requestModelExecute` at `0x12106e`.
Both call the same imported model-name ID generator (`0xdffb8`),
the same local selector transformation helper (`0x12d780`), and
the same named event-factory PLT entry (`0xdfbdc`). In both
instruction sequences, the transformed selector becomes the event
factory's **r2** input, the model name's generated ID becomes **r1**,
and the original ParamList pointer becomes **r3**.

The frontends **diverge at submission**: the ViewBase method tail-branches
at `0x1210a4` to imported `View::requestApplicationExecute`
(`0xdb578`), whereas the viewManagerIf method tail-branches at
`0x1250f6` to **local function candidate `0x125084`**, whose body is
not included in the saved research report. The manager also obtains
its utility-manager receiver via a different indirection from the
ViewBase stored `this+0x7c` receiver. Static shared inputs do not
prove matching runtime delivery, thread behavior, function signatures,
or the interpretation of `0x12d780`'s returned value.

A bounded, candidate-only validation command checks both paths
against the local saved disassembly and optionally cross-references
the prior event envelope's precise ELF SHA identity:

```powershell
python -m fwplatform.cli sdk request-frontends --json
python -m fwplatform.cli sdk request-frontends --saved-disassembly C:\private\boot-static-analysis\model-camera-methods.txt --event-envelope sdk/camera_3_21_model_execute_envelope.json --json
```

Without `--saved-disassembly`, this reports
`TWO_FRONTEND_RESEARCH_LEADS_ONLY`. With the saved source, it checks
33 **reported disassembly-text sites** in two separate function regions,
including exact PLT target annotations, registers, and distinct tail
branch targets. The connected private workspace was directly queried
and **33/33 reported site expectations matched** the previously saved
instruction text. This is **not** re-reading the original ELF bytes,
nor verification of the unknown helper or event consumer. Synthetic
regression tests exercise mismatched targets, register swaps and
unjustified ABI/runtime claims without shipping proprietary firmware.

## Phase 3.15: two request frontends and bounded private Thumb tracing

The saved `libObj.so` disassembly now provides a **second independent
frontend observation**, `viewManagerIf::requestModelExecute` at
`0x1250c0`. Both this method and `ViewBase::requestModelExecute`
(`0x12106e`) call the **same local helper target `0x12d780`** and
**same named factory import stub target `0xdfbdc`**. The alternate
frontend's tail branch is `0x125084`, not the known ViewBase
`requestApplicationExecute` PLT symbol; no event queue consumer is
therefore inferred from that address or the common factory symbol.
Its original `r0` meaning remains unknown. The new saved text
validator covers **50 exact annotated instruction sites** across the
two frontends and candidate event factory (16+15+19). This exact
site count was directly matched against the PRIVATE saved local
`model-camera-methods.txt`, not a new full-file original ELF scan.

To perform the **next local source-byte analysis step** without
replaying Ghidra's earlier whole-module timeout, use the added bounded
Capstone CLI on a PRIVATE original 3.21 `libObj.so`:

```powershell
python -m fwplatform.cli sdk trace-selector --elf C:\private\firmware\libObj.so --region-bytes 1536 --json
```

This command requires the original `libObj.so` full-file SHA-256
`8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`
by default and checks unambiguous executable PT_LOAD mapping. It
performs **nonexecuting** bounded Thumb decoding of `0x12d780` and
`0x125084`, reports visited opcodes/branch targets, bounded literal
loads and separately lists raw occurrences of `0x11004003`.
**Raw-word occurrences are not event-consumer xrefs.** It does not
recursively follow BL calls into unrelated code, deduce ABI/struct
ownership, patch firmware or communicate with hardware. Targets,
region width and SHA can be explicitly overridden for synthetic
fixtures or other authorized local investigations; the default
SHA pin prevents accidentally analyzing the wrong Sony release.

As a diagnostic CLI, the output can include address-annotated
instruction mnemonics from a *private* binary: retain the output
locally and do not commit proprietary trace material or any firmware
to this public repository. The connected workspace's text file API
explicitly rejects `libObj.so` as BINARY_FILE, so this capability
was tested with **synthetic ELF32/Thumb fixtures**, **not** executed
against Sony's original private ELF in this session. The exact
`0x12d780` selector transform and `0x11004003` consumer are still
UNKNOWN; no runtime-callable Sony API has been asserted.

## Phase 3.14: recover model-request event envelope (saved static assembly)

An additional previously saved original-ELF ARM/Thumb report for `libObj.so`
provides a **new, intermediate part** of the previously unknown UI→Camera
routing. `ViewBase::requestModelExecute` (`0x12106e`) calls the model
name `IdGenerator::Get` at `0x121082`, an **unresolved transformation
helper** `0x12d780` at `0x12108c`, the symbolic
`AbstractUtilityManager::createRequestModelExecuteEvent` import at
`0x121098`, and tail-branches to
`View::requestApplicationExecute` at `0x1210a4`. This is a source
code-path observation, **not** proof that the separately found factory
implementation is the function dynamically linked by the import.

The independently found, same-named
`AbstractUtilityManager::createRequestModelExecuteEvent` implementation
candidate at `0x7f0b0c` builds an `Event` with reported event ID
`0x11004003` and constructor byte values 2 and 0. If its incoming
`ParamList` is non-null, it calls `Event::setParamList`. It additionally
creates two event parameters under **keys 7 and 8**:

- Key 7: the model-name identifier value passed into the factory.
- Key 8: the output of the unresolved `0x12d780` selector helper.

These are *static caller-register-flow hypotheses and observed
`Event::addParameter` sites*, not a verified transferable wire format,
application queue consumer, symbol relocation binding, parameter
ownership contract, or callable ABI. In particular **key 8's numeric
value cannot safely be equated to `0x0f01`** without disassembling
the `0x12d780` transformation and its recipient. The eventual
`ModelCamera::ActionGpSetSetting` linkage is still missing.

```powershell
python -m fwplatform.cli sdk event-envelope --json
python -m fwplatform.cli sdk event-envelope --saved-disassembly C:\private\boot-static-analysis\model-camera-methods.txt --json
```

`sdk event-envelope` cross-checks **reported instruction text**
exactly (function boundaries, register carries, PLT/branch target annotations,
event constructor and parameter keys) when a saved report is available.
Without that report it explicitly states `EVENT_ENVELOPE_CANDIDATE_ONLY`.
The tool runs before any SQLite migration and never opens, writes or
executes firmware. Synthetic tests reject miswired registers, changed
key identifiers, invented dynamic binding, and misleading ABI status.
It does **not** authenticate instruction bytes against a fresh private
original ELF; Phase 3.12's separate `--verify-elf` is needed for that.

## Phase 3.13: REA/Ghidra saved UI-to-Camera endpoint audit

The connected private research workspace contains saved
`reverse-engineer-anything` (REA 4.1.0) / Ghidra 12.1.4 findings for
`viewUnified2.so` and separate, **non-REA** original-ELF/Capstone
instruction observations for `libObj.so`. The optional saved inputs
are never committed: `rea-analysis/ui-setinit/0x1b2504.c` and
`rea-analysis/camera-neutral/audit_obj_selectors.json`.

The UI saved decompilation of `CmnViewBigModelUtil::setInitForRec`
contains 20 **static textual sites** requesting selector `0x0f01`
to `model/CAMERA` and 6 requesting it to `model/STILL_REC`.
Different mode branches cannot be counted as live repetitions. UI Ghidra
VMA `0x1b2504` maps to **UI ELF** VMA `0x1a2504` due to
**UI-specific** image bias `+0x10000`. Do not apply that bias to
`libObj.so`.

The separate saved Camera `audit_obj_selectors.json` byte span at
`0x4cfe8a` contains a Thumb MOVW selector immediate `0x0f01`, and
at `0x4cfe98` a Thumb BL targeting `pvt_ActionSetInit=0x4cf7a8`.
A newly implemented bounded decoder can recheck these *saved* bytes
and their Capstone metadata. This is **not** a fresh full-original-ELF
verification, nor Ghidra pseudocode for `libObj.so`.

```powershell
python -m fwplatform.cli sdk rea-bridge --json
python -m fwplatform.cli sdk rea-bridge --fixture sdk/ui_camera_3_21_rea_bridge.json --ui-decompile C:\private\rea-analysis\ui-setinit\0x1b2504.c --camera-audit C:\private\rea-analysis\camera-neutral\audit_obj_selectors.json --json
```

The first command reports missing local artifact checks explicitly;
the second requires observed direct UI request counts, correct UI
rebase, matching camera saved source SHA and exact MOVW/BL
instruction targets. Neither executes Ghidra, a firmware binary, or a
camera; neither writes a research database. Even with both endpoints
rechecked, the intermediate `ViewBase::requestModelExecute`
message routing, queue delivery and event normalization remain
**UNVERIFIED**. No Camera ABI/runtime callable inference is permitted.
CI uses synthetic inputs with different addresses, not redistributed
Sony instructions.

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
python -m fwplatform.cli sdk research --verify-elf C:\\private\\firmware\\libObj.so --json
python -m fwplatform.cli sdk research --compare-db C:\private\firmware-copy.db --json
python -m fwplatform.cli --db C:\private\firmware-copy.db sdk import --fixture sdk/camera_3_21_static_candidates.json --json
python -m fwplatform.cli --db C:\private\firmware-copy.db sdk audit --json
```

`sdk research` verifies *internal consistency* of ELF digests, candidate
entry ownership, reported direct-branch targets, field observation and
selector metadata. It rejects forged VERIFIED_STATIC/runtime/ABI assertions,
numeric entry alias collisions and raw private source paths. **Phase 3.12 — independent read-only ELF opcode checks.** Supply
`--verify-elf` pointing to the PRIVATE, original `libObj.so`; this verifies
the complete expected SHA-256 before reading instructions through the
ELF32 little-endian ARM executable `PT_LOAD` VMA mapping. It decodes only
Thumb-2 direct `BL` and unconditional `B.W` target addresses plus
`LDRB.W` / `STRB.W` unsigned-immediate byte field operations. A
mismatch or unsupported encoding yields a nonzero CLI exit code; corrupted
or differently hashed firmware is explicitly rejected. Only matched
**instruction encodings and immediate displacements** are proven by this
check. The `+0x2680` ModelCamera object-base adjustment and causal
semantics of the field are separate research inferences, not established
by reading one byte instruction. The verifier does not publish raw opcode
bytes or run/call/modify any camera firmware; CI uses synthetic ELF32 ARM
fixtures instead of a Sony binary.

A supplied `--compare-db` opens the SQLite research index read-only,
does not migrate it, and checks whether the exact ELF SHA, normalized
function-entry VMA, and direct caller/callee IDs are present. Missing,
ambiguous and mismatching entries remain explicit; successful index
matches **do not** promote API/ABI status.

It **cannot**
revalidate instruction bytes without the private original ELF, prove ABI,
trace runtime execution or authorize callable Camera APIs. The private
`libObj.so` reverse-engineering results were generated before this PR and
their detailed provenance remains in local research artifacts.

Separate `sdk/core_3_21_lifecycle_research_leads.json` records the static
phase-8 IMDb LensCommunicator init/exit and CameraProfile init/exit callbacks.
IMDb descriptor offsets are **not** function VMAs, and no lens focus/iris,
sensor-imager or media processing ABI is claimed by these leads.

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
# Primary ParamList lookup contracts

`parameter_types_lifetime_3_21.json` adds PrmNumber/PrmBool constructor, RTTI,
vtable, payload and deletion evidence. Query it using `fw sdk parameter-types
--json`. `decode_payload` requires an exact vptr+discriminator pair and explicit
load bias for relocated addresses. It distinguishes signed int from one-byte
bool and leaves unknown types unresolved. These checks belong to the offline
parser, not Sony firmware. Shared lifetime does not protect against replacement.

`core_3_21_primary_helper_contracts.json` contains field-scoped primary/static
evidence, including ParamList::get and adjacent query wrappers. Candidate C++
declarations live in `paramlist_3_21_candidate.hpp`; they expose no native
address binding. `fwplatform.paramlist_snapshot.lookup_snapshot` reads only
self-contained offline memory bytes, with bounds checks and a resource budget.
The returned payload word's concrete type is UNKNOWN. No runtime-safe API is
provided. The same contract records the static `0x42acd4` factory mapping for
discriminators 5/1/3 to Bool/Number/Point construction and its four direct
callers. It also records the discriminator-5/3 lookup forwarders and the
Bool/Point payload-word getters used by those branches; source-level ownership
and helper semantics remain UNKNOWN. See
`reports/CORE_PRIMARY_HELPER_AUDIT.md` for exact witness locations.
