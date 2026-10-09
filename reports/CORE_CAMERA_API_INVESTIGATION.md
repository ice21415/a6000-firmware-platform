# Core Camera / Lens / Sensor / Media API Investigation

Research scope: Sony ILCE-6000 firmware 3.21; offline, descriptive only.
This report distinguishes **known static artifacts** from **unknown API semantics**.
The private firmware database, ELF files, Ghidra JSONL and physical camera observations
are not included or copied into the public repository.

## Existing leads and their evidence limits

| Research area | Static lead | What is actually supported | Still missing |
|---|---|---|---|
| Camera / ModelCamera | `ModelCamera.selector_dispatch` associated with `libObj.so` in the older local architecture atlas | A named state-machine observation with a module association; publicly summarized state transitions are static only | Exact dispatcher function entry, independent branch-to-action and payload evidence, camera-ready/first-shot causality |
| Lens / focus | Lens/focus lexical symbol review queue | Candidate names and individually inventoried ELF entry locations, if present in a local database | Independently established focus ABI, callback/queue causality and lens hardware effect |
| Sensor / ISP | `libObj.so` lists a `libsencore.so` dynamic dependency in the older local atlas | A module-level loader dependency, **not** proof of an imager-control call | Unique symbol provider, sensor register/payload semantics and validated dataflow |
| Media / imaging | `libObj.so` lists `libInfraMediaCommon.so` as a dependency in the older local atlas | A module-level loader dependency only | Image pipeline callsites, buffers, ownership, thread context and return/error semantics |
| UI / readiness | Separate UI-ready and camera-ready concepts in existing state-machine research | Distinct symbolic states in research records | Verified transition from user event to camera prepare, ready and first shot |

The architecture atlas is a historical local metadata snapshot from 2026-10-08,
not a newly reproduced Ghidra analysis. It reported 709 ELF records and 707
structurally analyzed, while Ghidra CFG analysis had been executed on a much
smaller sample set. ELF indexing **must not** be described as full function
semantic recovery. The public phase-three camera report summarizes two state
machines and 28 transitions; that does not establish on-device behavior.

## Evidence-first procedure

Use a **backed-up private database copy**. All commands below query evidence
and do not call or patch camera firmware:

```powershell
python -m fwplatform.cli --db C:\private\firmware-copy.db sdk investigate --domain Camera --limit 25 --json
python -m fwplatform.cli --db C:\private\firmware-copy.db sdk investigate --domain Lens --include-internal --limit 50 --json
python -m fwplatform.cli --db C:\private\firmware-copy.db sdk investigate --domain Sensor --json
python -m fwplatform.cli --db C:\private\firmware-copy.db sdk investigate --domain Media --json
python -m fwplatform.cli --db C:\private\firmware-copy.db sdk inspect --function-id 12345 --json
```

The final command uses **an example database-local function ID**, not an actual
Sony function/address. Take a real ID from the local `sdk investigate` output,
Ghidra import, or a database function query. For stripped functions, ID-based
inspection is preferred to assigning a domain by a generated name.

For each interface proposed as core SDK work, independently gather and verify:

1. ELF SHA-256, address space, normalized entry and Ghidra body/CFG proof.
2. Exact caller/callee function IDs with source evidence (not name-only matching).
3. Calling convention, parameter layout, return/error behavior and independent
   instruction or callsite evidence (Ghidra prototypes alone are not ABI).
4. OSAL queue namespace, command/payload, function-id producer/consumer and
   callback relationships **only** when expressly supported; JNI requires
   exact native/DEX method linkage.
5. Camera selector state and readiness links only where a direct causal edge is
   independently established; otherwise mark as **UNKNOWN**.

## Current status

- **Implementation:** `sdk investigate`, `sdk inspect`, bounded direct-reference
  retrieval and synthetic provenance tests are in the pull request.
- **Static API candidate discovery:** available, with ELF/linkage evidence and
  explicit ambiguity handling.
- **Real Camera/Lens/Sensor ABI recovery:** **NOT ESTABLISHED** by available public evidence.
- **Real device runtime/callability/safety:** **UNKNOWN**; no physical-device
  or firmware write operations are implemented here.
- **Full core API denominator:** **UNKNOWN**; there is no justified completion
  percentage and no published complete executable Sony SDK.


## Phase 3.11 research update (2026-10-09)

The connected private research workspace **does contain** an extracted Sony
3.21 `libObj.so` (17,436,172 bytes) and Lens, Camera Profile, Media,
OSAL and other ELF libraries. Therefore the next blocker is **not** the
absence of firmware files: it is that the indexed symbols and saved static
disassembly reports do not independently prove complete calling conventions,
parameter/return layouts or safe firmware runtime invocation. A prior
full-`libObj` Ghidra provider import timed out; the preserved Camera
instruction-level notes were analyzed via other offline tooling and are
not represented as successful new Ghidra pseudocode evidence.

The backed-up notes identify the 3.21 `libObj.so` ELF SHA-256
`8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`.
The descriptive candidate catalog now covers 14 Camera function-entry
research aliases, while the report-only graph transcribes 9 direct
branch/call relations, 6 ModelCamera byte-field observations, 4
normalized-selector research results, and an unresolved
`ObjIf::IssueCommandAsync` indirect dispatch.

The particularly useful reported static chains are:

- `ActionGpSetSetting (0x4cfb9c)` reaches `pvt_ActionSetInit (0x4cf7a8)`
  on the **normalized** `0x0f01` selector branch.
- `pvt_ActionSetInit` invokes the EE-neutral helper at `0x4b1a20`
  and the preparation check at `0x4b096c`. The neutral helper invokes
  a sender at `0x443d14`, while the asynchronous message's concrete
  delivery/completion and synchronous status meaning remain unresolved.
- `PrepON`, `PrepOFF` and `PrepChk` branch to common setter
  `0x132028`, which can defer publishing the model's prepared flag.
  Publishing a boolean is **not** proof that sensor/lens/first-shot
  hardware prerequisites have completed.

`fw sdk research --json` audits internal consistency of these
**report-level** claims without SQLite or ELF execution;
`--compare-db <private-copy.sqlite>` reads an existing SQLite index
strictly in read-only mode to report which exact binary hashes, entry
VMAs and direct callsite foreign keys exist. An indexed callsite never
automatically turns into verified ABI or safe camera control.

Separate Lens/Camera Profile lifecycle leads are in
`sdk/core_3_21_lifecycle_research_leads.json`. IMDb phase-8 registration
record 131 names `LensCommunicator_Init/Exit`; record 125 names
`infra_cameraProfile_init/exit`. The record offsets `0xd76c` and
`0xd664` are *not function-entry VMAs*. Actual Lens focus, aperture,
sensor-imager, media pipeline and OSAL API signatures remain unknown.


## Phase 3.12: private original ELF opcode verification

The candidate graph can now be independently checked against a private
Sony ILCE-6000 3.21 `libObj.so` using the read-only command:

```powershell
python -m fwplatform.cli sdk research --verify-elf C:\private\firmware\libObj.so --json
```

Verification requires the **exact full-file SHA-256**
`8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`.
`fwplatform/camera_elf_verify.py` maps ELF32 little-endian ARM executable
program headers to ELF VMA and decodes restricted Thumb-2 `BL`/`B.W`
branch offsets, `LDRB.W` and `STRB.W` immediate field operands. The saved
Camera research now explicitly distinguishes the byte instruction's raw
displacement `0x7c` from the *inferred* model-object offset `0x26fc`
(the intermediate register base is considered to add `0x2680`).
The opcode verifier can check `0x7c` but **cannot** on its own confirm
the original object's identity or complete dataflow provenance.

A failed exact digest or ambiguous executable VMA mapping prevents
verification, and an opcode/target/offset mismatch returns an incomplete
result with nonzero CLI status. The verifier does not publish original binary
bytes, call firmware functions, modify ELF contents or access a camera.
Synthetic ELF32/Thumb tests cover positive and negative relative branches,
immediate fields, target corruption, ambiguous mappings and CLI failure.

**Verification performed in CI:** only on generated synthetic ELF fixtures.
**Verification of the private Sony source ELF:** not executed in the
connected workspace by this patch, because the connected read-only workspace
interface can list native binaries and read text, but does not expose byte
reading or a command runner. Therefore no real 3.21 Sony opcode check count
or ABI/runtime success claim is made here. Further local analysis should
import the verified raw-byte observations as *static instruction evidence*,
followed by separate ABI and event/OSAL causality review.


## Phase 3.13: REA/Ghidra UI-to-Camera selector endpoint cross-check

Private offline research preserves an earlier successful
reverse-engineer-anything (REA 4.1.0) / Ghidra 12.1.4 session on
`viewUnified2.so` (SHA-256:
`7fbfa8539717ba3dca0cb5a82cf976b50a2b97443972fe321a064cbb09a75588`).
Its saved `0x1b2504.c` decompilation is **Ghidra VMA**, offset by
`+0x10000` relative to that ELF's `0x1a2504` entry. This
specific UI image rebasing cannot be applied to `libObj.so`.

A fresh read of the **saved** UI decompilation located 20 textual sites
where `requestModelExecute` supplies `model/CAMERA` with selector
`0x0f01`, six where it supplies `model/STILL_REC`, and four
`setInitForRec` invocation sites in the saved UI helper decompilation.
These numbers are static call-expression counts in different branches,
not observed per-boot execution counts. The existing REA evidence ID
for the main successful decompile is
`ev_816bea3002eac3bf155723d8554c23c6087e58c8c1cfec8db7c7078636feb8c7`.
Its pseudocode should not be mistaken for vendor source or a verified ABI.

The **separate** saved `libObj.so` raw-ELF/Capstone audit
(`audit_obj_selectors.json`, source SHA-256
`8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`)
contains an instruction span beginning `0x4cfe8a`. Independently
decoding the saved Thumb bytes gives MOVW immediate `0x0f01` at
`0x4cfe8a` and BL target `0x4cf7a8` at `0x4cfe98`.
This validates the **stored instruction slice against the saved
disassembly**, not the whole current original ELF, and is not
successful REA pseudocode for `libObj.so`: that target previously
timed out in the Ghidra provider.

These two observations form a **cross-ELF investigation lead**, not a
proven call chain. The `ViewBase::requestModelExecute` routing,
message/event namespace translation, queue delivery, native
`EventFilter`, callback producer and runtime branch conditions are
not yet traced. No runtime device operation or SDK ABI verification
is claimed.

The public changes include
`sdk/ui_camera_3_21_rea_bridge.json`,
`fwplatform/rea_bridge.py`, synthetic tests, and:

```powershell
python -m fwplatform.cli sdk rea-bridge --json
python -m fwplatform.cli sdk rea-bridge --ui-decompile C:\private\rea-analysis\ui-setinit\0x1b2504.c --camera-audit C:\private\rea-analysis\camera-neutral\audit_obj_selectors.json --json
```

The first command **does not claim to have rechecked unavailable
private source files**. The second independently checks the supplied
saved pseudocode's request expressions, source names, offsets,
bounded MOVW immediate/BL target and Capstone text. It is read-only,
does not launch REA/Ghidra or execute an ELF, and preserves the
unresolved middle routing boundary. CI exercises synthetic examples
rather than publishing private Sony instruction bytes.


## Phase 3.14: recovered model-execute event envelope from preserved static code

An additional original-firmware *saved instruction report*
(`model-camera-methods.txt`) includes two critical `libObj.so`
symbol/function regions not fully reconstructed in the earlier UI→Camera
report:

| Entry / callsite | Saved static observation | Evidence boundary |
|---|---|---|
| `0x12106e` | `ViewBase::requestModelExecute` front end | Named instruction region in original-target report |
| `0x121082` | Call `IdGenerator::Get` using model-name input | Imported call symbol, not runtime ID |
| `0x12108c` | Direct call `0x12d780` with model name and selector | Transformation semantics not recovered |
| `0x121098` | Call imported `createRequestModelExecuteEvent` | Concrete dynamic relocation target not re-proven |
| `0x1210a4` | Tail branch `View::requestApplicationExecute` | Queue consumer/dispatch remains unknown |
| `0x7f0b0c` | Separately indexed factory implementation *with matching symbol name* | Exact binding to imported PLT remains unknown |
| `0x7f0b1e` | Factory loads event ID `0x11004003` | Static event construction, not proof of delivery |
| `0x7f0b26` | Calls `Event` constructor with byte arguments 2 and 0 | No ABI/ownership proof |
| `0x7f0b2a–0x7f0b30` | Conditionally attaches incoming `ParamList` | Null guard observed, lifetime unknown |
| `0x7f0b44–0x7f0b48` | Adds wrapped name-ID parameter under key `7` | Recipient parsing not traced |
| `0x7f0b5c–0x7f0b60` | Adds wrapped transformed-selector parameter under key `8` | Not proven identical to caller's `0x0f01` |

The saved ARM instruction register sequence shows the caller preserving
the result of `IdGenerator::Get` and the result of the
`0x12d780` helper separately before calling the factory symbol.
The same-named factory candidate preserves those incoming values
separately, makes wrapped parameter objects, and adds them to the
event under IDs 7 and 8. This narrows the investigation from an
entirely opaque `requestModelExecute` implementation to a **concrete
event envelope creation and application submission boundary**.

During this update the connected read-only private workspace was
queried again at the two original saved disassembly regions. All
**35 of the 35** opcode-text expectations embedded in the
`fwplatform/event_envelope.py` report validator matched the
stored, address-annotated instruction lines. This is confirmation of
*saved text evidence*, **not a new read of every original ELF opcode**
and not proof that the program executes this path during startup.

To inspect the same source report without SQLite/device access:

```powershell
python -m fwplatform.cli sdk event-envelope --json
python -m fwplatform.cli sdk event-envelope --saved-disassembly C:\private\boot-static-analysis\model-camera-methods.txt --json
```

The no-source invocation returns `EVENT_ENVELOPE_CANDIDATE_ONLY`.
The saved source invocation audits exact imported symbol and PLT
callsite text, bounded register lineage and Event constructor,
optional ParamList and parameter key observations. It returns
`SAVED_STATIC_EVENT_ENVELOPE_TEXT_MATCH` only if every site agrees;
otherwise it fails closed. Tests use synthetic instruction text and
do not publish original firmware.

**Next high-value reverse-engineering targets**: recover the
`0x12d780` model+selector transformation, resolve the imported
factory/function identity through precise relocation evidence,
follow `View::requestApplicationExecute` to the consumer of
event `0x11004003`, determine the extraction of parameter keys
7/8 and translation into the ModelCamera selector/action, then
complete the independent ABI/return/error review. Until those steps
are proven, `requestModelExecute` is not a general-purpose verified
camera-control API and the core SDK is not complete.


## Phase 3.15: independently found two request-model frontend code paths

The preserved private `libObj.so` source investigation has another important
request path besides the earlier documented `ViewBase` wrapper:

| Caller (libObj ELF VMA) | model-ID import | selector helper | factory PLT | submission tail |
|---|---|---|---|---|
| `ViewBase::requestModelExecute` `0x12106e` | `0x121082 → 0xdffb8` | `0x12108c → 0x12d780` | `0x121098 → 0xdfbdc` | `0x1210a4 → 0xdb578` imported `View::requestApplicationExecute` |
| `viewManagerIf::requestModelExecute` `0x1250c0` | `0x1250d8 → 0xdffb8` | `0x1250e2 → 0x12d780` | `0x1250ee → 0xdfbdc` | `0x1250f6 → 0x125084` **unnamed local candidate** |

In the ARM register sequences for both callers, the ID generator result is
saved separately from the selector helper's result. Before the same named
factory import, the saved report moves the model ID into `r1`, the helper
output into `r2`, and `ParamList*` into `r3`. The receiver in `r0`
comes from different indirections: `this+0x7c` in the ViewBase wrapper
and a global-linked manager pointer in viewManagerIf. The evidence
**does not reveal the body of `0x12d780`** and **does not equate the
runtime event destination of `0x125084` with the imported View method**.
In particular, two callers of the same helper cannot establish the
selector's transformed numeric value or the real ABI.

The saved `model-camera-methods.txt` first 58 lines were directly read
from the connected private research workspace. The public validator's
instruction expectations were checked **33/33 against saved disassembly
text**, not against an independently read fresh Sony ELF.

The bounded, read-only fixture `sdk/camera_3_21_model_request_frontends.json`
and `fwplatform/model_request_frontends.py` implement:

```powershell
python -m fwplatform.cli sdk request-frontends --json
python -m fwplatform.cli sdk request-frontends --saved-disassembly C:\private\boot-static-analysis\model-camera-methods.txt --event-envelope sdk/camera_3_21_model_execute_envelope.json --json
```

The second command checks exact named region boundaries, first and second
call sites, symbol annotations, register provenance, and **different
submission tail targets**. It refuses to promote undocumented selector,
loader relocation, event consumption or calling-convention claims.
Tests exercise swapped registers, changed PLT targets, duplicate entries,
incorrect ELF SHA and no-SQLite behavior using artificial text.

This resolves an additional, repeated **event creation envelope upstream
dependency**. The immediate next target is the code body of
`0x12d780`, plus downstream local `0x125084`, App/Event delivery,
and the parser of Event keys 7/8. Until these are independently checked
there is no proven end-to-end UI→ModelCamera route or executable API.


## Phase 3.15 — shared helper between two request frontends; private scoped ELF decoder

The connected private research report contains **another distinct**
`libObj.so` request entry:

| Entry | Saved direct call | Reported target | Interpretation |
|---|---|---|---|
| `ViewBase::requestModelExecute` `0x12106e` | `0x12108c` | `0x12d780` | unknown selector/name helper |
| `viewManagerIf::requestModelExecute` `0x1250c0` | `0x1250e2` | `0x12d780` | the **same exact local helper target** |
| `ViewBase::requestModelExecute` | `0x121098` | `0xdfbdc` | named factory import stub |
| `viewManagerIf::requestModelExecute` | `0x1250ee` | `0xdfbdc` | the **same exact import stub target** |
| `ViewBase::requestModelExecute` | `0x1210a4` | `0xdb578` | named `View::requestApplicationExecute` tail |
| `viewManagerIf::requestModelExecute` | `0x1250f6` | `0x125084` | tail target **not yet semantically identified** |

Do **not** infer that the second frontend has the same original
`r0` source/meaning as the first; the static calling context is not
yet sufficiently established. The two routines do share a concrete
*callsite destination* for `0x12d780` and the factory stub, which
narrows where to focus the next static investigation.

`sdk event-envelope --saved-disassembly` now checks exact
function-entry annotation, branch/PLT target and register carry
observations from **both** request entry points and the candidate
factory. The connected workspace was read directly and **50/50**
selected saved instruction *text* positions matched the validator
(16 first frontend, 15 alternate frontend, 19 factory). These do
**not** constitute 50 verified APIs, a new Ghidra run, original
opcode-byte validation, or proof of event delivery.

The new `fw sdk trace-selector --elf <private-libObj.so>` utility
provides a bounded read-only Capstone analysis of the target
`0x12d780` and follow-on candidate `0x125084`. It:
- refuses a wrong full-file SHA-256 (pin:
  `8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`);
- requires a uniquely file-backed ELF32 LE ARM executable load
  segment for the starting target; does not execute firmware;
- bounds visited instructions, local branches and literal
  interpretations; does not recursively follow external calls;
- reports occurrences of the raw `0x11004003` word as unclassified
  bytes, **not** event consumer cross-references;
- leaves complete function CFG, helper semantics, ABI and physical
  runtime callability explicitly UNVERIFIED.

The connected read-file tool responds to raw `libObj.so` with
`BINARY_FILE` and does not expose its 17,436,172 bytes, so
**no new original Sony opcode analysis was run in this interaction**.
The local Capstone analyzer has synthetic ELF32 ARM regression
coverage and makes the precise next piece of real private-file
reverse-engineering reproducible without another whole-Ghidra run.


## Phase 3.18: typed request-bridge arguments and first ModelCamera internal argument shape

This phase prioritizes ABI reconstruction over additional broad
research inventory. The preserved `libObj.so` C++ Itanium
mangled symbols have reliable **explicit argument** types,
while normal return types and static-vs-instance method form
are not encoded. Saved ARM AAPCS32 register-flow observations
disambiguate method form:

| Entry | Explicit C++ arguments | Static evidence for physical argument mapping |
|---|---|---|
| `0x12106e` `ViewBase::requestModelExecute` | `char const*, unsigned long, ParamList*` | `r0=this`, `r1=name`, `r2=selector`, `r3=ParamList*`; `[r0+0x7c]` context load |
| `0x1250c0` `viewManagerIf::requestModelExecute` | same | **static-form candidate**: `r0=name`, `r1=selector`, `r2=ParamList*`; original `r3` overwritten with GOT/literal setup before use |
| `0x7f0b0c` `AbstractUtilityManager::createRequestModelExecuteEvent` | `int, unsigned long, ParamList*` | instance/context form: `r0=context`, `r1=model ID`, `r2=helper-transformed selector`, `r3=ParamList*` |

Both frontends pass the **original model name and selector**
to the **same** unknown helper `0x12d780`:
`ViewBase` moves original `r1,r2` into helper
`r0,r1`; `viewManagerIf` uses original `r0,r1`.
Their common factory stub at `0xdfbdc` receives the
helper's `r0` result as factory `r2`, the original
ParamList pointer as factory `r3`, and the
`IdGenerator::Get` result as factory `r1`.
This resolves an earlier superficial difference in caller
register identities without pretending the helper's
transformation algorithm has been recovered.

The candidate factory implementation at `0x7f0b0c`
allocates `0x10` bytes, constructs an `Event` in
the allocated memory, retains that pointer in `r4`,
and returns that same pointer in `r0` at
`0x7f0b64–66`. Thus `Event*` is a strong
**static return-object inference**, but not an
Itanium-declared return-type proof or verified ownership
and exception/error ABI. Return types for the other two
request entrypoints remain unknown.

Independently, a saved `viewUnified2.so` callsite at
ELF VMA `0x1a26e6` calls the named import with
`r1='model/CAMERA'`, `r2=0x0f01`
and candidate `ParamList*` in `r3`.
As before, that matches a source caller but does not
prove complete dynamic link resolution to ModelCamera.

**Closer to the real Camera core**, the un-mangled
`ActionGpSetSetting` research entry at
`0x4cfb9c` preserves entry `r0` in `r5`,
calls `0x13200a` and stores its returned `r0`
in `r4`, then calls `0x131fd2` to recover a
selector value. At `0x4cfe8a–0x4cfe98`
the dispatch checks `0x0f01` and invokes
`pvt_ActionSetInit=0x4cf7a8` with
**`r0=saved Camera object candidate`** and
**`r1=0x13200a return value`**.
The callee saves `r0→r4` and `r1→sl`,
later passes `sl` to `0x42abcc`,
then calls the previously identified EE-neutral
sender and `PrepChk` helpers.
This recovers an internal **two-argument register
shape**, but the actual second-argument C++ type,
return/error semantics and safe runtime call order
are not established. It is not yet a completed ABI.

The new read-only command validates these exact observations
against optional previous offline text reports:

```powershell
python -m fwplatform.cli sdk request-abi --json
python -m fwplatform.cli sdk request-abi --saved-libobj C:\private\boot-static-analysis\model-camera-methods.txt --saved-view C:\private\boot-static-analysis\view-boot-methods.txt --json
```

This command enforces encoded argument types, non-encoded
return type, per-ELF SHA metadata, strict entrypoint
and register-source matches, ModelCamera selector guard
and the external UI `0x0f01` callsite. Missing private
source reports produce a **candidate-only** status.
It does not load or execute original Sony ELF bytes,
commit Sony instruction bytes, claim an Event consumer
or mark any core Camera function callable.
 
## Phase 3.17: app status gate exact local Boolean semantics and semaphore wait leads

Private original-`libObj.so` saved static ARM report
`app-event-functions.txt` provides a useful refinement of
the Appframework event loop. In the labeled `app_event_wait_or_check`
scan, entry `0x7eaa14` loads `[r0+0xa4]` and executes a
nonzero-to-Boolean test, with `IT NE / MOVNE r0,#1` before return.
An adjacent, **not proven same-C++-function** region at
`0x7eaa68` also reads `+0xa4` and compares against
`0x50000`, `0x70000`, `0x40000` as candidate
state selection.

In the queue-state helper at `0x7eeec8`, the guard call
`0x7eeed0→0x7f29ec` short circuits to return 0
when its result is nonzero. Otherwise
`0x7eeed8→0x7eaa14` reads the status, then
`0x7eeedc EOR r0,#1` and `0x7eeee0 UXTB`
invert/normalize it. Hence, **on the unshort-circuited
path only**, status `+0xa4 == 0` yields queue result
1, while nonzero yields queue result 0. The app thread
at `0x7ef180` tests this returned queue result and
uses `0x7ef188 BEQ 0x7eeefa` for the zero/sleep
branch. Neither outcome proves physical Camera ready.

Existing separate saved secondary report
`app-status-wait-chain.json` says the following
three wrappers use semaphore ID `0x830451` with
indefinite wait argument `-1` and then call a helper:

| Reported wrapper | Helper after wait | Known static caller |
|---|---|---|
| `0x7f21e8` | `0x7f0aa0` | `0x7eecb6` |
| `0x7f2210` | `0x7f099c` | `0x7ef0c6` and `0x7ef15a` |
| `0x7f2238` | `0x7f0aac` | `0x10b144` |

Only `0x7f2210` was also reviewed through a saved
instruction-level source in previous phases. The other
two wait wrapper bodies and completion helpers **were
not just now disassembled from the primary ELF**.
That report also records the `0x7eb118`
ModelManager `+0xa4` setter with five candidate
state/callsite pairs: `0x7ec9b6→0x40000`,
`0x7ed038→0x30000`, `0x7ed1d2→0x70000`,
`0x7ed250→0x50000`, `0x7ed47c→0x40000`.
The exact object C++ ABI and one-to-one relationship to
Camera readiness have not been established.

The new `sdk app-sync` proof-preserving command separates
the two evidence tiers:

```powershell
python -m fwplatform.cli sdk app-sync --json
python -m fwplatform.cli sdk app-sync --saved-disassembly C:\private\boot-static-analysis\app-event-functions.txt --saved-status-chain C:\private\boot-static-analysis\app-status-wait-chain.json --json
```

The connected workspace's **saved disassembly text**
was reread: **18/18** narrowly specified instruction
locations matched the expected Boolean/inversion
and adjacent status comparison sites. This does
not mean any original `libObj.so` bytes were
redecoded in the current session. The saved secondary
JSON is independently available for checking the
semaphore graph, but its claims must not be promoted
to primary-ELF opcode proof. The command never executes
Sony firmware, writes SQLite or declares runtime-callable
Camera APIs.

There is still **no proven consumer of event
`0x11004003`**, nor evidence that event key 7/8
data reaches `ModelCamera::ActionGpSetSetting`.
The newly clarified Boolean guard is a *separate*
Appframework status-gate observation, not a substitute
for the missing event route. Avoid disabling
semaphores or altering `+0xa4` in any camera.
 
## Phase 3.16: Appframework loop boundary is now source-scoped (event consumer still unresolved)

Connected private source `app-event-functions.txt` (saved static
`libObj.so` ARM/Thumb instruction text) and
`libobj-appframework-chain.json` include an **independent**
Appframework loop/queue candidate. It is a follow-up investigation
target for the `0x11004003` Event factory, not proof that the event is
handled here.

Six separately named source instruction regions now observed:

| Saved named region | ELF VMA | Narrow observable effect |
|---|---|---|
| application_thread_body | `0x7eeee8` | checks queue state `0x7ef180→0x7eeec8`; directly calls dispatch candidate at `0x7ef0d4` and `0x7ef16e` |
| app_event_pop | `0x7eec8c` | invokes count-like EventManager import from queue field `+0x10` |
| app_event_dispatch | `0x7eecac` | passes object pointer loaded at `+0x18` onward via direct tail `0x7eecb6→0x7f21e8` |
| app_event_cleanup | `0x7eecbc` | direct call at `0x7eecec→0x7eecac`, conditional further processing |
| app_event_queue_receive | `0x7eeec8` | upstream guarded checks at `0x7eeed0→0x7f29ec` and `0x7eeed8→0x7eaa14` |
| application_event_candidate | `0x7f2210` | semaphore `0x830451` around internal helper `0x7f099c` |

**Source overlap correction:** the earlier `app-event-functions.txt`
report includes overlapping bounded scans of `app_event_pop`,
`app_event_dispatch`, and `app_event_cleanup`. The instructions
around `0x7eecac` may recur in more than one scan window; that is
not evidence of distinct runtime function executions or a whole CFG.
The new `fwplatform/app_event_loop.py` validator demands each
explicit `FUNCTION name address` header and checks its own
instruction sites instead of treating scan overlap as proof.

I re-read the saved original-firmware *text* report through the
connected workspace and verified that **26/26 specified instruction
locations match under their six named source headings**. This
rechecks preexisting instruction *text*, not the Sony ELF primary
instruction bytes. The connector currently declines to expose the
original 17.4 MB `libObj.so` as binary data, and no live Ghidra
session or camera event trace was run in this phase.

```powershell
python -m fwplatform.cli sdk event-loop --json
python -m fwplatform.cli sdk event-loop --saved-disassembly C:\private\boot-static-analysis\app-event-functions.txt --json
```

Without `--saved-disassembly`, the CLI marks the output
`APP_EVENT_LOOP_BOUNDARY_CANDIDATES_ONLY` and verifies no opcode
sites. With saved source it checks the six named entry ranges and
returns `SAVED_APP_EVENT_LOOP_TEXT_MATCH_EVENT_CONSUMER_UNPROVEN`.
CI uses synthetic saved instruction samples; there is no proprietary
Sony ELF or decompiled source in the repository.

**Outstanding crucial edges:** the imported `View::requestApplicationExecute`
and alternate viewManagerIf tail cannot yet be connected to this
specific event queue; the `0x11004003` Event's actual consumer
has not been found. The downstream `0x7f21e8` path, key 7/8
extraction, `0x12d780` selector transform and ModelCamera dispatcher
still require private primary-ELF byte/code analysis. Queue presence
is not a verified Camera API or evidence that Camera initialization
waits on this semaphore.
