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
