# Codex Handoff — Sony A6000 Firmware 3.21 Core SDK

## Purpose

## Current continuation checkpoint (2026-10-09)

The latest private ELF caller pass adds `fwplatform/param_factory_probe.py` and
`fw sdk parameter-factory --elf <private-libObj.so>`.  It revalidates the pinned
SHA and confirms four factory callsites (`0x4cf9be`, `0x60ece0`, `0x66d574`,
`0x682a88`) prepare dynamic `r1/r2` values, guard the factory result for null,
and reach PLT `0xdfdc0` on their success paths.  Exact relocation resolution
identifies that PLT as `_ZN9ParamList3addEmP9ParamBase` (GOT `0x102e340`, local
Thumb symbol `0x7ee0e7`, 48-byte body at `0x7ee0e6`).  The local add body calls
replacement helper `0x7ededa`, sets the new object's key via `0x7eda84`, and
inserts through `0x7ee0b8`; equal key/discriminator replacement dispatches the
old element's virtual deletion slot.  Dynamic table values, ownership transfer,
exception behavior, locks and runtime callability remain unknown.  The
descriptive contract has 14 interfaces and still grants zero callable or
runtime-verified APIs.  `ParamListTargets.java` now includes the add and
storage/replacement bodies for the next private Ghidra cross-check.

The latest mutation checkpoint adds `fwplatform/paramlist_mutation_probe.py` and
`fw sdk parameter-mutation --elf <private-libObj.so>`. It verifies the clear
wrapper `0x7edb76` -> `0x7edb40`, element virtual deletion slot `+8`, destructor
counter decrement/zero cleanup at `0x7edd08`, and the unnamed assignment-like
share operation at `0x7edcc6`. Destructor delete PLT `0xdd620` resolves to
`_ZdlPv` through GOT `0x102d6bc`. The assignment body has no detach path in
the observed region; source-level identity, allocator/exception semantics,
thread safety and runtime callability remain unknown. The private targeted
Ghidra rerun exits 0 with 21 targets, 343 instruction rows, 79 blocks and 135
edges. The descriptive contract now has 17 interfaces; callable/runtime count
remains zero. The latest full public synthetic suite passes 263 tests.

The next primary-ELF checkpoint adds `fwplatform/param_numberlist_probe.py`
and `fw sdk parameter-numberlist --elf <private-libObj.so>`. It validates nine
PrmNumberList regions: indexed uint32 access, length, append/capacity branch,
default/copy construction and both destruction paths. The result is a
descriptive `sdk/param_numberlist_3_21.json`; runtime/callable counts remain
zero and vector allocator, bounds, synchronization and exception behavior are
unknown.
The latest full public synthetic suite passes 238 tests after the NumberList
probe fixtures were added.

The next checkpoint adds `fwplatform/param_cntinfolist_probe.py` and
`fw sdk parameter-cntinfolist --elf <private-libObj.so>`. Twelve primary-ELF
regions cover discriminator initialization, dual collection get/set/append,
constructors and destruction. The contract is descriptive only; collection
element types, bounds, allocator, exception and synchronization behavior stay
UNKNOWN.
The full public synthetic suite now passes 242 tests after these fixtures.

The next primary-ELF checkpoint adds `fwplatform/camera_selector_probe.py`
and `fw sdk camera-selector --elf <private-libObj.so>`. It validates
`ELF_VMA 0x12d780`: the `[r0] == 0x40` branch calls the relocation-bound
`IdGenerator::Get`, maps second-byte `M`/`V` to bases `0x12000000`/`0x13000000`,
and calls `0x120168` with the model ID and original selector. The non-special
branch constructs temporaries, checks for a null prepared object and invokes
vtable slot `+8`; the null path returns `-1`. The transform, C++ identity,
return type, helper semantics and ModelCamera causality are UNKNOWN. Its
contract is `sdk/camera_3_21_selector_transform.json`; runtime and callable
claims remain false. `tests/test_camera_selector_probe.py` contains four
synthetic fail-closed checks.

The selector probe now also validates the local transform at `0x120168`:
after clearing the low 12 bits of `r2`, a non-zero result returns the original
`r2`; the aligned path returns `r2 + (r1 << 12) + r0`. This arithmetic and
register flow are primary-ELF static facts. The helper's C++ identity, return
type, selector domain and downstream ModelCamera causality remain UNKNOWN.

Latest continuation additionally resolves PrmNumber (discriminator 1, signed
32-bit payload) and PrmBool (discriminator 5, byte bool) using constructor,
RTTI/base relocation, vtable and named setters. See the report's current
derived-types checkpoint and `parameter_types_lifetime_3_21.json`.
Concrete slot +8 deleting paths bind operator delete; assignment-like sharing
and replacement deletion are confirmed. Borrowed pointers can be invalidated
by replacement even while another list retains the container. Runtime locks
remain unknown. Offline decoder checks vptr+tag with explicit load bias;
its guards are not Sony behavior. Next: map the ten concrete families to
verified ParamList construction/use sites, then resolve source-level assignment
identity, full mutation/COW and synchronization contracts.

Latest private-only continuation also recovered three additional ParamBase
families using `fwplatform/param_family_probe.py` and the SHA-pinned ELF:
`PrmNumberList` (tag 10, RTTI `0xfe7ed8`, object-size witness `0x18`,
embedded vector words at `+0x0c`), `PrmCntInfoList` (tag 9, RTTI `0xfeb5a4`,
object-size witness `0x5c`, collection regions at `+0x0c` and `+0x34`), and
`PrmObjMsg` (tag 8, local RTTI/vtable `0xfec488`/`0xfec498`, object-size
witness `0x10`, incoming `MWF::ObjMsg*` stored at `+0x0c`). Their vtable clone
and deleting-destructor slots are recorded in
`sdk/parameter_types_lifetime_3_21.json`; these remain descriptive static
layouts, with pointer ownership, allocator behavior and runtime callability
UNKNOWN. The probe emits metadata only and publishes no firmware bytes.

The follow-up RTTI/vtable discovery now finds ten direct ParamBase-derived
records in the same ELF. It adds static constructor/layout witnesses for
`PrmString` (tag 2), `PrmPoint` (tag 3), `PrmDimension` (tag 4), `PrmStruct`
(tag 6), and `PrmSet` (tag 7). These include object-size witnesses and
destructor slots, while string/helper ownership, semantic field types and
runtime ABI remain UNKNOWN. `PrmNumber` and `PrmBool` remain the only payload
semantics decoded beyond raw layout.

The old missing-primary-byte blocker below is historical and superseded.
Read `reports/CORE_PRIMARY_HELPER_AUDIT.md` and the current helper contracts.
Authenticated private libObj.so has been read with Capstone. ParamList::get
at ELF VMA 0x7edaca (Thumb-tagged symbol 0x7edacb, size 76) now has primary
loop/return evidence and a successful ASCII-path Ghidra run (exit 0).
It returns the first existing element matching words +4 and +8, or null.
The +0x0c payload word remains concretely untyped. ParamList destructor uses
a shared counter and element vptr +8 dispatch; borrowed-result semantics are
STATIC_INFERRED, not runtime validated. See `fwplatform/paramlist_snapshot.py`
for the strictly offline snapshot reader and `sdk/paramlist_3_21_candidate.hpp`
for candidate declarations. Next: resolve concrete family usage sites,
mutations/copy-on-write and payload type mapping beyond Number/Bool.
The latest ASCII-path lifecycle export completed with exit 0 for 22 bounded
targets (including the Point deleting destructor at 0xff904), 342 instruction
rows, 43 basic blocks and 72 CFG edges; its raw output remains private.
The next private primary checkpoint recovered the local factory candidate at
0x42acd4. Its explicit discriminator branches construct Bool (5, 0xe50e8),
Number (1, 0xf0fb0) and Point (3, 0xffa3c) with allocation sizes 0x10, 0x10
and 0x14. Unsupported or failed source lookups return null. Four direct
callers were identified at 0x4cf9be, 0x60ece0, 0x66d574 and 0x682a88;
source-level name, ownership and helper semantics remain unknown. The
descriptive contract is in `sdk/core_3_21_primary_helper_contracts.json`.
The private metadata-only Ghidra xref export completed exit 0 with 25 target
records and 2,290 xrefs; its four factory callsites were retained as address
metadata only.
The helper chain is now bounded as well: `0x120970` fixes lookup discriminator
5 and `0x120968` loads `+0x0c`; `0xfe9be` fixes discriminator 3 and
`0xfe9ae`/`0xfe9b6` load `+0x0c`/`+0x10`. The private Ghidra core export
completed exit 0 for 16 targets, 198 instruction rows, 46 blocks and 73
edges. Coordinate semantics, source-level names and ownership remain unknown.
Callable/runtime-verified core API count remains zero. Private raw exports and
Ghidra projects are outside this public checkout.

Continue static reverse engineering of the Sony ILCE-6000 (A6000)
firmware 3.21 **core Camera SDK** in PR #1. This repository contains
the public-safe, evidence-gated analysis tooling and SDK candidate
fixtures built during previous ChatGPT sessions. This document
preserves the *material technical state* for Codex; it is **not**
a full transcript of ChatGPT messages or a substitute for the
original private firmware.

- Repository: `ice21415/a6000-firmware-platform`
- Working branch: `phase3/semantic-analysis`
- PR: <https://github.com/ice21415/a6000-firmware-platform/pull/1>
- Project Skill: `.agents/skills/a6000-core-abi/SKILL.md`
- Firmware ELF: `libObj.so`, 17,436,172 bytes; full-file SHA-256
  `8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`
- Core Camera APIs with full ABI and runtime callability verified: **0**
- PR / CI must remain evidence-based. Last reviewed state
  before this handoff had GitHub push+PR tests passing on 3.11 and 3.12.

## What actually exists

### Static evidence and tools

- `sdk/camera_3_21_request_abi_leads.json`,
  `fwplatform/request_abi.py`: original ARM AAPCS32 register-shape
  inferences for two `requestModelExecute` call entrypoints and the
  Event factory. Itanium mangling identifies three *explicit argument*
  types (`char const*, unsigned long, ParamList*`) but does not prove
  static/instance form or declared return type without register evidence.
- `ViewBase::requestModelExecute=0x12106e` appears instance-form
  `r0=this, r1=model name, r2=selector, r3=ParamList*`.
  `viewManagerIf::requestModelExecute=0x1250c0` appears static-form
  `r0=name, r1=selector, r2=ParamList*`; both feed unknown selector
  transform `0x12d780` and event factory PLT `0xdfbdc`.
- `AbstractUtilityManager::createRequestModelExecuteEvent=0x7f0b0c`
  constructs an Event with ID `0x11004003`. Its pointer-like return
  is inferred from allocation/constructor/r0 flow; declared C++
  return/lifetime/error semantics are NOT fully verified. The event
  consumer/ModelCamera binding is still unresolved.
- `viewUnified2.so` saved callsite `0x1a26e6` uses model/CAMERA
  selector `0x0f01`; a `ModelCamera::ActionGpSetSetting=0x4cfb9c`
  selector branch calls `pvt_ActionSetInit=0x4cf7a8` at `0x4cfe98`.
  Treat the cross-ELF/event-dispatch connection as a candidate,
  NOT a verified end-to-end runtime chain.
- `sdk/camera_3_21_action_payload_leads.json`,
  `fwplatform/action_payload_abi.py`: several action callers use
  `0x13200a` as an *opaque payload getter*; results are passed
  to wrapper `0x42abcc`. The result's declared C++ type is UNKNOWN,
  even though some consumers have `Invalid ParamList` branches.
- `sdk/camera_3_21_param_lookup_abi.json`,
  `fwplatform/param_lookup_abi.py`: `0x42ac00` sampled caller
  register roles appear `r0=local payload view`, `r1=parameter ID`,
  `r2=output address`, with zero-result branches accepting output.
  `r3`, exact C++ types and error contract are UNKNOWN.
  Nearby `0x42abdc` is a distinct unverified EasyMode lookup target.
- `fwplatform/private_thumb_research.py`,
  `fwplatform/core_abi_probe.py`: SHA-locked read-only ELF32 ARM
  Thumb probes, bounded CFG/call/literal/return and memory-operand
  observations, visited-byte fingerprints; output is *not* a
  completed function/type proof.
- `tests/test_core_abi_probe.py` and related ABI tests use
  *synthetic ELF and synthetic saved instructions*, not Sony bytes.
  Prior stored instruction-text matches are secondary evidence only.
- SDK / research docs: `sdk/README.md`, `ROADMAP.md`,
  `reports/CORE_CAMERA_API_INVESTIGATION.md` and PR timeline comments.

### Historical blocker (resolved locally; retained for provenance)

The ChatGPT-connected `a6000` Codex workspace can search/read **text**
and reports, but its `read_file` interface returned `BINARY_FILE`
when asked for the actual `libObj.so`. The original ELF is present
under a private firmware tree but **its machine bytes have not been
returned to ChatGPT**, so no exact primary-opcode reconstruction of
`0x13200a` or `0x42ac00` has yet happened in the ChatGPT sessions.

No Skill can bypass missing ELF read/terminal access. Codex must run
in an environment that has permission to read the private binary
and execute local analysis tools. If that is not available, say so
and avoid repeating saved caller evidence as a new breakthrough.

## Immediate Codex execution plan

1. Ensure this branch and `a6000-core-abi` Skill are present.
   Inspect git status; do not overwrite local uncommitted work.
2. Resolve the existing authorized private original `libObj.so`
   path. Verify full-file SHA against the hash above.
   Keep ELF and firmware-derived detailed output outside the
   public repository. Never put the binary, Ghidra project or
   raw opcode export into the public PR.
3. From the repository root on the local machine, run:

   ```powershell
   python -m fwplatform.cli sdk probe-core-abi --elf "C:\private\firmware\libObj.so" --json > "C:\private\core-abi-evidence.json"
   ```

   Defaults to **`0x13200a` and `0x42ac00`**.
   The private exact path is illustrative and must be replaced
   by the path verified on the local host.
4. Audit observed return paths, arguments actually dereferenced,
   whether `0x42ac00` writes through input `r2`,
   the status return use, any `r3` reads and branches.
   If needed, run additional bounded reads for `0x42abcc`
   and `0x42abdc`, or use the existing
   `tools/run-ghidra-headless.ps1` /
   `ghidra-scripts/AnalyzeBinary.java` in a local private
   Ghidra project.
5. Produce a short evidence table per target:
   verified raw ELF SHA; exact VMA; input registers;
   memory reads/writes; return path; object lifetime;
   `PRIMARY_ELF_VERIFIED / SAVED_TEXT_ONLY / UNVERIFIED`.
   Do not call a function 'ABI complete' without types and
   return/error/lifetime context. Do not claim device-callable APIs
   from offline disassembly alone.
6. Add focused code and synthetic tests. Run:
   `python -m unittest discover -s tests -v`.
   Commit and push to `phase3/semantic-analysis`, then
   check GitHub Actions CI on PR #1. Never merge to main
   without user instruction.

## Continuation instruction for Codex chat

> Use the project Skill `a6000-core-abi` and this
> `CODEX_HANDOFF.md`. Continue the existing A6000 3.21
> core API reverse engineering without rediscovering prior work.
> Start with the exact SHA-pinned private `libObj.so`
> and `0x13200a` / `0x42ac00` function bodies.
> Prioritize primary ELF opcode evidence and a genuinely
> verified ABI; no more broad callsite reports or guessed
> 'completed' APIs. Keep Sony binary private. Add tests and
> continue PR #1. Report blockers honestly.

## Security and evidence

This is a non-invasive static research project; do not provide
or run hardware flashing, bypass, exploitation or destructive
operations. Keep private binaries and trace exports private.
The handoff copies only technical context and file references
from previous chats; it does NOT automatically sync private
ChatGPT conversation transcripts or private file contents.

The next ParamBase family checkpoint adds `fwplatform/param_objmsg_probe.py`
and `fw sdk parameter-objmsg --elf <private-libObj.so>`. Five bounded
primary-ELF regions validate `PrmObjMsg` discriminator `8`, the constructor's
`MWF::ObjMsg*` candidate store at `+0x0c`, the getter, non-null destruction
release and clone candidate. Pointee layout, ownership, allocator pairing,
exception behavior and clone C++ identity remain UNKNOWN; runtime and callable
claims remain false. The descriptive contract is
`sdk/param_objmsg_3_21.json`, with four synthetic fail-closed tests.

The next Camera checkpoint adds `fwplatform/camera_prepare_envelope_probe.py`
and `fw sdk camera-prepare-envelope --elf <private-libObj.so>`. It validates
the bounded `0x125084` path: 16-byte allocation, direct `0xf0fb0` call with
`r1=0`, key `6` and the unique `Event::addParameter` PLT binding at `0xdd194`.
The tail branch `0x7f25e0`, receiver identity, event delivery/completion and
complete constructor ABI remain UNKNOWN; runtime and callable claims stay
false. The descriptive contract is
`sdk/camera_3_21_prepare_envelope.json`.

The `camera_prepare_envelope` probe now follows its tail helper `0x7f25e0`:
that helper sets `r2=1`, loads receiver `+0x10`, and branches to `0xdf270`,
whose unique PLT relocation names `EventManager::push(Event*,bool)`. This is
static symbol/dispatch evidence only; runtime binding, receiver identity,
event delivery/completion and complete C++ signature remain UNKNOWN.

The next Event checkpoint adds `fwplatform/event_manager_push_probe.py` and
`fw sdk event-manager-push --elf <private-libObj.so>`. It validates the actual
symbol-bound implementation at `0x7ef960` (156 bytes): AAPCS32 candidates
`r0=this`, `r1=Event*`, `r2=bool`, status branch via `0x7ef88c`, dispatch via
`[this+8]`, optional completion via `[this+4]`, and visible zero returns.
Indirect targets, helper semantics, queue/thread behavior, ownership and
runtime/callable status remain UNKNOWN. Contract:
`sdk/event_manager_push_3_21.json`.

The `event-manager-init` checkpoint adds a bounded primary-ELF probe for
`0x7ef894` and contract `sdk/event_manager_init_3_21.json`. It verifies the
incoming callback candidate at receiver `+0x04`, mutex initialization at
`+0x0c`, provider vtable `+0x30` result at `+0x08`, and `_Znaj`/`_Znwj`
allocations for two eight-byte state words. This is a layout-compatible
`STATIC_INFERRED` relation to `EventManager::push`, not proof of constructor
identity. Helper `0x7f09be`, ownership, full destruction, exception behavior,
runtime binding, runtime verification and callability remain UNKNOWN/false.
Four synthetic fail-closed tests cover identity, binding and non-callable
metadata. The private ELF remains outside the public repository.

Ghidra cross-check for the initializer used the ASCII Ghidra 12.1.3 install
with a private `-noanalysis` target profile. It exited 0 and produced one
bounded target: image base `0x10000`, mapped program address `0x7ff894` for
`ELF_VMA 0x7ef894`, body `[[0x7ff894,0x7ff8e1]]`, 27 matching instruction
boundaries and six call edges. The decompiler retains undefined parameter
types, so it does not prove C++ class identity or callability. A separate
full Auto Analysis attempt was stopped before completion and is recorded as
INCOMPLETE, not successful.

The request-model Event factory checkpoint adds
`fwplatform/camera_request_event_probe.py`, contract
`sdk/camera_request_event_3_21.json`, and CLI command
`fw sdk request-event-factory`. The SHA-pinned primary ELF symbol at
`0x7f0b0c` supplies explicit `int`, `unsigned long` and `ParamList*`
arguments after the receiver. The body constructs event `0x11004003`,
conditionally attaches ParamList, and adds model/selector PrmNumber
candidates under keys 7 and 8. This is static evidence only; Event return
type, ownership, consumer delivery, exception semantics, runtime binding and
callability remain unknown/false. A private ASCII Ghidra targeted run exited
0 and reproduced 36 instructions and 12 edges. Four synthetic fail-closed
tests cover identity, event ID, binding and non-callable metadata.

The Event core checkpoint adds `fwplatform/event_core_probe.py`,
`sdk/event_core_3_21.json`, and `fw sdk event-core`. It verifies Event object
fields, shared counter copy/destructor behavior, ParamList initialization and
replacement branches, plus add/get forwarding to the existing ParamList
symbols. `setParamList` may invalidate aliases when replacing a pointer;
caller synchronization and ownership context remain unknown. Private Ghidra
cross-check: exit 0, 77 instructions, 24 edges, 15 blocks. Four synthetic
fail-closed tests cover identity, bindings and non-callable metadata.

## Latest checkpoint: PrmSet embedded payload (2026-10-10)

`fwplatform/param_set_probe.py` and `sdk/param_set_3_21.json` add a
SHA-pinned private-ELF probe for the discriminator-7 `PrmSet` family. It
confirms `getSet` returns the interior address `this+0x0c`, the GET wrapper
uses discriminator 7, the constructor allocates 36 bytes and initializes an
embedded 24-byte payload, and the clone/destructor paths copy/release that
payload. Relative payload fields +0x04, +0x08 and +0x14 are zeroed; +0x0c and
+0x10 are self-linked sentinels; relative +0x00 remains UNKNOWN. The payload
is intentionally called ordered-container-like, not `std::set`.

The private ASCII Ghidra 12.1.3 `param-set` profile exited 0 with 13 bounded
targets, 161 instruction rows, 17 blocks and 33 CFG edges. Source-level
container type, element/comparator/allocator ABI, alias invalidation,
exception paths, synchronization, runtime binding and callability remain
UNKNOWN. Runtime-verified/callable SDK counts remain zero. Raw ELF, Ghidra
project and instruction export remain private.

The four new synthetic PrmSet validator tests and the complete local suite
(275 tests) pass; this does not change the runtime-verified/callable count of
zero.

## Latest checkpoint: PrmPoint / PrmDimension inline words (2026-10-10)

`fwplatform/param_pair_probe.py` and `sdk/param_pair_3_21.json` add a reusable
SHA-pinned profile for `PrmPoint` (discriminator 3, vtable 0xfe9610) and
`PrmDimension` (discriminator 4, vtable 0xfe6e48). Both constructors take two
word candidates in r1/r2, store them at object +0x0c/+0x10, initialize the
vptr and allocate 0x14-byte objects through their clone paths. Destructors
call ParamBase destruction; Dimension's deleting wrapper resolves its named
D1 PLT separately from Point's direct call.

No coordinate, size, unit, hardware, exception, synchronization, runtime or
callable claim is made. Private Ghidra cross-check: 8 targets, 96 instructions,
8 blocks, 12 edges, exit 0. The full public test count is updated by the next
checkpoint after this change; raw firmware and Ghidra exports remain private.

After the pair-family checkpoint, the complete local suite passes 279 tests; runtime-verified and callable counts remain zero.

## Phase 3.30 — PrmString payload ownership evidence

`fwplatform/param_string_probe.py`, `sdk/param_string_3_21.json` and
`fw sdk parameter-string` add a SHA-pinned bounded probe for the discriminator-2
PrmString candidate. Primary ELF evidence confirms the vtable/RTTI slots, a
16-byte object, `strlen`/`new[]`/`strncpy` construction, conditional `delete[]`
destruction and clone allocation. The payload is only an owned byte-buffer
candidate; encoding, invalid-input behavior, exception/allocator semantics,
aliasing, synchronization, runtime binding and source-level return type remain
UNKNOWN. Runtime-verified and callable counts remain zero.

Private ASCII Ghidra 12.1.3 targeted output exited 0 with 4 targets, 60
instructions, 6 blocks and 14 edges. Five synthetic validator tests were
added; no firmware bytes or private analysis exports were committed.
The complete local suite now passes 283 tests; runtime-verified and callable
counts remain zero.

## Phase 3.31 — PrmStruct pointer/length payload evidence

`fwplatform/param_struct_probe.py`, `sdk/param_struct_3_21.json` and
`fw sdk parameter-struct` add a SHA-pinned bounded probe for the discriminator-6
PrmStruct candidate. Primary ELF evidence confirms the vtable/RTTI slots, a
20-byte object, `malloc`/`memcpy` construction of a pointer-plus-length
payload, `free` destruction, the deleting wrapper and clone allocation.
Nested schema/type, serialization, invalid-input, allocator/exception,
aliasing, synchronization, runtime binding and source-level return type remain
UNKNOWN. Runtime-verified and callable counts remain zero.

Private ASCII Ghidra 12.1.3 targeted output exited 0 with 4 targets, 54
instructions, 4 blocks and 9 edges. Five synthetic validator tests were
added; no firmware bytes or private analysis exports were committed.

## Phase 3.32 — PrmCntInfoList collection growth evidence

The SHA-pinned private probe now covers the CntInfoList indexing helper at
`0x11d47e`, length forwarding at `0xe77a2`, full-capacity append at `0x11d8b0`,
and the 32-bit word copy helper at `0xecd7a`. These observations support
only a word-width candidate and two 0x28-byte collection regions; the C++
container, allocator, bounds, exception and synchronization contracts remain
unknown. The targeted private Ghidra profile exited 0 with 18 targets, 237
instruction rows, 22 blocks and 47 CFG edges. Runtime-verified and callable
SDK counts remain zero.
The CntInfoList lifecycle extension now includes clone target `0x11da18` and
the deleting destructor target `0x11d590`; both remain static-only and
non-callable. The current targeted Ghidra run is 18 targets, 237 instructions,
22 blocks and 47 edges, exit 0.

## Phase 3.33 — PrmCntInfoList removal evidence

The private-only CntInfoList probe now includes `remove(unsigned)` at `0x11d82e`,
its local rebuild helper `0x11d72a`, the four-word copy wrapper `0x11d468`, and
the drop-first helper `0xe7e86`. The evidence shows temporary reconstruction
and word-width front removal; it does not establish bounds, ownership, alias
or concurrency behavior. Targeted Ghidra exited 0 with 22 targets, 384
instructions, 38 blocks and 96 edges. Runtime/callable counts remain zero.

## Current continuation checkpoint (2026-10-10) — PrmObjMsg ABI/lifetime

The latest private SHA-pinned pass extends `fwplatform/param_objmsg_probe.py`.
It validates RTTI `0xfec488` (`9PrmObjMsg`), vtable prefix `0xfec498` and
address point `0xfec4a0`, and the direct `_ZTI9ParamBase` relocation at RTTI
`+0x08`, plus the five existing bounded bodies. Unique static
PLT resolution changes the interpretation of the clone/destructor path:
`0xddd94` is `_ZN3MWF6ObjMsgD1Ev`, `0xddee4` is
`_ZNK9PrmObjMsg18getParamTypeObjMsgEv`, `0xe0388` is
`_ZN3MWF6ObjMsgC1ERKS0_`, `0xe2080` is the PrmObjMsg constructor, and
`0xdd620` is `_ZdlPv`. The clone therefore has a primary-ELF deep-copy
candidate: getter -> 8-byte allocation -> ObjMsg copy constructor -> 16-byte
PrmObjMsg allocation/constructor. This is static evidence only; ownership
transfer, exception/allocator behavior, concurrency, runtime binding and
callability remain unknown/false.

Targeted ASCII Ghidra 12.1.3 `-noanalysis` profile `param-objmsg` exited 0:
5 target bodies, 62 instruction rows, 7 blocks and 14 edges. The public
contract is `sdk/param_objmsg_3_21.json`; raw ELF/Ghidra output stays private.
The synthetic ObjMsg validator now has six fail-closed tests. Continue next by
mapping verified ParamBase construction sites and source-level ownership uses;
do not treat the destructor sequence as proof that arbitrary external pointers
are safe to pass.

## Current continuation checkpoint (2026-10-10) — PrmObjMsg usage xrefs

`ghidra-scripts/ParamObjMsgUsage.java` is a metadata-only private Ghidra
profile. On the existing SHA-pinned `libObj.so` project it exited 0 with
language `ARM:LE:32:v8` and eight xrefs. The only internal PrmObjMsg payload
family callsites observed were in clone entry `0x12c784`: constructor PLT
`0xe2080` at `0x12c7a6`, getter PLT `0xddee4` at `0x12c788`, and ObjMsg copy
constructor PLT `0xe0388` at `0x12c798`; destructor entry `0x12c700` calls
ObjMsg D1 PLT `0xddd94` at `0x12c718`. The local constructor has external/data
references but no additional internal caller in this targeted export.

This is targeted Ghidra xref metadata (`STATIC_INFERRED`), not an exhaustive
whole-firmware call graph. Generated labels are not semantic names, and the
result does not prove that arbitrary external pointers are safely transferable.
The normalized usage observations are recorded in
`sdk/param_objmsg_3_21.json`; raw output remains private.

## Current continuation checkpoint (2026-10-10) — ParamBase family usage index

`ghidra-scripts/ParamFamilyUsage.java` now indexes constructor-target
references for all ten ParamBase family records. Its symbol lookup uses the
Ghidra 12.1.3 `List<Symbol>` API, and the export includes the program SHA,
language, image base, address-space metadata, completion marker, reference
kind, callsite and caller entry. `fwplatform/param_family_usage.py` provides a
strict parser, public count summarizer and fail-closed validator; the read-only
CLI view is `fw sdk parameter-family-usage`.

The xref export keeps `FROM_ELF_VMA`/`FROM_GHIDRA` and caller-entry addresses
separate and records the Ghidra address space. This prevents the `0x10000`
Ghidra image base from being silently mixed into the original ELF VMA.

The private ASCII Ghidra project used `ARM:LE:32:v8`, image base `0x10000` and
a 300-second Auto Analysis bound. Auto Analysis timed out; the post-script
still completed with exit 0. The resulting public contract
`sdk/parameter_family_usage_3_21.json` therefore records
`analysis_status=PARTIAL_TIMEOUT`, ten target records and 858 observed xrefs,
not exhaustive usage. Counts are: PrmBool 95, PrmNumber 628, PrmString 21,
PrmPoint 10, PrmDimension 13, PrmStruct 82, PrmSet 0, PrmNumberList 3,
PrmCntInfoList 3 and PrmObjMsg 3. The three symbol-resolved records each have
one computed call plus external/data references. `PrmSet`'s zero is a coverage
gap, not an unused proof. Runtime verification and callable SDK counts remain
zero; generated labels, ownership, locking and source-level caller types are
not promoted.

## Current continuation checkpoint (2026-10-10) — constructor argument provenance

`fwplatform/param_family_callsite_probe.py` performs a SHA-pinned, bounded
Capstone Thumb check over five direct constructor callsites selected from the
private Ghidra xref export. `sdk/param_family_callsites_3_21.json` records
verified branch targets and nearest `_Znwj` size witnesses (0x10 for Bool,
Number and String; 0x14 for Point and Struct), plus only the visible AAPCS32
register definitions. Point's two signed-halfword loads and Struct's
pointer-plus-length candidate are preserved as memory-source observations; the
Bool and Struct post-dispatch key values are candidates tied to their specific
callsite, not a global key rule. Register values after allocator calls are
reset to UNKNOWN. Runtime, ownership, locking and callable status remain false.

## Current continuation checkpoint (2026-10-10) — ParamBase foundation

`fwplatform/param_base_probe.py` and `sdk/param_base_3_21.json` now record the
base RTTI/vtable and bounded constructor/destructor evidence from the exact
SHA-pinned ELF. The base vtable prefix is `0xfe6e30` with address point
`0xfe6e38`; clone slot `+8` is an ELF relocation to `__cxa_pure_virtual`, and
the base destructor slots resolve to `0xe4734`/`0xe4854`. The base constructor
at `0xe50b4` stores the discriminator candidate at `+0x04` and the base vptr
at `+0x00`, with no bounded store to key `+0x08` or payload `+0x0c`. The key
setter remains the separate `0x7eda84` witness.

The probe independently discovers ten direct RTTI `+0x08` relocations to
`_ZTI9ParamBase`. A private Ghidra 12.1.3 `ParamBaseTargets.java` targeted
`-noanalysis` run exited 0 with four targets, 31 instruction rows, four blocks
and two CFG edges. These are static facts only; source-level ownership,
exception behavior, locking, runtime binding and callable SDK status remain
unknown/false. Seven synthetic validator tests were added and the complete
local suite now passes 318 tests.

## Current continuation checkpoint (2026-10-10) — PrmSet tree payload

The exact SHA-pinned primary ELF was re-read with Capstone and cross-checked
using the private ASCII-path Ghidra 12.1.3 `ParamListTargets.java param-set`
profile. The public probe and SDK metadata now cover the bounded PrmSet tree
helper family without publishing bytes or decompiler output.

Direct primary-ELF facts:

- `0x7efb00` calls `ParamBaseC2` with discriminator `7`, installs the derived
  vtable address point at object `+0x00`, advances to object `+0x0c`, and calls
  the payload default initializer. It does not write key `+0x08` in the
  bounded body.
- `0xffcf6`/`0xffce4` zero payload fields `+0x04..+0x13`, clear `+0x14`, and
  self-link the header fields `+0x0c` and `+0x10` to payload `+0x04`.
- `0xffe1c` multiplies a count by `0x14`; `0xffe4c` writes/copies a node
  value beginning at `node+0x10`; `0xffe70` calls the uniquely relocated
  libstdc++ `_Rb_tree_insert_and_rebalance` PLT and increments `[tree+0x14]`.
- `0x63e83a` has a self-copy guard and copies the source node count from
  `+0x14`; `0xffd80` is a direct recursive node-release helper reached from
  the PrmSet payload destruction path.
- PLT/GOT relocation bindings for `_Rb_tree_increment`, insertion/rebalance,
  erase/rebalance, and decrement are preserved as static evidence. This does
  not prove `std::set<uint32_t>` or any runtime loader binding.

`sdk/param_set_3_21.json` records the direct tree facts as
`PRIMARY_ELF_VERIFIED` and the source family as `STATIC_INFERRED`; exact
PrmSet source alias, element type, comparator, mutation caller and exception
paths remain UNKNOWN. `sdk/paramlist_3_21_candidate.hpp` adds descriptive
24-byte tree words and constants only; it is not a live-object wrapper.

The private Ghidra run exited 0 with 17 target bodies, 243 instruction rows,
30 blocks and 60 CFG edges, completion marker
`COMPLETE_TARGET_EXPORT`, language `ARM:LE:32:v8`, image base `0x10000`, and
`-noanalysis`. It is a bounded cross-check, not whole-program Auto Analysis.

ParamList lifetime conclusions remain unchanged: the shared counter is at
`ParamList+0x04`; clear/destructor release non-null elements through their
virtual destructor slot and free shared storage only when the counter reaches
zero. `ParamList::get` and `PrmSet::getSet` therefore expose borrowed interior
pointer candidates whose validity is bounded by replacement/destruction;
null, concurrency, copy-on-write, allocator and runtime safety remain
unverified. Runtime-verified and callable SDK counts remain zero.

The final local regression run after this checkpoint passed **318 tests**.

Next investigation targets: identify a unique PrmSet mutation caller for
`0xffe70`, recover the exact value/comparator type, and trace all exception and
owner-release paths before any stronger ABI declaration is considered.

## Continuation checkpoint — ParamSet value helpers and direct callsites (2026-10-10)

The exact private ELF was re-verified before decoding. `fwplatform/param_set_probe.py`
now records these additional primary static facts:

- `0xecd7a` conditionally copies one 32-bit word from `[r2]` to `[r1]`.
- `0xefe6c` compares one word at each value pointer with unsigned condition
  codes and returns the lower-than result.
- `0x63e796` supplies source node `+0x10` to the node constructor, copies the
  source header word and clears destination links at `+8` and `+0xc`.
- `0xffed0` is a bounded unique-insert wrapper with insertion branches at
  `0xfff4e` and `0xfff86`.
- A Capstone-confirmed Thumb `BL` scan found direct `0xffe70` callsites at
  `0xfff4e`, `0xfff86` and `0x7f4402`. No one is identified as a PrmSet
  mutator; function identity remains UNKNOWN rather than using nearest-address
  assignment.

The fresh private Ghidra 12.1.3 ASCII-path `param-set` export completed with
`COMPLETE_TARGET_EXPORT`: 21 target bodies, 354 instruction rows, 49 blocks and
97 edges, language `ARM:LE:32:v8`, image base `0x10000`, `-noanalysis`. Ghidra's
decompiler independently showed `uint*` comparator operands and a one-word
copy. The raw export/project remain private.

The public SDK metadata/header and report now describe the one-word evidence,
helper VMAs and direct callsites while keeping the source element alias,
PrmSet mutation entry, ownership, exception paths, null/concurrency behavior,
runtime binding and callable status UNKNOWN/false. Runtime-verified and
callable API counts remain zero.

Validation after this checkpoint: the ParamSet tests and complete local suite
pass **321 tests**. Next target is a uniquely typed/cross-module caller for
`PrmSet::getSet`, followed by exception and owner-release coverage.

## Continuation checkpoint — cross-ELF PrmSet caller (2026-10-10)

The private library-set scan found one dependent ELF with both exact undefined
imports: `libScalarDaemon.so` (SHA-256
`ca28cbf4c5c6402160ad80f6ad9f5e99052f42c3fabc382c557fcded18addc29`). The
authenticated `libObj.so` exports the two provider symbols at Thumb-tagged ELF
VMAs `0x7efae9` (`getSet`) and `0x7efaf1` (`GET`). No other scanned library
was promoted by basename or same-name coincidence.

`ghidra-scripts/ImportedSymbolReferences.java` is now a reusable
metadata-only exporter. It preserves Ghidra image base `0x10000`, Ghidra
addresses, ELF VMAs, address spaces, symbol namespaces, reference kinds and
caller entries. The latest private metadata export is SHA-256
`c3244eed2f746ae43e63b294681be3c590707b411ff16d7a1fa1cb650cf2dfac`.
`fwplatform/paramset_cross_elf.py` validates complete JSONL,
resolves `.rel.plt` `R_ARM_JUMP_SLOT` entries and ARM PLT instructions, then
uses Capstone to validate each application callsite. The private Ghidra 12.1.3
auto-analysis run succeeded; its raw project/export remain private.

The recovered chain is:

`EventDispatcher::dispatchSystemEvent` entry `0xd5b5c` (Thumb symbol value
`0xd5b5d`) → `PrmSet::GET` PLT callsite `0xd5b7a` with `r1=0x19` → `CBZ r0`
at `0xd5b7e` → `PrmSet::getSet` PLT callsite `0xd5b80`, with `r0` carrying the
non-null `GET` result. Both callsites are `PRIMARY_ELF_VERIFIED` by Ghidra
references plus Capstone Thumb `BLX`; the contract keeps the observed chain
status at `PRIMARY_ELF_VERIFIED` but records its composed C++ return/ownership
meaning separately as `chain_semantic_status=STATIC_INFERRED`. Ghidra
references inside the PLT stubs are excluded as `PLT_SELF_REFERENCE`.

The descriptive public record is `sdk/paramset_cross_elf_3_21.json`, and the
CLI is `fw sdk parameter-set-cross-elf` (private ELF/export mode or checked-in
contract mode). The header adds non-callable cross-ELF evidence constants.
`runtime_verified=false`, `callable=false`, loader load bias, ownership,
concurrency and exact source-level return types remain UNKNOWN. Synthetic
cross-ELF parser/validator/CLI tests pass (7 targeted; 328 full-suite tests);
no original bytes or private export were added to the repository.

Next targets: recover ParamSet exception/owner-release paths and determine the
source element alias without promoting the observed one-word comparator to an
exact typedef. Continue to use `sdk/param_set_3_21.json` and the separate
cross-ELF contract rather than treating the generic `0xffe70` helper as the
mutation caller.

## Continuation checkpoint — ParamSet header/node lifetime (2026-10-10)

The exact private `libObj.so` was re-verified at SHA-256
`8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`. The
bounded Capstone probe now records the following additional facts without
repeating the recovered `ParamList::get` body:

- `0xffc40` returns `[payload + 0x08]`; `0xffc60` and `0xffc68` load node
  words at `+0x0c` and `+0x08`.
- `0xffc70`, `0xffccc`, `0xffcd4` and `0xffcdc` are direct address accessors
  for payload/header offsets `+0x04`, `+0x0c`, `+0x08` and `+0x10`.
- Sentinel initialization at `0xffce4` and payload initialization at `0xffcf6`
  produce the observed header words and clear the node-count candidate at
  `+0x14`.
- Recursive destruction at `0xffd80` follows the observed links until null,
  releases nodes through the local path ending at the `_ZdlPv` PLT, and
  `0xffdf6` obtains the root through `0xffc40`.
- The insertion helper at `0xffe70` passes the standard `_Rb_tree` rebalance
  argument shape and increments the observed count word.

The direct offsets are `PRIMARY_ELF_VERIFIED`; compatibility with a 20-byte
libstdc++ `_Rb_tree` header/node family is `STATIC_INFERRED`. The exact source
alias, element typedef/comparator, allocator pairing, virtual destructor
ownership, null/invalid-element behavior beyond the observed null link,
exception cleanup, and concurrency remain `UNKNOWN`. `getSet` remains a
borrowed interior-pointer candidate; no runtime-safe or callable API is
created. `runtime_verified=false` and `callable=false` remain mandatory.

`fwplatform/param_set_probe.py`, `sdk/param_set_3_21.json` and
`sdk/paramlist_3_21_candidate.hpp` carry the evidence-gated layout. The
private Ghidra profile includes the accessor region; its project/export stay
outside the public checkout. Targeted tests pass after this checkpoint; run
the full suite before committing.

Next target: recover a uniquely typed PrmSet mutation/owner caller, then map
exception and virtual-release paths. Do not promote `_Rb_tree` compatibility
to `std::set` or expose a live wrapper.

## Verification update — accessor profile rerun (2026-10-10)

The first attempt to extend the private Ghidra profile exposed an overlapping
bounded target; it is not counted as success. `ParamListTargets.java` now
clears overlapping existing functions and uses non-overlapping helper ranges.
The corrected ASCII-path Ghidra 12.1.3 run (ARM:LE:32:v8, image base
0x10000, -noanalysis) exited 0 and wrote `COMPLETE_TARGET_EXPORT` with 28
bodies, 375 instruction rows, 55 blocks and 96 CFG edges. Accessor targets
were present at 0xffc40, 0xffc60, 0xffc68, 0xffc70, 0xffccc, 0xffcd4 and
0xffcdc. The private export remains outside the repository.

The complete public synthetic suite passes 330 tests. This is static evidence
and tooling validation; runtime-verified and callable SDK counts remain zero.

## Continuation checkpoint — ParamSet helper caller ranges (2026-10-10)

`ghidra-scripts/TargetCallers.java` now exports SHA-pinned, metadata-only
caller references with explicit Ghidra image-base addresses, ELF VMAs, address
space, caller entry and actual (possibly non-contiguous) body ranges. Generated
function labels are retained only as non-semantic locators. The bounded
five-target `param-set-callers` profile also includes the wrapper at `0xfffb6`
and insertion wrapper at `0x7f44ce`, which was
needed to resolve the previously Capstone-only call at `0xfffc0`.

The private ASCII-path Ghidra 12.1.3 rerun exited 0 with
`COMPLETE_TARGET_CALLER_EXPORT`, three targets and eight references. Capstone's
exact Thumb `BL` scan agrees with all eight: `0xffe70` is called at
`0x7f4402`, `0xfff4e` and `0xfff86`; `0xffed0` is called at `0x7f4440`,
`0x7f44a0`, `0x7f44c6` and `0xfffc0`; the helper `0x7f4390` is called at
`0x7f44fc`. Ghidra reports caller bodies `0x7f4390..0x7f44cd`,
`0x7f44ce..0x7f4519`, `0xffed0..0xfffb5` and `0xfffb6..0xfffe5`.

`fwplatform/target_callers.py` parses the private export, rejects truncation,
hash/address-space mismatches, duplicate references and out-of-body callsites,
then emits the public-safe `sdk/param_set_tree_callers_3_21.json`. The CLI is
`fw sdk parameter-set-callers`; private mode accepts `--ghidra-export` and
`--elf`, while the default reads the sanitized contract. The callsites are
`PRIMARY_ELF_VERIFIED` from Ghidra plus Capstone; caller identity is only
`GHIDRA_DERIVED`, and `prmset_mutator_entry`, runtime verification and callable
status remain `UNKNOWN`/false. No private export or firmware bytes are checked
in.

The new synthetic caller-parser/CLI tests pass. Next target remains a uniquely
typed ParamSet mutation/owner path; do not promote the generic ordered-tree
helper or generated labels to a source-level API.

## Continuation checkpoint — PrmSet vtable word verification (2026-10-10)

The exact private `libObj.so` was re-read after validating SHA-256
`8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`. This
checkpoint did not repeat the `ParamList::get` recovery. A new bounded data
reader in `fwplatform/param_set_probe.py` requires a unique file-backed
`PT_LOAD` and verifies the PrmSet vtable prefix `0x1019d18`, RTTI pointer
`0x1019d08`, and address point `0x1019d20`.

The three file words are `0x7efbb5`, `0x7efb2d` and `0x7efb59`, respectively
mapping to body entries `0x7efbb4` (clone candidate), `0x7efb2c` (non-deleting
destructor candidate) and `0x7efb58` (deleting destructor candidate). Target
words and Thumb tags are `PRIMARY_ELF_VERIFIED`; the source-level virtual-role
labels remain `STATIC_INFERRED`. `param_family_probe` independently reports
the same targets. A fresh isolated ASCII-path `ParamListTargets.java
param-set` run against the same ELF exited 0 with `COMPLETE_TARGET_EXPORT`, 28
target bodies, 375 instruction rows, 55 blocks and 96 edges. No raw bytes,
Ghidra output or private path was added to the repository.

`sdk/param_set_3_21.json` now carries `inheritance.vtable_slots` and the
descriptive header exposes ELF VMA/Thumb-tag constants. The constructor still
has no observed `+0x08` key store; `0x7eda84` remains the direct key-setter
witness. New fail-closed tests reject missing slots and wrong/untagged values.
The private probe returned `validation={'valid': True, 'errors': []}` and the
targeted ParamSet suite passes 18 tests. The complete local suite passes 343
tests. Runtime verification and callable API counts remain zero.
The contract also keeps bounded null-guard observations separate from unknown
invalid-node, alias-invalidation and concurrency behavior; none is a runtime
safety guarantee.
