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

## Latest checkpoint — PrmSet exception/owner boundary work (2026-10-10)

The pinned primary ELF was revalidated. This round did not repeat `ParamList::get`.
`fwplatform/param_set_probe.py` now includes the compiler-generated cleanup-shaped
regions after the PrmSet copy helper (`0x7efb9c`) and clone candidate (`0x7efbce`).
Capstone verifies the bounded calls; `.ARM.exidx` has one EXTAB record for each
entry (`0xfb2a74 -> 0xf19718` and `0xfb2a7c -> 0xf19730`). The PLT at `0xdd4f8`
resolves uniquely to `__cxa_end_cleanup` through GOT `0x102d660`.

The copy-helper cleanup candidate calls `0xffe0c`, `0xe4734` and
`__cxa_end_cleanup`. The clone cleanup candidate calls `_ZdlPv` at `0xdd620`
and then `__cxa_end_cleanup`. Direct machine/relocation facts are
`PRIMARY_ELF_VERIFIED`; the exception relationship remains `STATIC_INFERRED`.
EHABI coverage does not prove every throw edge, exception object, allocator
pairing or source-level clone return type.

A private ASCII-path Ghidra 12.1.3 `param-set-exceptions` profile (ARM:LE:32:v8,
image base `0x10000`, `-noanalysis`) exited 0 with
`COMPLETE_TARGET_EXPORT`: 4 bounded targets, 39 instructions, 4 blocks and
11 edges. Ghidra and Capstone agree on the cleanup call targets. Raw export and
private projects remain outside the repository.

Public SDK metadata/header and the validator now record this EHABI evidence and
reject cleanup/runtime/callable status promotion. Runtime verification and
callable SDK counts remain zero. Targeted tests pass 22/22; the full local
suite passes 347 tests. The source element
typedef, unique PrmSet mutator, complete exception object semantics, owner
identity, allocator pairing, locking and runtime ABI remain unknown.

Next target: owner-release and concrete construction/use evidence, without
promoting the generic ordered-tree helper or generated Ghidra names to a
PrmSet API.

## Latest checkpoint — ParamBase family EHABI lifecycle index (2026-10-10)

`fwplatform/param_family_probe.py` now resolves sanitized ARM EHABI
`.ARM.exidx` metadata for every profiled ParamBase-derived family.  The
authenticated private ELF produced one unique constructor, clone,
non-deleting-destructor and deleting-destructor entry for each of the ten
direct RTTI families (40 lifecycle records total).  The probe rejects a
missing/ambiguous/truncated entry and never emits unwind words or firmware
bytes.  `PrmSet`, `PrmNumberList` and `PrmObjMsg` entries were independently
checked against their exact ELF VMAs and `.exidx` locations.

The public `sdk/parameter_types_lifetime_3_21.json` contract now carries the
sanitized metadata and an explicit semantic limit: EHABI presence does not
prove every throw edge, exception object, allocator pairing, ownership or
runtime lifetime contract.  `runtime_verified=false` and `callable=false`
remain mandatory.  Synthetic family tests now cover the metadata shape and
reject runtime promotion.  This checkpoint did not run a large Ghidra job and
does not turn the generic ordered-tree callers into a ParamSet mutator.
The complete local suite now passes 351 tests; runtime-verified and callable
core API counts remain zero.

## Latest checkpoint — PrmSet direct lifecycle caller scan (2026-10-10)

The PrmSet probe now performs one conservative scan of the authenticated
`libObj.so` executable `.text`: each 32-bit Thumb `BL` candidate is decoded by
Capstone and matched against the six named PrmSet lifecycle VMAs.  No direct
caller was found for `getSet`, `GET`, the constructor, deleting destructor or
clone; the non-deleting destructor has one callsite at `0x7efb5e` from its
deleting path.  The result is stored in `sdk/param_set_3_21.json` with
`PRIMARY_ELF_VERIFIED` callsite facts and UNKNOWN caller identity.

The scan does not cover BLX/register/vtable dispatch or callers in another ELF,
so it is a bounded negative result and does not establish that the functions
are unused.  It also does not identify a ParamSet owner or mutator; the generic
ordered-tree helper remains unassigned.  The new validator and checked-in
contract tests keep this scope explicit and continue to reject runtime or
callable promotion.

## Latest continuation checkpoint — ParamList::add replacement/lifetime boundary (2026-10-10)

This round did not repeat the recovered `ParamList::get` body. The new
`fwplatform/paramlist_add_probe.py` reads the exact SHA-pinned primary ELF and
verifies the symbol-bound `ParamList::add` at `0x7ee0e6`, key setter `0x7eda84`,
unnamed replacement body `0x7ededa`, slot-removal helper `0x7ede7a` and storage
append helper `0x7ee0b8`. The result is kept in
`sdk/paramlist_add_3_21.json`; no firmware bytes or private exports are in the
repository.

Primary facts: `add` forwards `r0/r1/r2` to the replacement candidate; a
nonzero result writes the new key at element `+0x08` and appends the element
pointer. The add body does not write subclass payload `+0x0c`. The replacement
candidate returns before traversal for a null new pointer, rejects an identical
existing pointer, and compares existing `+0x08` key plus `+0x04` discriminator.
On a match it loads the old object's vptr, invokes slot `+8`, removes one
four-byte pointer slot and returns a nonzero result. The instruction facts are
`PRIMARY_ELF_VERIFIED`; the source-level replacement name and composed
ownership interpretation remain `UNKNOWN`/`STATIC_INFERRED`.

The old element is destroyed before removal, so an earlier `ParamList::get`
result remains a borrowed interior pointer candidate and can be invalidated by
replacement. Key/discriminator reads occur before the later null check, so the
later check is not a general null-safety guarantee. No lock or atomic operation
was observed. Ownership transfer, allocator pairing, exception paths,
concurrency, runtime binding and callable ABI remain unknown; runtime and
callable counts stay zero.

An ASCII-path Ghidra 12.1.3 `ARM:LE:32:v8` `ParamListTargets.java` targeted
export with image base `0x10000` and `-noanalysis` exited 0 with
`COMPLETE_TARGET_EXPORT`: 21 targets, 343 instructions, 79 blocks and 135
edges. Capstone and Ghidra agree on the add/replacement bodies after VMA
mapping. The private project/export remains outside the public checkout.

Targeted synthetic tests: 6 new ParamList add validator tests. The next
investigation target is a uniquely typed owner/construction path in a dependent
ELF; do not treat this replacement helper as a callable SDK API. The complete
local regression suite passes **357 tests**; this is public evidence-gate
coverage only and does not add runtime-verified or callable APIs.

## Latest continuation checkpoint — EventManager::count indexed-state boundary (2026-10-10)

The exact SHA-pinned `libObj.so` was checked without repeating the already
recovered ParamList::get body. `fwplatform/event_manager_count_probe.py` now
verifies the symbol `_ZN12EventManager5countEj` at even ELF VMA `0x7ef9fc`
(`0x7ef9fd` Thumb value, 34 bytes). Capstone confirms `r0` as a receiver
candidate and `r1` as an unsigned index, followed by the state pointer load,
`[state + (index << 2)]` word access, helper `0x7f0aa0`, and cleanup helper
`0x7ef902`. The helper result is returned in `r0`; the C++ return type remains
UNKNOWN. No local conditional index-bound check is present in the bounded body,
so state allocation, valid range, helper meaning, ownership, null behavior and
runtime safety remain UNKNOWN. Runtime and callable flags stay false.

The corrected private ASCII-path Ghidra 12.1.3 `event-manager-count` profile
used `ARM:LE:32:v8`, image base `0x10000`, `-noanalysis`, and exited 0 with
`COMPLETE_TARGET_EXPORT`: 13 instruction rows, one block and three call edges.
The private project/export remains outside the public checkout. The next
investigation target is resolving the helper/state ownership boundary without
turning the indexed access into a safe callable API.

The current full local `python -m unittest discover -s tests -v` run passed
**364 tests**. This is public evidence-gate coverage only; it does not add
runtime-verified or callable APIs.

## Latest continuation checkpoint — EventManager helper/mutex refinement (2026-10-10)

The exact SHA-pinned `libObj.so` was rechecked with the existing count target,
without repeating `ParamList::get`. The new bounded helper evidence verifies
the chain `0x7f0aa0 -> 0x7f0a84 -> 0x7f0a7a -> 0x7f0a4e`: `0x7f0a32`
compares current and sentinel pointers, `0x7f0a42` follows the current
node's first word, and `0x7f0a4e` returns the number of forward-link steps.
`0x7f096a` supplies the input object's first word and `0x7f0984` preserves
the input as the sentinel. This is a `STATIC_INFERRED` structural operation,
not a source-level `std::list` or other container identification; termination,
ownership and valid index range remain UNKNOWN.

The count lock/unlock wrappers at `0x7ef8f4` and `0x7ef902` operate on
receiver `+0x0c` and resolve uniquely through ARM/Thumb veneers to
`pthread_mutex_lock` (`0xdcc70`, GOT `0x102d3ac`) and
`pthread_mutex_unlock` (`0xe29e8`, GOT `0x102f130`). Runtime loader binding
and complete concurrency safety remain unknown. The corrected private Ghidra
profile exited 0 with `COMPLETE_TARGET_EXPORT`: 12 targets, 100 instruction
rows, 15 blocks and 18 edges. The local full suite remains 364 tests passed;
runtime-verified and callable API counts remain 0.

Next target: trace the EventManager state allocation/sentinel ownership path
without promoting the forward-link candidate to a source-level container API.

## Latest continuation checkpoint — EventManager state-link initialization (2026-10-10)

The exact SHA-pinned `libObj.so` was rechecked at initializer candidate
`0x7ef894`. Its two `_Znwj` allocations each request 8 bytes and pass through
`0x7f09be`. The bounded helper chain calls `0x1111cc` and `0x1114b0`; the
`0x1111b8` path writes zero to `[object]` and `[object+4]` before calling
`0x1111a2`, whose exact stores set both words to the object pointer. The second
path calls `0x111438` and tail-branches to the same self-link helper. This
supports an 8-byte two-word link-object candidate and explains the empty-chain
shape observed by `EventManager::count`, but it does not identify a C++ class
or standard container. Allocation/deallocation pairing, ownership,
termination/cycle invariants and runtime behavior remain UNKNOWN.

The private ASCII-path Ghidra 12.1.3 `event-manager-init` profile exited 0
with `COMPLETE_TARGET_EXPORT`: 15 targets, 162 instruction rows, 23 blocks and
37 edges. The adjacent cleanup candidate `0x7f09d2` statically binds its
`current+8` payload release path to `Event::~Event`, `_ZdlPv` and an exception
cleanup through `__cxa_end_cleanup`. It is not proven to be an EventManager
destructor or ownership path. The local full suite is now 367 tests passed;
runtime-verified and callable API counts remain 0. Next target: prove or
disprove the allocation/deallocation pairing for the two state objects without
treating the static link layout as a safe callable API.

## Latest continuation checkpoint — ParamBase scalar lifecycle closure (2026-10-10)

The exact SHA-pinned `libObj.so` was rechecked with the new
`fwplatform.param_scalar_probe.py`; the recovered `ParamList::get` body was
not repeated.  The probe closes two reusable scalar-family chains:
`PrmBool` constructor `0xe50e8` / clone `0xe5110` / D1 `0xe4750` / D0
`0xe4840`, and `PrmNumber` constructor `0xf0fb0` / clone `0xf1034` / D1
`0xf0f2c` / D0 `0xf0f5c`.  RTTI/vtable records point directly to ParamBase;
the base-constructor PLT binding is unique.

Capstone facts are `PRIMARY_ELF_VERIFIED`: the original constructor `r1` is
saved before the discriminator is passed to `ParamBaseC2Em`, then written as a
byte (`PrmBool`, `+0x0c`) or word (`PrmNumber`, `+0x0c`); each vptr is written
at `+0x00`.  The clone allocates 0x10 bytes and reloads only source `+0x0c`.
Neither constructor nor clone writes/reads element key `+0x08`.  The
independent key setter `0x7eda84` remains the only direct key-initialization
witness in the insertion path.  `PrmBool::setBool` (`0x426acc`) and
`PrmNumber::setNumber` (`0x10f9fc`) independently write the same payload
offsets.  D1 restores the family vptr and calls ParamBase D1; D0 dispatches
D1 then `_ZdlPv`.  Semantic domain, owner, allocator interposition, exception
edges, synchronization and runtime ABI remain UNKNOWN/STATIC_INFERRED as
appropriate; no callable API is declared.

The sanitized contract is `sdk/param_scalar_lifetime_3_21.json`, the read-only
CLI is `fw sdk parameter-scalar --elf <private-libObj.so> --json`, and the
descriptive header constants are in `sdk/paramlist_3_21_candidate.hpp`.
The private ASCII-path Ghidra 12.1.3 `lifecycle` cross-check used
`ARM:LE:32:v8`, image base `0x10000`, `-noanalysis`, and completed with
`COMPLETE_TARGET_EXPORT`: 22 targets, 342 instruction rows, 43 blocks and 72
edges.  The private project/export is outside this checkout.  Six new
fail-closed synthetic tests cover identity, phase completeness, key-scope and
runtime/callable promotion.  The next target remains a concrete ParamList
owner/use path; runtime-verified and callable API counts remain zero.

## Latest continuation checkpoint — ParamList owner/lifetime boundary (2026-10-10)

The exact SHA-pinned `libObj.so` was rechecked without repeating
`ParamList::get`. `fwplatform/paramlist_lifetime_probe.py` now verifies the
exported constructor `_ZN9ParamListC1Ev` at `0x7edc3e`, `clear` at `0x7edb76`,
and destructor `_ZN9ParamListD1Ev` at `0x7edd08`, plus the bounded unnamed
rebind candidate at `0x7edcc6`.

Primary facts: construction allocates a 12-byte pointer container at object
`+0x00`, zeros begin/end/capacity at container `+0/+4/+8`, allocates a 4-byte
shared counter at object `+0x04`, and initializes that counter to `1`. Clear
uses `(end - begin) >> 2`, treats each slot as a 4-byte pointer, skips null
slots, invokes the element vtable slot `+8`, and resets end to begin. The
rebind candidate decrements the old counter, performs clear/container release
and object deletion at zero, increments the source counter, then copies source
container/counter pointers to the destination. The destructor has the same
last-owner branch and deletes the counter through the uniquely resolved
`_ZdlPv` PLT.

The field/call/branch facts are `PRIMARY_ELF_VERIFIED`; the shared-counter and
aliasing interpretations are `STATIC_INFERRED`. The unnamed rebind source
operator, container deallocator at `0x7edc84`, allocation failure behavior,
exception cleanup, atomicity, concurrency, loader binding and copy-on-write
remain UNKNOWN. The contract is `sdk/paramlist_lifetime_3_21.json`, the
descriptive constants are in `sdk/paramlist_3_21_candidate.hpp`, and the CLI
is `fw sdk parameter-lifetime --elf <private-libObj.so> --json`. A private
Ghidra 12.1.3 `paramlist-lifetime` export completed with 11 targets, 130
instruction rows, 26 blocks and 43 edges. Runtime-verified and callable API
counts remain 0. The next target is a uniquely identified external
construction/use caller, not a live wrapper.

## Latest continuation checkpoint — ParamList external owner/use witness (2026-10-10)

The exact SHA-pinned ELF was scanned with Capstone and the new
`fwplatform/paramlist_owner_use_probe.py`. It verifies the complete exported
symbol `_ZN12InputService19getInputEventStatusEP9ParamListPKS0_` at
`0x114104` (356 bytes), without repeating `ParamList::get`. The body preserves
the incoming `r0`, uses incoming `r1` for a lookup of key `0x17005003`, creates
two local ParamLists at stack `+0x18` and `+0x20` through the relocation-bound
constructor PLT, allocates a 16-byte PrmNumber candidate, adds it with key
`0x17005003`, then looks up `0x17005008` in the second local list. A guarded
call at `0x1141e2` passes the original input as the destination and local
`+0x20` as the source of the shared-rebind candidate `0x7edcc6`. Both local
lists are destroyed through the uniquely bound ParamList destructor PLT at
`0xe0080`.

These register/call/literal/relocation facts are `PRIMARY_ELF_VERIFIED`; the
shared-rebind and ownership interpretation is `STATIC_INFERRED`. The
InputService C++ static/member form, return type, dispatch registration,
ParamList::add ownership transfer, exception cleanup, locking and runtime
binding remain UNKNOWN. A bounded whole-text Thumb direct-BL scan found no caller for
this exported function, which leaves dispatch coverage unresolved. The
descriptive contract is `sdk/paramlist_owner_use_3_21.json`, the CLI is
`fw sdk parameter-owner-use --elf <private-libObj.so> --json`, and the private
Ghidra profile completed with 6 targets, 210 instructions, 37 blocks and 87
edges. Eleven fail-closed synthetic validator tests pass; the complete local
suite passes 392 tests. Runtime-verified and callable API counts remain zero.

## Latest continuation checkpoint — InputService cross-ELF imports (2026-10-10)

The generic `fwplatform.cross_elf_import_probe` was run against the private
official 3.21 extracted root. It scanned 511 `.so`/`.elf` files and found
nine importers of the exact undefined symbol
`_ZN12InputService19getInputEventStatusEP9ParamListPKS0_`:
`cmn_view_processDataMgr.so`, `libInputServant.so`, `viewUnified2.so`,
`viewUnified4.so`, `viewUnified6.so`, `viewUnified7.so`, `viewUnified8.so`,
`waterProofHousing.so` and `wrapperSettingUtil.so`.

Each has one `R_ARM_JUMP_SLOT` relocation and a unique ARM PLT/GOT witness.
The provider export in the SHA-pinned `libObj.so` is `0x114105`, size 356.
The import/relocation/export facts are `PRIMARY_ELF_VERIFIED`; provider
selection is `STATIC_INFERRED` because DT_NEEDED does not list `libObj.so` and
runtime loader search/binding is unknown.

A bounded ARM/Thumb direct-immediate BL/BLX scan found no direct caller in
these nine importers. This remains UNKNOWN coverage: register/GOT/vtable and
other dispatch paths were not resolved, and the result is not an unused proof.
The sanitized contract is `sdk/input_service_cross_elf_3_21.json` and the
generic CLI is `fw sdk parameter-cross-elf --root <private-root> --provider-elf
<private-libObj.so> --provider-sha256 <sha256> --json`. Runtime/callable counts
remain zero. Next target: resolve one importer’s register/GOT callsite with a
targeted Ghidra/Capstone body export, then extend the method to other ParamBase
family imports.

The targeted private Ghidra 12.1.3 run for `viewUnified4.so` then completed
with exit 0 using `ARM:LE:32:v8`, image base `0x10000`, and the isolated ASCII
path. Exact mangled lookup was unresolved in Ghidra, but a wildcard lookup
resolved the demangled external `InputService::getInputEventStatus` and its
PLT/GOT references (`ELF_VMA` GOT `0x1ae5c8`, PLT `0x3d434`). The export had
37 metadata records. This confirms the importer/PLT mapping and the address
space translation; it does not prove a source caller, loader binding, runtime
execution, or callable ABI. The raw Ghidra JSONL and project remain private.
The cross-ELF validator has nine synthetic checks, and the latest complete
local suite passes 401 tests; these are evidence-gate results only.

## Latest continuation checkpoint — ParamList cross-ELF profile (2026-10-10)

The generic `fwplatform.cross_elf_import_probe` is now composed by
`fwplatform.paramlist_cross_elf` for the three core ParamList symbols:
`_ZN9ParamList3addEmP9ParamBase`, `_ZNK9ParamList3getEmm` and
`_ZN9ParamListD1Ev`. This is a profile adapter; the low-level scanner still
accepts arbitrary symbols and contains no Sony-specific constants.

The exact SHA-pinned private official root was scanned read-only (511 ELF
files). The three symbol reports contain 27, 29 and 30 importers, with 32
distinct source binaries in the union and 86 observations total. The provider
exports in the authenticated `libObj.so` are `0x7ee0e7`/48 bytes,
`0x7edacb`/76 bytes and `0x7edd09`/46 bytes; the odd values preserve the
Thumb tags. Every observation has `.dynsym` undefined-symbol, `R_ARM_JUMP_SLOT`
relocation and PLT/GOT evidence. Provider selection is `STATIC_INFERRED`;
runtime loader binding, direct caller coverage, C++ ownership and live ABI
remain unknown.

The sanitized public contract is `sdk/paramlist_cross_elf_3_21.json` and the
profile command is:

```powershell
python -m fwplatform.cli sdk parameter-cross-elf-set --root <private-root> --provider-elf <private-libObj.so> --provider-sha256 8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a --json
```

The contract also contains a metadata-only private Ghidra 12.1.3 check for
`viewUnified4.so`: process exit 0, `ARM:LE:32:v8`, image base `0x10000`, and
GOT data references at ELF VMA `0x1ae37c`, `0x1ae47c` and `0x1ae494` for add,
get and D1. Ghidra did not identify a containing caller for those data
references; this is explicitly `UNRESOLVED` and is not a negative proof.
Raw JSONL and project files remain private. Seven new fail-closed synthetic
tests cover profile identity, empty custom symbol sets, Ghidra provenance,
provider mismatch, duplicate symbols and runtime promotion. Runtime-verified
and callable API counts remain zero.

## Latest continuation checkpoint — ParamList query callsite index (2026-10-10)

`fwplatform/param_query_callers.py` adds a generic address-aware Thumb
callsite scanner for the SHA-pinned primary ELF. It validates candidate
two-halfword branches with Capstone and assigns a caller only from an exact
ELF symbol range; there is no nearest-function fallback. The private pass
found 4,504 direct Thumb rows across the query wrapper/forwarder targets:
`0x42abcc` 312, `0x42abdc` 243, `0x42ac00` 402, `0xe5b20` 1,659,
`0xe5b18` 1,668, `0x120970` 198 and `0xfe9be` 22. Only 9 and 14 rows for
`0xe5b20` and `0xe5b18` respectively fall inside a unique ELF symbol range;
the remaining caller identities are intentionally `UNRESOLVED`.

The helper chain is directly witnessed at `0x42ac0c` -> `0xe5b20`,
`0x42ac12` -> `0xe5b18`, `0x42abe8` -> `0xe5b20` and `0x42abee` ->
`0xe5b18`. The sanitized contract is `sdk/param_query_callers_3_21.json`,
and the core contract links it under `query_callsite_index`. This is a
bounded Capstone callsite index, not a full CFG or new whole-ELF Ghidra
analysis; register/GOT/vtable dispatch, loader binding, ownership,
synchronization and runtime callability remain unknown. The read-only command
is:

```powershell
python -m fwplatform.cli sdk parameter-query-callers --elf <private-libObj.so> --json
```

Seven synthetic tests cover target decoding, exact caller-range matching,
unresolved callers, target identity, chain identity and status promotion. Runtime-verified
and callable core API counts remain zero.

## Latest continuation checkpoint — EventManager cleanup ownership boundary (2026-10-10)

The exact private `libObj.so` was rehashed to
`8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a` before
decoding. The new bounded probe `fwplatform/event_manager_destroy_probe.py`
covers the unnamed even-VMA body `0x7efa1e..0x7efa68` (76 bytes). It verifies
that the body clears receiver `+0x08`, locks via `0x7ef8f4`, null-checks and
releases two state roots through `0x7f09d2` and the uniquely bound `_ZdlPv`
PLT, releases the state array through `_ZdaPv`, unlocks via `0x7ef902`, and
passes receiver `+0x0c` to the uniquely bound `pthread_mutex_destroy` PLT.
The instruction and relocation facts are `PRIMARY_ELF_VERIFIED`; field roles,
release ordering and cleanup/destructor role are `STATIC_INFERRED` because no
EventManager destructor symbol, RTTI record or vtable proof was found. The
probe therefore uses `event_manager_cleanup_candidate` and keeps
`destructor_role=STATIC_INFERRED`, `runtime_verified=false` and `callable=false`.
Null-receiver, double-destroy, exception/EHABI, allocator interposition,
concurrency and runtime-loader behavior remain UNKNOWN.

The sanitized contract is `sdk/event_manager_destroy_3_21.json`; query it with:

```powershell
python -m fwplatform.cli sdk event-manager-destroy --elf C:\private\libObj.so --json
```

Six fail-closed synthetic tests cover identity, static-only status, binding
identity and promotion rejection. A private ASCII-path Ghidra 12.1.3 targeted
`-noanalysis` run used `ARM:LE:32:v8`, image base `0x10000`, exited 0 and
emitted `COMPLETE_TARGET_EXPORT` for four targets, 15 blocks and 35 CFG/call
records. The raw project/export remain private. A separate full Auto Analysis
attempt stalled on instruction conflicts, returned `4294967295`, and emitted
no completion marker; it is recorded as a blocker and is not represented as a
successful whole-program analysis. The targeted tests pass 6 tests and the
complete local `python -m unittest discover -s tests -v` suite passes 422 tests.
The next target is a unique constructor or source-level destructor identity for
this cleanup body. Runtime-verified and
callable API counts remain zero.

## Latest continuation checkpoint — EventManager cleanup owner witness (2026-10-10)

The exact SHA-pinned `libObj.so` was scanned again without executing it. A
Capstone-validated direct Thumb call at `0x7ef432` now connects a bounded
owner-function candidate beginning at `0x7ef3d8` to cleanup candidate
`0x7efa1e`. The caller loads `[owner + 0x10]`, null-checks it, calls the
cleanup candidate, then passes the same pointer to the unique `_ZdlPv` PLT at
`0x7ef438`; it later calls the adjacent base-cleanup candidate `0x7ef3a8` and
returns. This is `PRIMARY_ELF_VERIFIED` instruction/relocation evidence.

The relationship is recorded as `STATIC_INFERRED` heap-owned-subobject
cleanup. The owner class, source destructor identity, RTTI/vtable, constructor
path and complete lifetime remain UNKNOWN. It does not prove that either
unnamed function is an `EventManager` public/virtual destructor, and null
guards do not establish general memory safety, double-destroy behavior,
exception cleanup, concurrency or runtime loader binding.

`fwplatform/event_manager_destroy_probe.py` and
`sdk/event_manager_destroy_3_21.json` now include `owner_target` and
`owner_observation`; the command remains:

```powershell
python -m fwplatform.cli sdk event-manager-destroy --elf C:\private\libObj.so --json
```

The private targeted Ghidra 12.1.3 profile was rerun with six targets. It
exited 0 with `COMPLETE_TARGET_EXPORT`, `ARM:LE:32:v8`, image base `0x10000`,
30 basic blocks and 70 CFG/call records. The full Auto Analysis attempt still
returned `4294967295` without a completion marker and remains a blocker. Nine
targeted tests now pass; the complete local `python -m unittest discover -s tests -v` suite passes 425 tests; runtime-verified and callable API counts remain zero.
Next target: identify a constructor or source-level class for the owner field
at `+0x10`.

## Latest continuation checkpoint — direct InputService importer callsites (2026-10-10)

The generic cross-ELF importer now decodes from executable section starts and
excludes PLT sections. This fixes a real Thumb alignment issue in the former
PT_LOAD-origin scan without changing the evidence gate. A read-only scan of
the authenticated private root considered 491 ELF/DSO files and retained the
nine exact `InputService::getInputEventStatus` import observations. It now
recovers two exact direct Thumb calls:

* `waterProofHousing.so` callsite `0x1310`, caller
  `_ZN20CmnWaterProofHousing19getHousingKeyStatusEj`, importer PLT `0x1130`;
  bounded preceding assignments are `r0=r7+0x08`, `r1=r7`, `r2=r4`.
* `wrapperSettingUtil.so` callsite `0x3dea`, caller
  `_ZN18WrapperSettingUtil19_getEyeSensorStatusEP15ViewBaseProductPa`,
  importer PLT `0x2b90`; bounded preceding assignments are `r0=r7`,
  `r1=r7+0x08`, `r2=r4`.

These callsite, exact symbol-range caller and register-assignment facts are
`PRIMARY_ELF_VERIFIED`; the bounded flow is not complete ABI or interprocedural
data-flow proof. The provider export and relocation facts remain static, and
runtime loader binding remains unknown. `viewUnified4.so` still has no direct
callsite in this pass; register/GOT/vtable/callback dispatch remains
unresolved. The public metadata is in
`sdk/input_service_cross_elf_3_21.json`, and the fail-closed cross-ELF tests
now cover section-origin recovery and direct-call provenance. Runtime-verified
and callable API counts remain zero.

## Latest continuation checkpoint — ParamList direct cross-ELF callers (2026-10-10)

The corrected executable-section scanner was reused by
`fwplatform.paramlist_cross_elf` for `_ZN9ParamList3addEmP9ParamBase`,
`_ZNK9ParamList3getEmm` and `_ZN9ParamListD1Ev`. The current private root
contains 491 ELF/DSO files and retains 27/29/30 importers respectively (86
observations). It now recovers 154 direct Thumb `add` callsites, zero direct
immediate `get` callsites, and 185 direct Thumb destructor callsites. The
callsite rows include `.text` section, mode, exact VMA, target PLT and exact
symbol-range caller candidates when available, plus a bounded direct register
flow. These are `PRIMARY_ELF_VERIFIED` instruction facts; no complete C++ ABI,
loader binding, ownership or runtime claim is made. The public profile is
`sdk/paramlist_cross_elf_3_21.json`, and the profile tests now assert the
direct-call counts and provenance. The focused set passes 18 tests and the
complete local suite passes 427 tests.

## Latest continuation checkpoint — EventManager owner-field construction (2026-10-10)

The next primary-ELF pass did not repeat `ParamList::get`. It added
`fwplatform/event_manager_owner_probe.py` and the sanitized contract
`sdk/event_manager_owner_init_3_21.json`. In the bounded Thumb region at
`0x7ef254`, `0x7ef2b4` supplies a `0x24` allocation size, `0x7ef2ba` calls
the unique `_Znwj` PLT binding, `0x7ef2ca` calls local initializer `0x7ef894`
with the allocated pointer retained in `r0`, and `0x7ef2d4` stores that
pointer at owner `+0x10`. The observed initializer inputs include `r1=r8`
and `r2=[owner+0x14]`; their source semantics remain UNKNOWN.

The existing owner cleanup witness at `0x7ef432`/`0x7ef438` therefore has a
matching allocation/store fact, but the owner class, constructor identity,
complete function boundary, failure/exception behavior and runtime ownership
remain UNKNOWN/STATIC_INFERRED. A private Ghidra 12.1.3 targeted profile
(`event-manager-owner-init`) exited 0 with `COMPLETE_TARGET_EXPORT`: four
targets, 157 instructions, 20 blocks and 70 edges; the owner body maps to
Ghidra `0x7ff254..0x7ff2db` after image-base subtraction. Seven synthetic
fail-closed tests cover the new validator, and runtime/callable API counts
remain zero. The new validator set is seven tests; the complete local suite
passes 434 tests.

## Latest continuation checkpoint — ParamList query contract and EventManager constructor candidate (2026-10-10)

The exact private `libObj.so` remains SHA-pinned to
`8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`. The new
`fwplatform.paramlist_get_probe.py` and
`sdk/paramlist_get_3_21.json` make the prior query recovery reproducible:
`0x7edaca` is checked as the 76-byte `_ZNK9ParamList3getEmm` body, with
`r1` as key, `r2` as discriminator, element fields at `+0x08`/`+0x04`, and a
borrowed element-pointer result. The `0x42ac00` wrapper's output write and
observed `0`/`1` status paths are checked together with `0x42abcc`, `0x42abdc`,
`0xe5b20` and `0xe5b18`. C++ return type, null-element behavior outside the
bounded body, external locking and concurrent safety remain UNKNOWN.

The new `fwplatform/event_manager_constructor_probe.py` and
`sdk/event_manager_constructor_3_21.json` record the bounded `0x7ef254`
owner-initializer candidate. It initializes fields through `+0x28`, stores a
provider candidate at `+0x14`, allocates a 0x24-byte subobject at `+0x10`
through `_Znwj`/`0x7ef894`, and is related by static evidence to the earlier
`0x7ef432` cleanup/delete witness. No EventManager constructor symbol,
RTTI/vtable ownership, provider type or complete destructor identity was
found; layout compatibility is `STATIC_INFERRED` only.

The private targeted Ghidra 12.1.3 profile `event-manager-constructor` exited
0 with a completion marker (`ARM:LE:32:v8`, default compiler spec, image base
`0x10000`, `ram`), and its sanitized metadata records 5 targets, 260
instructions, 18 blocks and 65 CFG/call edges. It ran in targeted
`-noanalysis` mode; whole-program Auto Analysis remains a blocker and is not
counted as success. Raw Ghidra output and projects remain private.
The script-emitted Ghidra program SHA equals the pinned ELF SHA, so the
cross-check metadata is identity-scoped rather than a free-standing count.

New public commands:

```powershell
python -m fwplatform.cli sdk paramlist-get --elf C:\private\libObj.so --json
python -m fwplatform.cli sdk event-manager-constructor --elf C:\private\libObj.so --json
```

The primary contract now links the query contract and the descriptive header
contains the query offsets/status constants. Runtime-verified and callable
core API counts remain zero. The focused suites and complete local
`python -m unittest discover -s tests -q` run now pass **450 tests**.

## Latest continuation checkpoint — ParamBase constructor/clone field audit (2026-10-10)

The SHA-pinned private `libObj.so` was audited with the reusable
`fwplatform.param_lifecycle_probe` rather than repeating the recovered
`ParamList::get` body. The normalized public contract is
`sdk/param_lifecycle_3_21.json`; private ELF bytes, raw Capstone streams and
the Ghidra project remain outside the repository.

The audit covers all ten direct ParamBase families. It found no direct
`+0x08` key access in any bounded constructor or clone body (10/10 each).
The key witness remains the separate ParamList insertion setter at
`0x7eda84`. Nine clone bodies contain direct payload-region access; the
`PrmObjMsg` clone calls a getter/helper and has no direct receiver payload
load in the bounded body. `PrmCntInfoList` uses a local initializer path, so
the absence of a ParamBase PLT call is not interpreted as absent base
initialization.

The private targeted Ghidra 12.1.3 profile `param-lifecycle-field-audit`
completed with exit 0 and `COMPLETE_TARGET_EXPORT`: 20 target bodies, 312
instructions, 20 blocks and 52 CFG edges. It records matching binary/program
SHA-256, ARM:LE:32:v8, default compiler, image base `0x10000` and `ram`.
This is a bounded `-noanalysis` cross-check; the full Auto Analysis blocker
is unchanged and `auto_analysis_completed=false` is preserved.

Run the repeatable private check with:

```powershell
python -m fwplatform.cli sdk parameter-lifecycle-audit --elf C:\private\libObj.so --json
```

The check proves direct receiver-field instructions only. Complete C++ type
identity, clone ownership, allocator/exception behavior, shared-counter
semantics, null/invalid-element behavior, locking, concurrent validity and
runtime binding remain UNKNOWN. Runtime-verified and callable SDK counts are
0. The seven focused tests and the complete local suite (**457 tests**) pass;
the commit hash is recorded after this checkpoint is committed.


## Latest continuation checkpoint -- ParamBase destructor and D1/D0 cleanup audit (2026-10-10)

The authenticated private `libObj.so` was checked again by
`fwplatform.param_destructor_probe` using the exact SHA-256
`8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`. The
bounded pass covers all ten known ParamBase-derived families and records
direct receiver-relative field operations, direct Thumb call targets and
statically resolved PLT/GOT bindings only.

The primary ELF facts are 10/10 nondeleting D1 bodies calling the ParamBase
nondeleting destructor at `0xe4734`, and 10/10 D0 candidates calling their
family D1 then `_ZdlPv` at `0xdd620`. Six D1 bodies contain a payload-cleanup
call candidate: PrmString (`+0x0c` to `_ZdaPv`), PrmStruct (`+0x0c` to a
`free` binding), PrmSet, PrmNumberList, PrmCntInfoList and PrmObjMsg. These
are direct static observations; helper semantics and allocator ownership are
not established.

The private Ghidra 12.1.3 targeted `param-destructor-field-audit` export
completed with exit code 0 and its completion marker: 20 target bodies, 233
instructions, 24 blocks and 47 CFG/call edges. It ran in targeted
`-noanalysis` mode, so `auto_analysis_completed=false` remains explicit and
whole-program Ghidra coverage is still a blocker. The sanitized contract is
`sdk/param_destructor_3_21.json`; the raw export and project remain private.

The repeatable local command is:

```powershell
python -m fwplatform.cli sdk parameter-destructor-audit --elf C:\private\libObj.so --json
```

The contract is descriptive and remains `runtime_verified=false`,
`callable=false`, with runtime-verified and callable core API counts at zero.
It does not prove a complete C++ destructor ABI, null/invalid-object policy,
double-destroy behavior, exception cleanup, locking, concurrent validity or
safe invocation on a camera. Seven new fail-closed tests cover identity,
cleanup-chain and unsafe-status regressions; the complete local suite passes
**464 tests**.

## Latest continuation checkpoint -- ParamList virtual destructor dispatch (2026-10-10)

The next bounded pass resolves the previously unresolved indirect call in the
ParamList clear helper. `fwplatform.paramlist_virtual_dispatch_probe` checks
the exact private ELF SHA-256
`8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`, then
decodes the clear-site sequence at `0x7edb60`, `0x7edb62` and `0x7edb64`.
The sequence is `ldr r3,[r0]`, `ldr r3,[r3,#8]`, `blx r3` after a bounded
null-element guard.

All ten known ParamBase-family vtable records independently match clone,
nondeleting-destructor and deleting-destructor words. The clear call uses the
deleting-destructor slot for all ten records (10/10/10/10 aggregate). This is
`PRIMARY_ELF_VERIFIED` file-backed slot and instruction evidence; it does not
prove that an arbitrary runtime pointer has one of these dynamic types or that
the caller owns the object.

The sanitized public contract is
`sdk/paramlist_virtual_dispatch_3_21.json`, linked from
`sdk/core_3_21_primary_helper_contracts.json`. The read-only private command is:

```powershell
python -m fwplatform.cli sdk paramlist-virtual-dispatch-audit --elf C:\private\libObj.so --json
```

A private Ghidra 12.1.3 targeted `-noanalysis` cross-check exited 0 with its
completion marker: one target, 22 instructions, 6 basic blocks and 10 CFG
edges. The contract records Ghidra `ram` and ELF VMA separately and preserves
the body range `0x007fdb40`--`0x007fdb75`; raw export/project data stays
private. Runtime dynamic type, allocation provenance, double-destroy policy,
locking, concurrent safety, exception behavior, whole-program Auto Analysis,
runtime verification and callable status remain UNKNOWN/false.

The focused fail-closed suite contains nine tests for identity, slot layout,
relocation provenance, address-space separation, Ghidra range integrity, CLI
exposure and unsafe-status rejection. The complete local suite passes **473
tests**. PR #1 CI also passes all four jobs (Python 3.11 and 3.12 across the
two configured workflow runs); the branch remains open and is not merged.
