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
