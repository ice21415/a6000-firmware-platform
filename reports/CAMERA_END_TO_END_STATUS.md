# Camera Core Request → Event → ModelCamera 狀態

本文件是目前 Camera Core 端到端研究狀態的單一摘要。資料來自
`fwplatform.camera_core_chain` 對 SHA-256 固定的 Sony ILCE-6000 3.21
`libObj.so` 私人副本所做的有界 Capstone 讀取；原始韌體位元組、反編譯
文字和私人資料庫沒有放入 repository。

## 已由原始 ELF 證明的連接

| 連接 | ELF VMA / callsite | 等級 |
|---|---|---|
| `ViewBase::requestModelExecute` → request Event factory | `0x121098` → `0x7f0b0c` | `PRIMARY_ELF_VERIFIED` |
| `viewManagerIf::requestModelExecute` → request Event factory | `0x1250ee` → `0x7f0b0c` | `PRIMARY_ELF_VERIFIED` |
| ViewBase factory result → `View::requestApplicationExecute` | `0x1210a4` → `0x7f1b0c` | `PRIMARY_ELF_VERIFIED` |
| factory → Event `0x11004003` | literal locator `0x7f0b74` | `PRIMARY_ELF_VERIFIED` |
| factory → request keys 7 and 8 | `0x7f0b44`, `0x7f0b5c` | `PRIMARY_ELF_VERIFIED` |
| `View::requestApplicationExecute` → `Event::addParameter` key 6 | `0x7f1b2a` | `PRIMARY_ELF_VERIFIED` |
| View submit helper → `EventManager::push` | `0x7f25ec` → `0x7ef960` | `PRIMARY_ELF_VERIFIED` |
| selector `0x0f01` → `ModelCamera::pvt_ActionSetInit` | `0x4cfe98` → `0x4cf7a8` | `PRIMARY_ELF_VERIFIED` |
| `pvt_ActionSetInit` → EE-neutral / `PrepChk` | `0x4cf814`, `0x4cf81a` | `PRIMARY_ELF_VERIFIED` |
| EE-neutral → sender candidate `0x443d14` | `0x4b1a42` | `PRIMARY_ELF_VERIFIED` |
| owner candidate → provider helper candidate `0x7ef1e4` | `0x7ef268` | `PRIMARY_ELF_VERIFIED` |
| owner candidate `0x7ef254` → layout initializer `0x7ef894` | `0x7ef2ca` | `PRIMARY_ELF_VERIFIED` |
| owner candidate → `EventManager::push` | `0x7ef35a` → `0x7ef960` | `PRIMARY_ELF_VERIFIED` |
| layout initializer → provider vtable slot `+0x30` | `0x7ef8b0` | `PRIMARY_ELF_VERIFIED` |
| layout initializer → push dispatch state `+0x08` | `0x7ef8b2` | `PRIMARY_ELF_VERIFIED` |

The integrated probe currently emits **39 verified static edges** and **5
unresolved edges**.  Every verified edge carries the pinned binary hash,
`ELF_VMA`, source/callsite address, evidence method and verification status.

The five new setup edges are bounded owner/initializer observations.  They
prove object-field writes, a unique PLT binding to `EventManager::push`, and
the provider vtable slot used to populate the later indirect dispatch state.
They do not identify the callback target or prove that this owner is the
ModelCamera event consumer.

The latest bounded provider audit records a separate candidate path.  The
anonymous initializer at `0x45f2fc` writes the vtable address point
`0x1007528`, whose RTTI name bytes decode to `11AppConfigAC`.  Its `+0x30`
slot at `0x1007558` resolves through an `R_ARM_RELATIVE` word to
`0x45ee64`; that method loads another relocated word and returns the Thumb
address `0x45ee5c`.  The `0x45ee5c` body is only a `push/add/pop` leaf and
contains no event-consumer call.  The name helper has a separate external
`getConfig` branch, and the owner input selecting either branch is not proven.
Therefore this is a `PRIMARY_ELF_VERIFIED` candidate observation with
`STATIC_INFERRED` scope, not an EventManager callback edge or a ModelCamera
connection.

The executable-PT_LOAD literal inventory found `0x11004003` at `0x463448`,
`0x4637e4` and the factory literal at `0x7f0b74`.  This is an address inventory
only: matching a 32-bit word does not identify a receiver or prove a dispatch
edge, so the ModelCamera consumer remains `UNKNOWN`.

## 尚未接通的關鍵邊

- `EventManager::push` invokes `[this + 0x08]`, passing
  `r0=[state + 0x04]` and `r1=Event*`; the callback target is
  unresolved.
- The owner candidate at `0x7ef254` allocates a `0x24`-byte layout, invokes
  the bounded initializer at `0x7ef894`, stores it at owner `+0x10`, obtains
  an event through provider vtable slot `+0x2c`, and calls the uniquely bound
  `EventManager::push` PLT entry with `r2 = 1`.
- The initializer obtains an indirect factory result from provider vtable
  slot `+0x30` and stores it at `EventManager +0x08`, which is the field read
  by the dispatch site.  The slot target and eventual callback remain
  `UNKNOWN`.
- The optional completion path invokes a callback from `[this + 0x04]`; its
  target and ABI are unresolved.
- The generic consumer now proves receiver-side extraction of keys 7/8.
  Its registry entry and actual ModelCamera virtual target remain UNKNOWN.
- `0x12d780` is called by both request frontends and returns in `r0`, but its
  selector semantics remain `UNKNOWN`.
- UI/application submission and Camera prepare/action paths are proven static
  paths, not proof that UI ready, Camera Prepare, Camera Ready, or first-shot
  readiness has been reached.

Accordingly `event_consumer_model_camera`,
`event_keys_7_8_to_model_camera`, indirect callback targets, runtime
verification, and callable SDK status remain `UNKNOWN`/`false`.

## SDK 與可重現命令

- `sdk/camera_core_3_21.json` stores the sanitized relation contract.
- `sdk/camera_core_3_21.hpp` stores descriptive register/field observations;
  it is not a callable wrapper.
- `fwplatform/camera_core_chain.py` is reusable for the same evidence batch;
  it does not hard-code a fabricated event consumer.
- CLI: `python -m fwplatform.cli sdk camera-core-chain --elf <private-libObj.so> --json`
- Private Ghidra targeted profile: `camera-request-chain` in
  `ghidra-scripts/ParamListTargets.java`.  Its `-noanalysis` export is a
  cross-check only; it must not be counted as whole-program Auto Analysis.

The private Ghidra 12.1.3 run for that profile exited 0 with
`COMPLETE_TARGET_EXPORT`: 12 targets, 324 instruction rows, 26 blocks and 97
CFG/flow edges.  The exported program uses `ARM:LE:32:v8`, image base
`0x10000`, and Ghidra `ram` address space.  `auto_analysis_completed=false`
is retained; the raw export and project remain private.

## 驗證

The fail-closed camera-chain tests in
`tests/test_camera_core_chain.py` pass.  They reject binary identity errors,
missing evidence, callable promotion and promotion of the unresolved
ModelCamera consumer.  No runtime or hardware test was performed.

## Generic request consumer — current breakthrough

`0x7ed49c` calls `Event::getId` at `0x7ed4aa` and retains the result
in r6. Literal `0x11004005` at `0x7ed750` is reduced by 3 then increased
by 1 before comparison at `0x7ed4fe`. Equality branches at `0x7ed502`
to `0x7ed5c8`. This proves the computed request-ID comparison, rather
than merely a matching literal or a guessed function name.

| Proven connection | Callsite/dataflow | Grade |
|---|---|---|
| Application event router → generic consumer | `0x7eedf0` → `0x7ed49c`, destination bit 2 | PRIMARY_ELF_VERIFIED |
| Consumer → key 7 lookup | `0x7ed5d4` → `0x7ea918`; word getter `0x7ed5da` | PRIMARY_ELF_VERIFIED |
| Consumer → key 8 lookup | `0x7ed5ea` → `0x7ea918`; word getter `0x7ed5f2` | PRIMARY_ELF_VERIFIED |
| key 7 → registry lookup | `0x7ed5fc` → `0x7eb8fa`, r1=model identifier | PRIMARY_ELF_VERIFIED |
| key 8 → new Event ID | r1=sb at `0x7ed624`, constructor `0x7ed62a` | PRIMARY_ELF_VERIFIED |
| Registry result/new Event → model forwarder | `0x7ed650` → `0x7f124a`, r0=model, r1=Event | PRIMARY_ELF_VERIFIED |
| Forwarder → execution candidate | `0x7f1252` → `0x7efcca`, Event store at receiver +0x14 | PRIMARY_ELF_VERIFIED |

Missing key 7 uses `0xffffffff`; missing key 8 leaves zero. A null registry
result or out-of-range model ID follows another branch. The original
ParamList passes through copy-constructor candidate `0x7eda9c` before
`Event::setParamList`; ownership and concurrent aliases remain UNKNOWN.

The other literal regions have EHABI intervals `0x4633a0..0x46344c`
and `0x46364c..0x4637f4`. Inspected creation/insertion paths are producer
witnesses. EHABI intervals are boundary metadata, not complete CFG proof.

## Provider source and next missing intersection

Direct caller `0x7ed996` creates the owner on its stack and passes a name
pointer into BSS at `0x10df828`; its contents are UNKNOWN. `getConfig`
has local symbol entry `0x106c6c`; `initializeConfig` at `0x106da8`
creates the object through `0x106c7c`. Both use singleton `0x10a8a9c`.
Candidate vtable address point `0xfe9b70` has slot +0x30 at `0xfe9ba0`
pointing to `0x106900`, which returns GOT-relocated callback candidate
`0x11130c` via `0x1030f6c`. Owner-name selection and runtime symbol
interposition remain UNKNOWN; this does not resolve the actual push callback.

The registry writer, descriptor loader and Camera slots are now linked
conditionally below. A particular request's successful loader resolution
and selected registry instance remain unverified.

Private targeted Ghidra `camera-consumer-chain` exited 0 with
`COMPLETE_TARGET_EXPORT`: 11 targets, 480 instructions, 107 blocks,
231 flow references. Language `ARM:LE:32:v8`, image base `0x10000`,
space `ram`; Auto Analysis was not run. Forced bounded bodies are
cross-check ranges, not proof of source-level function extents.

Overall status: PARTIAL. Generic request consumption is proven; five
Camera/provider/normalization links remain unresolved. Fully verified
callable core APIs: **0**. Raw exports remain private.

## Model Registry → Camera：有前置條件的靜態鏈

`0x7eb8fa` searches the tree at receiver +0x88 through `0x7eb8f0`
and `0x7eb896`. The node payload starts at +0x10; key is +0x10 and
the returned record pointer is +0x14. End-iterator comparison yields a
zero result on miss. Registration `0x7ec8a4` checks for an existing key,
allocates a 0x24-byte record, initializes it at `0x7f1156`, and inserts
it via `0x7ec954 → 0x7ec6cc`. Duplicate entries skip this allocation path.
The registry is initialized in `0x7ec384`; cleanup/removal witnesses at
`0x7ec274` and `0x7ec476` are scoped observations, not a complete concurrent
ownership contract.

The configuration witness at `0x40208c..0x4020a3` supplies
`@M00B`, `modelCamera.so`, and `ModelCameraToInstance` to `IdSoTable::add`.
The compact ID parser `0x12d71a..0x12d744` interprets the final three
hexadecimal digits, giving **Model ID 11**. This identifies configured
metadata; it does not establish that initialization ran on a device.

The record has library string at +0x10, factory symbol string at +0x14,
loader handle at +0x18, instance at +0x1c, and context at +0x20.
`0x7f11ca` performs dlopen/dlsym and invokes the returned symbol at
`0x7f11f2`; its result is stored at +0x1c (`0x7f11f4`). Failed steps
take the cleanup path. The available extracted directory contains no
`modelCamera.so` file or preserved symlink proving its alias to `libObj.so`.
A read-only directory walk of the original ext-family root image also
found no such name: 29 directories / 744 entries. Image SHA-256:
`938daf4f8ed2bec72497a8f992d565832517de1311357eb79064869b6d183a99`.
Its `/lib/libObj.so` inode 135903 (inode record offset 0x8801f00) reconstructs
to the pinned ELF SHA-256. This excludes a lost symlink in that image only;
other mounted filesystems, runtime aliases or loader name rewriting remain
unverified. Library alias identity therefore remains UNKNOWN.

Phase 4.8 instruction-level loader dataflow confirms internal helper calls and
field flow without claiming imported API identity: `0x7f11d8` calls internal
helper `0xe0cec` with record `+0x10`, and stores its result at `+0x18`
(`0x7f11dc`); `0x7f11e6` calls internal helper `0xdfed0` with the handle and
record `+0x14`; `0x7f11f2` calls the returned function pointer with record
`+0x20` in `r1`; and `0x7f11f4` stores the factory result at `+0x1c`.
Separate `dlopen`/`dlsym` PLT candidates exist, but the helper-to-PLT
relationship is not proven. Registration reaches the record initializer at
`0x7ec91c`.
Null handle, symbol, dlsym result and instance branches remain explicit
failure paths. The selected DSO, registry key-to-instance mapping and
ModelCamera vtable identity remain `UNKNOWN`.

The SHA-pinned ELF does export `ModelCameraToInstance` at `0x4c8c64`:
it allocates 0x27d4 bytes, calls `0x4c8af4`, stores context at +0x20,
and returns the allocation. The initializer writes vptr **0x100a330**
at `0x4c8b10`; its typeinfo `0x100a31c` references RTTI name
`11ModelCamera`. These are direct static facts.

| Conditional Camera vtable relation | Slot / target | Evidence |
|---|---|---|
| Executor checker bridge | +0x08 → `0x1326fc` | slot `0x100a338`; call `0x7efc50` |
| Checker | +0x40 → `0x4acf80` | slot `0x100a370`; call `0x13271c` |
| Action bridge | +0x14 → `0x131cf6` | slot `0x100a344`; call `0x7efca6` |
| Action dispatcher | +0x44 → `0x4d02e4` | slot `0x100a374`; call `0x131d0a` |
| Final callback | +0x18 → `0x132624` | slot `0x100a348`; call `0x7efce0` |

The slot words and R_ARM_RELATIVE records are PRIMARY_ELF_VERIFIED.
The five instance-specific call edges are separately stored as
**STATIC_INFERRED**, conditioned on the receiver having this factory's
vptr. The final +0x18 callback is not the Action entry: Action executes
earlier in the TBB state machine. State 1 selects `0x7efc3a`; state 4
selects `0x7efc9a` and passes pending action field +0x10.

## Phase 4.8 EventManager completion callback provenance

The completion callsite at `0x7ef9ce` reads `EventManager +0x04` and invokes
it only when the incoming `r2` flag is non-zero. The owner initialization path
loads a Thumb pointer from relocated slot `0x1031894` (`R_ARM_RELATIVE`, stored
value `0x7eeb25`), yielding entry `0x7eeb24`. The bounded body is an
error/termination path (`write`, `__errno_location`, `fprintf`, `exit`), so it
is retained as `STATIC_INFERRED` callback provenance and explicitly excluded
as a ModelCamera consumer. Provider selection, activation conditions and
runtime object identity remain unresolved; the main dispatch at `0x7ef988`
and ModelCamera consumer are still `UNKNOWN`.

## Selector、Event ID 和 Action index

For compact `@M00B`, `0x12d840 → 0x120168` encodes a selector with no
bits above bit 11 as `0x12000000 + (11 << 12) + selector`.
Already encoded selectors are returned unchanged. Thus input **0x0f01**
produces Model Event ID **0x1200bf01**, distinct from request
Event ID **0x11004003**.

`0x131fd2` looks up the Event ID through the +0x24 mapping object and
subtracts the matching model prefix. Mapping aliases/completeness are
not fully audited. The checker must pass `0x131cd0 == 1`, and the audited
state branch requires Camera state 2. Its compare at `0x4ad242` reaches
`0x4adafc`, writing **Action index 25** through the forwarded output
pointer. The TBH word at `0x4d0326` maps index 25 to `0x4d04a4`;
tail branch `0x4d04a8` reaches `ActionGpSetSetting` (`0x4cfb9c`).
The independently verified selector arm then calls `pvt_ActionSetInit`.

The offline Python arithmetic model and ARM32 descriptive header preserve
these namespaces and expose no executable camera wrapper. Borrowed Event
at instance +0x14, ParamList aliases, current state, loader success and
threading requirements remain necessary ABI constraints.

## 本輪交叉驗證與下一個阻礙

Two private Ghidra 12.1.3 profiles completed with exit 0 and explicit
completion markers: registry (15 targets / 317 instructions / 46 blocks /
135 flow references), selector (11 / 148 / 35 / 54). Both are targeted
`-noanalysis` cross-checks. Two earlier registry attempts returned process
exit 0 but had a script decompiler timeout and no completion marker;
they are recorded INCOMPLETE. The final registry export explicitly skips
decompilation of its truncated TBH header while retaining instructions/CFG.
Capstone and original table words independently verify that table.

Current graph: **39 primary static edges, 5 conditional inferred edges,
5 unresolved edges**. End-to-end status remains PARTIAL. The next decisive
input is original filesystem symlink/loader metadata for `modelCamera.so`;
then audit the descriptor initialization state and Event-filter mapping
for `0x1200bf01`. EventManager provider selection and completion handoff
also remain UNKNOWN. No runtime verification or callable API was added.

## Phase 4.7 loader audit

The pinned ELF contains the configured `modelCamera.so` and
`ModelCameraToInstance` strings, and the factory symbol is present. A bounded
search of the authorized extracted filesystem found no separate
`modelCamera.so` file. This excludes one candidate file but does not prove the
runtime DSO alias, loader selection, or registry instance identity. Graph
counts remain 39 primary, 5 inferred and 5 unresolved.
