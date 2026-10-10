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

The integrated probe currently emits **28 verified static edges** and **5
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

Next targets: registry population for `0x7eb8fa` (receiver +0x88), the
returned object's +0x1c pointer used by `0x7f124a`, and state machine
`0x7efbfe`. It dispatches through TBB and vtable slots +0x0c/+0x08
before the final +0x18 call at `0x7efce0`. ModelCamera vtable candidates
alone cannot prove registry identity or delivery to `ActionGpSetSetting`.

Private targeted Ghidra `camera-consumer-chain` exited 0 with
`COMPLETE_TARGET_EXPORT`: 11 targets, 480 instructions, 107 blocks,
231 flow references. Language `ARM:LE:32:v8`, image base `0x10000`,
space `ram`; Auto Analysis was not run. Forced bounded bodies are
cross-check ranges, not proof of source-level function extents.

Overall status: PARTIAL. Generic request consumption is proven; five
Camera/provider/normalization links remain unresolved. Fully verified
callable core APIs: **0**. Raw exports remain private.
