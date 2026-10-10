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

The integrated probe currently emits **21 verified static edges** and **5
unresolved edges**.  Every verified edge carries the pinned binary hash,
`ELF_VMA`, source/callsite address, evidence method and verification status.

The five new setup edges are bounded owner/initializer observations.  They
prove object-field writes, a unique PLT binding to `EventManager::push`, and
the provider vtable slot used to populate the later indirect dispatch state.
They do not identify the callback target or prove that this owner is the
ModelCamera event consumer.

The executable-PT_LOAD literal inventory found `0x11004003` at `0x463448`,
`0x4637e4` and the factory literal at `0x7f0b74`.  This is an address inventory
only: matching a 32-bit word does not identify a receiver or prove a dispatch
edge, so the ModelCamera consumer remains `UNKNOWN`.

## 尚未接通的關鍵邊

- `EventManager::push` invokes a function pointer reached through a state
  object at `[this + 0x00]` and `[state + 0x08]`; the callback target is
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
- No bounded primary-ELF evidence currently links event ID `0x11004003` to a
  ModelCamera event consumer or proves receiver-side extraction of keys 7/8.
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
