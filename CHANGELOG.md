# Changelog

## Unreleased — ParamList query ABI and EventManager constructor boundary

- Added SHA-pinned `fwplatform.paramlist_get_probe` and the
  `fw sdk paramlist-get` command. The sanitized contract records the
  `ParamList::get` key/discriminator comparisons, payload forwarding and
  `0x42ac00` output/status behavior while retaining UNKNOWN C++ return,
  lifetime, locking and concurrency semantics.
- Added the bounded EventManager owner-constructor candidate probe and
  `fw sdk event-manager-constructor`. Its contract records field allocation
  and initialization evidence without assigning an unproven constructor,
  RTTI/vtable owner or provider type.
- Added a sanitized private Ghidra 12.1.3 targeted cross-check: exit 0,
  completion marker, 5 targets, 260 instructions, 18 blocks and 65 CFG/call
  edges. The script-emitted program SHA matches the pinned ELF SHA. It is
  explicitly `-noanalysis` metadata, not whole-program coverage; raw output
  remains private.
- Added descriptive query ABI constants and linked the new contracts from the
  primary helper contract. Runtime-verified and callable core API counts stay
  at 0.

## Unreleased — executable-section cross-ELF callsite recovery

- Fixed the generic cross-ELF direct-call scanner to decode from executable
  section starts and exclude PLT sections, preserving Thumb alignment.
- Added bounded register-flow metadata and exact symbol-range caller identity
  for two real `InputService::getInputEventStatus` importer calls at
  `waterProofHousing.so:0x1310` and `wrapperSettingUtil.so:0x3dea`.
- Updated the sanitized cross-ELF contract and fail-closed provenance tests;
  runtime-verified and callable API counts remain 0.

## Unreleased — EventManager cleanup ownership boundary

- Added the SHA-pinned `fwplatform.event_manager_destroy_probe` and
  `fw sdk event-manager-destroy` for the unnamed cleanup body at even ELF VMA
  `0x7efa1e`. The bounded primary-ELF facts cover receiver `+0x08` clearing,
  two null-guarded linked roots, `_ZdlPv`/`_ZdaPv` release bindings, the
  EventManager-associated mutex wrappers and `pthread_mutex_destroy`.
- Added `sdk/event_manager_destroy_3_21.json` and nine fail-closed synthetic
  tests. The cleanup/destructor role remains `STATIC_INFERRED` because no
  EventManager destructor symbol or RTTI/vtable proof was found; runtime and
  callable flags remain false.
- Added the direct owner witness at `0x7ef432`: owner candidate `0x7ef3d8`
  loads `+0x10`, calls the cleanup candidate, and deletes the same pointer via
  `_ZdlPv`. The owner type and constructor remain UNKNOWN/STATIC_INFERRED.
- Added an isolated Ghidra metadata cross-check to the research record
  (12.1.3, `ARM:LE:32:v8`, image base `0x10000`, targeted `-noanalysis`, exit
  0, complete marker, six targets/30 blocks/70 CFG-call records). The failed
  full Auto Analysis attempt is recorded as a blocker; no private export or
  firmware bytes are included.
- The nine targeted tests and complete local `python -m unittest discover -s
  tests -v` suite (425 tests) pass; runtime-verified and callable API counts
  remain 0.

## Unreleased — ParamList direct cross-ELF caller index

- Reused the executable-section direct-call scanner for the ParamList profile.
  The sanitized 3.21 metadata now records 154 `add` callsites, zero direct
  immediate `get` callsites and 185 destructor callsites across the current
  private-root import set.
- Preserved exact caller candidates, section/mode/address provenance and
  bounded register flow without promoting loader, ownership or runtime ABI.

## Unreleased — EventManager owner-field construction witness

- Added a SHA-pinned primary-ELF probe for the bounded `0x7ef254` region.
  It verifies the `0x24` `_Znwj` allocation, direct call to initializer
  `0x7ef894`, and store of the initialized pointer into owner `+0x10`.
- Added private Ghidra 12.1.3 cross-check metadata and a fail-closed CLI/test
  path. The owner class, constructor identity, lifetime safety and callable
  status remain explicitly unknown.

## Unreleased — ParamList query callsite index

- Added the generic `fwplatform.param_query_callers` scanner and
  `fw sdk parameter-query-callers`. It validates instruction-aligned Thumb
  direct branches with Capstone and assigns callers only from exact ELF symbol
  ranges; no nearest-function fallback is used.
- Added `sdk/param_query_callers_3_21.json` with 4,504 sanitized callsite rows
  from the private SHA-pinned `libObj.so`, including the direct helper chain
  between `0x42ac00`/`0x42abdc` and `0xe5b20`/`0xe5b18`. Unresolved caller
  ranges stay unresolved and no CFG, ownership, loader or runtime claim is
  made.
- Linked the index from the descriptive core contract and added seven
  fail-closed synthetic tests. Firmware bytes, private paths and callable
  wrappers remain excluded; runtime-verified and callable API counts remain 0.

## Unreleased — ParamList cross-ELF profile

- Added the reusable `fwplatform.paramlist_cross_elf` profile and
  `fw sdk parameter-cross-elf-set`. It composes the generic exact-symbol
  import scanner for ParamList `add`, const `get` and deleting-destructor
  symbols; the generic scanner remains free of Sony-specific constants.
- Added `sdk/paramlist_cross_elf_3_21.json` with 86 sanitized import
  observations from the private 3.21 root (27/29/30 importers; 32 distinct
  source binaries), provider Thumb-tagged export VMAs and a metadata-only
  Ghidra cross-check. No firmware bytes, private absolute paths, runtime
  claims or callable wrapper were added.
- Added seven fail-closed regression tests for profile identity, custom symbol
  sets, Ghidra provenance, duplicate/mismatched providers and unsafe status
  promotion. Runtime-verified and callable API counts remain 0.

## Unreleased — EventManager::count static ABI evidence

- Added the SHA-pinned `fwplatform.event_manager_count_probe` and
  `fw sdk event-manager-count`. It verifies the symbol-bound Thumb body at
  `0x7ef9fc`, the `unsigned int` index from the mangled symbol, the indexed
  32-bit state-word load, and the helper/cleanup sequence without exposing
  Sony bytes or providing a callable wrapper.
- Added `sdk/event_manager_count_3_21.json` and seven fail-closed tests. The
  bounded body has no local index-bound check; the valid state allocation,
  index range, helper meaning, ownership and runtime safety remain UNKNOWN.
- A corrected private ASCII-path Ghidra 12.1.3 `event-manager-count` profile
  exited 0 with `COMPLETE_TARGET_EXPORT`, 13 instruction rows, 1 block and
  3 call edges. The private project/export remains outside this repository.
- The full local regression suite passes 367 tests; runtime-verified and
  callable API counts remain 0.
- Refined the private-only `event-manager-init` probe through `0x7f09be`:
  `0x1111b8` zeroes the two words and `0x1111a2` writes the two self-links;
  the source-level container, ownership and destruction path remain UNKNOWN.
- The updated private initializer Ghidra profile exited 0 with
  `COMPLETE_TARGET_EXPORT`: 15 targets, 162 instruction rows, 23 blocks and
  37 edges. The export remains outside the repository.
- The adjacent cleanup candidate `0x7f09d2` now has static bindings to
  `Event::~Event`, `_ZdlPv` and `__cxa_end_cleanup`; its relationship to
  EventManager ownership remains UNKNOWN.
- Extended the probe with the bounded `0x7f0aa0` forward-link distance chain
  and unique static PLT bindings for `pthread_mutex_lock` and
  `pthread_mutex_unlock` at the receiver `+0x0c` field. The source-level
  container type, terminating-chain invariant and index range remain unknown.
- The updated private ASCII-path Ghidra profile exported 12 targets, 100
  instruction rows, 15 blocks and 18 edges with `COMPLETE_TARGET_EXPORT`.

## Unreleased — ParamList::add replacement and borrowed-lifetime evidence

- Added the SHA-pinned `fwplatform.paramlist_add_probe` and
  `fw sdk parameter-add` command. It verifies the primary-ELF key setter,
  `ParamList::add`, unnamed replacement body, pointer-slot removal and storage
  append path without exposing Sony bytes or providing a callable wrapper.
- Added `sdk/paramlist_add_3_21.json`, descriptive header constants and six
  synthetic fail-closed tests. The add body writes key `+0x08` before append
  and does not write payload `+0x0c`; matching replacement destroys the old
  element through virtual slot `+8` before removing its pointer slot.
- Re-ran the private ASCII-path Ghidra targeted export: exit 0,
  `COMPLETE_TARGET_EXPORT`, 21 targets, 343 instruction rows, 79 blocks and
  135 CFG edges. Ownership, allocator, exception, locking, runtime and
  callable status remain unknown/false.

## Unreleased — PrmSet RTTI/vtable word verification

- Added a SHA-pinned, file-backed `PT_LOAD` reader to the private PrmSet probe.
  It verifies the `PrmSet` RTTI/vtable prefix, concrete slot targets and
  Thumb tags without decoding data as instructions.
- Added evidence-gated `inheritance.vtable_slots`, descriptive SDK constants
  and fail-closed tests for missing, wrong or untagged slot words. Slot target
  addresses are `PRIMARY_ELF_VERIFIED`; source-level clone/destructor roles,
  ownership, runtime dispatch and callable status remain unverified.
- Added structured safety boundaries for the bounded getter/destructor guard
  observations, borrowed-pointer invalidation, invalid elements and
  concurrency. Unknown behavior remains unknown and `runtime_safe` is false.
- Re-ran the bounded private Ghidra `param-set` profile on the pinned ELF;
  exit 0, complete marker, 28 target bodies, 375 instructions, 55 blocks and
  96 CFG edges. The export remains outside the public repository.

## Unreleased — address-space-aware ParamSet helper callers

- Added the metadata-only `TargetCallers.java` exporter and bounded caller
  profile. It records exact caller entries and body ranges without publishing
  firmware bytes or decompiler text; generated Ghidra labels remain
  non-semantic.
- Added `fwplatform.target_callers` and the descriptive
  `sdk/param_set_tree_callers_3_21.json`. Eight helper callsites (including
  the `0x7f4390` wrapper relation) are cross-checked by Ghidra metadata and Capstone; the new parser rejects
  truncated exports, address-space mismatches, duplicate references and
  callsites outside reported function ranges.
- Added `fw sdk parameter-set-callers` and synthetic fail-closed tests. Caller
  identity remains `GHIDRA_DERIVED`; ParamSet mutator ownership, runtime
  verification and callable API status remain unknown/false.

## Unreleased — PrmSet header/node lifetime evidence

- Added SHA-pinned primary-ELF observations for the payload root/header and
  node-link accessors (`0xffc40`, `0xffc60`, `0xffc68`, `0xffc70`, `0xffccc`,
  `0xffcd4`, `0xffcdc`) and the recursive release path through `_ZdlPv`.
- Added evidence-gated header/node metadata to the descriptive SDK contract,
  generic node snapshot declarations and fail-closed regression tests. Direct
  offsets are `PRIMARY_ELF_VERIFIED`; `_Rb_tree` family compatibility remains
  `STATIC_INFERRED`. Exact source alias, value type, ownership, exceptions,
  concurrency and runtime callability remain unknown.
- Extended the private Ghidra target profile with the accessor region. No
  firmware bytes, private Ghidra output or runtime/device data are published.

## Unreleased — cross-ELF ParamSet caller evidence

- Added the generic metadata-only `ImportedSymbolReferences.java` exporter and
  `fwplatform.paramset_cross_elf` importer. They preserve Ghidra image-base
  addresses separately from ELF VMAs, validate complete JSONL exports, resolve
  undefined imports through relocation-bound ARM PLT entries and cross-check
  application callsites with Capstone.
- Integrated the private, SHA-identified `libScalarDaemon.so` evidence. The
  recovered Thumb chain is `dispatchSystemEvent` → `PrmSet::GET(0x19)` → null
  guard → `PrmSet::getSet`; the two call edges are primary static evidence and
  the composed C++ return/ownership interpretation remains static-inferred.
- Added `sdk/paramset_cross_elf_3_21.json`, descriptive cross-ELF header
  constants, CLI contract/probe support and seven synthetic fail-closed tests.
  Imported references are accepted only when their exact ELF VMA matches the
  relocation-bound PLT, so same-name `GET` symbols from other ParamBase
  families are not promoted.
  Runtime verification and callable SDK counts remain zero; private ELF,
  Ghidra project and raw JSONL export remain excluded.

## Unreleased — PrmSet tree/lifetime evidence checkpoint

- Extended the SHA-pinned `PrmSet` probe with bounded node destruction,
  allocation-size, node-value, ordered-tree insertion and copy observations.
  Direct PLT/GOT checks identify six libstdc++ `_Rb_tree` traversal/rebalance
  imports; the public contract records an ordered-associative-tree-like model,
  not an exact source template or callable API.
- Added primary evidence for a one-word node value/copy path, an unsigned-order
  comparator helper, a bounded unique-insert wrapper and three direct Thumb
  callsites to `0xffe70`; no callsite is promoted to a PrmSet mutator.
  The private Ghidra `param-set` cross-check now exits 0 with 21 targets, 354
  instructions, 49 blocks and 97 CFG edges. Added descriptive width/helper
  constants and three additional fail-closed promotion tests. Runtime
  verification and callable SDK counts remain zero; raw firmware and Ghidra
  output remain private.

## Unreleased — ParamBase foundation checkpoint

- Added the SHA-pinned `parameter-base` probe and descriptive contract. It
  verifies the ParamBase RTTI/vtable, pure-virtual clone slot, base
  constructor `+0x00/+0x04` writes, base destructor/deleting-destructor path,
  and the separate ParamList key setter at `0x7eda84`. It also indexes ten
  direct derived RTTI relations. A private Ghidra 12.1.3 targeted run exited
  0 with four targets, 31 instructions, four blocks and two CFG edges. No
  ownership, exception, locking, runtime or callable claim is made.

## Unreleased — Phase 3 semantic-analysis

- Extended the private-only `parameter-objmsg` probe with direct RTTI/vtable
  validation and seven unique static PLT bindings. The primary ELF now
  identifies the ObjMsg destructor, PrmObjMsg getter, ObjMsg copy constructor,
  and PrmObjMsg constructor in the clone/destruction paths. This supports a
  static deep-copy and release sequence only; ownership transfer, exception,
  locking, runtime binding and callability remain unknown. The targeted ASCII
  Ghidra profile exits 0 with 5 targets, 62 instructions, 7 blocks and 14
  edges. Six fail-closed ObjMsg tests and the 295-test public suite pass; no
  firmware bytes or private Ghidra output are published.

- Added the metadata-only `ParamObjMsgUsage.java` Ghidra profile. The private
  targeted run records the clone constructor/getter/copy-constructor callsites
  and the ObjMsg destructor callsite, while keeping generated labels,
  ownership and whole-firmware usage explicitly unverified.

- Added the reusable `ParamFamilyUsage.java` metadata profile and its strict
  Python normalizer/validator. A bounded private Ghidra 12.1.3 pass indexed
  ten constructor targets and 858 observed references before the 300-second
  Auto Analysis timeout; the public contract records `PARTIAL_TIMEOUT`, keeps
  raw export private, and does not promote usage observations to ownership,
  runtime or callable ABI claims. `fw sdk parameter-family-usage` provides a
  read-only contract query with synthetic regression coverage.

- Added the bounded `param_family_callsite_probe` Capstone layer for five
  representative direct constructors. It verifies branch targets and
  allocation-size witnesses, preserves visible AAPCS32 register provenance,
  and keeps branch/interprocedural values, ownership and runtime safety
  unknown. The separate contract and CLI query are descriptive only.

- Added the private-only `parameter-struct` probe and descriptive contract for
  the discriminator-6 PrmStruct family. Primary ELF evidence verifies the
  vtable/RTTI, `malloc`/`memcpy` pointer-plus-length payload construction,
  `free` destruction and clone allocation. Nested schema, invalid-input,
  allocator, aliasing, runtime and callability semantics remain unknown; no
  firmware bytes are published.

- Added the private-only `parameter-string` probe and descriptive contract for
  the discriminator-2 PrmString family. Primary ELF evidence verifies the
  vtable/RTTI, `strlen`/`new[]`/`strncpy` construction, conditional `delete[]`
  destruction and clone allocation. Encoding, invalid-input, allocator,
  aliasing, runtime and callability semantics remain unknown; no firmware
  bytes are published.

- Added the reusable private-only `parameter-pair` probe and contract for
  `PrmPoint` and `PrmDimension`. It verifies discriminator-specific
  constructors, two inline payload words, vptr/base destruction and clone
  paths. Word meanings, allocator/runtime behavior and callability remain
  unknown; the Dimension destructor PLT binding is preserved separately.

- Added the private-only `parameter-set` primary-ELF probe and descriptive
  contract. It verifies the discriminator-7 getter/GET wrapper, 36-byte
  construction and clone paths, embedded 24-byte payload initialization with
  sentinel links, and payload destruction/copy helpers. The payload remains
  an ordered-container-like candidate with unknown source type, element type,
  allocator, synchronization and runtime/callable status; no firmware bytes
  are published.

- Added the SHA-pinned `event-core` probe for Event construction, copying,
  destruction, ParamList replacement and parameter forwarding. It verifies
  the shared counter/layout fields and last-owner cleanup, while keeping
  aliasing, external ownership, synchronization, runtime binding and
  callability unknown. Four fail-closed tests were added.

- Added the SHA-pinned `request-event-factory` probe for the real
  `AbstractUtilityManager::createRequestModelExecuteEvent` body at
  `0x7f0b0c`. It verifies Event ID `0x11004003`, optional ParamList
  attachment, and key-7/key-8 `PrmNumber` construction with unique PLT
  bindings. Return type, ownership, consumer delivery, runtime binding and
  callability remain unknown; four fail-closed tests were added.

- Added the private-only `event-manager-init` primary-ELF probe for the
  bounded initializer candidate at `0x7ef894`. It records the mutex,
  callback/provider fields and two eight-byte state allocations with unique
  PLT bindings, while keeping constructor identity, helper semantics,
  ownership, runtime binding and callability unknown. Four synthetic
  fail-closed tests were added; no firmware bytes are published.

- ParamList mutation checkpoint: added the SHA-pinned `parameter-mutation`
  probe for clear, final destruction and the unnamed shared-assignment body.
  It verifies element vtable deletion, zero-counter cleanup, `_ZdlPv` PLT
  binding and source/container pointer sharing while keeping copy-on-write,
  locking, exception behavior and runtime callability unknown. The targeted
  private Ghidra export now covers 21 bounded targets; the full public suite
  passes 234 tests; no firmware bytes are published.

- Added the SHA-pinned `parameter-numberlist` probe and descriptive contract.
  Nine primary-ELF regions cover `PrmNumberList` indexed access, length,
  append/capacity behavior, construction and destruction. Bounds, allocator,
  synchronization, exceptions and runtime callability remain unknown.

- Added the SHA-pinned `parameter-cntinfolist` probe and descriptive contract.
  Twelve primary-ELF regions cover the discriminator initializer, dual
  collection accessors, append path, constructors and destruction while
  preserving unknown element, bounds, allocator and synchronization semantics.

- Added the SHA-pinned `camera-selector` probe and descriptive contract for
  the primary-ELF helper at `0x12d780`. It verifies the `0x40` model-token
  branch, `M`/`V` base selection, the relocation-bound ID lookup and the
  guarded normal-branch virtual dispatch. The transformation, C++ type,
  downstream ModelCamera causality and runtime callability remain unknown.

- ParamList factory caller checkpoint: added the private SHA-pinned
  `parameter-factory` probe. Four factory callsites now have bounded register
  provenance, null-result guards and success-path calls to the relocation-
  resolved `_ZN9ParamList3addEmP9ParamBase` PLT (`0xdfdc0`, GOT `0x102e340`).
  The local add/replacement/storage bodies are descriptive static contracts;
  dynamic table values, ownership, locking and runtime callability remain
  unknown. Added synthetic fail-closed tests and expanded the targeted Ghidra
  profile without publishing firmware bytes.

- ParamBase family follow-up: extended the private SHA-pinned metadata probe
  with independent RTTI/vtable discovery and primary static contracts for all
  ten direct ParamBase-derived records. Added constructor/layout witnesses for
  `PrmString` (tag 2), `PrmPoint` (tag 3), `PrmDimension` (tag 4), `PrmStruct`
  (tag 6), and `PrmSet` (tag 7), alongside the earlier families. Pointer
  ownership, helper/allocator behavior, runtime safety and callable APIs remain
  unknown; 223 synthetic tests pass.

- Core factory follow-up: added a primary static contract for the local Thumb
  factory candidate at `0x42acd4`. Its discriminator 5/1/3 branches allocate
  and construct Bool/Number/Point candidates, with four direct callers and
  explicit null paths. Source-level identity, helper semantics, ownership and
  runtime callability remain unknown.

- Core factory helper follow-up: bounded and cross-checked the discriminator-5
  and discriminator-3 lookup forwarders plus Bool/Point payload-word getters;
  no coordinate semantics or ownership claims were added.

- Derived payload/lifetime follow-up: primary constructor/RTTI/vtable evidence
  confirms PrmNumber signed-word and PrmBool byte payloads. Verified deleting
  destructor bindings, shared assignment-like count changes and replacement
  invalidation. Added typed offline decoding and guarded type/lifetime CLI.
  Runtime and external synchronization remain unknown.

- ParamList continuation: recovered the 76-byte get body, first-match/null
  returns, container/element prefix, shared-count destruction and wrapper
  initialization from private primary bytes. ASCII-path Ghidra exits 0.
  Added offline snapshot reader, candidate C++ declarations and regression
  tests; concrete payload types and runtime callability remain unresolved.

- Primary helper follow-up: authenticated the real private libObj.so and recovered
  the two requested Thumb bodies. Added relocation-bound PLT resolution,
  descriptive helper contracts, evidence validation and synthetic tests.
  Ghidra targeted instruction cross-check completed with recorded logging/tail-call
  limitations; callable/runtime-verified APIs remain zero.

- Phase 3.22：針對 0x13200a 與 0x42ac00 的原始 ELF 局部探測，新增解碼後的記憶體運算元方向／base/index／位移、`r2`-based store 線索；明確禁止從該線索直接宣稱 output-pointer ABI。修正 Thumb 16-bit 返回指令落於 executable PT_LOAD 最後一個 halfword 時的讀取問題，新增合成 ELF 邊界測試；仍未取得私人 Sony binary 的真實函式指令。
- Phase 3.21：重點回到原始 ELF 函式本體，新增 `sdk probe-core-abi --elf <private-libObj.so>`，預設只針對 `0x13200a` 與 `0x42ac00` 做 SHA 鎖定的局部 Thumb 反組譯、入口暫存器讀寫線索、返回點及機器碼指紋。以合成 ARM ELF 測試雜湊拒絕、唯一可執行段、指令變化指紋、return sites、CLI 不寫入 SQLite；未宣稱已實際分析私人 Sony ELF 或完成任何可呼叫核心 ABI。

- Phase 3.20：從兩個獨立 Camera action 追回 `0x42ac00` 的穩定 AAPCS32 呼叫時 `r0` view、`r1` 參數 ID、`r2` output pointer，以及返回零後讀取輸出／跳過 `Invalid ParamList` 的控制流；`r3`、實際 C++ 型別及完整錯誤 ABI 保持未知。
- 另將 SetInit 的 `0x42abdc` `0x12000005` EasyMode lookup 列為另一候選，沒有假定和 `0x42ac00` 等價；新增 `sdk param-lookup`、39 處來源指令位址稽核及 synthetic tests。

- Phase 3.19：核心 ABI 逆向直接研究 `0x13200a` 的**回傳用途**；保存組語可見多個 Action 把該值交給 `0x42abcc`，其中一條接著用 `0x42ac00` 查 `0x3fe`／`0x3ff` 及走 `Invalid ParamList` 分支。另確認 SetInit 也接收同一 wrapper 的 payload。結論只達到 ParamList-compatible opaque value，未確認 C++ `ParamList*` 返回型別。
- 新增 `sdk action-payload`、獨立 `fwplatform/action_payload_abi.py`、五個具名來源／36 個地址約束及 synthetic tests。禁止將回傳型別、runtime Camera API 或事件接收路徑冒充已驗證。

- Phase 3.18：改以實際 ABI 引數還原優先。從保存的 `libObj.so` ARM 指令和 Itanium C++ 符號，區分 `ViewBase::requestModelExecute` 的成員函式式暫存器配置與 `viewManagerIf::requestModelExecute` 的靜態式配置；另推導 Event factory 的顯式參數型別與 Event 物件指標返回路徑，但不偽稱 C++ return type 或 owner 已驗證。
- 新增 `ModelCamera::ActionGpSetSetting` 對 `0x0f01` 的內部 `pvt_ActionSetInit` `r0/r1` 引數來源核對、跨 ELF UI selector 引數交叉檢查，以及 `sdk request-abi`、typed candidate fixture 和 synthetic 測試；完整 Camera core API ABI 仍為 0 個，物件生命週期與原始 ELF opcode 驗證待完成。

- Phase 3.17：區分 `ModelManager +0xa4` 的 word-nonzero 正規化（`0x7eaa14`）與 Appframework 上游 guard／`EOR 1` 反相（`0x7eeec8`），核對 18／18 個保存 ARM 指令文字位址，不再把該位元組欄位泛稱 Camera READY。
- 匯整 `app-status-wait-chain.json` 次級研究中的共用 semaphore `0x830451` 及三條等待／completion helper 路徑，保留五處 status setter 呼叫點與未證實的事件 `0x11004003` 消費者。新增 `fw sdk app-sync`、獨立唯讀核對與 synthetic 測試。

- Phase 3.16：從先前保存的 `libObj.so` Appframework 組語確認事件迴圈、guard、dispatch (`0x7eecac→0x7f21e8`)、cleanup 和 semaphore helper。明確拆分重疊 disassembly 掃描窗口，補上 loop 第二個派送 callsite，建立六個具名研究入口／26 個靜態文字核對位址。
- 新增 `sdk event-loop`、唯讀 `fwplatform/app_event_loop.py`、保守的事件消費者／ABI 證據驗證與 synthetic 測試；未宣稱事件 `0x11004003` 已追到 Camera 接收者，也未執行 Sony 原始 ELF。

- Phase 3.15：原始保存組語另找到 `viewManagerIf::requestModelExecute` (`0x1250c0`) 與 `ViewBase` 入口共享 `0x12d780` selector helper／`0xdfbdc` factory stub；兩入口＋event factory 共 50/50 靜態組語文本位址核對。
- 新增 `fw sdk trace-selector` 與 `fwplatform/private_thumb_research.py`：嚴格本機 ELF SHA-256、ARM Thumb 區段邊界、局部控制流／常數及事件 word 掃描；合成 ARM ELF 測試不依賴 Sony 專有二進位。SHA 偏差或無唯一可執行映射直接拒絕。實際 Sony `0x12d780` 函式位元組、event consumer、完整 ABI 仍待原始 ELF 本機驗證。


- Phase 3.15：已從私有保存的 `libObj.so` ARM 指令檔找到第二條 `viewManagerIf::requestModelExecute` 靜態路徑。與 `ViewBase` 前端共用 model-ID import `0xdffb8`、selector helper `0x12d780` 和 event factory `0xdfbdc`，但提交事件的尾分支不同（`0xdb578` vs `0x125084`）。新增可再現 `sdk request-frontends` 文本核對、fixture 與 synthetic 測試；保存的組語報告 **33/33** 位址及操作符符合，不視為新 ELF byte/ABI 證明。


- Phase 3.14：由先前保存的 `libObj.so` 組語追回 `ViewBase::requestModelExecute` 前端與 `AbstractUtilityManager::createRequestModelExecuteEvent` 的靜態 event envelope：事件 `0x11004003`、可能包含 `ParamList`、參數鍵 7／8、入口與 callsite 位址。
- 新增 `sdk event-envelope [--saved-disassembly]`、保守的函式邊界／call-target／寄存器來源文字核對及 synthetic 測試。將 `0x12d780` 轉換、符號動態解析與事件投遞端明列 UNKNOWN；不宣稱 Sony ABI 或 runtime API 已完成。


- Phase 3.13：利用已保存的 REA/Ghidra UI 反編譯與獨立 Camera raw ELF/Capstone 區段，建立 `sdk rea-bridge` 跨 ELF selector 研究核對；區分 UI 地址 `0x1b2504→0x1a2504`、兩端 `0x0f01`、事件投遞未證實，以及靜態呼叫位置不等於 runtime 次數。
- 新增 REA metadata fixture、嚴格 saved UI pseudocode count 和 Thumb MOVW/BL byte decoder 的 synthetic 測試。沒有執行任何韌體、接觸設備或聲稱 Sony ABI 已完成。


- Phase 3.12：新增 `fw sdk research --verify-elf`，只讀原始私有 ELF，驗證 SHA-256、ELF32 ARM executable segment VMA、Thumb BL/B.W 直接分支與 LDRB.W/STRB.W byte displacement；失配非零退出，不執行任何 firmware code。另將 ModelCamera byte instruction immediate 與研究推論 object-root 調整量分開保存。
- 增加純合成 ELF32/Thumb 負位移和欄位立即數回歸測試；沒有假定報告可直接提供 Sony ABI、parameters、return values 或 runtime callability。


- Phase 3.11：在已連線 workspace 找到原本未定位的 Sony 3.21 Camera/Lens/Media 韌體 ELF；新增 14 個源自既有私有反組譯的 Camera 候選入口與 9 條報告層級直接呼叫／尾分支、6 筆 ModelCamera 欄位觀測、4 條 bounded selector 和 1 個 unresolved indirect dispatch。
- `fw sdk research --compare-db` 支援對私有 SQLite 索引做唯讀身份及 callsite FK 比對，不自動修改 DB 或提高 ABI 驗證狀態；新增缺失與重複 ELF 身分的回歸測試。
- `fw sdk research` 可純離線驗證指令目標與候選 ELF VMA 一致性、拒絕偽造的 ABI/VERIFIED/runtime 宣稱，並用 `--focus` 追蹤已記錄的 Camera call graph；回歸測試不分發韌體、沒有 live camera SDK 呼叫。


- Phase 3.10：新增 `sdk investigate` 對 Camera/Lens/Sensor/Media/UI/OSAL/Android/Networking 候選，交叉呈現有明確 FK 的 callsite、CFG/body range、OSAL、JNI 與 lifecycle 靜態證據。
- 新增 `sdk inspect --function-id`，可針對 Ghidra 自動命名或無 Camera 字樣的內部函式研究，保留跨二進位位址歧義、未知 ABI 及模組 state-machine-only 脈絡。
- 新增 `tests/test_core_api.py`（合成隔離、read-only、CLI、地址歧義、OSAL/JNI/狀態機），以及 Camera/Lens/Sensor/Media 研究缺口報告；沒有原廠韌體、實機 SDK 或 runtime 呼叫。
- Phase 3.9：ELF 匯入解析只接受已確定 DT_NEEDED 依賴的唯一 export 位址／版本候選，採 catalog fingerprint 重掃及失敗回滾；SDK discover/draft 可列出 incoming import evidence ID。
- Phase 3.8：強化 SDK ELF SHA／數值位址唯一性、匯出位址配對與重複候選審核，排除 SDK fixture 自我充當 ABI 證據。


- Phase 3.7：新增受限、可恢復的 `analyze ghidra-batch` 多 ELF 計畫與選擇性本機執行工具。
- 校驗 inventory SHA、避免危險來源路徑、限制分析批量與逾時；輸出保留在 firmware root 之外，不匯入 stale／截斷 JSONL。
- 新增 synthetic batch planner、mock headless 寫入、失敗隔離與 resume skip 測試，沒有將原廠 firmware 納入 CI。

- Phase 3.6：Ghidra function records 獨立保存來源 SHA 與 entry locator；不把 prototype 直接推定成 ABI。
- `fw sdk discover` 以 ELF export + binary identity 搜尋待審核 API，列出候選與證據缺口，不寫入 SDK。
- `fw sdk draft` 產出需人工確認、全部標 CANDIDATE 的 SDK fixture，保留 domain 搜尋提示而不自動確認語意。
- 新增 multi-ELF 同名函式、來源歸屬、受控查詢與 review-fixture roundtrip 的合成測試。

- Phase 3.5：加入純離線 `fw sdk mock --scenario`，以名稱空間隔離的命令與狀態轉移建立 deterministic tests；不觸及硬體。
- 強化 SDK `VERIFIED_STATIC` 合約，要求 primary evidence 同時支持 ELF SHA、function address、ABI 與 parameter/return layout。
- OSAL/JNI fixture 匯入改為整批 SQLite savepoint rollback；native role/function 綁定要求 ELF SHA，避免跨 binary name/address 誤配。
- 新增合成 mock、異常中斷回滾、跨 ELF native 歸屬與 ABI 不一致 regression tests。

- Phase 3.4：新增 offline SDK contracts 匯入、完整性稽核與 Camera/Lens/Sensor/Media/UI/OSAL/Android/Networking domain readiness matrix。
- 靜態狀態需函式與 ELF 身分唯一匹配，且來源 evidence 明確綁定相同 binary SHA-256 與 function address；不符時降級 CANDIDATE。
- CLI 新增 `fw sdk import --fixture` 和 `fw sdk audit`；SDK export 忽略單純的 CALLABLE_VALIDATED 資料庫旗標，不宣稱實機可執行。
- 新增 synthetic contract fixture 以及證據完整性、runtime 欄位拒絕、idempotence、rollback 測試。

- Phase 3.3：JNI semantic graph 以精確 DEX path 和 evidence ID 配對，修正 JNI registration module ID 誤作 binary ID 的風險。
- DEX parser 提供 bounded string/type/proto/method/class-def table 解析；class definition 和 method reference 分開記錄，不推定方法實作。
- DEX `research_observation` 採交易回滾，新增跨 DEX、防錯誤索引、重跑與部分匯入失敗的合成回歸測試。

- Phase 3.2：schema v7 保留 legacy DB identity 與 FK，移除衝突的 module dependency、OSAL queue、JNI bridge 唯一性約束，並補上 v6 upgrade tests。
- JNI bridge identity 綁定 native binary SHA、DEX path 與 address space，不再依相同虛擬位址覆寫其他韌體的對應。
- 增加 evidence-bound DEX string/candidate persistence、`fw analyze dex` 與 `fw query dex` 以及 CLI 回歸測試。
- Semantic graph stale node/edge cleanup、ELF `$ORIGIN` normalization、Ghidra completion identity validation 與回歸測試。


- Phase 3.1：migration v6 新增函式不連續 body ranges、證據 adapter run/observation 與 graph provenance。
- Ghidra exporter/importer 改用 AddressSet body ranges；缺少 range 的 caller 保留 unresolved。
- GraphML 改用標準 key/data；加入 provenance gap validator。
- 新增私有 SyncAndroid/ModelCamera evidence adapter、`fw evidence`、`fw unresolved`、`fw sdk coverage` 和 Phase 3.1 reports。

- 新增 schema v5 Semantic Graph、CFG edge、OSAL message、JNI bridge 和 SDK evidence model；Phase 3.1 增加 migration v6 body range/provenance tables。
- 修正同名 ELF 的 SONAME/搜尋路徑解析；無法唯一判定的依賴與 symbol 會保存 unresolved edge。
- 修正 Ghidra callsite caller 必須由明確 function entry 和 code range 驗證，新增 JSONL complete marker、hash/record-count validation、rollback。
- 新增 OSAL/JNI fixture analyzer、保守 DEX inventory、跨模組 trace、protocol/state/API 查詢及 JSON/GraphML export。
- 新增 5 組 P0/P1/P2 synthetic regression tests；不包含原廠 firmware 或私人資料庫。

## 0.2.0-alpha — 2026-10-08

- 建立 allowlist 公開發布目錄。
- 加入繁體中文 README、架構、資料模型、重現性、AI context 和研究狀態文件。
- 排除本機 SQLite、firmware、Ghidra project、raw JSONL、manifest 和 private runtime data。
- 保留 Phase 2 工具、schema、mock、合成測試與清理後報告。
- 採用 MIT License；公開發布只包含 allowlist 內容，不包含原廠韌體或私人研究資料。

- Added the SHA-pinned `parameter-objmsg` probe and descriptive contract.
  Five bounded regions verify `PrmObjMsg` construction, `+0x0c` getter,
  non-null destruction, deleting destruction and the clone candidate. The
  `MWF::ObjMsg` pointee, ownership, allocator pairing and runtime callability
  remain unknown.

- Extended `camera-selector` with direct primary-ELF validation of the local
  transform at `0x120168`: the low-12-bit guard, direct-return path and aligned
  `r2 + (r1 << 12) + r0` arithmetic are now recorded. C++ identity, return
  type, selector domain and downstream ModelCamera causality remain unknown.

- Added the `camera-prepare-envelope` primary-ELF probe for `0x125084`.
  It verifies the 16-byte allocation, zero-valued direct constructor call and
  key-6 `Event::addParameter` PLT binding while keeping the `0x7f25e0` tail
  target, receiver, delivery and completion semantics unresolved.

- Extended `camera-prepare-envelope` through its tail helper `0x7f25e0`.
  The probe now verifies `r2=1`, receiver `+0x10` loading and the unique
  `EventManager::push` PLT binding at `0xdf270`; runtime binding and delivery
  semantics remain unknown.

- Added the primary-ELF `event-manager-push` probe for symbol-bound entry
  `0x7ef960`. It records the AAPCS32 candidates, status branch, `[this+8]`
  dispatch, optional `[this+4]` completion callback and zero return while
  preserving indirect target and runtime semantics as unknown.

## 2026-10-10 — PrmCntInfoList collection growth evidence

Extended the private-only CntInfoList probe and Ghidra target profile with
index, length, growth and word-copy helpers. Updated the descriptive contract
and public snapshot header. No firmware bytes, raw disassembly or private
Ghidra output were added; runtime and callable API counts remain zero.

## 2026-10-10 — PrmCntInfoList removal evidence

Added bounded static evidence for CntInfoList removal, front-drop, temporary
copy and rebuild paths. Updated the descriptive contract, tests and private
Ghidra profile without adding firmware bytes or private analysis artifacts.

## Unreleased — corrected ParamSet Ghidra accessor profile

- Added bounded payload header/node accessors and recursive release evidence to
  the SHA-pinned private probe and descriptive SDK metadata. Direct offsets are
  `PRIMARY_ELF_VERIFIED`; `_Rb_tree` compatibility is `STATIC_INFERRED`.
- Fixed the targeted `ParamListTargets.java` profile to remove overlapping
  functions, use non-overlapping helper ranges and recreate missing targets.
  The corrected private run exits 0 with 28 bodies, 375 instructions, 55
  blocks, 96 edges and `COMPLETE_TARGET_EXPORT`.
- Full synthetic regression suite: 330 tests passed. Runtime verification and
  callable SDK counts remain zero; private firmware/Ghidra exports remain
  excluded.

- Added SHA-pinned PrmSet ARM EHABI metadata and bounded copy/clone cleanup
  observations. `__cxa_end_cleanup` PLT binding, copy cleanup and clone
  allocation cleanup remain static/inferred evidence; runtime/callable counts
  remain zero.
- Added the private-only `param-set-exceptions` Ghidra profile. The validated
  run exited 0 with 4 target bodies, 39 instructions, 4 blocks and 11 edges;
  raw export and private projects remain excluded.
- Added fail-closed validator coverage for missing or promoted exception
  evidence. Targeted PrmSet tests pass 22/22; the full local suite passes 347 tests.
## Unreleased — ParamBase family EHABI lifecycle evidence

- Added a generic, SHA-pinned `.ARM.exidx` metadata pass for all ten direct
  ParamBase-derived families, covering constructor, clone and destructor
  entries without publishing unwind words or firmware bytes.
- Extended the descriptive parameter lifetime contract and fail-closed tests;
  exception-object semantics, ownership, allocator pairing, runtime safety and
  callable status remain unknown.

## Unreleased — bounded PrmSet lifecycle caller scan

- Added a single-pass Thumb `BL` scan for the six named PrmSet lifecycle
  targets. The public contract records exact callsite counts and the scan
  boundary; absent direct calls do not rule out indirect dispatch or callers in
  another ELF.
- Kept owner/mutator identity and runtime/callable status unknown.

## Unreleased — ParamBase scalar constructor and lifetime evidence

- Added the SHA-pinned `parameter-scalar` probe and descriptive contract for
  `PrmBool` and `PrmNumber`. It verifies RTTI/vtable identity, ParamBase
  constructor calls, payload source/width at `+0x0c`, clone reloads, and D1/D0
  destruction paths without publishing firmware bytes.
- Recorded that constructors and clones do not initialize/copy element key
  `+0x08`; the ParamList insertion setter remains a separate key witness.
- Added six fail-closed regression tests and a private Ghidra lifecycle
  cross-check (22 targets, 342 instructions, 43 blocks, 72 edges). Runtime
  verification and callable SDK counts remain zero.

## Unreleased — ParamList shared-counter lifetime evidence

- Added the SHA-pinned `parameter-lifetime` probe and descriptive contract for
  ParamList construction, pointer-container initialization, `clear`, the
  unnamed shared rebind candidate, and the exported destructor.
- Recorded the observed object/container offsets and last-owner decrement path
  without promoting the shared-counter interpretation to a thread-safe or
  callable ownership API.
- Added eight fail-closed regression tests and a private Ghidra cross-check
  (11 targets, 130 instructions, 26 blocks, 43 edges). Runtime verification
  and callable SDK counts remain zero.

## Unreleased — ParamList external owner/use witness

- Added the SHA-pinned `parameter-owner-use` probe for the bounded
  `InputService::getInputEventStatus` body, including local ParamList
  construction/destruction, PrmNumber allocation, `ParamList::add`, lookup
  literals and the guarded shared-rebind call.
- Added a descriptive contract and eleven fail-closed regression tests. The
  C++ static/member form, ownership, dispatch, exception, concurrency and
  runtime/callable semantics remain unknown.
- Added a private Ghidra cross-check (6 targets, 210 instructions, 37 blocks,
  87 edges) without publishing firmware-derived bytes or exports.

## Unreleased — InputService cross-ELF import evidence

- Added the generic, symbol-parameterized `cross_elf_import_probe` and
  `parameter-cross-elf` CLI. It records exact undefined dynamic symbols,
  `R_ARM_JUMP_SLOT` relocations and ARM PLT/GOT bindings without publishing
  firmware bytes or absolute private paths.
- The private official 3.21 scan covered 511 ELF files and found nine
  importers of `InputService::getInputEventStatus`; the pinned `libObj.so`
  export was verified at `0x114105` with size 356.
- Provider selection remains `STATIC_INFERRED`, because DT_NEEDED and runtime
  loader binding are not established. The bounded direct BL/BLX scan found no
  immediate caller and retains that result as UNKNOWN coverage.
- Added the sanitized contract `sdk/input_service_cross_elf_3_21.json` and
  nine fail-closed regression tests. Runtime-verified and callable API
  counts remain zero.
- Added a private Ghidra 12.1.3 cross-check for `viewUnified4.so` (exit 0,
  ARM:LE:32:v8, image base `0x10000`) and recorded only sanitized importer,
  GOT and PLT metadata. The exact mangled name remains Ghidra-UNRESOLVED;
  the demangled external import is static evidence, not runtime or callable
  API proof.
