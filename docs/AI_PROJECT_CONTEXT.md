# AI Project Context

## 專案邊界

這是 Sony ILCE-6000 firmware 3.21 的離線逆向研究平台，不是 Sony 官方專案，也不
是 boot optimization 或 raw transfer patch。AI 工具只能修改公開 source、schema、
synthetic tests 和文件；不要要求或提交私人 firmware。

## 程式碼入口

- `fwplatform/db.py`：SQLite connection、migration、evidence upsert。
- `fwplatform/inventory.py`：格式辨識、SHA-256、manifest checkpoint。
- `fwplatform/importer.py`：既有研究 JSON 的保守匯入。
- `fwplatform/migration_v3.py`：identity、evidence merge、partition/module repair。
- `fwplatform/migration_v4.py`、`fwplatform/migration_v6.py`：Ghidra provenance、函式 body range、研究證據 adapter schema。
- `fwplatform/ghidra_importer.py`：JSONL validation、CFG/XREF import、failure checkpoint。
- `fwplatform/linkage.py`：SONAME、DT_NEEDED、loader search path、unique import/export graph 和 unresolved edges。
- `fwplatform/semantic_graph.py`：typed node/edge materialization、cross-module traversal、JSON/GraphML export。
- `fwplatform/osal.py`、`fwplatform/jni.py`：evidence-bound OSAL/JNI fixture import。
- `fwplatform/evidence_ingestion.py`：allowlisted、可重跑的 SyncAndroid/Camera historical evidence adapters；來源 hash、locator 和原始 status 會保留。
- `fwplatform/phase3_1_reports.py`：從 SQLite 產生 Phase 3.1 稽核與 coverage 報告。
- `analyzers/dex_analyzer.py`：對 DEX header/string/type/proto/method/class_def tables 做邊界檢查與保守解析；method_id 僅是引用。
- `fwplatform/dex_index.py`：將 DEX 表格的靜態結構觀測存入 SQLite，確保 SHA-256 與解析位元組一致，異常時 rollback。
- `fwplatform/cli.py`：inventory、分析、protocol/state/API/semantic graph 查詢和報告命令。
- `database/migrations/005_semantic_graph.sql`、`006_ranges_evidence.sql`、`007_identity_repairs.sql`、`fwplatform/migration_v5.py`、`migration_v6.py`、`migration_v7.py`：Phase 3.1–3.3 schema。
- `fwplatform/phase2_reports.py`：從 SQLite 產生 audit files。

## Ghidra pipeline

1. Wrapper 計算 input SHA-256、讀取 Ghidra version、清除舊輸出。
2. `analyzeHeadless` 使用 Auto Analysis 載入單一 ELF。
3. `AnalyzeBinary.java` 輸出 metadata、functions、ARM/Thumb instructions、basic blocks、
   CFG edges、callsites、XREF 和 symbols；輸出 JSONL 有 complete marker，不追加舊 run。
   `ParamFamilyReferences.java` 可在既有私有 Ghidra project 上輸出 ParamBase
   constructor/destructor 與 factory 的 address-space-aware xrefs；它只輸出
   metadata，不輸出指令 bytes。
4. Importer 驗證 binary hash、program identity、record count 和 complete marker，使用
   transaction/savepoint 寫入 `analysis_run`、`evidence`、CFG tables；失敗會 rollback。
5. 同一輸入與 analyzer version 可增量重跑；錯誤會保留 FAILED checkpoint。

## 已驗證成果

本地 Phase 2 audit 已驗證一個 ARM/Thumb ELF 的實際 headless execution、CFG、XREF、
call graph query 和 repeated import。公開版只保留 sanitized report，不包含 raw export。

## 未解決問題

Phase 3.1 已可在私有 DB 副本匯入 SyncAndroid/ModelCamera 的選定研究檔案；receiver
function identity、Java body 的執行期含義、message completion、camera ready/first-shot
條件仍是 UNKNOWN 或 CANDIDATE。不要從 function name、同值 numeric ID 或 symbol index
推導完整功能。

## CLI

```text
fw manifest build --root <private-workspace>
fw coverage --json
fw analyze elf --root <private-workspace> --limit 1
fw analyze ghidra --root <private-workspace> --binary <elf> --jsonl <output>
fw analyze linkage --root <private-workspace>
fw analyze osal --fixture <osal.json>
fw analyze jni --fixture <jni.json>
fw analyze dex --path <local.dex>
fw query dex <name-or-descriptor>
fw analyze semantic
fw callers <function>
fw callees <function>
fw callsite <address>
fw xrefs <binary>:<address>
fw trace <function> --depth 3
fw trace <function> --cross-module --depth 3
fw protocol queue <queue-id>
fw state <state-machine>
fw query api <name>
fw evidence <relation-or-id> --json
fw unresolved --json
fw coverage --domain camera_core --json
fw sdk coverage --json
fw analyze evidence --root <private-research-root> --profile targeted --json
fw graph export --format graphml --output <graphml>
```

## 下一步

優先擴充真實證據 adapter 的 locator/ABI 驗證、受控 multi-ELF Ghidra checkpoint、事件
與狀態機關係及 SDK evidence schema；任何實機研究都必須另行保留、不得自動同步到公開目錄。
# Primary helper continuation (2026-10-09)

Newest checkpoint: `sdk/parameter_types_lifetime_3_21.json` describes real
PrmNumber/PrmBool layouts plus primary RTTI/vtable/layout evidence for all
ten direct ParamBase-derived records, including PrmString, PrmPoint,
PrmDimension, PrmStruct and PrmSet. Inspect
`test_parameter_types.py` before changing offline decoding: tag alone is
insufficient, Bool padding is not value, and relocated vptrs need load bias.
Assignment-like sharing and replacement deletion are confirmed locally; get
results have no lifetime extension. External synchronization remains unknown.

`fwplatform/param_family_probe.py` is a private SHA-pinned metadata extractor;
it publishes no instruction bytes and always keeps runtime/callable flags false.
Its independent discovery pass finds ten direct ParamBase-derived RTTI/vtable
records. PrmString, PrmPoint, PrmDimension, PrmStruct and PrmSet now have
static object-size/layout witnesses in addition to the earlier three families;
their allocator/helper details, pointer ownership and complete copy paths
remain UNKNOWN. Only PrmNumber and PrmBool payload semantics are decoded.

Latest: `ParamListTargets.java` in an ASCII Ghidra installation exits 0. The
lifecycle profile exported 22 bounded targets, 342 instruction rows, 43 basic
blocks and 72 CFG edges to a private output file.
The current private checkpoint also verifies the bounded factory candidate
`0x42acd4`: discriminator values 5, 1 and 3 route to Bool, Number and Point
constructors, respectively, with four direct callers. Its descriptive ABI is
recorded in `sdk/core_3_21_primary_helper_contracts.json`; ownership and
runtime safety remain unknown.
The supporting forwarders/getters are bounded at `0x120970`, `0x120968`,
`0xfe9be`, `0xfe9ae` and `0xfe9b6`; the latest private core export has 16
targets, 198 instruction rows, 46 blocks and 73 edges.
The new `fw sdk parameter-factory --elf <private-libObj.so>` probe confirms
four factory callers prepare dynamic table-derived `r1/r2` values, guard the
factory result, and call the relocation-resolved `ParamList::add` PLT
(`0xdfdc0`, GOT `0x102e340`) on success. Its local implementation is the
48-byte Thumb symbol `0x7ee0e7` at `0x7ee0e6`; replacement can dispatch an
existing element's virtual deletion slot before insertion. Values, ownership,
locking and runtime callability remain unknown. This is metadata-only output;
the private probe result must stay outside the public checkout.
The 76-byte ParamList::get has 30 matched instruction boundaries, 7 blocks,
8 local CFG edges and 4 calls. Lookup returns an existing matched object or null.
The follow-up ASCII Ghidra run covering factory plus mutation/storage targets
exited 0 with 19 bounded targets, 292 instruction rows, 66 blocks and 112
edges. It remains targeted evidence rather than full-libObj analysis.
The subsequent `parameter-mutation` probe verifies clear (`0x7edb76`/`0x7edb40`),
destructor (`0x7edd08`) and unnamed shared-assignment (`0x7edcc6`) facts. The
destructor delete PLT resolves to `_ZdlPv` at GOT `0x102d6bc`; copy-on-write,
locks, exception behavior and runtime safety remain unknown. A private
`-noanalysis` Ghidra rerun exits 0 with 21 targets, 343 instructions, 79 blocks
and 135 edges.
The `parameter-numberlist` probe then validates nine primary-ELF regions for
`PrmNumberList`: vector layout at `+0x0c`, indexed access, length, append
capacity handling, default/copy constructors and destruction. Its contract is
`sdk/param_numberlist_3_21.json`; allocator, bounds, synchronization,
exception and runtime behavior remain unknown.
The `parameter-cntinfolist` probe then validates twelve primary-ELF regions for
`PrmCntInfoList`, including discriminator initialization, both collection
regions, accessors, append, constructors and destruction. Its contract is
`sdk/param_cntinfolist_3_21.json`; collection element types and safety remain
unknown.
The latest private checkpoint also validates the bounded Camera selector helper
at `ELF_VMA 0x12d780` with `fw sdk camera-selector --elf <private-libObj.so>`.
The exact SHA-pinned ELF shows a `[r0] == 0x40` branch that calls the
relocation-bound `IdGenerator::Get`, selects `0x12000000` for second byte `M`
and `0x13000000` for `V`, then calls `0x120168` with the model ID and original
selector. The general branch reaches a guarded vtable-slot `+8` call and
returns `-1` for a null prepared object. The transform, helper semantics,
return type, ModelCamera causality, runtime behavior and callability are
UNKNOWN; the SDK contract is descriptive only. Four synthetic fail-closed
tests cover the metadata validator, and the private probe is never committed.
Its local transform at `0x120168` is now directly checked as well: non-aligned
selectors return the original `r2`, while aligned selectors return
`r2 + (r1 << 12) + r0`. The arithmetic is primary-ELF verified; C++ identity,
return type, selector domain and ModelCamera causality remain UNKNOWN.
Read `paramlist_snapshot.py` for offline parsing and the candidate SDK header.
Other payload families, complete mutation/copy paths and runtime ABI remain
unresolved; the older logging exit-1 paragraph below describes the preserved
earlier attempt.

Read `reports/CORE_PRIMARY_HELPER_AUDIT.md` before repeating the handoff's
missing-byte conclusion. Real private SHA-pinned libObj.so was read with Capstone.
`fwplatform/elf_plt.py` resolves interworking PLT relocations;
`fwplatform/primary_contracts.py` validates the additive descriptive SDK fixture.
Targeted Ghidra instructions agree after image-base mapping, but tail-call
decompilation is rejected. The earlier non-ASCII process exit 1 remains a
preserved historical environment record; the ASCII rerun is the current
successful path.
No runtime/callable interface was validated. Next targets are the remaining
ParamBase subclasses, source-level copy identity, and caller synchronization.

The `parameter-objmsg` probe now validates five bounded primary-ELF regions for
`PrmObjMsg`: discriminator `8`, constructor input copied to `+0x0c`, the
getter, non-null release path and clone candidate. The pointee layout,
ownership/allocator pairing, exception behavior, clone C++ identity and
runtime/callable status remain UNKNOWN. Its contract is
`sdk/param_objmsg_3_21.json`; four synthetic fail-closed tests cover the
metadata validator.

The Camera prepare envelope probe at `0x125084` independently confirms a
16-byte allocation, a zero-valued direct call to `0xf0fb0`, and key `6` passed
with the new parameter object through the unique PLT binding of
`Event::addParameter`. The tail target `0x7f25e0`, receiver identity, event
delivery/completion and full constructor C++ identity remain UNKNOWN. Its
contract is `sdk/camera_3_21_prepare_envelope.json`; runtime/callable flags
remain false.

## Phase 3.31 — PrmStruct evidence

`fwplatform/param_struct_probe.py` adds the private-only discriminator-6
PrmStruct probe. It validates the vtable/RTTI pair and bounded constructor,
destructor, deleting-destructor and clone paths. The constructor uses
`malloc`/`memcpy` for a pointer-plus-length payload at `+0x0c/+0x10`; the
destructor calls `free`. Nested schema, serialization, invalid-input,
allocator, aliasing, synchronization and runtime semantics remain unknown.

CLI: `fw sdk parameter-struct --elf <private-libObj.so> --json`.
Contract: `sdk/param_struct_3_21.json`. Five fail-closed synthetic tests are
included. Private Ghidra targeted cross-check: exit 0, 4 targets, 54
instructions, 4 blocks and 9 edges. Runtime verification and callability
remain false.

The prepare envelope probe now follows `0x7f25e0`: it verifies `r2=1`, a
receiver `+0x10` load and the unique PLT relocation of `0xdf270` to
`EventManager::push(Event*,bool)`. This is a static symbol/dispatch fact only;
runtime binding, receiver class, event delivery/completion and complete C++
signature remain UNKNOWN.

The `event-manager-push` probe now validates the implementation at symbol-bound
entry `0x7ef960`: `r0=this`, `r1=Event*`, `r2=bool`, status branch through
`0x7ef88c`, success dispatch through `[this+8]`, optional completion callback
through `[this+4]`, and visible zero returns. Indirect targets, helper
semantics, queue/thread behavior, ownership and runtime callability remain
UNKNOWN. Contract: `sdk/event_manager_push_3_21.json`.

## Phase 3.25 — EventManager initializer evidence

`fwplatform/event_manager_init_probe.py` and
`sdk/event_manager_init_3_21.json` add a bounded, SHA-pinned check at
`ELF_VMA 0x7ef894`. Primary instructions verify the receiver `+0x04` callback
candidate, `pthread_mutex_init(receiver +0x0c, 0)`, provider vtable slot
`+0x30` result at `+0x08`, and two eight-byte state allocations initialized
through local `0x7f09be`. PLT bindings for `pthread_mutex_init`, `_Znaj` and
`_Znwj` are unique static evidence. The association with EventManager is
`STATIC_INFERRED` because no constructor symbol was proven. The bounded helper
chain now verifies that `0x1111b8` clears the two words and `0x1111a2` writes
the two self-links at `+0x00` and `+0x04`; this is a structural observation,
not a source-level container name. Ownership, destruction, exception behavior,
runtime binding and callability remain unknown/false. Seven fail-closed synthetic
tests accompany `fw sdk event-manager-init`; the private firmware is never
committed.

The private Ghidra cross-check for the initializer uses the ASCII Ghidra
12.1.3 installation and a dedicated `event-manager-init` target profile in
`ghidra-scripts/ParamListTargets.java`. With `-noanalysis`, headless execution
exited 0 and reproduced the 78-byte body at image-base-mapped address
`0x7ff894` (original `ELF_VMA 0x7ef894`), all 27 instruction boundaries and
six call edges. The updated profile also exports the bounded helper chain as
15 targets, 162 instruction rows, 23 blocks and 37 edges. The adjacent
cleanup candidate `0x7f09d2` iterates the same link words, passes each
`current+8` payload through static `Event::~Event` and `_ZdlPv` bindings, and
retains an exception cleanup path through `__cxa_end_cleanup`; this does not
prove EventManager ownership or destructor identity. The decompiler leaves
parameters undefined, so Capstone and Ghidra agree on instruction/layout facts
only. A separate full Auto Analysis
attempt was intentionally stopped before completion; it is not counted as a
successful analysis.

## EventManager::count evidence

`fwplatform/event_manager_count_probe.py` and
`sdk/event_manager_count_3_21.json` add a primary-ELF static contract for the
symbol `_ZN12EventManager5countEj` at `ELF_VMA 0x7ef9fc` (Thumb value
`0x7ef9fd`, 34 bytes). The symbol supplies an unsigned index parameter;
Capstone verifies the receiver/index register shape, the state pointer load,
the indexed word access `[state + (index << 2)]`, helper `0x7f0aa0`, and
cleanup helper `0x7ef902`. There is no local conditional bounds check in the
bounded body, so state allocation, valid index range, helper semantics,
ownership and null/runtime safety stay UNKNOWN. The CLI is
`fw sdk event-manager-count --elf <private-libObj.so> --json`.

The private ASCII-path Ghidra 12.1.3 `event-manager-count` profile used
`ARM:LE:32:v8`, image base `0x10000`, `-noanalysis`, and exited 0 with the
complete marker, 13 instruction rows, one block and three call edges. The
export is private; generated Ghidra names are not semantic API names. Runtime
verification and callable SDK status remain false.

The follow-up probe also verifies the bounded helper chain at `0x7f0a32`,
`0x7f0a42`, `0x7f0a4e`, `0x7f0a7a`, `0x7f0a84` and `0x7f0aa0`: it compares a
current pointer with a sentinel, follows the current node's first word and
counts forward-link steps. This is a `STATIC_INFERRED` structural operation;
it does not identify a source-level standard container or prove a terminating
chain. The lock/unlock wrappers at `0x7ef8f4` and `0x7ef902` have unique static
PLT bindings to `pthread_mutex_lock` and `pthread_mutex_unlock`, respectively,
while runtime loader binding and complete concurrency safety remain unknown.
The corrected private Ghidra export contains 12 targets, 100 instructions,
15 blocks and 18 edges.

## Phase 3.26 — request-model Event factory

`fwplatform/camera_request_event_probe.py` verifies the symbol-bound primary
ELF factory `_ZN22AbstractUtilityManager30createRequestModelExecuteEventEimP9ParamList`
at `0x7f0b0c`. It records the explicit AAPCS32 argument shape, literal event
ID `0x11004003`, optional ParamList attachment, and model/selector parameter
keys 7/8. Unique PLT bindings are retained as static evidence. The local
PrmNumber constructor, Event return type, ownership, exception table,
consumer delivery, runtime binding and callability remain unresolved.
The private Ghidra targeted profile exits 0 with 36 instruction rows and 12
edges; it is not full-library Auto Analysis. The public contract remains
runtime/callable false.

## Phase 3.27 — Event object/lifetime evidence

`fwplatform/event_core_probe.py` adds primary static contracts for six Event
methods. The constructor creates a shared counter and ParamList storage; the
copy constructor shares the counter/ParamList pointer; the destructor performs
last-counter cleanup. `setParamList` has explicit null, same-pointer and
replacement branches. Parameter add/get forward to ParamList through
ARM/Thumb interworking veneers. These facts do not prove external ownership,
thread safety, runtime loader binding or callability. The targeted private
Ghidra profile exits 0 with 77 instructions, 24 edges and 15 blocks.

## Phase 3.28 — PrmSet embedded payload evidence

`fwplatform/param_set_probe.py` adds the bounded `fw sdk parameter-set` probe
and `sdk/param_set_3_21.json`. Primary ELF evidence confirms the discriminator-7
`getSet`/GET methods, 36-byte construction, a 24-byte embedded payload, clone
copy path and destructor path. The payload is documented only as an
ordered-container-like candidate: source type, element type, comparator,
allocator, alias and synchronization semantics remain UNKNOWN. The latest
private ASCII Ghidra `param-set` profile exits 0 with 21 targets, 354
instruction rows, 49 blocks and 97 CFG edges. Runtime verification and
callable SDK counts remain zero.

## Phase 3.31 — PrmSet tree-helper and lifetime boundary

The same authenticated ELF now has direct relocation evidence for six
libstdc++ `_Rb_tree` traversal/insertion symbols. Bounded helpers show a
20-byte node allocation unit, node value copy at `+0x10`, header sentinel at
payload `+0x04`, and node count at `+0x14`; the PrmSet copy and recursive
release paths preserve/use those fields. This establishes an
ordered-associative-tree-like **ELF-local model**, not an exact `std::set`
source declaration. The `0xffe70` insert helper has not been uniquely tied to
a named PrmSet mutator.

`sdk/param_set_3_21.json` and `sdk/paramlist_3_21_candidate.hpp` preserve the
offsets, PLT/GOT identities, direct `6PrmSet` to `ParamBase` RTTI relation and
all UNKNOWN boundaries. ParamList's shared counter and virtual element
destruction imply that `ParamList::get`/`PrmSet::getSet` results are borrowed
interior-pointer candidates; replacement or destruction can invalidate them.

The follow-up value-helper probe records a one-word node value at `+0x10`, a
Capstone/Ghidra-confirmed unsigned-order comparator at `0xefe6c`, a conditional
single-word copy helper at `0xecd7a`, and direct `0xffe70` callsites at
`0xfff4e`, `0xfff86` and `0x7f4402`. These facts do not identify the source
typedef or prove that any caller is a PrmSet mutator; those relations remain
UNKNOWN.
Null behavior, synchronization, exception cleanup, runtime loader binding and
callability remain unverified.

## Phase 3.29 — PrmPoint / PrmDimension inline-word evidence

`fwplatform/param_pair_probe.py` adds the reusable `fw sdk parameter-pair`
profile and `sdk/param_pair_3_21.json`. It verifies `PrmPoint` discriminator 3
and `PrmDimension` discriminator 4, their 20-byte constructors, inline words
at object `+0x0c/+0x10`, vptr/base destruction and clone paths. The two words
remain semantic UNKNOWN; no coordinate, dimension or hardware unit is inferred.
The private Ghidra profile exits 0 with 8 targets, 96 instruction rows, 8
blocks and 12 edges. Runtime verification and callable SDK counts remain zero.

## Phase 3.30 — PrmString evidence

`fwplatform/param_string_probe.py` is the next private-only ParamBase probe.
It validates the discriminator-2 vtable/RTTI pair and bounded constructor,
destructor, deleting-destructor and clone paths. The constructor uses
`strlen`, `new[]` with length plus one and `strncpy`; the destructor conditionally
uses `delete[]`. The payload is documented as an owned byte-buffer pointer
candidate at `+0x0c`, with encoding and ownership transfer rules unknown.

CLI: `fw sdk parameter-string --elf <private-libObj.so> --json`.
Contract: `sdk/param_string_3_21.json`. Five fail-closed synthetic tests are
included. Private Ghidra targeted cross-check: exit 0, 4 targets, 60
instructions, 6 blocks and 14 edges. Runtime verification and callability
remain false.

## Phase 3.32 — PrmCntInfoList collection growth evidence

The new bounded probe regions are available through
`fw sdk parameter-cntinfolist --elf <private-libObj.so> --json`. It records the
index helper, length arithmetic, full-capacity append branch and guarded
32-bit word copy. The public header exposes two ten-word storage candidates at
`+0x0c` and `+0x34` without naming a standard container. Private targeted
Ghidra exited 0 with 18 targets, 237 instructions, 22 blocks and 47 edges.
This remains PRIMARY_ELF_VERIFIED static evidence only; runtime verification,
thread safety, null safety and callable ABI remain UNKNOWN/false.

## Phase 3.33 — PrmCntInfoList removal evidence

`fw sdk parameter-cntinfolist --elf <private-libObj.so> --json` now records the
`remove(unsigned)` control flow, copy/drop-first helpers and rebuild branch.
The result remains a descriptive PRIMARY_ELF_VERIFIED record: invalid-index,
ownership, aliasing, exception, synchronization and runtime behavior remain
unknown. Private targeted Ghidra: exit 0, 22 targets, 384 instructions, 38
blocks and 96 edges.

## Latest primary checkpoint: PrmObjMsg RTTI and payload lifetime (2026-10-10)

`fwplatform/param_objmsg_probe.py` now cross-checks the exact SHA-pinned ELF's
RTTI/vtable and PLT relocations, not only the five bounded bodies. It verifies
RTTI `0xfec488` (`9PrmObjMsg`), vtable prefix/address point
`0xfec498`/`0xfec4a0`, direct `_ZTI9ParamBase` base relocation, and slots for
clone/destructors. The key relocation
correction is that `0xddd94` is `MWF::ObjMsgD1`, `0xddee4` is the
`PrmObjMsg` getter veneer, and `0xe0388` is `MWF::ObjMsg`'s copy constructor.
The clone candidate consequently follows getter -> `_Znwj(8)` -> ObjMsg copy ->
`_Znwj(0x10)` -> PrmObjMsg constructor. The non-null destructor path calls
ObjMsg D1 then `_ZdlPv` before the ParamBase path.

These relations are `PRIMARY_ELF_VERIFIED` static facts with
`runtime_binding=UNKNOWN`; ownership transfer, MWF object layout, exception
handling, locking, concurrent use and runtime/callable safety remain unknown.
The descriptive contract is `sdk/param_objmsg_3_21.json`, and the probe's six
synthetic fail-closed tests do not require private firmware. A private ASCII
Ghidra 12.1.3 targeted run exited 0 with 5 targets, 62 instructions, 7 blocks
and 14 edges. No firmware bytes or raw Ghidra output is part of the public tree.

## Latest usage-xref checkpoint: PrmObjMsg clone/lifetime path (2026-10-10)

The new metadata-only `ghidra-scripts/ParamObjMsgUsage.java` profile validates
against the pinned ELF SHA and exports only target/reference/function-entry
metadata. Its private `-noanalysis` run exits 0 with eight xrefs. Four direct
internal relations are observed: clone `0x12c784` calls the constructor PLT at
`0x12c7a6`, getter PLT at `0x12c788`, and ObjMsg copy constructor PLT at
`0x12c798`; destructor `0x12c700` calls ObjMsg D1 at `0x12c718`. The local
constructor has only external/data references in this targeted program.

The SDK contract stores these observations as `STATIC_INFERRED` usage evidence.
They narrow the observed libObj-only path but are not an exhaustive whole
firmware call graph, ownership proof, or runtime validation.

## ParamBase family constructor usage checkpoint (2026-10-10)

`ghidra-scripts/ParamFamilyUsage.java` is the reusable metadata-only xref
profile for the ten family constructor targets. It validates the pinned
`libObj.so` SHA and exports only target/callsite/reference/caller-entry
metadata. `fwplatform/param_family_usage.py` rejects truncated or mismatched
exports, normalizes reference kinds and produces a fail-closed public summary.
The read-only query is `fw sdk parameter-family-usage`.

A private Ghidra 12.1.3 ARM:LE:32:v8 project with image base `0x10000` was
bounded to 300 seconds. Auto Analysis timed out, although the post-script
completed; the checked-in contract therefore marks `PARTIAL_TIMEOUT`. It has
10 family records and 858 observed xrefs: Bool 95, Number 628, String 21,
Point 10, Dimension 13, Struct 82, Set 0, NumberList 3, CntInfoList 3 and
ObjMsg 3. These are partial observations, not exhaustive usage counts. The
three symbol records have one computed-call relation plus external/data
references; a computed PrmObjMsg constructor call at `0xf2088` is kept
separate from its earlier direct PLT clone callsites. No runtime or callable
claim is made, and no raw export is committed.

The export keeps `FROM_ELF_VMA`/`FROM_GHIDRA` and caller-entry addresses
separate, together with the Ghidra address space, so the image-base mapping is
explicit rather than mixed into the original ELF VMA.

`fwplatform/param_family_callsite_probe.py` adds a second, independent static
layer for five direct constructor callsites. It verifies the direct Thumb
branch and nearest allocator-size witness, then reports visible pre-call
AAPCS32 register definitions without treating them as complete data-flow. The
public contract is `sdk/param_family_callsites_3_21.json`; Point's signed
halfword pair and Struct's pointer-plus-length candidate are recorded as
memory-source observations, while Bool/Struct post-dispatch numeric keys are
scoped to their callsites. Allocator calls clobber unknown registers in the
summary. No runtime or callable API claim is made.

## ParamBase foundation checkpoint (2026-10-10)

`fwplatform/param_base_probe.py` provides the independent base-class evidence
layer. Against the SHA-pinned private `libObj.so`, it verifies ParamBase RTTI
`0xfe6e24`, vtable prefix/address point `0xfe6e30`/`0xfe6e38`, the
`__cxa_pure_virtual` clone slot, destructor slots `0xe4734`/`0xe4854`, and
the constructor's writes to vptr `+0x00` and discriminator `+0x04`. The
bounded base constructor does not write key `+0x08` or payload `+0x0c`; the
separate key setter is `0x7eda84`. Ten direct derived RTTI relations are
recorded in `sdk/param_base_3_21.json`.

The private `ParamBaseTargets.java` Ghidra 12.1.3 `-noanalysis` cross-check
used `ARM:LE:32:v8`, image base `0x10000`, and exited 0 with four targets, 31
instruction rows, four blocks and two CFG edges. This is targeted static
evidence only. Ownership, copy/assignment, exception handling, locking,
runtime binding and callable SDK status remain unknown/false.

## Cross-ELF ParamSet caller checkpoint (2026-10-10)

`fwplatform/paramset_cross_elf.py` is the reusable cross-ELF importer for
metadata-only Ghidra symbol-reference exports. It validates the complete
JSONL marker and record count, keeps Ghidra image-base addresses separate from
ELF VMAs, resolves undefined dynamic symbols through `.rel.plt` and ARM PLT
instructions, and validates each application call instruction with Capstone.
It never executes firmware and never emits instruction bytes or decompiler
text. It resolves Ghidra references by exact relocation-bound PLT VMA rather
than by a demangled name, preventing same-name `GET` symbols from other
ParamBase families from being treated as `PrmSet` calls.

`ghidra-scripts/ImportedSymbolReferences.java` accepts an output path and one
or more exact or wildcard symbol names. It records symbol namespace, Ghidra
address, ELF VMA, reference type, callsite, caller entry, address space and
program SHA. PLT self references stay visible in private export data but are
excluded from application caller relations by the Python analyzer.

The first real dependent-ELF contract is
`sdk/paramset_cross_elf_3_21.json`. The private 3.21 library scan found
`libScalarDaemon.so` as the only scanned ELF importing both `PrmSet::GET` and
`PrmSet::getSet`; the contract records its SHA, the authenticated `libObj.so`
provider exports, relocation/GOT/PLT identities and the two application
callsites. The static chain is:

`EventDispatcher::dispatchSystemEvent` (`0xd5b5c`) → `GET` (`0xd5b7a`,
`r1=0x19`) → null guard (`0xd5b7e`) → `getSet` (`0xd5b80`).

The exact call edges are `PRIMARY_ELF_VERIFIED` through Ghidra plus Capstone;
the contract exposes this as `chain_status=PRIMARY_ELF_VERIFIED` together with
`chain_semantic_status=STATIC_INFERRED` for the composed source-level
return/ownership interpretation. `runtime_verified=false` and `callable=false`
are required.
Run the private evidence path with:

```text
fw sdk parameter-set-cross-elf --elf <private-libScalarDaemon.so> \
  --ghidra-export <private-imported-symbols.jsonl> \
  --provider-elf <private-libObj.so> --json
```

Without private inputs, `fw sdk parameter-set-cross-elf --json` validates and
prints the sanitized checked-in contract. Seven targeted parser/validator/CLI
tests and the 328-test local suite pass. Raw firmware, Ghidra projects, JSONL
exports and private paths stay outside the public checkout.

## ParamSet header/node lifetime checkpoint (2026-10-10)

The private-only `fwplatform.param_set_probe` now validates direct accessors in
`libObj.so` at `0xffc40`, `0xffc60`, `0xffc68`, `0xffc70`, `0xffccc`,
`0xffcd4` and `0xffcdc`, plus recursive release at `0xffd80`/`0xffdf6`.
The observed payload header begins at `payload +0x04`, links are initialized at
`+0x0c`/`+0x10`, the root is read from `+0x08`, and the count candidate is at
`+0x14`. The separately allocated node is 20 bytes with one-word value storage
at `+0x10` and link candidates at `+0x08`/`+0x0c`.

These offsets are `PRIMARY_ELF_VERIFIED`; compatibility with the imported
libstdc++ `_Rb_tree` header/node ABI is `STATIC_INFERRED`. The exact source
container alias, element type/comparator, allocator, owner-release and
concurrency behavior remain `UNKNOWN`. This is descriptive offline metadata,
not a live object declaration. The probe enforces the private ELF SHA and
never emits firmware bytes. `runtime_verified=false` and `callable=false`.
The targeted Ghidra profile includes the accessor range, while its project and
export remain private.

The corrected private Ghidra accessor rerun used non-overlapping target ranges
and explicit overlap cleanup. It exited 0 with `COMPLETE_TARGET_EXPORT`, 28
bodies, 375 instruction rows, 55 blocks and 96 CFG edges; the first overlapping
range attempt is retained as a failed run observation and is not counted.

## ParamSet helper caller-range checkpoint (2026-10-10)

`ghidra-scripts/TargetCallers.java` is a metadata-only, SHA-pinned exporter
for exact target VMAs. `fwplatform/target_callers.py` validates its completion
marker, program identity, image-base mapping, caller body ranges and reference
counts, then separates Ghidra-derived caller identity from Capstone-confirmed
callsite facts. The public, sanitized contract is
`sdk/param_set_tree_callers_3_21.json`; raw export text remains private.

The current private run used Ghidra 12.1.3 `ARM:LE:32:v8`, image base
`0x10000`, and exited 0. It records eight references to the generic helpers:
three calls to `0xffe70` from `0x7f4390`/`0xffed0`, four calls to `0xffed0`
from `0x7f4390`/`0xfffb6`, and one call to `0x7f4390` from `0x7f44ce`.
Capstone's exact Thumb `BL` scan agrees with all eight. The body ranges are preserved in ELF VMA form, and generated
`FUN_...` labels are explicitly non-semantic. The generic helper has not been
identified as a PrmSet mutator; runtime ownership, exception behavior,
locking and callable safety remain unknown/false.

Use `fw sdk parameter-set-callers --json` to validate the checked-in contract,
or supply private `--ghidra-export` and `--elf` inputs for a local reparse.

## PrmSet vtable metadata checkpoint (2026-10-10)

`fwplatform.param_set_probe` now reads PrmSet RTTI/vtable words only from a
unique file-backed ELF `PT_LOAD`. The SHA-pinned private run verifies the
prefix `0x1019d18`, RTTI `0x1019d08`, address point `0x1019d20`, and Thumb
targets `0x7efbb4`, `0x7efb2c`, `0x7efb58` (raw words `0x7efbb5`, `0x7efb2d`,
`0x7efb59`). Target addresses are primary static facts; clone/destructor role
labels are static inferences from the bounded bodies and vtable slot position.
The sanitized result is in `sdk/param_set_3_21.json`, with descriptive
constants in `sdk/paramlist_3_21_candidate.hpp`. The constructor still has no
observed key `+0x08` store; key initialization remains scoped to `0x7eda84`.
The same contract separates bounded no-null-guard observations from unknown
invalid-node, alias-invalidation and concurrency behavior. Runtime verification
and callable API counts remain zero. A fresh private ASCII-path Ghidra
`ParamListTargets.java param-set` run exited 0 with 28 target bodies, 375
instruction rows, 55 blocks and 96 CFG edges; its export remains private.


## PrmSet exception-boundary checkpoint (2026-10-10)

The primary-ELF-only `fwplatform.param_set_probe` now indexes ARM EHABI
`.ARM.exidx` records for the PrmSet copy helper (`0x7efb6c`) and clone
candidate (`0x7efbb4`). Capstone verifies cleanup-shaped calls at `0x7efb9c`
and `0x7efbce`; the unique PLT binding at `0xdd4f8` is
`__cxa_end_cleanup`. The public contract is `sdk/param_set_3_21.json` and
the descriptive constants are in `sdk/paramlist_3_21_candidate.hpp`.

These records distinguish direct instruction/relocation facts
(`PRIMARY_ELF_VERIFIED`) from exception relationship interpretation
(`STATIC_INFERRED`). The bounded cleanup path does not prove all throw edges,
exception-object semantics, allocator pairing, source-level clone return type,
owner identity or runtime safety. `runtime_verified=false` and
`callable=false` remain required.

The private `ParamListTargets.java param-set-exceptions` profile uses
non-overlapping cleanup ranges and completed with Ghidra 12.1.3,
`ARM:LE:32:v8`, image base `0x10000`, exit 0, `COMPLETE_TARGET_EXPORT`,
4 targets, 39 instructions, 4 blocks and 11 edges. Raw exports and projects
remain private.
### ParamBase family EHABI lifecycle index (2026-10-10)

`fwplatform/param_family_probe.py` now records sanitized `.ARM.exidx`
metadata for the constructor, clone, non-deleting destructor and deleting
destructor of all ten direct ParamBase RTTI families.  The primary ELF pass
requires one exact entry per target and keeps the function VMA, `.exidx`
locator, address space and compact/EXTAB classification; it does not publish
unwind words or raw firmware.  The checked-in
`sdk/parameter_types_lifetime_3_21.json` metadata and regression tests preserve
this evidence.  EHABI metadata remains static evidence only: exception-object
types, complete throw paths, allocator pairing, ownership, locking, runtime
binding and callable safety are UNKNOWN; runtime/callable counts remain zero.

The PrmSet probe also records a bounded direct Thumb `BL` caller scan for
`getSet`, `GET`, constructor, both destructor slots and clone.  The pinned
`libObj.so` has no direct `BL` callers for the first, second, constructor,
deleting-destructor or clone targets; `0x7efb5e` calls the non-deleting
destructor from the deleting path.  This does not cover BLX/register/vtable
dispatch or other ELFs, so owner/mutator identity remains UNKNOWN.

### ParamList::add replacement boundary (2026-10-10)

`fwplatform/paramlist_add_probe.py` and `sdk/paramlist_add_3_21.json` record a
new primary-ELF static checkpoint that complements the existing `get` and
destructor evidence. The exact symbol `_ZN9ParamList3addEmP9ParamBase` is at
ELF VMA `0x7ee0e6`. It calls an unnamed replacement body at `0x7ededa`; on the
nonzero path it invokes the key setter `0x7eda84`, which stores the key at
element `+0x08`, and then appends the pointer through `0x7ee0b8`. The add body
does not write subclass payload `+0x0c`.

The replacement body compares pointer identity, key `+0x08` and discriminator
`+0x04`; a matching old element is dispatched through vtable slot `+8` and its
four-byte pointer slot is removed. This is static evidence supporting a
`STATIC_INFERRED` borrowed-pointer invalidation risk for an earlier
`ParamList::get` result. The replacement body has no source-level name, and
ownership, allocator pairing, exception paths, locking, concurrency, runtime
binding and callable safety remain UNKNOWN. Run the private-only probe with:

```powershell
python -m fwplatform.cli sdk parameter-add --elf C:\private\libObj.so --json
```

An ASCII-path Ghidra 12.1.3 targeted export cross-checked 21 bounded targets,
343 instructions, 79 blocks and 135 edges with exit 0 and the complete marker.
The private export is not part of the public checkout.

### ParamBase scalar lifecycle checkpoint (2026-10-10)

`fwplatform/param_scalar_probe.py` is the reusable bounded probe for the two
scalar ParamBase families where the constructor, clone and destructor paths can
be checked as one chain.  Against the exact SHA-pinned private ELF it verifies
RTTI/vtable headers, the unique ParamBase constructor PLT binding, the saved
original `r1` payload source, vptr stores, object allocation and object-delete
bindings, plus the named `setBool`/`setNumber` payload stores.  `PrmBool`
stores one byte at `+0x0c` with discriminator 5; `PrmNumber` stores one word
at `+0x0c` with discriminator 1.  The clone paths reload `+0x0c` and do not
copy `+0x08` in their bounded bodies.  D1 calls the base destructor and D0
performs object deletion.

The key remains a separate insertion concern: `+0x08` is not written by either
constructor or clone, and `0x7eda84` is the only direct key setter witness.
The sanitized contract is `sdk/param_scalar_lifetime_3_21.json`, the command
is `fw sdk parameter-scalar --elf <private-libObj.so> --json`, and descriptive
constants are in `sdk/paramlist_3_21_candidate.hpp`.  The private Ghidra
12.1.3 lifecycle cross-check completed with 22 targets, 342 instruction rows,
43 blocks and 72 edges.  Runtime verification, external ownership,
allocator/exception semantics, synchronization and callable status remain
unknown; do not use these records as live object wrappers.

### ParamList shared-counter lifetime checkpoint (2026-10-10)

`fwplatform/paramlist_lifetime_probe.py` authenticates the exact SHA-pinned
private ELF and verifies the bounded ParamList owner boundary. The exported
constructor `0x7edc3e` allocates a 12-byte pointer container at object `+0`
and a 4-byte counter at `+4`, initializing the counter to one. The exported
`clear` path `0x7edb76 -> 0x7edb40` walks 4-byte element pointers, invokes the
indirect deleting-destructor slot at vtable `+8` for non-null elements, and
resets the end pointer. The destructor `0x7edd08` and unnamed rebind candidate
`0x7edcc6` decrement the shared counter and release the container only on the
last-owner path; the rebind path then shares source container/counter
pointers.

The field and instruction facts are `PRIMARY_ELF_VERIFIED`; shared-counter and
aliasing interpretations are `STATIC_INFERRED`. Copy-on-write, atomicity,
exception cleanup, allocator interposition, runtime ownership and concurrency
remain `UNKNOWN`. The sanitized contract is
`sdk/paramlist_lifetime_3_21.json`; use
`fw sdk parameter-lifetime --elf <private-libObj.so> --json` for the read-only
probe. The private Ghidra profile completed with 11 targets, 130 instruction
rows, 26 blocks and 43 edges. Runtime verification and callable API counts
remain zero.

### ParamList external owner/use witness (2026-10-10)

`fwplatform/paramlist_owner_use_probe.py` verifies the symbol-bounded
`_ZN12InputService19getInputEventStatusEP9ParamListPKS0_` body at ELF VMA
`0x114104` (356 bytes) from the exact SHA-pinned private ELF. The body uses
incoming registers in a ParamList-shaped flow, looks up key `0x17005003`,
constructs local ParamLists at stack `+0x18` and `+0x20` through the unique
ParamList constructor PLT, allocates a 16-byte PrmNumber candidate, adds it
with key `0x17005003`, and looks up `0x17005008` in the second local list. A
guarded call at `0x1141e2` passes the preserved input as destination and the
`+0x20` local list as source to the shared-rebind candidate `0x7edcc6`; both
locals are destroyed through the unique ParamList destructor PLT.

These are `PRIMARY_ELF_VERIFIED` register, literal, callsite and relocation
facts. C++ static/member form, return type, dispatch registration, ownership
transfer, exception cleanup and concurrency remain `UNKNOWN`; the rebind
interpretation is `STATIC_INFERRED`. The sanitized contract is
`sdk/paramlist_owner_use_3_21.json`, and the read-only CLI is
`fw sdk parameter-owner-use --elf <private-libObj.so> --json`. The private
Ghidra cross-check completed with 6 targets, 210 instructions, 37 blocks and
87 edges. Runtime-verified and callable API counts remain zero.

### InputService cross-ELF import checkpoint (2026-10-10)

`fwplatform/cross_elf_import_probe.py` is a generic, symbol-parameterized
private-root analyzer. It verifies exact `.dynsym` undefined imports,
`R_ARM_JUMP_SLOT` relocations and ARM PLT/GOT stubs, then performs a bounded
direct-immediate BL/BLX scan. It does not assume basename identity, DT_NEEDED
presence or runtime loader binding.

The authenticated official 3.21 root contained 511 ELF files and nine
importers of `_ZN12InputService19getInputEventStatusEP9ParamListPKS0_`.
The provider export in the SHA-pinned `libObj.so` is VMA `0x114105`, size 356.
The sanitized public contract is
`sdk/input_service_cross_elf_3_21.json`; the private scan found no direct
immediate caller, which remains UNKNOWN coverage for register/GOT/vtable
dispatch. Provider selection is `STATIC_INFERRED`; runtime and callable flags
remain false.

```powershell
python -m fwplatform.cli sdk parameter-cross-elf --root <private-root> --provider-elf <private-libObj.so> --provider-sha256 8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a --json
```

The ParamList profile `fwplatform/paramlist_cross_elf.py` composes that
generic scanner for the 3.21 `add`, const `get` and deleting-destructor
symbols. The private root scan considered 511 ELF files and found 27, 29 and
30 importers (32 distinct source binaries in the union). The sanitized
contract is `sdk/paramlist_cross_elf_3_21.json`; it has 86 import observations
with SHA-256, relative path, ELF-VMA relocation and PLT/GOT evidence, plus a
metadata-only Ghidra cross-check for `viewUnified4.so`. The provider export
VMAs retain their Thumb tags: `0x7ee0e7` (add), `0x7edacb` (get) and
`0x7edd09` (D1 destructor). These are linkage facts, not proof of loader
binding, source-level ownership or a callable API. Use
`fw sdk parameter-cross-elf-set --root <private-root> --provider-elf
<private-libObj.so> --provider-sha256 <sha256> --json`; repeat `--symbol` to
run the same generic engine with another symbol set.

The private `viewUnified4.so` Ghidra 12.1.3 cross-check completed with exit
0 using `ARM:LE:32:v8`, image base `0x10000` and `ram` address space. Ghidra's
exact mangled-name lookup is recorded as `UNRESOLVED`; a wildcard lookup found
the demangled external `InputService::getInputEventStatus` and static GOT/PLT
references at ELF VMA `0x1ae5c8` / `0x3d434`. Only sanitized metadata is in
the checked-in contract; the raw JSONL and project stay private. This does
not prove a runtime call path, loader binding or callable ABI.

### ParamList query callsite index (2026-10-10)

`fwplatform/param_query_callers.py` scans the authenticated private `libObj.so`
for direct Thumb `BL`/`BLX` candidates to `0x42abcc`, `0x42abdc`, `0x42ac00`,
`0xe5b20`, `0xe5b18`, `0x120970` and `0xfe9be`. Each candidate is validated
with Capstone; caller identity is supplied only by an exact ELF symbol range.
The private run produced 4,504 rows and the sanitized contract is
`sdk/param_query_callers_3_21.json`.

The direct local chain is recorded at `0x42ac0c` -> `0xe5b20`, `0x42ac12` ->
`0xe5b18`, `0x42abe8` -> `0xe5b20` and `0x42abee` -> `0xe5b18`. Aggregate
counts remain `STATIC_INFERRED`; unresolved caller ranges, full CFG path
reachability, ARM calls, indirect dispatch, loader binding, ownership,
synchronization and runtime callability remain unknown. Run it with:

```powershell
python -m fwplatform.cli sdk parameter-query-callers --elf <private-libObj.so> --json
```
