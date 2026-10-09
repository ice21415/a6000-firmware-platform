# Core helper primary evidence — 2026-10-09

## Derived types and lifetime — current checkpoint

Original ELF hash revalidated. This round deliberately did not repeat get's
previously recovered loop. The ASCII-path Ghidra lifecycle profile completed
with exit 0 and exported **22 bounded target bodies, 342 instruction rows,
43 blocks and 72 edges** to a private file. The export includes the newly
profiled Point deleting destructor at `0xff904`; it contains no public firmware
bytes. Capstone remains the source for the exact static field observations,
while Ghidra supplies an independent disassembly/CFG cross-check. The new
type/lifetime contract is `sdk/parameter_types_lifetime_3_21.json`.

| New witness | Primary result | Limitation |
|---|---|---|
| 0x7eda84 / 0x7eda88 | key setter writes original r1 at element +8 | Constructors do not initialize key in observed paths |
| 0xf0fb0 / 0xf0fc8 | PrmNumber constructor sets discriminator 1 and stores word payload at +12 | Caller must establish valid ownership/key |
| 0x10f9fc / symbol `_ZN9PrmNumber9setNumberEi` | 32-bit setter accepts signed int | Not all numeric IDs mapped to hardware meanings |
| 0xe50e8 / 0xe5100 | PrmBool constructor sets discriminator 5 and stores byte at +12 | Remaining three bytes are not payload |
| 0x426acc / symbol `_ZN7PrmBool7setBoolEb` | bool setter writes one byte | Noncanonical snapshot byte stays unknown |
| RTTI 0xfe8938 / base relocation 0xfe8940 | PrmNumber derives from ParamBase | No complete hierarchy claim |
| RTTI 0xfe6e18 / base relocation 0xfe6e20 | PrmBool derives from ParamBase | Other families have layout witnesses below; no complete hierarchy claim |
| ctor GOT 0x10308f4 / 0x1033f7c | respective vptr address points 0xfe8928 / 0xfe6e08 | Runtime addresses require explicit load bias |
| virtual slot +8 -> 0xf0f5c | Number destruction calls 0xf0f2c then operator delete | Runtime interposition unknown |
| virtual slot +8 -> 0xe4840 | Bool destruction calls relocation-bound PrmBool D1 then operator delete | Runtime interposition unknown |
| relocation 0x102d6bc | both delete calls bind `_ZdlPv` | Allocator implementation not analyzed |
| 0x7edcc6..0x7edd06 | assignment-like body releases old share, increments source count and shares pointers | Source-level method name not independently known |
| 0x7ededa / 0x7edf36 / 0x7edf3c | replacement helper frees equal-key/type old element and erases its slot | Full set of mutation APIs remains unknown |

### Additional ParamBase families — new primary checkpoint

The private-only `fwplatform.param_family_probe` was extended with an
independent RTTI/vtable discovery pass and run against the authenticated ELF.
It emits metadata only (no instruction bytes). Ten direct ParamBase-derived
RTTI records were discovered and matched to bounded constructor/vtable
profiles. RTTI, the single-inheritance base relocation, vtable slots and
constructor/destructor addresses are independent ELF_VMA observations.

| Type | Primary ELF facts | Remaining limits |
|---|---|---|
| `PrmNumberList` | RTTI `0xfe7ed8`, vtable `0xfe7ee8`/address point `0xfe7ef0`, tag `10`, constructor `0xecdb8`; clone allocation witness `0x18`; vector-like words at `+0x0c/+0x10/+0x14`; slots `+8=0xed3a4`, `+12=0xece64`, `+16=0xece98` | element allocator, exception behavior and source-level virtual names remain UNKNOWN |
| `PrmCntInfoList` | RTTI `0xfeb5a4`, vtable `0xfeb5b0`/address point `0xfeb5b8`, tag `9` written by helper `0x11d42c`; clone allocation witness `0x5c`; two dynamic collection regions at `+0x0c` and `+0x34`; slots `+8=0x11da18`, `+12=0x11d54c`, `+16=0x11d590` | collection element/allocator representation and complete copy semantics remain UNKNOWN |
| `PrmObjMsg` | Local RTTI `0xfec488` with name `9PrmObjMsg`, local vtable `0xfec498`/address point `0xfec4a0`, tag `8`, constructor `0x12c754` stores incoming `MWF::ObjMsg*` at `+0x0c`; object-size witness `0x10`; slots `+8=0x12c784`, `+12=0x12c700`, `+16=0x12c740` | pointee ownership, `MWF::ObjMsg` ABI and runtime interposition remain UNKNOWN |
| `PrmString` | RTTI `0xfe9650`, vtable `0xfe9638`/address point `0xfe9640`, tag `2`, constructor `0xff9c8` allocates/copies a buffer at `+0x0c`; object-size witness `0x10`; destructor path `0xff954` releases the non-null payload through `0xdf098` | string encoding, allocator pairing and caller ownership remain UNKNOWN |
| `PrmPoint` | RTTI `0xfe9628`, vtable `0xfe9610`/address point `0xfe9618`, tag `3`, constructor `0xffa3c` stores two words at `+0x0c/+0x10`; object-size witness `0x14`; destructor slots `0xff904/0xff940` | coordinate semantics and caller type constraints remain UNKNOWN |
| `PrmDimension` | RTTI `0xfe6e60`, vtable `0xfe6e48`/address point `0xfe6e50`, tag `4`, constructor `0xe5128` stores two words at `+0x0c/+0x10`; object-size witness `0x14`; destructor slots `0xe4774/0xe4868` | dimension units and semantic range remain UNKNOWN |
| `PrmStruct` | RTTI `0xfe7418`, vtable `0xfe7400`/address point `0xfe7408`, tag `6`, constructor `0xe7260` stores helper-produced payload words; object-size witness `0x14`; destructor `0xe7150` passes `+0x0c` to `0xe0768` | helper ABI, nested type and ownership remain UNKNOWN |
| `PrmSet` | RTTI `0x1019d08`, vtable `0x1019d18`/address point `0x1019d20`, tag `7`, constructor `0x7efb00` initializes an opaque 24-byte region at `+0x0c`; object-size witness `0x24`; `getSet=0x7efae8`, GET wrapper `0x7efaf0` | payload field layout, helper ABI and ownership remain UNKNOWN |

The constructors do not write ParamList key `+0x08`; the observed key setter
`0x7eda84` remains the only primary key-initialization witness. The vtable
slot values use relocation symbol values when the file word is zero, preserving
Thumb tags without conflating an ELF VMA with a runtime address. These are
static type/layout contracts, not callable wrappers.

PrmNumber payload is signed int under ARM32, supported jointly by RTTI,
constructor, word stores and the named int setter. PrmBool payload is bool
with byte stores. Discriminator 1 routes the existing query wrapper toward
number-like storage; tag alone is NOT a unique dynamic type proof.
The offline decoder requires both vptr and discriminator, preserves unknown
subtypes, and never interprets Bool padding as part of its value.

### Validity and safety

PRIMARY_ELF_VERIFIED: shared count uses ordinary loads/stores; assignment
has a self-assignment guard, final count-zero destruction visits non-null
elements, concrete tested virtual deletion paths call operator delete, and
replacement can delete a previously returned element while a list still exists.
STATIC_INFERRED: get's borrowed result requires an owner retaining storage and
no deletion/replacement of that element. Holding another shared list does not
protect an element from replacement in the same shared container.
No detach was observed in the inspected assignment/add/replacement path;
this is not a statement about every mutation API.
UNVERIFIED: external locks, scheduler assumptions, concurrent-use correctness,
all other mutation/copy paths, exception/allocation contracts and runtime ABI.

Sony lookup has no null receiver/container/element guards. Query wrappers guard
list/output only after reading wrapper +4. No counter-zero guard precedes the
observed decrement. The public snapshot parser's bounds, budget, null, type and
canonical-bool checks are **self-authored protections**, not firmware behavior.
No firmware or original opcodes/decompiler bodies are included in this report.

New SDK functionality: `sdk parameter-types --json`,
`sdk parameter-family-probe --elf <private-libObj.so> --json`, exact-type
offline payload decoding, explicit load bias, and descriptive C++ Number/Bool,
String, Point, Dimension, Struct, Set, NumberList, CntInfoList and ObjMsg
snapshot structures. The probe's discovery pass reports ten direct
ParamBase-derived RTTI records in this ELF; payload semantics remain verified
only for Number and Bool.
The descriptive primary contract also records the `0x42acd4` factory's
discriminator-1/3/5 branch mapping and four direct callers; no callable or
runtime status is granted.
Runtime-verified / callable interfaces remain **0**.
This checkpoint: **223 synthetic tests passed**, exit 0; candidate header passed
the existing WSL g++ C++17 syntax check (host declarations only).

### ParamBase factory branch recovery — current primary checkpoint

The bounded Thumb body at ELF VMA `0x42acd4` is a local unnamed factory
candidate. Capstone and the private ASCII-path Ghidra export agree on its
three explicit discriminator comparisons and its null/success paths. It
allocates and constructs:

| `r2` discriminator | Allocation | Constructor | Static result | Remaining limits |
|---:|---:|---|---|---|
| `5` | `0x10` | `0xe50e8` | `PrmBool` candidate; payload comes through `0x120970`/`0x120968` | helper semantics and key relationship UNKNOWN |
| `1` | `0x10` | `0xf0fb0` | `PrmNumber` candidate; source lookup uses `0xe5b20`/`0xe5b18` | exact source object and ownership UNKNOWN |
| `3` | `0x14` | `0xffa3c` | `PrmPoint` candidate; two words come through `0xfe9be`/`0xfe9ae`/`0xfe9b6` | coordinate semantics and helper ABI UNKNOWN |

Unsupported discriminator values return a null pointer in the bounded body;
type-specific source failures also reach the null path. Four direct callers
were independently found at `0x4cf9be`, `0x60ece0`, `0x66d574` and `0x682a88`.
At each site `r0`, `r1` and `r2` are prepared from caller data before the
factory call and the returned `r0` is tested for null. The wrapper-like `r0`
object is dereferenced at `+4`, but its C++ type is not recovered. This is a
static factory contract, not evidence that the factory is safe to call on a
camera or that its returned object has a known owner.

The source helpers are now independently bounded and Ghidra-cross-checked:
`0x120970` fixes discriminator 5 and tail-calls the ParamList lookup PLT,
`0x120968` loads the Bool byte at `+0x0c`, `0xfe9be` fixes discriminator 3
and tail-calls the same lookup PLT, while `0xfe9ae` and `0xfe9b6` load the
Point candidate's words at `+0x0c` and `+0x10`. These are field/dispatch facts;
they do not establish coordinate units, source-level method names or ownership.

The public contract is `sdk/core_3_21_primary_helper_contracts.json`; the
metadata-only reusable xref export is `ghidra-scripts/ParamFamilyReferences.java`.
Its private SHA-pinned run completed with exit 0 and emitted 25 bounded target
records / 2,290 xrefs; the factory record contains four unconditional-call
xrefs. The core target export was rerun with the five helper bodies: 16
bounded targets, 198 instruction rows, 46 blocks and 73 edges, with a complete
marker. All raw exports remain private.


### Factory caller and ParamList::add checkpoint — 2026-10-09

The authenticated ELF was re-read with the new bounded
`fwplatform.param_factory_probe` (`fw sdk parameter-factory --elf <private-libObj.so>`).
The probe validates the complete SHA-256 before decoding and emits metadata
only. It confirms all four previously exported factory callsites and checks
the direct result guard in each caller:

| Factory callsite | r0 immediately before call | r1 source | r2 source | Result guard | Success-path add call |
|---|---|---|---|---|---|
| `0x4cf9be` | `r7+0x6a0` | load `[r3+0x4]` | load `[r3+0x8]` | `cmp r0,#0` at `0x4cf9ca` | `0x4cfa90 -> 0xdfdc0` |
| `0x60ece0` | `r7+0x0c` | load `[r3+0x4]` | load `[r3+0x8]` | `cbnz r0` at `0x60ecea` | `0x60ed48 -> 0xdfdc0` |
| `0x66d574` | `r7+0x30` | load `[r3+0x4]` | load `[r3+0x8]` | `cmp r0,#0` at `0x66d57a` | `0x66d614 -> 0xdfdc0` |
| `0x682a88` | register copy `sb` | load `[r4+r2<<3]` | load `[r3+0x4]` | `cbnz r0` at `0x682a8e` | `0x682b08 -> 0xdfdc0` |

The instruction sites are `PRIMARY_ELF_VERIFIED`; the straight-line register
provenance is `STATIC_INFERRED` because the values originate in dynamic table
memory and a full dominance/data-flow proof is not claimed. The add locations
are after the observed null guards in the bounded local windows, but the
reusable probe labels that path relation `STATIC_INFERRED` rather than claiming
a complete CFG proof. No key or discriminator value is a static constant at
these sites.

The PLT stub at `0xdfdc0` now resolves uniquely through `R_ARM_JUMP_SLOT`
GOT `0x102e340` to `_ZN9ParamList3addEmP9ParamBase`, whose local Thumb-tagged
symbol is `0x7ee0e7` with a 48-byte extent. The bounded local body at
`0x7ee0e6` saves `r2`, calls `0x7ededa`, sets the incoming ParamBase key via
`0x7eda84`, then calls storage helper `0x7ee0b8`. The replacement helper
compares key (`+8`) and discriminator (`+4`); on an equal match it dispatches
the existing element's virtual slot `+8` and removes that slot before the new
pointer is inserted. The storage helper appends when begin/end capacity is
available and otherwise takes a reallocation path. These are static mutation
facts; pointer ownership transfer, allocator pairing, exception behavior,
external locking and concurrent safety remain `UNKNOWN`.

`ParamList::add` and the storage helper are now descriptive entries in
`sdk/core_3_21_primary_helper_contracts.json`; both remain `safe_to_call=false`
and have unknown C++ return semantics. `ParamList::get` results are therefore
more concretely described as borrowed elements that can be invalidated by the
same-container replacement path. The probe is reusable and its generic
validation tests do not contain Sony bytes or fixed return answers.
The private CLI output is deterministic across two runs (identical output
hash) and passes `validate_param_factory_probe` with four caller records.

The updated `ParamListTargets.java` was then run in the private ASCII Ghidra
12.1.3 installation with auto-analysis enabled. It exited **0** and emitted a
complete private marker for 19 bounded targets, 292 instruction rows, 66 basic
blocks and 112 CFG edges. The new target bodies were `0x7ededa`, `0x7ee0b8`
and `0x7ee0e6`; the existing factory `0x42acd4` was included in the same run.
This is targeted cross-validation, not full-libObj coverage and not runtime
verification.

### ParamList clear/destruction/assignment checkpoint — 2026-10-09

The new `fwplatform.paramlist_mutation_probe` (`fw sdk parameter-mutation
--elf <private-libObj.so>`) revalidated the pinned ELF and decoded four bounded
targets. `ParamList::clear` at `0x7edb76` is a twelve-byte tail wrapper to the
local implementation `0x7edb40`. The implementation obtains the element count,
iterates from index zero, skips null slots, dispatches each non-null element's
vtable slot `+8`, then tail-branches to `0x7edb32` for container storage
release. This is direct instruction evidence for element destruction during
clear; it does not establish allocator or lock semantics.

The named destructor `_ZN9ParamListD1Ev` (`0x7edd08`, Thumb symbol `0x7edd09`,
46 bytes) loads the shared counter at receiver `+0x04`, decrements it, and
only when the result is zero calls the clear implementation and two delete
calls. The delete PLT `0xdd620` resolves uniquely through GOT `0x102d6bc` to
`_ZdlPv`; runtime interposition remains unknown. The unnamed body at
`0x7edcc6` has a self-assignment guard, releases the destination share when
needed, copies the source counter/container pointers and increments the
counter. It is `PRIMARY_ELF_VERIFIED` as machine behavior but only
`STATIC_INFERRED` as a C++ assignment identity; no detach or copy-on-write
path was observed in this body.

The public contract now includes descriptive entries for `ParamList::clear`,
`ParamList::~ParamList` and `ParamList::assignment_like_candidate`. All remain
`safe_to_call=false`; complete counter invariants, exception behavior,
allocator pairing, synchronization and concurrent safety are `UNKNOWN`.
The mutation probe's validator rejects missing targets, forged runtime claims
and copy-on-write claims. Its private output validated successfully against
all four targets. A targeted private ASCII Ghidra `-noanalysis` rerun exited
**0** with 21 bounded targets, 343 instruction rows, 79 blocks and 135 CFG
edges; the new clear/assignment/destructor bodies were included. Raw output
and project data remain private.

### PrmNumberList method and vector checkpoint — 2026-10-09

The new `fwplatform.param_numberlist_probe` (`fw sdk parameter-numberlist
--elf <private-libObj.so>`) revalidated the pinned ELF and independently
checked nine bounded regions. The probe records only metadata and returned a
valid report with all nine observations marked `PRIMARY_ELF_VERIFIED`:

| Region | Primary machine fact | Remaining unknown |
|---|---|---|
| `0xeccf4` `getList` | returns `this + 0x0c`, the embedded vector-like storage address | source return type and ownership |
| `0xecd26` `getNumberEj` | indexes `begin + index * 4` and loads one word | no local bounds check; invalid-index behavior |
| `0xecd42` `getLength` | computes `(end - begin) >> 2` | source return type and vector invariants |
| `0xed1a2` `addNumberEj` / `0xed174` | forwards a uint value; non-full path stores and advances end; full path branches to growth code | allocator, exception, and synchronization behavior |
| `0xecdb8` / `0xed35c` | initializes discriminator 10/vector storage; copy constructor forwards to local copy path `0xed29a` | exact base/helper C++ identities and argument reference ABI |
| `0xece64` / `0xece98` | destroys vector-like storage, invokes base path, and deleting path reaches PLT `0xdd620` | allocator interposition and callable destructor ABI |

The descriptive contract is `sdk/param_numberlist_3_21.json`; it keeps
`safe_to_call=false`, `runtime_verified=false` and `callable=false`. The
`uint32_t` element description is supported by the `Ej` symbols and word
loads/stores, while the public object layout remains a snapshot description,
not a live C++ wrapper. The probe's synthetic validator rejects missing
observations, wrong discriminator/type identity and runtime promotion.
After adding the NumberList fixtures, the full public synthetic suite passes
238 tests (process exit 0).

### PrmCntInfoList method and dual-collection checkpoint — 2026-10-09

The new `fwplatform.param_cntinfolist_probe` (`fw sdk parameter-cntinfolist
--elf <private-libObj.so>`) revalidated the pinned ELF and checked twelve
bounded regions. All twelve observations validate as `PRIMARY_ELF_VERIFIED`:

| Region | Primary machine fact | Remaining unknown |
|---|---|---|
| `0x11d42c` | stores vptr and discriminator 9 | source-level initializer identity |
| `0x11d44c` / `0x11d45a` | type-specific lookup tail-call and first-collection length forwarding | return type and lookup ownership |
| `0x11d4ac..0x11d4e6` | get/set accessors select collection `+0x0c` or `+0x34`, then read/write one word | element type, bounds and helper semantics |
| `0x11d8e6` / `0x11d90e` | append helper checks end/capacity; `addEjj` appends r1 and r2 to the two regions | growth allocator, exceptions and synchronization |
| `0x11d680` / `0x11d938` | default and two-argument constructors initialize both regions; argument constructor appends inputs | exact collection ABI and key initialization |
| `0x11d54c` | destructor cleans both regions then calls local base-destruction path `0xe4734` | ownership and allocator pairing |

The descriptive contract is `sdk/param_cntinfolist_3_21.json`; it keeps
`safe_to_call=false`, `runtime_verified=false` and `callable=false`. The
collection element type is intentionally `UNKNOWN`; the `Ejj` symbols only
support unsigned-int argument candidates. No runtime or device behavior was
executed.
After adding the CntInfoList fixtures, the full public synthetic suite passes
242 tests (process exit 0).

## ParamList continuation — latest checkpoint

The installation was copied to an ASCII path and the new
`ghidra-scripts/ParamListTargets.java` run returned **exit 0**. The original
non-ASCII installation and failed logs were preserved. Successful targeted
analysis does not imply full-libObj auto-analysis coverage.

The first lifecycle run performed Ghidra auto-analysis on the private ELF;
the repeat used the saved project with `-noanalysis` and completed the same
22-target export. Private output counts were obtained from the export marker,
bounded target records and CFG rows; no decompiler text or instruction bytes
are committed.

ParamList::get has dynamic symbol `_ZNK9ParamList3getEmm`, symbol value
0x7edacb, **76-byte** extent at ELF VMA **0x7edaca..0x7edb15**. Both
Capstone and correctly mapped Ghidra show the same loop and return sites:
0x7edb0c returns null after range exhaustion; 0x7edb12 returns the existing
element on the first match.
All **30 instruction addresses and sizes** agree. Ghidra emits **7 blocks**,
**8 intra-function CFG edges** and **4 direct helper calls**, kept distinct.
No explicit throw, allocation, cloning, refcount increment or element/list writes
occur in this body and its four local helpers.
Inputs: r0 const receiver; r1 unsigned-long key; r2 unsigned-long discriminator;
r3 has stack preservation only. Const and explicit types come from mangling;
declared return type is not encoded and remains a candidate.

| Witness | Confirmed role | Level |
|---|---|---|
| 0x7edad0 | receiver +0 points to pointer container | PRIMARY_ELF_VERIFIED |
| 0x7edab0 | count = arithmetic signed shift of (end - begin) by 2 | PRIMARY_ELF_VERIFIED |
| 0x7edabe | slot address = begin + index *4 | PRIMARY_ELF_VERIFIED |
| 0x7eda90 / 0x7edafc | element +4 compared with original r2 | PRIMARY_ELF_VERIFIED |
| 0x7eda98 / 0x7edb00 | element +8 compared with original r1 | PRIMARY_ELF_VERIFIED |
| 0xe5b22 | wrapper fixes discriminator to 1 | PRIMARY_ELF_VERIFIED |
| 0xe5b1c / 0x42ac16 | matching element +0xc copied to original r2 output | PRIMARY_ELF_VERIFIED |
| 0xe50c0 / 0xe50c4 | ParamBase C2 stores discriminator at +4 and vptr at +0 | PRIMARY_ELF_VERIFIED |
| GOT 0x1033a60 / 0xfe6e30 | constructor resolves vtable address point +8 | PRIMARY_ELF_VERIFIED |
| RTTI 0xfe6e24 / relocation 0xfe6e34 | ParamBase named type relation to vtable | PRIMARY_ELF_VERIFIED |
| 0x7edc52 / 0x7edc62 | ParamList stores container at +0, shared counter at +4 | PRIMARY_ELF_VERIFIED |
| 0x7edd12 / 0x7edd16 | destruction decrements counter, cleans only on zero | PRIMARY_ELF_VERIFIED |
| 0x7edb60..0x7edb64 | cleanup invokes element virtual slot +8 | PRIMARY_ELF_VERIFIED |
| return object | borrowed storage; last owner cleanup can invalidate it | STATIC_INFERRED |
| vptr slot +8 | deleting-destructor semantics require concrete target review | UNVERIFIED |

`0x42abcc` initializes an 8-byte view (literal word at +0, list pointer at +4).
No refcount acquisition appears in that initializer. `0x42abdc` independently
has the same observed lookup/value/store/status behavior as `0x42ac00`; their
C++ names and semantic specialization are still UNKNOWN. All six requested
entrypoints now have local register/body witnesses; only ParamList::get has
a confirmed C++ symbol identifying explicit argument types.

Concrete derived payload types, full inheritance, copy-on-write mutation rules,
thread safety and runtime binding remain unresolved. Null/corrupt elements are
not guarded by firmware lookup. The offline snapshot reader deliberately rejects
corrupt/unbounded ranges rather than executing or reproducing unsafe accesses.
The C++ header describes target words, never host pointers or callable wrappers.

Private sources: SHA-pinned ELF; new Capstone probes for lookup/lifecycle/base
constructor; Ghidra targeted listing/CFG/decompilation. Public output includes
only self-authored summaries, schema, tooling and synthetic tests.
Latest full public synthetic regression run: **263 tests passed**, process exit 0.
Candidate header passed a C++17 syntax check with the existing Ubuntu g++
through WSL (exit 0). This checks declarations/layout assertions on the host;
it does not link Sony code or validate a target ARM runtime ABI.

### Previous checkpoint (preserved; environment issue now resolved above)

This supersedes the handoff's missing-byte blocker for the two helpers only.
The private official 3.21 libObj.so is readable and its complete SHA256 matches
`8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`.
Raw probe exports, Ghidra projects, logs and decompiler output remain private.

## Confirmed machine facts

| ELF VMA | Primary fact | Remaining unknowns |
|---|---|---|
| 0x13200a | Loads receiver word at object +0x14, then tail-calls relocation-bound Event::getParamList() const | Original wrapper C++ class/signature; runtime symbol binding; ownership |
| 0xfe9d4 | Local Event getter loads word at Event +0x0c into r0 | Declared return type and object lifetime |
| 0x42ac00 | Reads wrapper +4; preserves original r2 in r4; validates list/output; success stores one word through r4 and returns 0; local failure returns 1 | Declared output type, underlying lookup side effects, threading |
| 0xe5b20 | Forwards receiver/key, sets second explicit lookup argument to 1, then tail-calls ParamList::get(unsigned long,unsigned long) const | Callee implementation and ownership |
| 0xe5b18 | Loads selected object word at +0x0c | Meaning/type of that word |

The local lookup body saves/restores r3 but does not use its incoming value as
a semantic argument. Register read-before-write heuristics must not equate
push/pop stack alignment with an additional C++ parameter.
Null wrapper r0 is NOT handled: it is dereferenced before the null checks.
No allocation, deallocation or ownership transfer is proved for these wrappers.

## Reproduction and tools

- Capstone 5.0.7, pyelftools; `sdk probe-core-abi --elf <private ELF> --json`.
- Reusable `fwplatform/elf_plt.py` computes GOT slots from ARM/Thumb interworking
  stubs and then resolves exact relocation entries. Rotated ARM immediates
  have a dedicated synthetic regression test.
- The two bindings resolve independently to GOT 0x102cec8 and 0x102f0c8,
  with R_ARM_JUMP_SLOT relocations and local symbol values 0xfe9d5 and 0x7edacb.
  Odd symbol values preserve Thumb tags; instruction VMAs are even.
- Ghidra 12.1.3 first imported the pinned ELF with auto-analysis enabled, then
  reran the targeted lifecycle export from the saved project with
  auto-analysis disabled. It is NOT counted as full binary CFG recovery.
- Ghidra image base was 0x10000; target addresses are ELF VMA +0x10000.
  Initial wrong-mode/wrong-address attempts were rejected and retained privately.
- Correctly mapped Thumb instruction rows agree with Capstone. The parameter
  wrapper and local getters have useful decompilation. Tail-call decompilation
  spills into PLT instructions and is rejected as semantic evidence.
- The original non-ASCII installation attempt remains a recorded exit-1
  environment failure. The ASCII installation completed the same targeted
  script with exit 0; this does not remove the historical failure record or
  imply full-library semantic recovery.

## SDK outcome

`sdk/core_3_21_primary_helper_contracts.json` records descriptive, field-scoped
contracts. `fw sdk primary-contracts --json` validates identity, address space,
evidence locators and absence of runtime/callability claims.
Old saved-text research remains preserved; this is additive primary evidence.

Fully verified callable core APIs: **0**. Runtime verification: **0**.
Historical public synthetic checkpoint: **206 tests passed** (Python 3.12),
including three PLT decoding tests and three descriptive-contract safety tests.
Current next blockers: establish the source-level identity and complete ABI of
the assignment-like body, trace all mutation/copy paths and synchronization,
and determine concrete payload ownership and runtime binding. The static
contracts remain descriptive and `safe_to_call=false`.

## Camera selector helper checkpoint (primary ELF, 2026-10-10)

The private SHA-pinned `libObj.so` was read locally with Capstone through the
bounded command `fw sdk camera-selector --elf <private-libObj.so> --json`.
At ELF VMA `0x12d780`, the exact instruction sites verify two visible paths:

- When byte `[r0]` is `0x40`, the helper calls the relocation-bound
  `IdGenerator::Get` PLT at `0xdffb8`. The second byte selects base
  `0x12000000` for `M` (`0x4d`) or `0x13000000` for `V` (`0x56`); other values
  take the visible `-1` path. The local call at `0x120168` receives the model
  ID in `r1`, the original selector in `r2`, and the selected base in `r0`.
- Otherwise, the helper constructs local temporaries, checks a prepared object,
  loads vtable slot `+8` and invokes it when non-null; a null object reaches
  the visible `-1` path.

These are `PRIMARY_ELF_VERIFIED` instruction/register facts only. The
transformation at `0x120168`, helper and vtable identities, C++ return type,
selector meaning, ModelCamera causality, ownership, runtime behavior and
callability remain UNKNOWN. The descriptive contract is
`sdk/camera_3_21_selector_transform.json`; `runtime_verified=false` and
`callable=false` are enforced. Four synthetic fail-closed tests cover the
validator, and the complete public suite now passes **246 tests**. No firmware
bytes, disassembly export or private probe output is included in the repository.

## PrmObjMsg lifecycle checkpoint (primary ELF, 2026-10-10)

The exact SHA-pinned private ELF probe `fw sdk parameter-objmsg --elf
<private-libObj.so> --json` validates five bounded regions. The constructor at
`0x12c754` receives an `MWF::ObjMsg*` candidate in `r1`, stores it at `+0x0c`,
sets discriminator `8` through the base initializer and stores the relocated
vtable address point. The getter at `0x12c77c` returns the word at `+0x0c`.
The non-deleting destructor at `0x12c700` checks that word, calls helper
`0xddd94`, then the operator-delete PLT `0xdd620`, and invokes the local
ParamBase destruction path `0xe4734`; the deleting wrapper at `0x12c740`
performs the non-deleting path followed by `0xdd620`. A clone candidate at
`0x12c784` allocates a 16-byte destination candidate, copies the payload via
`0xe0388`, and retains a visible delete failure path.

These are `PRIMARY_ELF_VERIFIED` instruction facts. The `MWF::ObjMsg` pointee
layout, ownership transfer, allocator pairing, exception behavior, clone C++
identity/return type, synchronization, runtime behavior and callability remain
UNKNOWN. The descriptive contract is `sdk/param_objmsg_3_21.json` and its
runtime/callable flags are false. Four synthetic fail-closed tests cover the
metadata validator; no firmware bytes or private probe output is committed.

## EventManager initializer / shared-layout checkpoint

The exact SHA-pinned private `libObj.so` was read only after full-file hash
verification. At Thumb `ELF_VMA 0x7ef894` (78 bytes), Capstone confirms an
initializer-like body that stores `r1` at receiver `+0x04`, initializes
`pthread_mutex_init(receiver +0x0c, 0)`, loads provider `r2`'s vtable slot
`+0x30` and stores the result at `+0x08`, and allocates one 8-byte state
array plus two 8-byte state words. The PLT stubs resolve uniquely in the
static ELF to `pthread_mutex_init`, `_Znaj` and `_Znwj`; dynamic loader
bindings remain UNKNOWN.

This is a `PRIMARY_ELF_VERIFIED` instruction/layout observation and only a
`STATIC_INFERRED` association with `EventManager::push`. No constructor or
RTTI witness proves the class identity. Local helper `0x7f09be`, state-word
meaning, ownership, destruction, exception behavior, synchronization beyond
the observed mutex initialization, and runtime callability remain UNKNOWN.
The descriptive contract is `sdk/event_manager_init_3_21.json`; the private
probe is `fw sdk event-manager-init --elf <private-libObj.so> --json`.

### Ghidra cross-check (private, targeted)

The ASCII-path Ghidra 12.1.3 headless project was opened with `-noanalysis`
for a bounded target profile after the full Auto Analysis attempt was stopped
without a completion marker. The private script exited 0 and emitted one
`0x7ef894` target. Ghidra image base was `0x10000`, so its program address
`0x7ff894` maps to original `ELF_VMA 0x7ef894`; the body was
`[[0x7ff894,0x7ff8e1]]`. It reproduced all 27 instruction boundaries,
the six call edges (including PLT stubs and local `0x7f09be`), and the same
receiver offsets. Ghidra's decompiler output uses `undefined4`/`param_*`
for unresolved types and is therefore supporting disassembly evidence, not
proof of a C++ constructor or callable ABI. Full Auto Analysis status for
this separate run is INCOMPLETE; no success is claimed for it.

## Request-model Event factory primary checkpoint

The exact SHA-pinned private ELF now has a bounded probe for the symbol-bound
`AbstractUtilityManager::createRequestModelExecuteEvent` at `0x7f0b0c`
(Thumb tag `0x7f0b0d`, 108 bytes). It verifies `r0` receiver/context,
explicit `int`/`unsigned long`/`ParamList*` argument positions, literal event
ID `0x11004003`, optional ParamList attachment, and key-7/key-8 PrmNumber
construction. Unique static PLT bindings identify Event construction,
ParamList attachment, parameter insertion, allocation, delete and exception
cleanup. The return pointer shape, constructor identity for local `0xf0fb0`,
ownership, event consumer, exception semantics, runtime binding and
callability remain UNKNOWN/false. Contract:
`sdk/camera_request_event_3_21.json`.

Private ASCII Ghidra 12.1.3 targeted `-noanalysis` exited 0 and reproduced
36 instruction rows and 12 edges at image-base-mapped address `0x800b0c`
(`ELF_VMA 0x7f0b0c`).
