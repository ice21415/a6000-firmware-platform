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

## Event core object checkpoint

The SHA-pinned primary ELF now directly verifies the Event constructor, copy
constructor, destructor, ParamList setter and parameter forwarders. Event
layout candidates are `+0x00` shared counter pointer, `+0x04` event ID,
`+0x08/+0x09` byte flags and `+0x0c` ParamList pointer. Copy/destruction
counter behavior and last-owner ParamList cleanup are machine-confirmed.
`setParamList` null/same-pointer/replacement branches are also confirmed,
but ownership and alias safety are only STATIC_INFERRED. `addParameter` and
`getParameter` delegate through ARM/Thumb veneers to `ParamList::add/get`.
Contract: `sdk/event_core_3_21.json`; runtime and callable flags remain false.

## PrmSet embedded payload checkpoint — 2026-10-10

The private SHA-pinned ELF probe `fwplatform/param_set_probe.py` adds a
bounded, metadata-only check for the discriminator-7 `PrmSet` family. It
verifies the named `getSet` entry at `0x7efae8`, the `GET` wrapper at
`0x7efaf0`, the 36-byte constructor at `0x7efb00`, the clone path at
`0x7efbb4`, both destructor paths, and the local payload initialization,
copy and release helpers. The probe passes the full ELF hash
`8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a` and
emits no firmware bytes.

Primary instruction facts:

- `getSet` returns the interior address `r0 + 0x0c` without loading or
  allocating. Its source-level return type is UNKNOWN, so the result is
  represented as a borrowed interior-pointer candidate.
- `GET` fixes discriminator `7` and tail-branches through the existing
  `ParamList::get` interworking veneer. The lookup return and ownership remain
  UNKNOWN.
- The constructor calls the relocation-bound `_ZN9ParamBaseC2Em` PLT with
  discriminator `7`, stores the relocated vtable address point, and invokes
  the default payload helper at `0xffd22`; the ParamList key at object `+0x08`
  is not written in this bounded body.
- The embedded payload occupies 24 bytes at object `+0x0c`. Its bounded
  initializer zeroes relative offsets `+0x04`, `+0x08` and `+0x14`, then
  writes self-linked sentinel pointers at relative `+0x0c` and `+0x10`.
  Relative `+0x00` is not written by that helper and remains UNKNOWN.
- The clone allocates a separate 36-byte object, passes source `+0x0c` to the
  local payload-copy wrapper, and returns a destination-shaped value in `r0`.
  The source-level clone return type and copy/container semantics remain
  UNKNOWN.
- Destruction routes the embedded payload through `0xffe0c`, then the local
  ParamBase destruction path `0xe4734`; the deleting wrapper calls
  `_ZdlPv` through its unique PLT binding.

The exact PLT bindings are retained in `sdk/param_set_3_21.json` with
`runtime_binding: UNKNOWN`. The payload is described only as an
**ordered-container-like candidate**; no `std::set` claim is made. Element
type, comparator, allocator pairing, exception behavior, interior-pointer
invalidation, synchronization and runtime ABI remain UNKNOWN. The private
ASCII Ghidra 12.1.3 `param-set` profile exited 0 with 13 bounded targets,
161 instruction rows, 17 blocks and 33 CFG edges. The decompiler emitted
ordinary undefined-type warnings for stripped code; this run is a static
cross-check, not a complete source-level recovery. Runtime-verified and
callable SDK counts remain zero. Four new fail-closed validator tests and the
full public suite (275 tests) pass locally.

## PrmPoint / PrmDimension inline-word checkpoint — 2026-10-10

The reusable `fwplatform/param_pair_probe.py` profile now validates the two
stripped inline-word families directly from the authenticated ELF:
`PrmPoint` (discriminator 3, vtable `0xfe9610`) and `PrmDimension`
(discriminator 4, vtable `0xfe6e48`). Their constructors are not exported with
source-level symbols, so the report does not invent C++ names for them.

For both families, the bounded constructor receives `r0` as the destination,
preserves `r1` and `r2`, calls the relocation-bound `_ZN9ParamBaseC2Em` with
the family discriminator, stores the two words at object `+0x0c` and
`+0x10`, and writes the relocated vtable address point at object `+0x00`.
Object `+0x08` is not written by either constructor. The object-size witness
and clone allocation are `0x14` bytes. Each clone reloads source `+0x0c` and
`+0x10`, calls its family constructor and returns a destination-shaped value.

The destructors restore the family vptr and call local ParamBase destruction
path `0xe4734`; the deleting wrappers then call `_ZdlPv`. Point uses a direct
call to its local destructor body. Dimension uses the unique PLT binding at
`0xdfb30` to `_ZN12PrmDimensionD1Ev` before the delete call. This distinction
is preserved as an ABI fact rather than normalized away.

The two payload words are intentionally described as **word candidates**.
Coordinate, width/height, unit, range, hardware meaning, external aliases,
exception paths, synchronization and runtime loader behavior remain UNKNOWN.
The probe also directly checks each vtable's offset-to-top word, RTTI pointer,
clone slot `+0x08` and deleting-destructor slot `+0x10`; the Dimension
destructor slot is preserved as a distinct relocation-bound witness.
The private ASCII Ghidra 12.1.3 `param-pair` profile exited 0 with 8 targets,
96 instruction rows, 8 blocks and 12 edges; undefined-type warnings from the
stripped program are supporting evidence only. Runtime-verified and callable
SDK counts remain zero.

The pair-family validator adds four synthetic regression cases; the complete local suite now passes 279 tests.

## PrmString ownership/layout checkpoint — 2026-10-10

The new `fwplatform/param_string_probe.py` validates the discriminator-2
`PrmString` candidate from the authenticated SHA-pinned ELF. The vtable at
`0xfe9638` points to RTTI `0xfe9650`, clone `0xffa18`, non-deleting
destructor `0xff954` and deleting destructor `0xff980`; the object-size
witness is `0x10` bytes.

The constructor at `0xff9c8` receives the source pointer candidate in `r1`,
calls the relocation-bound `strlen`, allocates `strlen + 1` bytes through the
`_Znaj` PLT, stores the destination at object `+0x0c`, and calls `strncpy`
with the same `length + 1` count. The destructor at `0xff954` tests the
payload pointer, calls the `_ZdaPv` (`delete[]`) PLT only for a non-null
payload, then enters the local ParamBase destruction path. The deleting
wrapper calls the object `_ZdlPv` PLT. The clone path allocates a separate
`0x10`-byte object and passes source `+0x0c` to the constructor.

These are `PRIMARY_ELF_VERIFIED` instruction and relocation facts. Encoding,
source-level constructor identity, allocator/exception behavior, alias and
transfer rules, synchronization, runtime loader binding and clone return type
remain `UNKNOWN`. Because `strlen` is called without a local null guard, the
probe does not describe null input as safe. Contract:
`sdk/param_string_3_21.json`; runtime verification and callability remain
false.

The private ASCII Ghidra 12.1.3 targeted `param-string` profile exited 0 with
4 targets, 60 instruction rows, 6 blocks and 14 CFG edges. Its undefined
types and unresolved external libraries are supporting cross-check evidence,
not complete C++ recovery. Five new fail-closed tests cover identity,
discriminator, observation completeness and non-callable metadata. The
complete local suite now passes 283 tests; runtime-verified and callable counts
remain zero.

## PrmStruct pointer/length payload checkpoint — 2026-10-10

The new `fwplatform/param_struct_probe.py` validates the discriminator-6
`PrmStruct` candidate from the authenticated ELF. Its vtable at `0xfe7400`
points to RTTI `0xfe7418`, clone `0xe72a0`, non-deleting destructor `0xe7150`
and deleting destructor `0xe717c`; the object-size witness is `0x14` bytes.

The constructor at `0xe7260` receives a source byte pointer candidate in `r1`
and a byte-length candidate in `r2`. It passes the length to the relocation-
bound `malloc`, stores the result at `+0x0c`, calls relocation-bound `memcpy`
with destination/source/length, and stores the length at `+0x10`. The
destructor passes `+0x0c` to `free` before the local ParamBase destruction
path. The deleting wrapper calls object `_ZdlPv`; clone allocates a separate
`0x14`-byte object and copies the pointer/length candidates into the
constructor.

These are `PRIMARY_ELF_VERIFIED` instruction and relocation facts. Nested
schema/type meaning, serialization, null/zero-length behavior, allocator and
exception semantics, alias/transfer rules, synchronization, runtime binding
and clone return type remain `UNKNOWN`. No local guard precedes malloc,
memcpy or free, so the probe makes no safety claim for invalid input. Contract:
`sdk/param_struct_3_21.json`; runtime verification and callability remain
false.

The private ASCII Ghidra 12.1.3 targeted `param-struct` profile exited 0 with
4 targets, 54 instruction rows, 4 blocks and 9 CFG edges. Its unresolved
external libraries and undefined decompiler types are supporting evidence,
not complete C++ recovery. Five fail-closed synthetic tests cover identity,
discriminator, observation completeness and non-callable metadata.

## PrmCntInfoList collection helper and word-copy checkpoint — 2026-10-10

The CntInfoList probe now covers eighteen bounded regions rather than only the
exported wrappers. The additional primary-ELF observations are:

| Region | Confirmed machine fact | Still unknown |
|---|---|---|
| `0x11d47e` | forwards the receiver/index through `0xe7cd6` and `0xe7e5c` using a 16-byte temporary, then reads its first word | bounds checking, iterator and source-level container type |
| `0xe77a2` | adjusts collection metadata addresses and tail-branches to `0xe7774` for length-like arithmetic | signedness, exact fields and container identity |
| `0x11d8b0` | full-capacity append requests one element, obtains replacement storage, copies one word, and rebuilds end/capacity metadata | allocator pairing, exception behavior, relocation safety and synchronization |
| `0xecd7a` | conditionally copies one 32-bit word from `[r2]` to `[r1]` | source validity, element type beyond width, ownership |

The existing `0x11d8e6` fast path and `PrmCntInfoList::add(unsigned,unsigned)`
now have a directly observed growth branch and copy helper. This supports a
**32-bit word element candidate** and two 0x28-byte collection regions at
object `+0x0c` and `+0x34`; it does not establish `std::vector`, a standard
allocator, or a callable C++ ABI. The public header represents both regions
as ten unnamed words each so that the offsets are queryable without inventing
field semantics.

The private ASCII-path Ghidra 12.1.3 targeted `param-cntinfolist` profile
exited 0 with 18 targets, 237 instruction rows, 22 blocks and 47 CFG edges.
The export is private and contains no firmware bytes in the repository. The
RTTI/vtable identity remains provided by the separate parameter-family probe:
it confirms the `PrmCntInfoList` RTTI/vtable relation and destructor slots, but
does not convert the collection into a named standard-library type.

The contract is `sdk/param_cntinfolist_3_21.json`; runtime verification,
thread-safety, null-input safety and callable SDK counts remain zero. The
synthetic validator now requires the growth helper observation and continues
to reject runtime/callable promotion.

The same profile now also includes the vtable clone target `0x11da18` and
non-deleting/destructor-delete target `0x11d590`. The clone allocates a new
0x5c-byte object and copies both collection regions through a local copy path;
the deleting path calls the relocation-bound `PrmCntInfoListD1` PLT then
`_ZdlPv`. These are lifetime/control-flow facts only: source-level clone
return type, ownership transfer, allocator pairing, exception paths and
runtime safety remain UNKNOWN.

## PrmCntInfoList removal/lifecycle checkpoint — 2026-10-10

The authenticated ELF now also verifies `_ZN14PrmCntInfoList6removeEj` at
`0x11d82e` and its bounded local rebuild path at `0x11d72a`. The method copies
both collection regions, repeats a copy/drop-first operation for both while
`r4 < r1`, then commits the transformed temporaries through `0x11d72a`.
`0xe7e86` advances a collection begin pointer by one 32-bit word and rebuilds
metadata when begin reaches end. The exact meaning of the index, invalid-index
behavior, aliasing, assignment identity, exception handling and pointer
invalidation remain UNKNOWN.

The private targeted Ghidra profile now exits 0 with 22 targets, 384
instruction rows, 38 blocks and 96 CFG edges. The public contract records
these as static evidence only; no runtime or callable ABI claim is made.

## PrmObjMsg RTTI, payload lifetime and ABI correction (primary ELF, 2026-10-10)

This checkpoint extends the existing ObjMsg probe without repeating the already
recovered `ParamList::get` loop. The private input was hash-checked before
parsing: SHA-256 `8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`.
The probe now validates the RTTI/vtable record and seven unique PLT relocation
bindings in addition to the five bounded function bodies.

| Evidence | Static result | Verification boundary |
|---|---|---|
| RTTI `0xfec488`, name `9PrmObjMsg`; `_ZTI9ParamBase` relocation at RTTI `+0x08` resolves to `0xfe6e24`; vtable prefix `0xfec498`, address point `0xfec4a0` | offset-to-top `0`, clone slot `+8 -> 0x12c784`, destructor `+12 -> 0x12c700`, deleting destructor `+16 -> 0x12c740` | direct ELF data/RTTI/vtable relation; complete inheritance beyond the direct base and runtime address relocation remain unknown |
| `0x12c754` | `r0` destination candidate, `r1` `MWF::ObjMsg*` candidate; discriminator `8` passed to `_ZN9ParamBaseC2Em`; incoming pointer stored at `+0x0c` | constructor symbol and stores are PRIMARY_ELF_VERIFIED; transfer/alias contract is unknown |
| `0x12c700` | non-null `+0x0c` calls PLT `0xddd94`, which uniquely relocates to `_ZN3MWF6ObjMsgD1Ev`, then PLT `0xdd620` `_ZdlPv`; base path `0xe4734` follows | destruction sequence is PRIMARY_ELF_VERIFIED; allocator pairing and external ownership are unknown |
| `0x12c77c` | loads `receiver +0x0c` into `r0` and returns without retain/clone | borrowed pointer candidate; null receiver behavior is unknown |
| `0x12c784` | getter PLT `0xddee4` -> `PrmObjMsg` getter; `_Znwj(8)` then `MWF::ObjMsg` copy constructor PLT `0xe0388`; `_Znwj(0x10)` then `PrmObjMsg` constructor PLT `0xe2080` | clone/deep-copy shape is PRIMARY_ELF_VERIFIED; virtual return type and full exception path are unknown |

The earlier generic descriptions of `0xddd94` as a helper and `0xe0388` as a
payload-copy helper are superseded by the relocation evidence above. The
correction is additive and does not delete the prior record. `0xddee4` is the
same class's getter veneer, not an independent payload routine. All bindings
have `status=VERIFIED_STATIC` and `runtime_binding=UNKNOWN`.

### Lifetime and safety interpretation

The destructor directly invokes `MWF::ObjMsgD1` followed by object deletion for a
non-null payload. This is a static release-on-destruction witness and supports a
`STATIC_INFERRED` expectation that the stored pointer is normally an owned
payload. The constructor itself only stores the incoming pointer, so ownership
transfer, borrowed-input handling and alias safety are not proven. The clone
path copies the payload before wrapping it in a new `PrmObjMsg`; this supports a
static deep-copy candidate but does not prove exception guarantees or source
lifetime rules. The getter returns the interior payload pointer with no retain,
so any containing-element replacement/destruction invalidation remains governed
by the separate ParamList evidence.

No bounded ObjMsg body initializes or acquires a lock. Null payload destruction
is explicitly skipped; constructor input, getter receiver, invalid/shared
payload, allocation failure, exception/unwind, scheduler and concurrent use
remain UNKNOWN. The offline snapshot decoder's checks are self-authored and
are not Sony behavior. Runtime-verified and callable SDK counts remain **0**.

### Targeted Ghidra cross-check

The ASCII-path Ghidra 12.1.3 headless run used the pinned private project and
`-noanalysis` profile `param-objmsg`. It exited `0` with image base `0x10000`,
**5 targets, 62 instruction rows, 7 basic blocks and 14 CFG/call edges**. The
mapped target bodies were `0x12c700`, `0x12c740`, `0x12c754`, `0x12c77c` and
`0x12c784`. Ghidra's undefined types and unresolved external libraries are
supporting CFG evidence only; this is not a complete Auto Analysis or runtime
validation.

The descriptive contract is `sdk/param_objmsg_3_21.json`. The probe now emits
explicit static PLT bindings and enforces vtable/RTTI completeness in its
validator. Six synthetic fail-closed tests cover identity, vtable, binding,
target and non-callable promotion checks. The complete public regression suite
passes **295 tests**; no test executes the Sony ELF or requires a camera.

### Targeted usage xrefs

The private Ghidra metadata-only usage export (`ParamObjMsgUsage.java`, exit 0)
found four direct internal callsites relevant to the family: the clone body
at `0x12c784` calls the PrmObjMsg constructor PLT at `0x12c7a6`, the getter
PLT at `0x12c788`, and the ObjMsg copy constructor PLT at `0x12c798`; the
non-deleting destructor calls ObjMsg D1 at `0x12c718`. The local constructor
symbol has only external/data references in this targeted export and no
additional internal constructor caller was observed. The export contains eight
xrefs total, including those external/data references.

This narrows the observed `libObj.so` usage to the clone/lifetime path, but it
does not prove that no other ELF or dynamically resolved caller exists. The
contract records this as `STATIC_INFERRED`, keeps generated Ghidra labels out
of semantic names, and does not promote ownership or runtime safety.

## ParamBase family construction/use index — 2026-10-10

`ghidra-scripts/ParamFamilyUsage.java` is now a reusable metadata-only profile
for the ten ParamBase-derived constructor targets already established by the
SHA-pinned family probe. The script records the target ELF VMA, reference kind,
callsite and containing function entry; it does not assign meaning to
Ghidra-generated names. `fwplatform/param_family_usage.py` validates the
completion marker, binary identity, family/xref counts and fail-closed runtime
flags before producing the public summary contract
`sdk/parameter_family_usage_3_21.json`. The CLI exposes this read-only record
as `fw sdk parameter-family-usage`. Each xref now stores separate
`FROM_ELF_VMA`/`FROM_GHIDRA` and caller-entry fields with the Ghidra address
space, so the image-base mapping is not silently mixed.

The private ASCII-path Ghidra 12.1.3 project used language `ARM:LE:32:v8` and
image base `0x10000`. Auto Analysis was deliberately bounded to 300 seconds;
Ghidra reported an analysis timeout, then the metadata post-script completed
with process exit 0. Therefore the following are **observed partial-export
counts**, not exhaustive constructor usage counts:

| Family | Target | Observed xrefs | Direct/ computed call xrefs | Unique caller entries | Unknown caller entries |
|---|---:|---:|---:|---:|---:|
| PrmBool | `0xe50e8` | 95 | 95 | 30 | 3 |
| PrmNumber | `0xf0fb0` | 628 | 628 | 149 | 17 |
| PrmString | `0xff9c8` | 21 | 21 | 13 | 0 |
| PrmPoint | `0xffa3c` | 10 | 10 | 8 | 1 |
| PrmDimension | `0xe5128` | 13 | 13 | 7 | 3 |
| PrmStruct | `0xe7260` | 82 | 82 | 42 | 14 |
| PrmSet | `0x7efb00` | 0 | 0 | 0 | 0 |
| PrmNumberList | `0xecdb8` | 3 | 1 computed | 1 | 0 |
| PrmCntInfoList | `0x11d680` | 3 | 1 computed | 1 | 0 |
| PrmObjMsg | `0x12c754` | 3 | 1 computed | 1 | 0 |
| **Total** | | **858** | **852** | | |

The three symbol-resolved constructor records each contain one `COMPUTED_CALL`
plus one external and one data reference. The six local VMA records with
observed calls are `UNCONDITIONAL_CALL` references. `PrmSet` has no reference in
this bounded export; that is an unresolved coverage gap, not evidence that the
constructor is unused. A computed call into the PrmObjMsg constructor at
`0xf2088` is retained as a callsite observation; it is not merged with the
earlier clone-body PLT callsites.

The contract explicitly records `analysis_status=PARTIAL_TIMEOUT`, keeps the
raw export private, and leaves `runtime_verified=false` and `callable=false`.
The counts support locating follow-up callers and lifecycle paths; they do not
prove source-level parameter types, ownership transfer, destructor pairing,
thread safety, runtime binding or safe invocation.

The added parser/contract/CLI tests pass with the current **305-test** public
suite; these synthetic tests do not execute the Sony ELF or connect to a
camera.

## Representative constructor argument cross-check — 2026-10-10

`fwplatform/param_family_callsite_probe.py` adds a bounded Capstone check for
five direct constructor callsites selected from the private Ghidra usage
metadata. The checked-in descriptive record is
`sdk/param_family_callsites_3_21.json`; raw bytes and disassembly remain
private. All five direct Thumb branches match their expected constructor VMA,
and the nearest `_Znwj` witness matches the object-size evidence: 0x10 bytes
for PrmBool, PrmNumber and PrmString, and 0x14 bytes for PrmPoint and
PrmStruct.

The visible pre-call register sources are:

| Family / callsite | Register source observed | Boundary |
|---|---|---|
| PrmBool / `0xfddd2` | `r1` copied from `r4` | source value/type unresolved; post-call `0xfdddc` passes `r1=0xa` and `r2` from `r8` to the existing Event add-parameter PLT target |
| PrmNumber / `0x111b96` | `r1` copied from `r5` | source value/type unresolved |
| PrmString / `0x10288c` | `r1` copied from `sb` | pointer/string encoding unresolved |
| PrmPoint / `0x113e8e` | `r1=[r7+0x26]`, `r2=[r7+0x24]` via signed halfword loads | field meaning and caller object type unresolved |
| PrmStruct / `0xe73d6` | `r1=[r4+0x17c]`, `r2=8` | pointer/length candidate only; schema unresolved; post-call `0xe73e0` passes key candidate 8 to the ParamList add PLT target |

The analyzer intentionally treats the allocator call as clobbering `r0-r3`:
the allocation-size witness is separate from the constructor's destination
pointer, and no register is promoted merely because an earlier instruction
loaded an immediate. It is a linear bounded observation, not complete
reaching-definitions analysis; branch joins, loop-carried values,
interprocedural sources, exception paths, ownership and concurrency remain
UNKNOWN. The contract and CLI remain `runtime_verified=false` and
`callable=false`.

## ParamBase foundation and direct RTTI relations — 2026-10-10

`fwplatform/param_base_probe.py` adds an independent SHA-pinned check of the
base ABI foundation. It reads the authenticated ELF before decoding and keeps
all addresses in `ELF_VMA`; the checked-in metadata contract is
`sdk/param_base_3_21.json`.

| Evidence | Static result | Boundary |
|---|---|---|
| Base RTTI `0xfe6e24`, vtable prefix `0xfe6e30`, address point `0xfe6e38` | RTTI name `9ParamBase`, offset-to-top `0`, clone slot `+8` relocates to `__cxa_pure_virtual`, destructor slots are `0xe4734` and `0xe4854` | Direct RTTI/vtable facts; source-level abstract-class declaration remains descriptive |
| Base constructor `_ZN9ParamBaseC2Em` at `0xe50b5` / bounded body `0xe50b4` | Stores incoming `r1` at object `+0x04`, resolves the base vtable through GOT `0x1033a60`, and stores its address point at `+0x00` | `r0` destination and `r1` discriminator are register-shape facts; no source-level exception/ABI safety claim |
| Base constructor bounded writes | No store to `+0x08` or `+0x0c` occurs in the verified body | This is scoped to the bounded body; derived constructors and ParamList insertion remain separate evidence |
| Base destructor `0xe4734` | Restores the base vptr and returns without payload release | Does not establish when callers may invoke it or whether an object is otherwise valid |
| Base deleting destructor `0xe4854` | Calls `0xe4734`, then the statically resolved `_ZdlPv` PLT `0xdd620` | Allocator interposition and ownership remain UNKNOWN |
| Key setter `0x7eda84` | Separate `str r1,[r0,#8]` witness for the ParamList element key | Key assignment is not part of the ParamBase constructor |

The same probe found **10** direct RTTI `+0x08` relations to `_ZTI9ParamBase`
(`PrmBool`, `PrmNumber`, `PrmString`, `PrmPoint`, `PrmDimension`, `PrmStruct`,
`PrmSet`, `PrmNumberList`, `PrmCntInfoList`, and `PrmObjMsg`). This is direct
single-inheritance RTTI evidence for this ELF, not a complete hierarchy or a
claim that all source-level virtual methods are recovered.

The private ASCII-path Ghidra 12.1.3 targeted `ParamBaseTargets.java` run used
`ARM:LE:32:v8`, image base `0x10000`, and `-noanalysis`. It exited `0` with
four target bodies, 31 instruction rows, four blocks and two CFG edges. The
raw export and project remain private. The public contract records this as a
static cross-check only; runtime verification and callable SDK counts remain
zero. Ownership, copy/assignment, exception handling, locking, concurrent
access and derived payload semantics remain UNKNOWN. The new validator adds
seven synthetic checks; the complete local suite now passes **318 tests**.

## PrmSet payload tree and lifetime cross-check — 2026-10-10

This checkpoint extends the earlier ParamBase/PrmSet bounded study. The
authenticated private ELF remains the exact SHA-256 pinned 3.21 `libObj.so`;
only descriptive metadata is checked in. `fwplatform/param_set_probe.py`
now validates the payload helper family and the standard-library relocation
identity without treating a stripped local helper as a source-level method.

The direct constructor/lifecycle facts are:

| ELF VMA | Evidence | Result | Boundary |
|---:|---|---|---|
| `0x7efb00` | `PrmSet` constructor calls `_ZN9ParamBaseC2Em` with `r1=7`, writes the derived vtable address point at `+0x00`, post-increments the object pointer by `0x0c`, and calls `0xffd22` | object size `0x24`; embedded payload starts at `+0x0c`; key `+0x08` is not written in this bounded constructor | source-level constructor exception/ownership behavior UNKNOWN |
| `0xffcf6` / `0xffce4` | payload initializer zeros 16 bytes at payload `+0x04`, clears `+0x14`, then writes `+0x0c`/`+0x10` links to payload `+0x04` | 24-byte payload word layout is directly observed | payload `+0x00` and exact node/header field names UNKNOWN |
| `0xffe1c` | bounded arithmetic uses `r0 = r1 * 0x14` after an overflow guard | node allocation unit is **20 bytes** | allocator and element type UNKNOWN |
| `0xffe4c` | node construction passes `r1` as `r2` to a word-copy helper with destination `node + 0x10` | node value begins at `+0x10` in this helper | value width/type and copy count UNKNOWN |
| `0xffe70` | constructs a node, calls the local comparator, passes `tree + 0x04` as the header argument, calls PLT `0xdc63c`, and increments `[tree + 0x14]` | ELF-local ordered-tree insertion helper | direct caller identity from a PrmSet mutator is not recovered |
| `0x63e83a` | self-copy guard, recursive copy helpers, and `ldr r3,[r5,#0x14]` / `str r3,[r4,#0x14]` | copy preserves the observed node-count field and returns destination | exception cleanup, aliases and source type UNKNOWN |
| `0xffd80` / `0xffdf6` | recursive child walk invokes local node-release helpers; `0xffe0c` delegates to it | embedded payload release is part of the PrmSet destructor path | exact node destructor and empty-tree guard semantics UNKNOWN |

The six dynamic imports below are uniquely resolved at their PLT/GOT slots in
the primary ELF. This is direct relocation evidence, not proof of the source
template or runtime loader binding:

| PLT VMA | Relocated symbol |
|---:|---|
| `0xdbb6c` | `_ZSt18_Rb_tree_incrementPKSt18_Rb_tree_node_base` |
| `0xdc63c` | `_ZSt29_Rb_tree_insert_and_rebalancebPSt18_Rb_tree_node_baseS0_RS_` |
| `0xdd17c` | `_ZSt28_Rb_tree_rebalance_for_erasePSt18_Rb_tree_node_baseRS_` |
| `0xde038` | `_ZSt18_Rb_tree_decrementPKSt18_Rb_tree_node_base` |
| `0xe0b00` | `_ZSt18_Rb_tree_incrementPSt18_Rb_tree_node_base` |
| `0xe186c` | `_ZSt18_Rb_tree_decrementPSt18_Rb_tree_node_base` |

Therefore the checked-in SDK contract records the payload as
**ordered-associative-tree-like** with `STATIC_INFERRED` source-family
metadata. It does not call the object `std::set<uint32_t>`, does not name a
comparator or element signedness, and does not expose a callable wrapper. The
new descriptive header words are in
`sdk/paramlist_3_21_candidate.hpp`; `sdk/param_set_3_21.json` records the
same offsets, relocation bindings, PrmSet RTTI relation (`6PrmSet` to
`ParamBase`) and unresolved boundaries. `runtime_verified=false` and
`callable=false` remain unchanged.

The ParamList lifetime evidence remains separate and applies to a pointer
returned through the lookup path: the list owns a shared counter at `+0x04`,
the clear/destructor paths invoke an element's virtual destructor slot only
for non-null elements, and storage is released when the counter reaches zero.
Consequently a `ParamList::get`/`PrmSet::getSet` result is a **borrowed
interior pointer candidate** whose validity ends on element replacement,
list destruction or another unverified owner release. No null-safety,
concurrency guarantee, copy-on-write detach, allocator interposition or
runtime ABI guarantee has been established.

A private ASCII-path Ghidra 12.1.3 `ParamListTargets.java param-set` run
cross-checked the new targets with `ARM:LE:32:v8`, image base `0x10000`, and
`-noanalysis`. It exited `0` with **17** target bodies, **243** instruction
rows, **30** basic blocks and **60** CFG edges, ending with
`COMPLETE_TARGET_EXPORT`. The raw export and project remain outside the public
checkout; the run is a targeted static cross-check, not whole-program Auto
Analysis and not runtime validation.

The new synthetic validator checks reject a wrong binary hash, wrong node
size, wrong `_Rb_tree` binding, missing tree evidence, wrong derived vtable,
exact source-type promotion and runtime/callable promotion. The complete
public suite now passes **318 tests**. Remaining blockers are the source-level ParamSet alias and
element type, a unique PrmSet mutation caller for `0xffe70`, complete
constructor/destructor exception paths, and any runtime/parallel safety
property.

## ParamSet value-width, comparator and caller evidence — 2026-10-10

This continuation re-read the same SHA-pinned private ELF with Capstone and
ran a fresh private Ghidra 12.1.3 targeted export. It did not repeat the
already recovered `ParamList::get` control flow. The public probe records only
metadata and addresses; no firmware bytes or decompiler text is checked in.

### New primary-ELF facts

| ELF VMA | Evidence | Result | Boundary |
|---:|---|---|---|
| `0xecd7a` | `cbz r1`; then `ldr r3,[r2]` and `str r3,[r1]` | the node-value copy helper transfers exactly one 32-bit word when the destination is non-null | source type, null-source behavior and exception semantics UNKNOWN |
| `0xefe6c` | loads `[r2]` and `[r1]`, compares with ARM unsigned condition codes, returns 1 only for the lower first word | local tree comparator is an unsigned 32-bit word less-than candidate | this proves the helper's operand width/order, not a source-level `PrmSet` typedef |
| `0x63e796` | adds `0x10` to the source node, calls `0xffe4c`, copies the source header word and clears destination links `+8/+0xc` | recursive copy path confirms a one-word value at node `+0x10` | exact node class, allocator and ownership UNKNOWN |
| `0xffed0` | bounded tree walk calls `0xffe70` at `0xfff4e` and `0xfff86` | generic unique-insert wrapper has two insertion paths | local symbol/function identity and relation to `PrmSet` UNKNOWN |

A bounded Thumb-`BL` scan over the executable `.text`, with Capstone
confirmation at each candidate, found direct calls to `0xffe70` at
`0xfff4e`, `0xfff86` and `0x7f4402`. No callsite was promoted to a
`PrmSet` mutation entry: the scan cannot prove that any caller consumed the
pointer returned by `PrmSet::getSet()`. This is preserved as UNKNOWN rather
than using a nearest-function heuristic.

### Ghidra cross-check

The fresh ASCII-path project used Ghidra **12.1.3**, language
`ARM:LE:32:v8`, image base `0x10000`, `-noanalysis`, and the exact private ELF
hash. `ParamListTargets.java param-set` exited successfully with the
`COMPLETE_TARGET_EXPORT` marker and exported **21** bounded target bodies,
**354** instruction rows, **49** basic blocks and **97** CFG edges. The
decompiler independently rendered the comparator as a `uint*` word comparison
and the copy helper as a single `undefined4` assignment. These are static
cross-checks only; this was not whole-program Auto Analysis and it provides no
runtime or callable-API proof.

The SDK contract `sdk/param_set_3_21.json` now records the one-word evidence,
comparator/copy helper VMAs and the three direct insertion callsites. The
descriptive header adds constants for the observed width and helper VMAs; it
still does not expose a live `std::set`, a host-pointer cast or a callable
wrapper. The targeted validator and complete local suite now pass **321
tests**. Runtime-verified and callable core API counts remain **0**.

The remaining blockers are narrower but unresolved: recover a cross-module or
uniquely typed caller for `PrmSet::getSet`, identify the exact source element
alias/comparator, and account for all constructor/destructor exception and
owner-release paths. Null safety, concurrent access and runtime ABI behavior
remain UNKNOWN.

## Cross-ELF PrmSet caller — 2026-10-10

The private unpacked 3.21 library set was scanned by dynamic symbol identity,
not basename.  Of 157 `.so` candidates, `libScalarDaemon.so` was the only
dependent ELF with undefined imports for both `_ZN6PrmSet6getSetEv` and
`_ZN6PrmSet3GETEPK9ParamListm`.  Its private SHA-256 is
`ca28cbf4c5c6402160ad80f6ad9f5e99052f42c3fabc382c557fcded18addc29`; the
provider `libObj.so` remains the authenticated
`8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`.

The reusable `fwplatform.paramset_cross_elf` analyzer resolves the two
undefined symbols through unique `R_ARM_JUMP_SLOT` relocations and an ARM PLT
instruction scan:

| Imported symbol | GOT relocation | PLT ELF VMA | Provider ELF VMA |
|---|---:|---:|---:|
| `PrmSet::getSet()` | `0x1c5858` | `0xcb224` | `0x7efae9` (Thumb-tagged) |
| `PrmSet::GET(ParamList const*, unsigned long)` | `0x1c8150` | `0xd30b8` | `0x7efaf1` (Thumb-tagged) |

The private Ghidra 12.1.3 project used `ARM:LE:32:v8`, Ghidra image base
`0x10000`, and completed Auto Analysis successfully.  The metadata-only
`ImportedSymbolReferences.java` exporter then located both application
references (private export SHA-256
`c3244eed2f746ae43e63b294681be3c590707b411ff16d7a1fa1cb650cf2dfac`) in the
Thumb function whose exact ELF symbol is
`_ZN12SCALARDAEMON15EventDispatcher19dispatchSystemEventER5Event` (entry
`0xd5b5c`, symbol Thumb value `0xd5b5d`, size `0xd0`):

* `0xd5b7a` is a Thumb `BLX` to the `GET` PLT.  The preceding instructions
  copy the preceding helper result through `r4` and set `r1` to the literal
  `0x19`.
* `0xd5b7e` performs `CBZ r0`; the following `0xd5b80` is a Thumb `BLX` to
  the `getSet` PLT.  Thus the non-null result of `GET` is used as the
  `getSet` receiver on this path.

The two exact callsites are `PRIMARY_ELF_VERIFIED` by independent Ghidra
reference and Capstone instruction evidence.  The composition
`ParamList/event helper → PrmSet::GET(0x19) → null guard → PrmSet::getSet()` is
recorded with `chain_status=PRIMARY_ELF_VERIFIED` for its observed instruction
shape and `chain_semantic_status=STATIC_INFERRED` for the composed C++ meaning:
the mangled symbols and bounded instructions do not encode a source-level
return type, ownership transfer, loader load bias, or runtime thread-safety
guarantee.  Ghidra's references inside the PLT stubs are retained as
`PLT_SELF_REFERENCE` exclusions rather than counted as application callers.

The public descriptive contract is `sdk/paramset_cross_elf_3_21.json`; the
private metadata export and all original bytes remain outside the repository.
`fw sdk parameter-set-cross-elf --elf <private-dependent-elf>
--ghidra-export <private-jsonl> --provider-elf <private-libObj.so>` reruns the
same checks.  `runtime_verified=false` and `callable=false` remain mandatory.
Seven synthetic parser/validator/CLI regression tests and the complete local
suite (328 tests) pass after this checkpoint.  This test result validates the
public evidence handling only; it is not runtime verification of the camera.

## PrmSet `_Rb_tree`-compatible header, node and release evidence — 2026-10-10

This checkpoint re-ran the bounded private probe against the exact SHA-pinned
Sony ILCE-6000 3.21 `libObj.so` (`8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`).
The new observations extend the earlier ParamList/PrmSet control-flow work;
they do not repeat the 76-byte `ParamList::get` recovery. The probe uses
Capstone 5.0.7 and the existing private Ghidra 12.1.3 targeted profile. The
Ghidra profile now includes the bounded accessor region at `0xffc40`; its
export remains private and the public repository contains only metadata.

### Direct primary-ELF facts

| ELF VMA | Direct observation | Status |
|---:|---|---|
| `0xffc40` | loads `[payload + 0x08]` and returns it | `PRIMARY_ELF_VERIFIED` |
| `0xffc60` / `0xffc68` | load node words at `+0x0c` and `+0x08` respectively | `PRIMARY_ELF_VERIFIED` |
| `0xffccc` / `0xffcd4` / `0xffcdc` / `0xffc70` | address accessors for `+0x0c`, `+0x08`, `+0x10`, and `+0x04` | `PRIMARY_ELF_VERIFIED` |
| `0xffce4` / `0xffcf6` | sentinel initialization makes `payload +0x0c` and `+0x10` point at `payload +0x04`; the initializer clears `+0x04..+0x13` and `+0x14` | `PRIMARY_ELF_VERIFIED` |
| `0xffd80` | follows the two observed node links, recurses until a selected link is null, then releases the node through the local delete path | `PRIMARY_ELF_VERIFIED` |
| `0xffdf6` / `0xffe0c` | payload destruction obtains the root through `0xffc40` and delegates to recursive release | `PRIMARY_ELF_VERIFIED` |
| `0xffe70` | passes `bool`, node, parent and `tree +0x04` header arguments to the relocation-resolved `_Rb_tree_insert_and_rebalance`, then increments `[tree +0x14]` | `PRIMARY_ELF_VERIFIED` |

The observed payload header begins at object-relative `+0x0c` and uses a
header base at payload-relative `+0x04`. Its words at `+0x04`, `+0x08`,
`+0x0c`, `+0x10` plus the count at `+0x14` are layout-compatible with the
20-byte libstdc++ `_Rb_tree_header` shape. A separately allocated node is
20 bytes: its `+0x08` and `+0x0c` words are followed by the recursive release
helper, and its one-word value storage is at `+0x10`. These offsets and the
imported `_Rb_tree` ABI are direct static facts; the compatibility statement
is `STATIC_INFERRED`.

### Lifetime and safety boundary

`PrmSet::getSet()` still returns an interior pointer candidate without a
retaining operation in its bounded body. The recursive release path reaches an
ARM interworking veneer and the `_ZdlPv` PLT binding, but allocator behavior,
exception cleanup, null/invalid-element policy outside the observed null link,
copy-on-write, owner identity, locks and concurrent access remain `UNKNOWN`.
A pointer obtained through `ParamList::get` or `getSet` must therefore remain a
descriptive borrowed-pointer candidate; it is not a safe host pointer or a
runtime SDK handle.

The exact source alias (`std::set`, another `_Rb_tree` wrapper, or a Sony
container), key/value typedef, comparator class, and full virtual destructor
ownership contract remain unresolved. No runtime verification was performed;
`runtime_verified=false` and `callable=false` are unchanged.

The updated probe, descriptive header and JSON contract add evidence-gated
header/node metadata and fail-closed tests for status promotion. The private
probe returned `validation={'valid': True, 'errors': []}` with the pinned
hash. The public test suite result and CI status are reported in the commit
that contains this checkpoint.

### Verification update after the accessor-profile rerun

The first rerun exposed an overlapping target range in the existing private
Ghidra profile; that run is retained as a failed environment observation and
is not counted as a successful export. `ParamListTargets.java` now removes
pre-existing overlapping functions, uses non-overlapping bounded helper
ranges, and recreates a missing target function before export. The corrected
ASCII-path Ghidra 12.1.3 run used `ARM:LE:32:v8`, image base `0x10000`, and
`-noanalysis`, exited `0`, and ended with `COMPLETE_TARGET_EXPORT`:

- 28 target bodies
- 375 instruction rows
- 55 basic blocks
- 96 CFG edges
- accessor targets present at `0xffc40`, `0xffc60`, `0xffc68`, `0xffc70`,
  `0xffccc`, `0xffcd4` and `0xffcdc`

The private export is not checked in. The full public synthetic regression
suite now passes **330 tests**. This validates the evidence gate and exporter
handling only; it does not add runtime or callable-API proof.

The public Windows environment has no `g++`, `clang++` or `cl`, so the
candidate C++ header was not compiler-checked in this session; its layout is
covered by the JSON/Python evidence gates and static assertions remain for a
future toolchain check.

### Address-space-aware caller recovery for the ordered-tree helpers — 2026-10-10

The new metadata-only `TargetCallers.java` export was rerun against the exact
SHA-pinned private ELF after adding a bounded profile for the small wrapper at
`0xfffb6`. The ASCII-path Ghidra 12.1.3 process exited `0` and emitted
`COMPLETE_TARGET_CALLER_EXPORT`; the export itself is private and is not part of
the public repository. Its program identity was `ARM:LE:32:v8`, Ghidra image
base `0x10000`, address space `ram`, and analyzer script version
`target-callers-1`. The companion five-target bounded CFG profile exported 295
instruction rows, 49 blocks and 116 edges; these counts are private validation metadata,
not a whole-ELF coverage claim.

The public contract `sdk/param_set_tree_callers_3_21.json` contains only
normalized metadata and evidence status. It records three helper targets and
eight caller references. All eight callsite VMAs were independently found by
the Capstone Thumb `BL` scan and mapped to a Ghidra caller whose reported body
range contains the callsite:

| Target | Callsite VMAs | Ghidra caller entry/body (ELF VMA) | Status |
|---:|---|---|---|
| `0xffe70` | `0x7f4402`, `0xfff4e`, `0xfff86` | `0x7f4390..0x7f44cd`; `0xffed0..0xfffb5` | callsites `PRIMARY_ELF_VERIFIED`; caller identity `GHIDRA_DERIVED` |
| `0xffed0` | `0x7f4440`, `0x7f44a0`, `0x7f44c6`, `0xfffc0` | `0x7f4390..0x7f44cd`; `0xfffb6..0xfffe5` | callsites `PRIMARY_ELF_VERIFIED`; caller identity `GHIDRA_DERIVED` |
| `0x7f4390` | `0x7f44fc` | `0x7f44ce..0x7f4519` | callsite `PRIMARY_ELF_VERIFIED`; caller identity `GHIDRA_DERIVED` |

The generated labels (`FUN_...`) remain locators and are explicitly marked
non-semantic. The `0x7f4390` body is a generic ordered-tree helper candidate;
the evidence still does **not** prove that it is a `PrmSet` mutator or that a
specific source-level class owns it. `prmset_mutator_entry` and
`prmset_relation` therefore remain `UNKNOWN`. The new parser rejects truncated
exports, hash/address-space mismatches, duplicate references and a callsite
outside its reported (possibly non-contiguous) body ranges. Runtime ownership,
exception cleanup, locking and callable safety remain unknown.

### PrmSet RTTI/vtable word confirmation — 2026-10-10

The exact SHA-pinned primary ELF was read again in a separate data-only pass;
the previously recovered `ParamList::get` control flow was not repeated. The
new `fwplatform.param_set_probe` reader accepts only a unique file-backed
`PT_LOAD`, so vtable words cannot be confused with instructions or zero-filled
runtime storage. It verified the `PrmSet` prefix and address point:

| ELF VMA | File word / target | Evidence level |
|---:|---|---|
| `0x1019d18` | offset-to-top `0x0` | `PRIMARY_ELF_VERIFIED` |
| `0x1019d1c` | RTTI pointer `0x1019d08` (`6PrmSet`) | `PRIMARY_ELF_VERIFIED` |
| `0x1019d20` | Thumb-tagged target `0x7efbb5`, body entry `0x7efbb4` | target `PRIMARY_ELF_VERIFIED`; clone role `STATIC_INFERRED` |
| `0x1019d24` | Thumb-tagged target `0x7efb2d`, body entry `0x7efb2c` | target `PRIMARY_ELF_VERIFIED`; destructor role `STATIC_INFERRED` |
| `0x1019d28` | Thumb-tagged target `0x7efb59`, body entry `0x7efb58` | target `PRIMARY_ELF_VERIFIED`; deleting role `STATIC_INFERRED` |

The independent `param_family_probe` reports the same three slot targets and
the direct RTTI `+0x08` relocation to `_ZTI9ParamBase`. The existing private
Ghidra 12.1.3 lifecycle/caller profiles contain bounded bodies for the clone
and both destructor targets and exit successfully; a fresh isolated ASCII-path
`ParamListTargets.java param-set` run against the same ELF also exited `0` with
the complete marker, 28 target bodies, 375 instruction rows, 55 blocks and 96
edges. Ghidra function labels are not used as semantic names. This is a
cross-check of target bodies and address-space mapping, not runtime dispatch
proof.

The probe now exposes the metadata through `inheritance.vtable_slots` and the
descriptive header constants in `sdk/paramlist_3_21_candidate.hpp`. Slot
positions and target addresses are preserved, while the source-level virtual
declarations, exception cleanup, allocator pairing and dispatch ABI remain
`UNKNOWN`/`STATIC_INFERRED` as stated. The constructor still has no observed
write to element key `+0x08`; the separate key setter at `0x7eda84` remains the
only direct key-initialization witness. The three new fail-closed tests reject a missing slot, an untagged/wrong slot
word or an unsafe concurrency promotion. Runtime-verified and callable
core API counts remain **0**.
The complete local synthetic suite passes **343 tests** after the vtable and safety validator additions.
The contract also records bounded null-guard observations, borrowed-pointer
invalidation, invalid-node behavior and concurrency as separate safety fields;
only the first two bounded no-guard observations are primary/static facts and
none is a runtime-safety guarantee.

## PrmSet copy/clone 例外清理與 ARM EHABI 交叉驗證 — 2026-10-10

本輪沒有重做 `ParamList::get`。在 SHA-pinned `libObj.so` 上，Capstone 重新讀取了 PrmSet 複製 helper `0x7efb6c` 和 clone candidate `0x7efbb4` 的正常與清理區段，並以 ELF `.ARM.exidx` 直接索引例外 unwind metadata。兩個 entry 各自只有一筆 `PRIMARY_ELF_VERIFIED` EHABI record：`0x7efb6c` 對應 `.ARM.exidx` entry `0xfb2a74` / EXTAB `0xf19718`，`0x7efbb4` 對應 `0xfb2a7c` / EXTAB `0xf19730`。這些是 ELF VMA metadata；沒有發布 unwind 編碼或韌體 bytes。

`0x7efb6c` 的正常路徑完成 ParamBase/payload 初始化並呼叫 payload copy `0x63e8a6`。同一 bounded region 的清理候選 `0x7efb9c` 依序呼叫 payload destroy `0xffe0c`、ParamBase destruction path `0xe4734`，再經 PLT `0xdd4f8`；該 PLT 的唯一 `.rel.plt` binding 是 `__cxa_end_cleanup`，GOT `0x102d660`。這支持「部分初始化 copy 路徑的 compiler-generated cleanup candidate」的描述，cleanup 語意保持 `STATIC_INFERRED`。

`0x7efbb4` 先配置 0x24 bytes、呼叫 `0x7efb6c`，正常返回新物件。其 bounded cleanup candidate `0x7efbce` 呼叫 `_ZdlPv` PLT `0xdd620`，再呼叫同一 `__cxa_end_cleanup` PLT。這支持「copy construction 失敗時釋放新配置物件」的靜態候選；不證明所有 throw edge、exception object、allocator pairing 或 source-level clone return type。

獨立 ASCII-path Ghidra 12.1.3 `param-set-exceptions` profile（ARM:LE:32:v8、image base `0x10000`、`-noanalysis`）exit `0`，寫出 `COMPLETE_TARGET_EXPORT`；四個 non-overlapping bounded targets、39 instruction rows、4 blocks、11 edges。Ghidra 與 Capstone 對 `0x7efb9c`／`0x7efbce` 的 direct call targets 一致；因 landing pad 在正常 CFG 外，Ghidra decompiler 的 bounded body 可能把相鄰資料／函式解讀成額外 flow，不能把該段 pseudo-C 當成語意證明。原始 export/project 仍只存於本機。

公開 `fwplatform/param_set_probe.py` 現在要求唯一 `.ARM.exidx` entry、唯一 `__cxa_end_cleanup` relocation binding，並把 exception cleanup status 固定在 `STATIC_INFERRED`；validator 會拒絕把 cleanup 或 runtime/callable 狀態提升。`sdk/param_set_3_21.json` 與 `sdk/paramlist_3_21_candidate.hpp` 加入描述性 EHABI/cleanup metadata；仍然不是可呼叫 wrapper。runtime verification 與 callable API counts 維持 **0**。本輪 targeted PrmSet regression tests：**22 passed**。 Full local regression suite: **347 tests passed in 16.666s**。

仍未解決：PrmSet 真實 source element typedef/comparator、唯一 mutation owner/caller、完整 EHABI throw-edge/exception-object semantics、allocator pairing、concurrency、runtime ABI 與可呼叫性。下一步應在不把 generic ordered-tree helper 誤標為 PrmSet mutator 的前提下，繼續追蹤 owner-release 與具體 construction/use sites。

## ParamBase 派生族 ARM EHABI lifecycle index — 2026-10-10

本輪把 `.ARM.exidx` 解析加入通用 `fwplatform.param_family_probe`。它只接受完整、SHA-pinned 的 primary ELF，對每個已由 RTTI/vtable 證實的 ParamBase 直接派生族，逐一要求 constructor、clone、non-deleting destructor 和 deleting destructor 的唯一 EHABI entry；回傳 section/VMA、EXTAB 或 compact 分類，不回傳 unwind words 或原始韌體 bytes。

私有 ELF 的十個 direct ParamBase RTTI records 均成功取得四個 lifecycle entries（共 40 筆 primary metadata）：`PrmBool`、`PrmNumber`、`PrmString`、`PrmPoint`、`PrmDimension`、`PrmStruct`、`PrmSet`、`PrmNumberList`、`PrmCntInfoList` 和 `PrmObjMsg`。`PrmSet` 的 entries 為 constructor `0x7efb00` / `.exidx 0xfb2a5c`、clone `0x7efbb4` / `0xfb2a7c`、D1 `0x7efb2c` / `0xfb2a64`、D0 `0x7efb58` / `0xfb2a6c`；`PrmNumberList` 的 entries 為 `0xecdb8` / `0xf60d3c`、`0xed3a4` / `0xf60e44`、`0xece64` / `0xf60d74`、`0xece98` / `0xf60d7c`；`PrmObjMsg` 的 entries 為 `0x12c754` / `0xf661bc`、`0x12c784` / `0xf661cc`、`0x12c700` / `0xf661ac`、`0x12c740` / `0xf661b4`。所有地址均為 `ELF_VMA`，每筆狀態為 `PRIMARY_ELF_VERIFIED`。

此 index 證實的是「某個精確函式 VMA 有唯一 EHABI metadata」；它不證明每條 throw edge、exception object、allocator pairing、source-level virtual declaration、所有權或並行生命週期。公開 `sdk/parameter_types_lifetime_3_21.json` 現在保存每一族的 sanitized entries，`runtime_verified=false`、`callable=false` 未變。通用 validator 會拒絕缺少 entry、錯誤地址空間或 runtime/callable promotion。這輪沒有重跑大型 Ghidra，也沒有把泛用 tree caller 歸屬到 ParamSet。

本輪新增的 family probe regression tests 與 checked-in contract shape checks 通過；完整本地測試為 **351 tests passed**。這只驗證 metadata 管線與 fail-closed 規則，不增加任何 runtime-verified 或 callable API。

## PrmSet direct lifecycle caller scan — 2026-10-10

為了縮小 owner/mutator 缺口，`fwplatform.param_set_probe` 新增一次性掃描：在同一份 primary ELF 的 executable `.text` 中，逐 2-byte 邊界辨識 Thumb `BL` encoding，再以 Capstone 確認候選指令。結果為：`getSet 0x7efae8`、`GET 0x7efaf0`、constructor `0x7efb00`、deleting destructor `0x7efb58` 和 clone `0x7efbb4` 均沒有 direct `BL` caller；non-deleting destructor `0x7efb2c` 只有 deleting path 內的 `0x7efb5e` 呼叫。這些 callsite 本身是 `PRIMARY_ELF_VERIFIED`，caller function identity 保持 `UNKNOWN`。

這是有明確掃描範圍的負向結果，不是「沒有任何 caller」的證明：它不涵蓋 `BLX`/register 或 vtable dispatch，也不涵蓋其他 ELF。公開 `sdk/param_set_3_21.json` 保存 target、callsite count/address 與 scope limit；因此 ParamSet owner/mutator 仍未確定，泛用 `_Rb_tree` helper 仍不可升級為 ParamSet API。

## ParamList::add key initialization and replacement lifetime — 2026-10-10

本輪沒有重做 `ParamList::get` 的 76-byte 控制流。新的
`fwplatform/paramlist_add_probe.py` 以完整 SHA-pinned `libObj.so`
`8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`
重新讀取並以 Capstone 驗證五個 bounded region；所有 VMA 均是
`ELF_VMA`，未輸出原始 bytes。

| ELF VMA | Primary ELF observation | Level |
|---:|---|---|
| `0x7ee0e6` | symbol-bound `_ZN9ParamList3addEmP9ParamBase`; forwards `r0/r1/r2` to the replacement candidate, then writes the key and appends the pointer on the nonzero path | `PRIMARY_ELF_VERIFIED` |
| `0x7eda84` | stores the incoming key word at element `+0x08` | `PRIMARY_ELF_VERIFIED` |
| `0x7ededa` | unnamed replacement body; compares object identity, key `+0x08` and discriminator `+0x04` | instruction facts `PRIMARY_ELF_VERIFIED`; composed operation `STATIC_INFERRED` |
| `0x7edf36` | loads the existing element vptr and invokes virtual slot `+8` after a key/discriminator match | `PRIMARY_ELF_VERIFIED` target/dispatch shape |
| `0x7ede7a` | removes one pointer slot and decrements the container end by four bytes | `PRIMARY_ELF_VERIFIED` |
| `0x7ee0b8` | appends the object pointer in the non-full path or delegates to growth/rebuild | `PRIMARY_ELF_VERIFIED` |

The add body does not write the incoming object's `+0x0c` payload. A null
incoming object returns before traversal; an identical existing pointer returns
without deletion. For a matching key and discriminator, the old element is
virtually destroyed before its slot is removed, so a prior `ParamList::get`
result is a borrowed interior pointer candidate that can become invalid. The
replacement body has no source-level name. It performs key/discriminator reads
before its later null check, so that later check is not a null-safety guarantee.
No lock or atomic operation was observed in the bounded body; ownership
transfer, allocator pairing, exception paths, cross-thread behavior and
runtime ABI remain `UNKNOWN`. `runtime_verified=false` and `callable=false`.

An isolated ASCII-path Ghidra 12.1.3 `ParamListTargets.java` export using
`ARM:LE:32:v8`, image base `0x10000` and `-noanalysis` exited `0` with
`COMPLETE_TARGET_EXPORT`: 21 bounded targets, 343 instruction rows, 79 basic
blocks and 135 CFG edges. The `0x7ee0e6` body and `0x7ededa` body ranges and
call targets agree with Capstone after subtracting the Ghidra image base.
The private export/project remains outside the repository; this is a static
cross-check, not runtime or callable-API validation.

The sanitized contract is `sdk/paramlist_add_3_21.json`, the descriptive
constants are in `sdk/paramlist_3_21_candidate.hpp`, and the CLI is:

```powershell
python -m fwplatform.cli sdk parameter-add --elf C:\private\libObj.so --json
```

Synthetic fail-closed coverage rejects wrong identity, missing observations,
payload-scope promotion, concurrency promotion and runtime/callable claims.
The complete local regression suite passes **357 tests** after this probe was
added; this validates the public evidence gates and does not increase the
runtime-verified or callable API counts.

## EventManager::count indexed-state boundary — 2026-10-10

The exact SHA-pinned primary ELF also contains the symbol
`_ZN12EventManager5countEj` at Thumb value `0x7ef9fd`, even entry `0x7ef9fc`,
with a 34-byte extent. The new bounded probe confirms `r0` as an EventManager
receiver candidate and `r1` as an unsigned index. It calls `0x7ef8f4`, loads a
state pointer from `[receiver]`, reads a 32-bit word at
`[state + (index << 2)]`, passes that word through `0x7f0aa0`, then calls
`0x7ef902` before moving the helper result to `r0`. The symbol does not encode
the C++ return type.

The indexed access has no local conditional bounds check in this bounded body.
That is a `PRIMARY_ELF_VERIFIED` instruction fact, not a claim of an invalid
index path or runtime memory safety. State allocation, valid index range,
helper semantics, receiver validity, ownership, loader binding and concurrency
remain `UNKNOWN`; `runtime_verified=false` and `callable=false`.

The corrected private ASCII-path Ghidra 12.1.3 `event-manager-count` profile
used `ARM:LE:32:v8`, image base `0x10000` and `-noanalysis`, exited 0 with
`COMPLETE_TARGET_EXPORT`, 13 instruction rows, one basic block and three call
edges. The mapped Ghidra body `0x7ff9fc..0x7ffa1d` agrees with Capstone after
subtracting the image base. The private export/project remains outside the
repository.

The current full local `python -m unittest discover -s tests -v` run passes
**367 tests**. These are synthetic/public evidence-gate tests; runtime
verification and callable API counts remain 0.

## EventManager helper-chain and mutex binding refinement — 2026-10-10

The SHA-pinned probe now checks the bounded helper chain behind
`EventManager::count`: `0x7f0a32` compares the current pointer with a
sentinel, `0x7f0a42` follows the current node's first word, and
`0x7f0a4e` increments a counter until the pointers compare equal. Wrappers
`0x7f096a` and `0x7f0984` respectively load the input's first word and return
the original input pointer; `0x7f0aa0` tail-branches into this chain. The
result supports a forward-link distance candidate (`STATIC_INFERRED`) while
the source-level container, ownership, cycle/termination invariant and index
range remain `UNKNOWN`.

The count method's `0x7ef8f4`/`0x7ef902` wrappers use receiver `+0x0c` and
have unique static ARM/Thumb veneer bindings to `pthread_mutex_lock` at
`0xdcc70` / GOT `0x102d3ac` and `pthread_mutex_unlock` at `0xe29e8` / GOT
`0x102f130`. Runtime loader binding and full concurrency correctness remain
unknown. The updated private Ghidra export completed with 12 targets, 100
instructions, 15 blocks and 18 edges. Runtime-verified and callable counts
remain 0.

## EventManager state-link initialization refinement — 2026-10-10

The initializer candidate at `0x7ef894` allocates an 8-byte state array and
two 8-byte state objects. The newly bounded helper probe confirms the local
chain `0x7f09be -> 0x1111cc/0x1114b0`: `0x1111b8` writes zero to the two words
before invoking `0x1111a2`, and `0x1111a2` stores the object pointer at both
`+0x00` and `+0x04`. The second path calls a clear traversal and ends with the
same self-link routine. These are `PRIMARY_ELF_VERIFIED` instruction facts;
the composed two-word link-object interpretation is `STATIC_INFERRED`.

No source-level container, constructor identity, allocation/deallocation
pairing, ownership, cycle/termination guarantee or runtime safety is claimed.
The private Ghidra cross-check exited 0 with 15 targets, 162 instruction rows,
23 blocks and 37 edges. The adjacent cleanup candidate statically binds the
payload release path to `Event::~Event`, `_ZdlPv` and `__cxa_end_cleanup`; its
EventManager ownership and destructor identity remain UNKNOWN. Runtime-verified
and callable counts remain 0.

## ParamBase scalar constructor, key and lifetime closure — 2026-10-10

This checkpoint adds `fwplatform.param_scalar_probe.py` and the sanitized
contract `sdk/param_scalar_lifetime_3_21.json`. It reads only the exact,
SHA-pinned primary `libObj.so` (`8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`),
decodes bounded Thumb regions with Capstone, and resolves the PLT bindings for
the ParamBase constructor, object allocation and object deletion. It does not
publish firmware bytes or execute the ELF.

The probe closes the following two scalar-family chains:

| Family | Constructor and payload | Clone | Destruction | Evidence boundary |
|---|---|---|---|---|
| `PrmBool` | `0xe50e8` calls the relocation-bound `_ZN9ParamBaseC2Em` PLT at `0xe11a4` with discriminator `5`; original `r1` is saved in `r6` and `0xe5100` stores one byte at `object +0x0c`; vptr is written at `+0x00` | `0xe5110` allocates `0x10` bytes, loads source `+0x0c` with `ldrb` and calls the constructor; no `+0x08` key load | D1 `0xe4750` restores the family vptr and calls base D1 `0xe4734`; D0 `0xe4840` dispatches the relocation-bound `PrmBoolD1` PLT and `_ZdlPv` | byte-width/source register are `PRIMARY_ELF_VERIFIED`; semantic domain, owner and allocator runtime remain unknown |
| `PrmNumber` | `0xf0fb0` calls the same ParamBase PLT with discriminator `1`; original `r1` is saved in `r6` and `0xf0fc8` stores one word at `object +0x0c`; vptr is written at `+0x00` | `0xf1034` allocates `0x10` bytes, loads source `+0x0c` with `ldr` and calls the constructor; no `+0x08` key load | D1 `0xf0f2c` restores the family vptr and calls base D1; D0 `0xf0f5c` calls D1 then `_ZdlPv` | word-width/source register are `PRIMARY_ELF_VERIFIED`; signed-int interpretation is supported by `_ZN9PrmNumber9setNumberEi` at `0x10f9fc`, while range/domain and ownership remain unknown |

Both constructors and clones have no bounded store/load of the ParamList key
at `+0x08`. The independent key setter at `0x7eda84`, reached from the
`ParamList::add` path, remains the only direct key-initialization witness.
Therefore a newly constructed scalar object is not treated as a complete
ParamList element until the insertion path is separately followed. This also
keeps a cloned element's key semantics unresolved; payload cloning alone does
not prove key copying.

The private ASCII-path Ghidra 12.1.3 `ParamListTargets.java lifecycle` run
used language `ARM:LE:32:v8`, image base `0x10000`, and `-noanalysis`. It
finished with `COMPLETE_TARGET_EXPORT`: **22** bounded targets, **342**
instruction rows, **43** blocks and **72** edges. The profile includes both
scalar constructors, clones, setters and D1/D0 paths; Ghidra is a CFG/address
cross-check and its generated names are not semantic proof. The private
project/export remain outside the repository.

The checked-in SDK record exposes read-only snapshot metadata and the new
`fw sdk parameter-scalar --elf <private-libObj.so> --json` command. Its
validator rejects wrong hashes, missing lifecycle phases, key-scope promotion
and runtime/callable claims. The new scalar regression tests and the existing
ParamBase/family tests pass. Runtime-verified and callable core API counts
remain **0**. Still unresolved are ParamList owner identity, allocator
interposition, C++ exception edges, synchronization, and whether any external
caller may safely construct or retain these objects.

## ParamList shared-counter construction and last-owner cleanup — 2026-10-10

This checkpoint closes the next owner/lifetime boundary without repeating the
already recovered `ParamList::get` body. The new
`fwplatform.paramlist_lifetime_probe.py` authenticates the complete private
ELF before decoding and records only normalized metadata in
`sdk/paramlist_lifetime_3_21.json`.

| VMA / symbol | Primary ELF observation | Boundary |
|---:|---|---|
| `0x7edc3e` `_ZN9ParamListC1Ev` | allocates 0x0c bytes for a pointer container, initializes begin/end/capacity to zero, stores it at object `+0x00`; allocates a 4-byte counter, writes `1`, stores it at `+0x04` | allocation failure and source-level counter type UNKNOWN |
| `0x7edb76` `_ZN9ParamList5clearEv` → `0x7edb40` | computes `(end - begin) >> 2`, visits 4-byte element pointers, skips null slots, and invokes each non-null element's vtable slot `+0x08`; resets end to begin | indirect target and container source type UNKNOWN |
| `0x7edcc6` unnamed rebind candidate | compares destination/source, decrements the old shared counter, clears/releases the old container only on zero, increments the source counter, then copies source container/counter pointers into the destination | source-level copy/assignment identity and return declaration UNKNOWN |
| `0x7edd08` `_ZN9ParamListD1Ev` | decrements the counter; nonzero skips storage cleanup; zero clears elements, conditionally releases/deletes the container and deletes the counter through `_ZdlPv` | allocator interposition, exception edges and runtime ownership UNKNOWN |

The shared-pointer interpretation is `STATIC_INFERRED` from the primary
increment/decrement and last-owner branches. The field offsets and branch/call
instructions are `PRIMARY_ELF_VERIFIED`; no lock or atomic operation appears
in these bounded bodies, so thread safety is **UNKNOWN**. The observed rebind
path shares the container and counter and therefore does not prove copy-on-
write. A `ParamList::get` result remains a borrowed interior pointer candidate
that may be invalidated by clear, replacement or last-owner destruction.

The private ASCII-path Ghidra 12.1.3 `paramlist-lifetime` profile used
`ARM:LE:32:v8`, image base `0x10000`, and `-noanalysis`. It completed with
`COMPLETE_TARGET_EXPORT`: **11** bounded targets, **130** instruction rows,
**26** blocks and **43** CFG edges. The profile is a cross-check of addresses
and control flow; generated names and decompiler prose are not semantic proof.
The project/export remain outside this repository.

The read-only CLI is:

```powershell
python -m fwplatform.cli sdk parameter-lifetime --elf C:\private\libObj.so --json
```

Eight new fail-closed tests cover identity, layout, observation completeness,
concurrency, copy-on-write and runtime/callable promotion. Runtime-verified
and callable core API counts remain **0**.

## ParamList external owner/use witness — 2026-10-10

The next bounded primary-ELF pass follows a real use site instead of repeating
the `ParamList::get` implementation. `fwplatform.paramlist_owner_use_probe.py`
authenticates the same SHA-pinned ELF and verifies the complete symbol-bounded
body of `_ZN12InputService19getInputEventStatusEP9ParamListPKS0_` at
`0x114104` (356 bytes). The sanitized result is
`sdk/paramlist_owner_use_3_21.json`.

| Evidence location | Observation | Status / boundary |
|---:|---|---|
| `0x11410a–0x114140` | preserves the incoming `r0`, moves incoming `r1` into the first `ParamList` lookup receiver, loads key `0x17005003`, calls `0xe5b20`, and forwards the result to `0xe5b18` | `PRIMARY_ELF_VERIFIED`; C++ static/member form UNKNOWN |
| `0x11416e`, `0x114176` | calls PLT `0xdf894`, uniquely bound to `_ZN9ParamListC1Ev`, for stack locals `+0x20` and `+0x18` | `PRIMARY_ELF_VERIFIED` |
| `0x114184–0x11419a` | allocates `0x10` bytes through `_Znwj`, calls the known `PrmNumber` constructor `0xf0fb0`, and calls PLT `0xdfdc0` (`ParamList::add`) with key `0x17005003` and the local element pointer | call/relocation facts `PRIMARY_ELF_VERIFIED`; value source and ownership UNKNOWN |
| `0x1141ac–0x1141b8` | looks up key `0x17005008` in the `+0x20` local list and reads its payload word | `PRIMARY_ELF_VERIFIED`; payload meaning UNKNOWN |
| `0x1141dc–0x1141e2` | conditionally calls `0x7edcc6` with preserved original `r0` as destination and stack `+0x20` as source | instruction fact `PRIMARY_ELF_VERIFIED`; shared-rebind interpretation `STATIC_INFERRED` |
| `0x1141f2–0x1141fe` | destroys the `+0x18` and `+0x20` local lists through PLT `0xe0080`, uniquely bound to `_ZN9ParamListD1Ev` | `PRIMARY_ELF_VERIFIED` |

The function itself is an exported symbol with exact ELF identity and size;
the mangled name alone does not prove whether it is a static member or has a
ParamList-shaped object at `r0`. The contract therefore leaves that form,
source-level return type, ParamList::add ownership transfer, exception cleanup,
locking, dispatch registration, and runtime binding UNKNOWN. No direct Thumb
BL caller for this function was found in the bounded whole-`.text` Capstone scan;
that is unresolved dispatch coverage, not evidence that the function is unused.

The private ASCII-path Ghidra 12.1.3 bounded cross-check used the same
`ARM:LE:32:v8` program and completed with `COMPLETE_TARGET_EXPORT`: **6**
targets, **210** instruction rows, **37** blocks and **87** CFG edges. It is
address/control-flow corroboration only; no generated decompiler semantics or
private export was added to the repository. Runtime-verified and callable
core API counts remain **0**. Eleven fail-closed synthetic validator tests cover
identity, callsite chain, static/member-form, rebind, return-type and
runtime/callable promotion guards; the complete local suite passes **392
tests**.

## InputService cross-ELF import boundary — 2026-10-10

The generic `fwplatform.cross_elf_import_probe` scans an explicitly supplied
private firmware root for one exact dynamic symbol. Against the official 3.21
extracted root it scanned **511** `.so`/`.elf` files and found **9** distinct
importers of `_ZN12InputService19getInputEventStatusEP9ParamListPKS0_`:
`cmn_view_processDataMgr.so`, `libInputServant.so`, `viewUnified2.so`,
`viewUnified4.so`, `viewUnified6.so`, `viewUnified7.so`, `viewUnified8.so`,
`waterProofHousing.so` and `wrapperSettingUtil.so`.

Every importer has one exact undefined dynamic symbol and one
`R_ARM_JUMP_SLOT` relocation. Each relocation maps to a unique ARM PLT stub
and GOT slot. The provider `libObj.so` export was checked against the pinned
SHA-256 `8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`
and export value `0x114105` / size `356`.

Import, relocation and export facts are `PRIMARY_ELF_VERIFIED`. The provider
edge is only `STATIC_INFERRED`: importer DT_NEEDED lists do not name
`libObj.so`, so runtime loader search order and binding remain unknown. A
bounded ARM/Thumb direct-immediate BL/BLX scan found no direct callsite in the
nine importer binaries. This is an `UNKNOWN` negative result because
register-indirect, GOT-indirect, vtable and other dispatch forms are outside
the scan; it does not establish that the function is unused.

The sanitized result is `sdk/input_service_cross_elf_3_21.json`. The generic
read-only command is:

```powershell
python -m fwplatform.cli sdk parameter-cross-elf --root C:\private\firmware-root --provider-elf C:\private\libObj.so --provider-sha256 8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a --json
```

Only hashes, relative paths, relocation/PLT addresses and scan limits are
published. No firmware bytes or private absolute paths are included. Runtime-
verified and callable API counts remain **0**.

### Ghidra cross-check for one importer

The private `viewUnified4.so` copy was independently verified against SHA-256
`149282ac0f1e1a1cf1ef7302214c6ab843e889945ce613cc9e7ec15823fd26e1` and
analysed with Ghidra **12.1.3** using `ARM:LE:32:v8`, compiler spec `default`,
image base `0x10000` and address space `ram`. Auto-analysis completed with
process exit **0**. A metadata-only post-script produced 37 records; the raw
JSONL remains private.

The exact mangled import lookup was `UNRESOLVED` because Ghidra represented the
import under the demangled external namespace
`<EXTERNAL>::InputService::getInputEventStatus`. A wildcard re-run found the
imported external symbol and its PLT/GOT references: the ELF-VMA GOT reference
is `0x1ae5c8`, the PLT entry is `0x3d434`, and Ghidra classified the PLT
transfer as `COMPUTED_CALL`. These are static importer/PLT observations only;
they do not prove a caller-to-PLT execution path or runtime loader binding.
The sanitized metadata is stored under the `viewUnified4.so` observation in
`sdk/input_service_cross_elf_3_21.json`, with `runtime_verified=false` and
`callable=false`.

The targeted cross-ELF regression file now has **9** synthetic checks for
identity, relocation/PLT completeness, generic symbol handling, Ghidra
cross-check identity and runtime/callable promotion rejection. The latest
full local suite passes **401 tests**; this count measures evidence-gate
behavior only and does not increase the runtime-verified or callable API
counts.
