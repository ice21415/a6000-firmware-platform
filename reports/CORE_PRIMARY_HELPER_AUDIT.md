# Core helper primary evidence — 2026-10-09

## ParamList continuation — latest checkpoint

The installation was copied to an ASCII path and the new
`ghidra-scripts/ParamListTargets.java` run returned **exit 0**. The original
non-ASCII installation and failed logs were preserved. Successful targeted
analysis does not imply full-libObj auto-analysis coverage.

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
Full public synthetic regression run: **210 tests passed**, process exit 0.
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
- Ghidra 12.1.3 targeted import/disassembly/decompilation ran with auto-analysis
  disabled. It is NOT counted as full binary CFG recovery.
- Ghidra image base was 0x10000; target addresses are ELF VMA +0x10000.
  Initial wrong-mode/wrong-address attempts were rejected and retained privately.
- Correctly mapped Thumb instruction rows agree with Capstone. The parameter
  wrapper and local getters have useful decompilation. Tail-call decompilation
  spills into PLT instructions and is rejected as semantic evidence.
- Target script reached its completion marker. Headless returned exit 1 because
  the installed Ghidra logging configuration fails on its non-ASCII installation
  path. This is a recorded environment limitation, not a clean headless success.

## SDK outcome

`sdk/core_3_21_primary_helper_contracts.json` records descriptive, field-scoped
contracts. `fw sdk primary-contracts --json` validates identity, address space,
evidence locators and absence of runtime/callability claims.
Old saved-text research remains preserved; this is additive primary evidence.

Fully verified callable core APIs: **0**. Runtime verification: **0**.
Public synthetic regression suite: **206 tests passed** (Python 3.12),
including three PLT decoding tests and three descriptive-contract safety tests.
Next: review the actual ParamList::get body at ELF VMA 0x7edaca, its returned
object layout and lookup invariants; recover the wrapper class via RTTI/vtables;
repair Ghidra logging and tail-call analysis before relying on decompiler types.
