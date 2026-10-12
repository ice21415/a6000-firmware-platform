# Phase 4.32 — `libIMDB.so` contains an allocated init-name pointer (user-observed)

**Firmware:** Sony A6000 3.21. **Source:** user's read-only local `inspect_a6000_init_literal.py` result (2026-10-11). The `libIMDB.so` bytes were not independently received or inspected in the assistant container. Do not treat speculative neighbors as verified facts.

## Raw observations

```text
ELF: libIMDB.so | exact token occurrences: 1
  STRING offset=0x3672 section=.rodata allocated=True vma=0x00003672
Candidate address-word references: 1 (not calls)
  PTR word at .data.rel.ro VMA 0x0000d200 -> 0x00003672
Dynamic symbols of interest: none
```

In a corpus of 649 unpacked ELF files, the preceding direct-import search reported no `Application_System_Init` undefined dynamic symbol; `libObj.so` uniquely exported that symbol, while `libIMDB.so` contained a literal only. Here the literal's **allocated `.rodata` address** is additionally pointed to by one 32-bit word in **`.data.rel.ro`**. Because that section commonly holds pointer-bearing structures, this is a promising **candidate table entry**, but **neither a function pointer nor a callable registration has been shown**. The pointer refers to the *name string*, **not** to the exported `Application_System_Init` code in `libObj.so`.

No direct `dlsym`, `dlopen`, `dlclose`, or `Application_System_Init` dynamic symbols of interest were observed by the bounded script. This doesn't exclude indirect library loader paths, a private lookup convention, a generic dispatcher or strings resolved elsewhere.

## Critical next questions

- What do the 4-byte words surrounding `0xD200` contain? Are there consistent rows with a function pointer, name pointer, module name, or flags?
- Is `.data.rel.ro[0xD200]` actually referenced by a relocation? Does that relocation merely adjust the string pointer at load time?
- Are neighboring pointer words directed to `.rodata`, `.text`, additional metadata records or other unknown addresses? Multiple references would strengthen the table interpretation.
- Is there *any direct disassembled consumer* that looks up, iterates, or calls through the putative table? **Without this, do not promote the string/table candidate to an initializer-call proof.**
- Regardless of `libIMDB` linkage, what argument (if any) reaches exported `Application_System_Init(r0)` at runtime? The established null-default `AppConfig.so` vs non-null selector branch remains conditional.

## New bounded local-only metadata experiment

A synthetic-tested, stdlib-only private-use Python helper `inspect_a6000_imdb_record.py` reads `libIMDB.so` and:

1. finds the allocated `Application_System_Init` token and the word pointing to its VMA;
2. prints a bounded ±8 words around the candidate pointer with ELF section classifications (NULL, string pointer, Thumb/code candidate, other data pointer, unresolved/scalar);
3. prints matching ELF relocation entries, if present, and a list of declared `DT_NEEDED` libraries;
4. never executes the ELF, runs a camera command, patches files or exposes arbitrarily long binary blobs.

Five synthetic tests passed locally, including candidate string/word matching, relocation handling, and ARM ELF rejection. The actual `libIMDB.so` output is **pending**; no surrounding-word or relocation contents are yet proven. This tool remains available as a local user-facing download; the public project records only analysis reports, not private Sony firmware binaries.

## No change to API verification status

**74 primary static / 5 inferred / 5 unresolved = 84 tracked.** End-to-end blockers resolved: 0. Runtime-verified or safe-to-invoke camera APIs: 0. A data pointer to the *string* does not justify a new core API graph edge, and certainly does not establish `modelCamera.so` runtime loader identity.

See `reports/PHASE4_30_APPLICATION_SYSTEM_INIT_SELECTOR_WRITER.md` for the ELF-proven `Application_System_Init` null/default conditional BSS writer, and `reports/PHASE4_31_INIT_REFERENCE_SWEEP.md` for the 649-ELF survey.
