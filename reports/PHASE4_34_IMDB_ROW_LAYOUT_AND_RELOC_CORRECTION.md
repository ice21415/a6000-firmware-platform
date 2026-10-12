# Phase 4.34 — Four adjacent IMDB records; relocation entries are **not** consumer XREFs

**Firmware:** Sony A6000 3.21. **Evidence:** user-run read-only `inspect_a6000_imdb_table.py` output for privately held `libIMDB.so`; `libObj.so` SHA256 `8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a` inspected independently.

## 1. Four contiguous records with an apparent 44-byte stride

| Row start | First word | Other observed fields |
|---|---|---|
| `0xD1C0` | `0x00000007` | `+0x04=1`; `+0x08/+0x0c=0`; remaining seven 32-bit pointers all point to `.rodata 0x3eea` |
| `0xD1EC` | `0x20000004` | `+0x04=1`; `+0x08=0xffffff9f`; `+0x0c=0x07fb0083`; `+0x10=appFw.so`; `+0x14=Application_System_Init`; `+0x18,+0x1c,+0x20=0x3eea`; `+0x24=AdjChkConfig.so`; `+0x28=AppConfig.so` |
| `0xD218` | `0x20000004` | `+0x04=1`; `+0x08=0x40`; `+0x0c=0x83`; `+0x10=subapp.so`; `+0x14=subapp_init`; `+0x18=subapp_exit`; `+0x1c/+0x20=0x3eea`; `+0x24=AdjChkConfig.so`; `+0x28=AppConfig.so` |
| `0xD244` | `0x00000008` | `+0x04=1`; `+0x08/+0x0c=0`; remaining seven pointers all target `0x3eea` |

Consecutive starts are spaced exactly `0x2c` apart. The 7/8 first-word values may be **row types**, not invalid markers; calling only 2/4 rows valid due to non-matching `0x20000004` would prematurely discard plausible table entries. No schema consumer or external spec has yet established actual row type semantics. The shared `0x3eea` target is currently just an allocated `.rodata` location; its exact contents are not demonstrated by this output.

## 2. Important correction: `.rel.dyn` 'references' were **relocation metadata**

The user scanner ended with:

```text
.rel.dyn + VMA 0x000019d4 -> 0x0000d1fc
.rel.dyn + VMA 0x000019dc -> 0x0000d200
.rel.dyn + VMA 0x000019fc -> 0x0000d210
.rel.dyn + VMA 0x00001a04 -> 0x0000d214
```

The same user output identifies each respective destination field as an **`R_ARM_RELATIVE`** relocation. In ELF32 `SHT_REL`, a relocation entry begins with a 32-bit **`r_offset`**, the memory word that needs loader relocation, followed by `r_info`. Therefore these are expected relocation descriptor words pointing **at the field being relocated**. They are *not* independent consumers of those fields, data-index references, function pointers or code callsites.

The previous `inspect_a6000_imdb_table.py` raw pointer search scanned allocated noncode sections **including `.rel.dyn`**, yielding a misleading heading `Exact address-word references`. Those values are real relocation-table offsets but **must be excluded when asking whether executable/data code references the descriptor record**.

A new local-only stdlib parser `inspect_a6000_imdb_xrefs.py` separates `SHT_REL/SHT_RELA` entries (reported as `RELOCATION_METADATA`) from 32-bit words in loaded `SHT_PROGBITS` sections (reported as code literal/data candidates). It prints concise adjacent record metadata and checks the pointer target at `0x3eea` for a zero byte. Four synthetic tests passed. Actual user run on `libIMDB.so` is pending.

## 3. Why appFw.so is not libObj.so identity proof

The independently available private `libObj.so` has ELF **`DT_SONAME=libObj.so`**, and exports `Application_System_Init` at Thumb value `0x007ed9f5`. The IMDB row names `appFw.so` but the named module was not among the previously directly imported ELF symbols. This means a straightforward SONAME equality is not present. This **does not** exclude runtime loader aliases, an install-time rename, a wrapper loader or a module namespace, none of which have yet been shown.

The IMDB candidate row's `AppConfig.so` field and the exported `Application_System_Init(NULL)` default are distinct pieces of evidence; combining them does not establish a null runtime argument, an executed initializer or a selected provider branch.

## 4. Next evidence target

1. Distinguish `SHT_REL` relocation metadata from actual pointers to records in loaded sections.
2. Locate the code or runtime loader that reads/deserializes the 44-byte records. A raw pointer in `.text` is only a literal pool **candidate**, not verified code control flow. If no raw pointer exists, use PC-relative instruction tracing (and/or relocation-aware disassembly) from an actual `libIMDB.so` binary; absence of a raw word match is not negative proof.
3. Establish whether the loader resolves `appFw.so` to the module exporting `Application_System_Init`, and exactly how the `+0x24/+0x28` config names are passed into that function; no runtime branch promoted yet.

**Graph unchanged:** 74 directly primary ELF-verified + 5 inferred + 5 unresolved = **84 tracked**. Five end-to-end blockers remain open. Zero runtime-verified/safe-to-invoke API entries.

No firmware binaries or sensitive RAM contents are committed, executed, or modified. All procedures are read-only offline.
