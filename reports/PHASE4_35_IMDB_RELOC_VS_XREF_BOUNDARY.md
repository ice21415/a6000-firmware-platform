# Phase 4.35 — Confirmed IMDB relocation metadata, no loaded raw pointer XREF

**Date:** 2026-10-11. Sony A6000 firmware 3.21. Primary new evidence is user-run `inspect_a6000_imdb_xrefs.py` against a locally owned `libIMDB.so`; the private IMDB binary itself was not uploaded in this turn.

## User tool results

The four contiguous `.data.rel.ro` records are spaced exactly **0x2c (44 bytes)**:

| Start | Header word | Names in +0x10 onward |
| --- | --- | --- |
| `0xd1c0` | `0x00000007` | Seven repeated pointers to a NUL-starting .rodata region |
| `0xd1ec` | `0x20000004` | `appFw.so`; `Application_System_Init`; three empty-string pointer candidates; `AdjChkConfig.so`; `AppConfig.so` |
| `0xd218` | `0x20000004` | `subapp.so`; `subapp_init`; `subapp_exit`; two empty-string pointer candidates; `AdjChkConfig.so`; `AppConfig.so` |
| `0xd244` | `0x00000008` | Seven repeated pointers to the NUL-starting .rodata region |

The seven relocation entries the scanner explicitly classified are:

| `.rel.dyn` entry offset | `r_offset` target in `.data.rel.ro` |
| --- | --- |
| `0x19d4` | `0xd1fc` |
| `0x19dc` | `0xd200` |
| `0x19fc` | `0xd210` |
| `0x1a04` | `0xd214` |
| `0x1a0c` | `0xd228` |
| `0x1a14` | `0xd22c` |
| `0x1a1c` | `0xd230` |

All are `R_ARM_RELATIVE`, symbol index 0. They relocate the *named fields*. **They are not independent code references.** The scanner reports **zero 32-bit address-word matches in loaded PROGBITS sections** for the chosen row/name target addresses. This negative result is bounded: it does **not** exclude an ARM/Thumb PC-relative access, arithmetic-derived pointer, GOT-based indirection, runtime-synthesized pointer, or references to a *table base different from the searched addresses*.

## Independent contextual observation, not linkage proof

The privately available SHA-pinned `libObj.so` contains a separate `appFw.so` string in its `.rodata` at ELF VMA/file offset **0x00cbc829**, adjacent in the data bytes to literals `initialize`, `@M001`, `modelRoot.so` and `ModelRootToInstance`. This is **string proximity only**; no executable reference or equivalence of `appFw.so` with the actual `libObj.so` SONAME was established. `libObj.so` does define `Application_System_Init`. The IMDB row's association between `appFw.so` and the init *name* is not, on its own, proof that the firmware loader resolves that pair, which provider branch runs, or what argument reaches the export.

## Next precise proof target

Read-only ARM32 disassembly and relocation-aware analysis of the **actual `libIMDB.so`** is now higher value than repeating name/pointer scans. Locate programmatic consumers of table start/end, `.data.rel.ro` or `0x2c` stride; inspect genuine PC-relative literal calculations, GOT accesses and function-pointer dispatches. Only a decoded code/data flow can connect a descriptor row to actual module resolution or the initializer argument.

The most effective next input is the original `libIMDB.so` file itself (read-only upload; no device connection), not more copies of the same table-metadata output.

**Static graph unchanged:** 74 directly primary ELF-verified + 5 inferred + 5 unresolved = 84 tracked; zero runtime-verified and zero safe-to-invoke SDK APIs. The above user-provided metadata is **not** SHA-pinned primary ELF instruction evidence and does not warrant graph count promotion.
