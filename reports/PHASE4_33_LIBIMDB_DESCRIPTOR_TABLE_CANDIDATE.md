# Phase 4.33 — libIMDB init-name entry: two 0x2c-spaced candidate module descriptors

**Source:** User's read-only `inspect_a6000_imdb_record.py --around 12` output for Sony A6000 3.21 `libIMDB.so`, 2026-10-11. This is user-provided metadata; the private `libIMDB.so` bytes have not been uploaded or independently disassembled here. **Do not treat the table pattern as confirmed function invocation.**

## Source-backed pointer/relocation facts

The ELF string `Application_System_Init` appears once in allocated `.rodata` at VMA **`0x00003672`** and file offset `0x3672`. The little-endian word in `.data.rel.ro` at VMA **`0x0000d200`** is `0x00003672` and has `R_ARM_RELATIVE` in `.rel.dyn`. This is a relocatable **pointer to the ASCII name**, not a function pointer to `libObj.so` code.

The surrounding `11 × 4`-byte **provisional record** is:

| Offset from `0xD1EC` | ELF VMA | Value / dereferenced string | Relocation | Interpretation |
|---:|---:|---|---|---|
| `+0x00` | `0xD1EC` | `0x20000004` | not reported | candidate entry flags / marker |
| `+0x04` | `0xD1F0` | `0x00000001` | not reported | scalar |
| `+0x08` | `0xD1F4` | `0xFFFFFF9F` | not reported | scalar |
| `+0x0C` | `0xD1F8` | `0x07FB0083` | not reported | scalar |
| `+0x10` | `0xD1FC` | `appFw.so` (`0x3669`) | `R_ARM_RELATIVE` | candidate module name |
| `+0x14` | `0xD200` | `Application_System_Init` (`0x3672`) | `R_ARM_RELATIVE` | candidate init-symbol name |
| `+0x18` | `0xD204` | `0x3EEA` | `R_ARM_RELATIVE` | points to `.rodata`; exact semantic unknown |
| `+0x1C` | `0xD208` | `0x3EEA` | `R_ARM_RELATIVE` | same `.rodata` pointer |
| `+0x20` | `0xD20C` | `0x3EEA` | `R_ARM_RELATIVE` | same `.rodata` pointer |
| `+0x24` | `0xD210` | `AdjChkConfig.so` (`0x368A`) | `R_ARM_RELATIVE` | other module / configuration name candidate |
| `+0x28` | `0xD214` | `AppConfig.so` (`0x369A`) | `R_ARM_RELATIVE` | other module / configuration name candidate |

The next **`0x20000004`** marker appears at `0xD218`, exactly **`0x2C = 44 bytes`** after `0xD1EC`. Its `+0x10` is `subapp.so`, `+0x14` is `subapp_init`, and `+0x18` is `subapp_exit`. Two similarly spaced marker-and-name pairs support a **fixed-stride candidate descriptor table**, not yet a conclusively decoded schema.

## Important distinction: module name is NOT loaded-object identity

The same user's whole-tree name scan showed only a **`libObj.so` dynamic export** of `Application_System_Init`, no ELF direct dynamic import; the `libIMDB.so` name was a literal. The `appFw.so` name in this candidate descriptor cannot be assumed to exist as a standalone file or be an alias for `libObj.so`. The `AppConfig.so` field in this candidate row is not proof that the exported `Application_System_Init` receives a null argument or that the actual camera selects the AppConfig provider.

`libIMDB.so` declares ELF `DT_NEEDED: libdl.so.2` (along with libc, libgcc_s, libm, libpthread, librt, libstdc++), but the user's targeted dynamic-symbol scan reported **no matching `dlopen`, `dlsym`, `dlclose` imports of interest**. A dependency on libdl is not a dynamic-loader callsite.

## Next falsifiable offline step

A local metadata-only helper `inspect_a6000_imdb_table.py` has been created and tested with four synthetic cases. It inspects the candidate `0x2C`-stride rows at `0xD1C0`, `0xD1EC`, `0xD218`, `0xD244` (unless adjusted), displays each word's section/string/relocation class, and searches for exact data-word references to chosen row/name addresses. **Output on real `libIMDB.so` remains pending.**

A follow-up can then identify whether an executable code path actually reads the table and which launch argument it supplies. Until that code path is proven, do not create a `PRIMARY_ELF_VERIFIED` or runtime graph edge based on metadata alone.

## Project accounting

Unchanged: **74 primary ELF static + 5 static inferred + 5 unresolved = 84 tracked**; all five end-to-end blockers remain open. Runtime-verified camera APIs: 0. `safe_to_invoke`: 0. No device access, firmware patching, loading or executing third-party ELF is required.
