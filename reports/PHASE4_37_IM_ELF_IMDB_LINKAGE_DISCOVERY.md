# Phase 4.37 — im.elf is the unique observed IMDB dynamic importer

**Sony A6000 3.21; date 2026-10-11.** This report records results from the user's **offline read-only** full extracted-tree scan `tools/scan_a6000_imdb_consumers.py`. The user's `im.elf` bytes have **not yet** been uploaded or independently disassembled. Do **not** promote this finding to a verified control-flow edge.

## Scanner output supplied by user

```text
ELF32 scanned: 649 | >256 MiB skipped: 0
  0700_part_image\dev\nflasha15_unpacked_unpacked\bin\im.elf: IMPORTS=IMDB_find_entry,IMDB_find_target_bit,IMDB_get_entries | NEEDED=libIMDB.so
  0700_part_image\dev\nflasha15_unpacked_unpacked\lib\libIMDB.so: EXPORTS=IMDB_find_entry,IMDB_find_target_bit,IMDB_get_entries,imdb_raw
Matching libraries: 2
```

**Observed exact static linkage:**

- `bin/im.elf` has three undefined `SHT_DYNSYM` symbols **`IMDB_find_entry`**, **`IMDB_find_target_bit`**, **`IMDB_get_entries`**.
- The same binary's `DT_NEEDED` lists **`libIMDB.so`**.
- `libIMDB.so` exports the same three methods (and the `imdb_raw` data symbol).
- The other ELF files in this parsed corpus did not produce an exact IMDB dynamic importer/dependency match.

The above strongly identifies `im.elf` as the next **binary to analyze**, but an undefined dynamic symbol alone does not prove a PLT call, a reachable callsite, an executed lookup, loader behavior, module name aliasing, or any runtime-initializer arguments. The scanner covered one extracted tree using ELF32 little-endian section-header parsing, not every execution context. Direct inference that `im.elf` is the entire or sole possible loader would be premature.

## Already verified independent primary ELF library behavior

The private `libIMDB.so`, SHA-256
`9ceb21092a4987ec782fd980818aee687cde649af0999608bd6c40e1f46a84ea`, was independently disassembled in Phase 4.36:

- `IMDB_find_entry` at Thumb entry `0x24b0` walks 44-byte records using an ID at `row+0x0c` (lower 16 bits) and bitmask at `row+0x08`, terminates on tag `0x28`.
- `IMDB_get_entries` returns `imdb_raw+0x84` at `0xc0e8`, with 143 valid records and one terminator.
- `IMDB_find_target_bit` maps names `default, qemu, sim, nfs, set, usbj, resub` to bitmasks.
- `appFw.so` / `Application_System_Init` metadata record is index 99, `0xd1ec`, target ID `0x83`, mask `0xffffff9f`; `subapp.so` / `subapp_init` row 100 has target ID `0x83`, mask `0x40` (named `resub` bit). These are descriptions, not executed calls.

Original `libObj.so` independently exports `Application_System_Init`, with null-input default `AppConfig.so` and caller-supplied nonnull input copied to BSS `0x010df828`. The fact that `libIMDB` row says `appFw.so` cannot by itself establish loader identity `appFw.so == libObj.so` or the actual `Application_System_Init` argument.

## Required next primary proof

**Obtain a read-only copy of this exact file:**

`firmware-analysis/official-3.21-dat/firmware.tar_unpacked/0700_part_image/dev/nflasha15_unpacked_unpacked/bin/im.elf`

Once the binary is available: calculate SHA-256; inspect `readelf -rW` for all three IMDB imports; resolve their PLT/GOT callsites in `.text`; disassemble target-name/ID/mask selection and the loop/consumer of returned 44-byte records; trace how the row fields select a module and its `Application_System_Init` argument. Also distinguish loader names and actual ELF identities with relocation/argument evidence. **Do not execute im.elf or use any real camera commands.**

If direct import symbols are only linked but unused, record that negative result instead of inventing a call. Static reachability and runtime invocation are separately evaluated.

**Core SDK graph remains:** 74 primary ELF-verified / 5 inferred / 5 unresolved = 84 tracked. Five end-to-end blockers open; zero runtime-verified and safe-to-invoke SDK APIs. The scan is a discovery event, **not** a new proven camera-core API edge.
