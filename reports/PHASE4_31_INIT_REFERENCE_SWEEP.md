# Phase 4.31 — 649-ELF direct import sweep and one libIMDB.so literal candidate

**Firmware:** Sony A6000 3.21; user-run read-only extracted filesystem sweep on 2026-10-11.

## Actual user-provided output

```text
ELF scanned: 649 | skipped >256 MiB: 0
  ELF_LITERAL_ONLY (not an exact dynamic import/export): 0700_part_image\dev\nflasha15_unpacked_unpacked\lib\libIMDB.so
  DYNAMIC_EXPORT (defines Application_System_Init): 0700_part_image\dev\nflasha15_unpacked_unpacked\lib\libObj.so
Matches: 2
```

These are the **only observed exact byte-string hits** across 649 ELF files processed by `tools/scan_a6000_init_refs.py`.

The scanner matches the exact case-sensitive bytes `Application_System_Init`, then classifies exact `SHT_DYNSYM` names using `st_shndx` (undefined versus defined). This survey does **not** detect indirect calls without the matching literal, runtime-constructed symbol names, callers outside the extracted tree, or ELF dynamic symbols when unsupported section metadata is absent.

**Direct finding:** No undefined `Application_System_Init` dynamic ELF import was detected in the scanned corpus. The `libObj.so` defining export remains verified. **The occurrence in `libIMDB.so` is a literal only, not yet a proven import, pointer xref, callsite, argument value, or initializer invocation.**

## Phase 4.30 prerequisite

`libObj.so` original Thumb disassembly proved exported `Application_System_Init` conditionally writes selector buffer at BSS `0x010df828`:

- null initializer argument -> default `AppConfig.so` source;
- non-null initializer argument -> external caller-supplied source;
- both -> `strncpy` to the same BSS used later by bootstrap provider selection.

Identifying an exact caller and the actual argument is still an unresolved requirement before asserting which provider (AppConfig/ModelConfig) a real camera selects.

## Next bounded offline experiment

Inspect **only** `libIMDB.so` with the new standalone stdlib script `inspect_a6000_init_literal.py`. It reports:

1. ELF section name, file offset and VMA for each exact `Application_System_Init` substring occurrence;
2. up to 20 raw 32-bit address-word candidate references from allocated sections to that VMA (**not proven code references**);
3. whether exact dynamic imports of `dlsym`, `dlopen`, `dlclose` occur.

Example local command from the user's `a6000` directory:

```powershell
$py = ".\tools\fwtool-venv\Scripts\python.exe"
$lib = ".\firmware-analysis\official-3.21-dat\firmware.tar_unpacked\0700_part_image\dev\nflasha15_unpacked_unpacked\lib\libIMDB.so"
& $py ".\inspect_a6000_init_literal.py" $lib
```

The local parser is tested against four synthetic ELF samples and includes filename/offset/section summaries only, not raw code, arbitrary RAM bytes or firmware execution. Its direct use on the user's `libIMDB.so` is **pending**; no actual libIMDB section/relocation claims should be made until receiving that output.

Any evidence of `dlsym` remains only a static *capability*, not confirmation it is called with this particular name. If the token appears only in `.dynstr`, `.strtab`, or `.debug_*`, it may be symbol metadata with no application-level call. If in `.rodata` or allocated data, additional control-flow or data-reference proof is needed.

## Progress accounting (unchanged)

**74 primary ELF-verified / 5 static-inferred / 5 unresolved = 84 tracked edges**; still five unresolved end-to-end blockers and zero runtime-verified or safe-to-invoke APIs. The tracked-edge ratio is not an overall SDK completion percentage.

No firmware bytes, ELF files or private WBI image have been committed; tests and scans are offline/read-only.
