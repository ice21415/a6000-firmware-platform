# Phase 4.36 — libIMDB primary Thumb proof: 143 × 0x2c registry entries, exported query APIs

**Source:** user's uploaded `libIMDB.so` file, independently analyzed offline (no execution), SHA-256
`9ceb21092a4987ec782fd980818aee687cde649af0999608bd6c40e1f46a84ea`.
Sony A6000 firmware 3.21. Original ELF32, little-endian ARM EABI5, stripped except dynamic symbol table. File size ~25 KiB. No Sony firmware bytes committed.

## 1. Exports and exact module role

Dynamic symbol table:

| Export | Thumb symbol value | Executable entry |
| --- | --- | --- |
| `IMDB_find_entry` | `0x24b1` | `0x24b0` |
| `IMDB_get_entries` | `0x2501` | `0x2500` |
| `IMDB_find_target_bit` | `0x2519` | `0x2518` |
| `imdb_raw` data symbol | `0xc064`, symbol size `0x84` | allocated `.data.rel.ro` |

The `imdb_raw` 132-byte header is followed **contiguously** at `imdb_raw + 0x84 = 0xc0e8` by the descriptor array. `IMDB_get_entries` returns precisely that address, derived by GOT `imdb_raw` at `0xdae0` (`R_ARM_GLOB_DAT`) followed by an `adds r0, #0x84` at **`0x250c`**. This establishes the base from executable code, not just string repetition.

`libIMDB.so` does **not** itself import `dlopen`, `dlsym`, `dlclose` or `Application_System_Init`. It does import `strncmp@GLIBC_2.4`. Its exported routines provide registry searches, not observed loading or initializer invocation. Its `DT_NEEDED libdl.so.2` dependency alone does not prove dynamic loader invocation.

## 2. IMDB_find_entry: precise query and iterator semantics

Direct Thumb disassembly:

```text
0x24b2  cmp.w   r1, #0xffffffff   ; invalid target-mask sentinel
0x24be  ldr     r2, [pc, #0x3c]  ; GOT offset +0x20
0x24c0  ldr     r3, [r3, r2]     ; GOT 0xdae0 -> imdb_raw = 0xc064
...
0x24c8  ldrh.w  r5, [r3, #0x90] ; 16-bit target ID at row+0x0c
0x24cc  cmp     r5, r0
0x24d0  ldr.w   r5, [r3, #0x8c] ; row+0x08 target bitmask
0x24d4  tst     r1, r5           ; require shared active target bit
0x24d8  movs    r0, #0x2c
0x24da  mla     r0, r0, r2, r4   ; record stride 44 bytes
0x24de  adds    r0, #0x84       ; pointer to indexed entry
0x24e4  adds    r3, #0x2c       ; advance current row
0x24e6  ldr.w   r5, [r3, #0x84] ; row type
0x24ea  cmp     r5, #0x28       ; end-of-array sentinel
```

**Static API shape:** `IMDB_find_entry(r0 = target_id, r1 = target_mask)` returns the first row matching both `(uint16_t)(row+0x0c) == target_id` and `(uint32_t)(row+0x08) & target_mask != 0`, or NULL upon invalid `target_mask == 0xffffffff` / exhaustion. Exact source-language types and caller conventions remain inferred from register semantics, not a public C header.

The `imdb_raw` first descriptor is at **`0xc0e8`**. Enumerating the 44-byte stride gives **143 data rows**, indices `0..142`; index **143** at **`0xd97c`** has type `0x28` (the loop's terminating sentinel). That 44-byte terminal row ends at `0xd9a8`, the beginning of `.dynamic`. These boundaries match all three: disassembly, original data and ELF section layout.

## 3. Confirmed appFw/subapp rows (same 16-bit target ID, different masks)

| Property | appFw row | subapp row |
| --- | --- | --- |
| Index (zero-based) | 99 | 100 |
| Row VMA | `0xd1ec` | `0xd218` |
| Type at `+0x00` | `0x20000004` | `0x20000004` |
| Mask at `+0x08` | `0xffffff9f` | `0x00000040` |
| 32-bit field at `+0x0c` | `0x07fb0083` | `0x00000083` |
| **Compared** 16-bit target ID | **`0x83`** | **`0x83`** |
| Module name at `+0x10` | `appFw.so` | `subapp.so` |
| Init name at `+0x14` | `Application_System_Init` | `subapp_init` |
| Exit name at `+0x18` | empty string | `subapp_exit` |
| Additional names at `+0x24/+0x28` | `AdjChkConfig.so`, `AppConfig.so` | same |

At the **same 16-bit target ID `0x83`**, an input bitmask containing **bit `0x40`** can match the subapp row, whereas an input mask with an included appFw bit can match the appFw row. The masks are disjoint at bit `0x40` (`0xffffff9f & 0x40 == 0`). The labels of bit `0x40` and of the other bits still require a caller or external naming proof. Do not say these are definitively two separate real boot modes.

## 4. IMDB_find_target_bit: translates target-name to bit mask

At `0x252c`, it iterates pointers in the `imdb_raw` header beginning at offset `+0x08`; `0x2534` sets the maximum `strncmp` length to **`0x28`** and `0x2536` calls `strncmp` via PLT. On equality, `0x253c..0x2540` returns `1 << index`; null input, exhausted list or no match returns `0xffffffff`. The header's first seven stored target names are `default`, `qemu`, `sim`, `nfs`, `set`, `usbj`, `resub`. Consequently bit `0x40` corresponds to the **named index 6, `resub`**, under the code's first-entry mapping.

This explains the `IMDB_find_entry` invalid-target-mask guard: the `IMDB_find_target_bit` unknown-name sentinel is `0xffffffff`. It **does not prove** the two functions are actually called together by any caller in this firmware.

## 5. End-to-end boundary

A real loader/dispatcher must now be found **outside `libIMDB.so`**. The IMDB library exports a query interface but does not itself dynamically resolve or call the `Application_System_Init` export. The `appFw.so` field is a *module name in a registry row*, not the SONAME of `libObj.so` (which remains `libObj.so`). No direct runtime alias or actual init argument has been established. The Phase4.30 conditional `Application_System_Init(NULL) -> AppConfig.so` default remains static-only.

Next local user experiment: scan the complete already-unpacked firmware ELF corpus for dynamic imports of `IMDB_find_entry`, `IMDB_get_entries`, `IMDB_find_target_bit` and `imdb_raw`, plus `DT_NEEDED libIMDB.so` dependencies; then independently disassemble a true importer. A provided stdlib-only scanner `scan_a6000_imdb_consumers.py` performs this read-only. It has passed five local synthetic checks. The limited uploaded 11-ELF subset contained only the defining `libIMDB.so`, no other IMDB API importer.

**Camera Core graph unchanged:** 74 primary static / 5 static inferred / 5 unresolved = 84 tracked. We keep the newly verified IMDB evidence **separate** under `sdk/imdb_registry_3_21.json` rather than inflating the original libObj-specific graph. Five end-to-end blockers remain unresolved. Runtime-verified/safe-to-invoke camera APIs: 0.

## Reproduction

```sh
sha256sum /private/libIMDB.so
readelf -sW /private/libIMDB.so
readelf -rW /private/libIMDB.so
readelf -SW /private/libIMDB.so
llvm-objdump -d --triple=thumbv7-none-eabi --start-address=0x24b0 --stop-address=0x2554 /private/libIMDB.so
```

No executable or firmware is run or changed by these offline inspections.
