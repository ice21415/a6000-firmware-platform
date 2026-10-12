# Phase 4.25 — Original LZPT symlink inventory and direct ModelManager IdSoTable bridge

**Scope:** Sony A6000 Firmware 3.21, static and read-only. No device access, no firmware writes, no private firmware bytes committed.

**Primary ELF:** private `libObj.so`, SHA-256 `8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`.

## A. Original filesystem survey, not just extracted files

The user successfully ran `scan_a6000_lzpt_links.py --all-links` against original `firmware.tar` partition images through the ma1co/fwtool.py LZPT/CramFS readers:

| Partition | Mount point from `mount.conf` | LZPT TOC entries | Decoded bytes | Symlinks | Result |
| --- | --- | ---: | ---: | ---: | --- |
| `nflasha15` | `/usr` | 2,373 | 155,516,928 | 31 | `/lib/libObj.so` present, no `modelCamera.so` file/link |
| `nflasha3` | `/system` | 369 | 24,182,784 | 0 | no matching modelCamera file/link |
| `nflasha7` | `/rootfs` | 98 | 6,422,528 | 87 | no matching modelCamera file/link |

**Interpretation:** the specific theory that `modelCamera.so` was a symlink in one of these three original images lost during ordinary extraction is unsupported. This is *negative evidence scoped only to these three images*. Other partitions, overlays, on-demand mounts, launch scripts, and dynamically created links were not comprehensively inventoried. The scan included all symlinks (`--all-links`); it does not prove absolute absence from the device's runtime namespace.

## B. New direct static bridge — ModelManager registration consults IdSoTable

This analysis replays the original ELF32 Thumb instructions (VMAs are the original ELF virtual addresses, not runtime relocated addresses). It discovers the **previously unjoined library/factory name provenance**:

1. **Descriptor numeric key**: registration function `0x7ec8a4` gets descriptor `+8` by `0x7ec8b6 -> 0x7ea930`, stores it in its stack slot `+0x20` at `0x7ec8be`.
2. **Library lookup**: `0x7ec8e4` loads that key into `r1`; `0x7ec8e6` passes the same ModelManager owner in `r0`; `0x7ec8e8` calls `0x7eaae8`. The accessor `0x7eaaec` loads `r0=[owner+8]` (table pointer) and branches to `0x7f05d2`, which calls integer-key search `0x7f04c0` and returns IdSoTable node field **`+8`** at `0x7f05f8`. `0x7ec8ee` retains the result in `r8`; `0x7ec912` passes `r8` to record initializer as `r3`; `0x7f115a` stores it at **`record+0x10`**.
3. **Factory lookup**: `0x7ec8ec` reloads the same numeric descriptor key into `r1`, `0x7ec8f0` passes same owner `r0`, `0x7ec8f2` calls accessor `0x7eaaf6`. `0x7eaafa` loads the table pointer from **`owner+8`**; `0x7eab00` jumps to `0x7f05a2`, which uses integer-key search `0x7f04c0` and obtains IdSoTable node **`+0xc`** via `0x7f05c8`. At `0x7ec8f6` the returned pointer is saved in `r10`; `0x7ec8f8` selects a fallback if null. The selected pointer goes on the constructor stack at `0x7ec914`, then `0x7f115e` and `0x7f116c` store it at **`record+0x14`**.
4. **Actual loader arguments**: `0x7f11d6` obtains **`record+0x10`** and sends it to `dlopen` at `0x7f11d8`; only after non-null handle and factory name checks does `0x7f11e2` use **`record+0x14`** in the `dlsym` call at `0x7f11e6`. A successful factory invocation `0x7f11f2` stores returned instance at **`record+0x1c`** at `0x7f11f4`.

A compact conceptual topology:

```text
ModelManager descriptor +0x8 (integer ID)
   |
   +-- same ID, table pointer [ModelManager owner +0x8] --> keyed IdSoTable lookup
          |                                         |
          node+0x8: library name                    node+0xc: factory name
          |                                         | (nullable; fallback)
          v                                         v
     Registry record+0x10                     Registry record+0x14
          |                                         |
          v                                         v
    dlopen(record+0x10)                    dlsym(handle, record+0x14)
                    \                        /
                     \--- conditional factory --> record+0x1c
```

**Critical unresolved equalities:** the `ModelManager owner+8` table pointer is *not yet proven* to be the **same runtime ModelIdSoTable singleton** that received the `@M00B → 11` registration. A particular ModelManager descriptor's ID is not yet shown to equal 11. Therefore the new direct static field bridge **does not** establish a `modelCamera.so → libObj.so` loader alias or an observed ModelCamera instance. The factory name has an explicit fallback branch.

## C. Evidence accounting, no runtime promotion

New primary static relations:

- `registry.modelmanager.idso_library_to_record`
- `registry.modelmanager.idso_factory_to_record`
- `registry.record.config_strings_to_loader`

Previous tracked graph: 64 primary / 5 inferred / 5 unresolved = 74.

After this phase: **67 primary / 5 inferred / 5 unresolved = 77 tracked**. This is approximately **87.0% of this project-defined, growing static edge list**; it is **not overall SDK completion**. All five original end-to-end blockers remain unresolved, runtime-verified and safe-to-invoke APIs remain **0**.

The GitHub Actions workflow can run all source/synthetic regression tests but **cannot independently verify user-private ELF bytes** in public CI. The static instruction witnesses in `fwplatform/camera_core_chain.py` explicitly require the SHA-matched private source.

## Reproduction without running firmware

```sh
sha256sum /private/path/libObj.so
llvm-objdump -d --triple=thumbv7-none-eabi --start-address=0x7ec8a4 --stop-address=0x7ec960 /private/path/libObj.so
llvm-objdump -d --triple=thumbv7-none-eabi --start-address=0x7eaae8 --stop-address=0x7eab04 /private/path/libObj.so
llvm-objdump -d --triple=thumbv7-none-eabi --start-address=0x7f05a2 --stop-address=0x7f0602 /private/path/libObj.so
llvm-objdump -d --triple=thumbv7-none-eabi --start-address=0x7f1156 --stop-address=0x7f117a /private/path/libObj.so
llvm-objdump -d --triple=thumbv7-none-eabi --start-address=0x7f11ca --stop-address=0x7f1250 /private/path/libObj.so
```

The next useful task is **proving ModelManager owner+0x8 initialization from ModelIdSoTable::getInstance, and identifying the concrete descriptor with key 11**, rather than speculative runtime flashing or loader invocation.
