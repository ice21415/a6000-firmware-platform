# Phase 4.27 — LZPT Android image inventory; conditional ModelConfig → ModelIdSoTable vtable resolution

**Firmware / binary:** Sony A6000 3.21; privately supplied ELF `libObj.so` SHA-256 `8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`. This report contains no Sony firmware payload.

**Safety and evidentiary scope:** all ELF work is read-only offline `llvm-objdump -d` / `readelf` / bounded file data inspection. LZPT metadata is the user's report from the existing read-only local scanner. A `PRIMARY_ELF_VERIFIED` label below means **static branch/vtable/callsite evidence in the SHA-pinned binary**, not successful runtime execution or runtime selection of a branch.

## 1. Fourth original filesystem image checked

The user ran `scan_a6000_lzpt_links.py` against the original compressed `0700_part_image/dev/nflasha16` image (twice, identical output):

| Item | Result |
| --- | --- |
| Mount point | `/android/system` (Sony `mount.conf`) |
| Format | LZPT (TPZL), block exponent 16, TOC offset 0x18 |
| Compressed bytes | 59,013,103 |
| TOC entries | 1,708 |
| Decompressed bytes | 111,935,488 |
| Filesystem entries | 485 |
| Symlinks | 53 |
| Camera-related matches | 10 (Sony cameraex framework and Android camera libraries) |
| `modelCamera.so` named file or symlink | **not found in filtered scan** |

The user's earlier scans found `/usr/lib/libObj.so`, but no `modelCamera.so` file or symlink under original /usr (nflasha15), /system (nflasha3), or /rootfs (nflasha7). This is meaningful scoped **negative filesystem evidence** for four images; it is not proof of absence from /wbi (nflasha5), other overlays, mount namespaces, dynamically created paths or firmware not represented by those images. The scan is not a runtime loader trace.

## 2. Startup selector provenance — runtime BSS, not a static constant string

A Thumb BL xref scan shows the bounded caller `0x7ed984` invokes bootstrap `0x7ef254` at `0x7ed996` after loading its second argument:

```text
0x7ed98e  ldr r1,[pc,#0x54]  ; raw word @0x7ed9e4: 0x008f1e90
0x7ed994  add r1,pc         ; r1 = 0x7ed998 + 0x008f1e90 = 0x010df828
0x7ed996  bl  0x7ef254
```

`0x010df828` lies within this ELF's `.bss` (NOBITS) range `0x010a88a8..0x010e2bd0`. The content of this string pointer **cannot be obtained from the static ELF bytes alone**. There can be runtime initialization, so no particular string/branch is selected yet.

`0x7ef254` invokes provider dispatcher `0x7ef1e4`, which compares an input string to the embedded `AppConfig.so` literal using bounded string compare operations. The **AppConfig.so-matching branch** calls `initializeConfig` and reads `getConfig`. The **nonmatching branch** calls `0x45f320`, the ModelConfig initializer, and reads its getter via the observed GOT raw function pointer `0x45f2ed` (Thumb pointer to `0x45f2ec`). This remains conditional upon the startup selector bytes.

## 3. ModelConfig branch concretely builds a resolvable provider vtable

On the non-AppConfig.so branch:

```text
0x7ef222 -> 0x45f320    initialize ModelConfig object
0x45f32c -> 0x45f2fc    call object constructor
0x45f30e                  dereference GOT 0x010345d8 -> 0x01007520
0x45f310                  add #8
0x45f312                  store provider vptr = 0x01007528
```

The original `.data.rel.ro` has an `R_ARM_RELATIVE` relocation at `0x01007544`, the provider vptr+0x1c slot, with raw **Thumb function pointer `0x0045ef29`**, meaning method entry `0x0045ef28`.

The method's first call is:

```text
0x45ef30  blx 0x000dbc58   ; ARM .plt
```

ARM PLT GOT calculation yields `0x0102ce88`. The ELF's `R_ARM_JUMP_SLOT` at that address identifies **`ModelIdSoTable::getInstance()` (`0x007ee361` Thumb export)**. `0x45ef3e` retains the result in `r4`; after guarded additional IdSoTable changes, `0x45ef8c` returns that pointer.

Therefore, **if** bootstrap selects this ModelConfig implementation, the `provider->vtable[+0x1c]()` used in ModelManager construction goes through **the same exported `ModelIdSoTable::getInstance` getter previously used during `@M00B` registration**. This is a direct static function-identity connection under an explicit condition. It is not a runtime pointer-equality observation across startup processes or proof of the exact Record, key 11, or factory success.

## 4. Alternative AppConfig branch must not be conflated

The AppConfig branch constructs a separate vtable pointer:

```text
GOT 0x01030350 -> vtable raw 0x00fe9b68
provider vptr       = 0x00fe9b70
slot +0x1c          = 0x00fe9b8c -> Thumb 0x001068c7
```

At `0x1068c6`, this method loads a nested object from `this+8` and dispatches **nested vptr+8**. This nested call is **not** statically established to return ModelIdSoTable. Do not treat the ModelConfig vtable target as universal across both branches.

## 5. New relations and remaining blockers

Three primary static relations added:

- `registry.provider.bootstrap_selector_bss` — caller forwards a BSS string pointer to selector.
- `registry.provider.modelconfig_vptr_construction` — ModelConfig constructor installs its known vptr.
- `registry.provider.modelconfig_slot_to_modelidso_singleton` — vptr slot+0x1c resolves to the singleton getter PLT.

Previous: 69 primary / 5 inferred / 5 unresolved = 79.
**Current: 72 primary / 5 inferred / 5 unresolved = 82 tracked.**

We have **87.8% directly proven of the evolving, project-defined static edges**, **not 87.8% of the SDK**. Zero runtime-verified/safe-to-invoke APIs. Five existing end-to-end blockers remain unresolved.

The next strict evidence target is startup BSS selector content after the corresponding initializer, plus a specific descriptor key 11 record and actual `modelCamera.so` runtime loading. No instruction here should be used to write, patch, mount or execute firmware on a physical device.

## Static replay commands

```sh
sha256sum /private/libObj.so
llvm-objdump -d --triple=thumbv7-none-eabi --start-address=0x7ed984 --stop-address=0x7ed9f4 /private/libObj.so
llvm-objdump -d --triple=thumbv7-none-eabi --start-address=0x7ef1e4 --stop-address=0x7ef254 /private/libObj.so
llvm-objdump -d --triple=thumbv7-none-eabi --start-address=0x45f2fc --stop-address=0x45f348 /private/libObj.so
llvm-objdump -d --triple=thumbv7-none-eabi --start-address=0x45ef28 --stop-address=0x45efa0 /private/libObj.so
llvm-objdump -d --triple=armv7-none-eabi --start-address=0xdbc58 --stop-address=0xdbc64 /private/libObj.so
readelf -Wr /private/libObj.so
```

Public GitHub Actions verifies code/tests using synthetic input; it cannot reproduce private ELF SHA-pinned instruction matches without a local private file.
