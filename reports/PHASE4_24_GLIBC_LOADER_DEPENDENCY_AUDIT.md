# Phase 4.24 — ARM glibc loader / libdl cross-ELF dependency evidence

**Date:** 2026-10-11  
**Scope:** authorized, privately uploaded ELF samples, inspected offline and read-only using `file`, `sha256sum`, `readelf -h/-d/-Ws/-rW/-A`, `strings`, and bytewise comparisons. No firmware or instruction bytes are included in this public report.

## Sample provenance and deduplication

| File | SHA-256 | SONAME |
| --- | --- | --- |
| `libObj.so` | `8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a` | `libObj.so` |
| `libBizFw.so` | `5065aa52ac05d3a7de24945a2c7be65c18394b7c9e02ab605476a0afa8fb8a8e` | `libBizFw.so` |
| `libBizFw2.so` | `e2fb58e42d1e471e0066e18281f9557bc0a6503ecac7c705633e211c5d00738e` | `libBizFw2.so` |
| `libMWF.so` | `2a7f469ac7aa49c1f04f666ede0c26604b78bd31608ee22650ac0d2bd26a0934` | `libMWF.so` |
| `libmpr.so` | `9a74a3bb42836559888509b6113d281b85ae53b03eb9cdf4a965eafb545e4c30` | `libmpr.so` |
| `libdl-2.11.2.so` | `baabb47959f633f0a5e80ad8179b87c8d74ab6b52e731ef543a1141822d92d20` | `libdl.so.2` |
| `ld-2.11.2.so` | `2d94f54d77ee3ac87fd73e145e1a4eb7f1663cc7492562479c16f01c279310a5` | `ld-linux.so.3` |

The uploads named `ld-2.11.2 (1).so` and `libdl-2.11.2 (1).so` have, respectively, exactly the same SHA-256 as their corresponding unsuffixed files; bytewise comparison also matches. These are **two unique new binaries**, not four independent witnesses.

All seven distinct samples are ARM ELF32 EABI5; ARM attributes identify ARMv7-A and Thumb-2 support. This matches the broad ABI class of the provided `libObj.so`, but does **not** independently prove all runtime dependencies/ABI constraints.

## New static dependency closure finding

Direct `DT_NEEDED` declarations establish the following **four distinct two-hop paths**:

```text
libObj.so --NEEDED--> libBizFw.so  --NEEDED--> libdl.so.2
libObj.so --NEEDED--> libBizFw2.so --NEEDED--> libdl.so.2
libObj.so --NEEDED--> libMWF.so    --NEEDED--> libdl.so.2
libObj.so --NEEDED--> libmpr.so    --NEEDED--> libdl.so.2
```

`libObj.so` does not directly list `libdl.so.2` as `DT_NEEDED`; these four direct dependencies do. This explains a plausible dynamic-symbol *provider candidate* for unresolved imports without inventing a missing direct dependency.

The observed `libObj.so` `R_ARM_JUMP_SLOT` relocations are:

| Symbol | GOT / PLT relocation offset | Import |
| --- | --- | --- |
| `dlclose` | `0x0102e13c` | undefined, unversioned |
| `dlsym` | `0x0102e398` | undefined, unversioned |
| `dlopen` | `0x0102e808` | undefined, unversioned |

The supplied `libdl-2.11.2.so` *defines* `dlopen`, `dlsym`, and `dlclose` with default `GLIBC_2.4` symbol versions. It declares `libc.so.6` and `ld-linux.so.3` as direct dependencies, and has a private `_dl_sym@GLIBC_PRIVATE` import. The supplied `ld-2.11.2.so` has SONAME `ld-linux.so.3`, and contains generic glibc search-path strings such as `LD_LIBRARY_PATH`, `/usr/lib/`, `/etc/ld.so.preload`, and `ld.so.cache`.

**Qualification:** `DT_NEEDED` closure + matching exported symbols is *not* proof of the actual runtime symbol-binding result. A dynamic-loader process map, concrete relocation binding, startup namespace/scope, and all relevant library candidates would be needed for that stronger claim. No `ldd` or execution on the host/camera was performed.

## modelCamera.so identity remains UNKNOWN

Exact-string inspection of these two GNU loader binaries did not find `modelCamera.so`, `ModelCameraToInstance`, or `libObj.so`. That is unsurprising for a general-purpose dynamic linker and is **not evidence against** a filesystem alias elsewhere. The provided firmware directory listing also lacks a file named `modelCamera.so`.

Neither these glibc binaries nor the four static dependency paths establish `modelCamera.so → libObj.so`; that requires evidence of a specific runtime search result, symlink/manifest, namespace mapping or another loader-specific resolution rule. No new model-camera consumer identity is asserted, and no runtime invocation is recommended.

## Reproduce without executing an ELF

```sh
sha256sum libObj.so libBizFw.so libBizFw2.so libMWF.so libmpr.so ld-2.11.2.so libdl-2.11.2.so
readelf -W -d libObj.so
readelf -W -d libBizFw.so
readelf -W -d libBizFw2.so
readelf -W -d libMWF.so
readelf -W -d libmpr.so
readelf -W -d libdl-2.11.2.so
readelf -W -d ld-2.11.2.so
readelf -rW libObj.so
readelf -Ws --wide libdl-2.11.2.so
```

**Evidence class:** multiple SHA-pinned primary ELF static dependency/relocation facts, **not** a newly completed Camera Core runtime relation. Graph unchanged at **64 primary / 5 inferred / 5 unresolved = 74 tracked**; all five original blockers remain unresolved; callable/safe-to-invoke APIs remain 0.
