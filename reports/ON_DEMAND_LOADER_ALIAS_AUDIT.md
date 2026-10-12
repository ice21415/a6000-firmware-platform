# External On-Demand Loader vs Camera Model Loader — Static Audit

**Scope:** User-provided Sony A6000 firmware 3.21 modules and a directory
listing. The source samples are private; this repository contains metadata
only, no ELF bytes, no firmware image, and no runtime trace.

## SHA-pinned uploaded samples

| File | SHA-256 |
| --- | --- |
| `libObj.so` | `8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a` |
| `libOnDemandLoader.so` | `4d1c6674070be9d144070f6a2955c1cbcc18f31c0ba93d0becc643f601ac4c08` |

`libOnDemandLoader.so` is a 38,212-byte ARM32 EABI5 ET_DYN ELF,
SONAME `libOnDemandLoader.so`. It directly depends on
`libpthread.so.0`, `libstdc++.so.6`, `libm.so.6`,
`libdl.so.2`, `libgcc_s.so.1`, `libc.so.6`, and `librt.so.1`.
It exports, among others, `OnDemandLoaderInitialize`,
`OnDemandLoaderFinalize`, `Odl_FileCtrl::loadPrgFile`,
`Odl_PrgManager::checkLoadPrg`, and `InfraOnDemandLoader::Main`.

The ELF's undefined symbol inventory includes `Backup_read`, `mmap`,
`mount`, `umount`, `open`, and OSAL message functions. Read-only
string inspection finds `/dev/mem`, `/dev/ms1`, and program-load
diagnostic strings. None of the strings `modelCamera.so`,
`ModelCameraToInstance`, or `@M00B` were found as exact strings.
`dlopen` and `dlsym` are **not directly imported** as dynamic
symbols. Import of `libdl.so.2` does **not** establish calls to these
functions.

By contrast, `libObj.so` directly imports `dlopen`, `dlsym`,
and `dlclose`, embeds the `modelCamera.so` string, and exports
`ModelCameraToInstance`. Neither ELF declares the other as a direct
`DT_NEEDED` dependency. This supports treating the On-Demand Loader as
a distinct **program-loading mechanism candidate**, not proof of the
ModelCamera ELF loader path. Indirect communication or runtime startup
linkage has not been ruled out.

## Firmware tree listing

The user's recursive `.so` listing does not contain a file named
`modelCamera.so`. Their `models` directory listing contains:

- `generic.swiarb`
- `generic11.lda`, `generic11_f.swimdl`, `generic11_m.swimdl`
- `generic8.lda`, `generic8_f.swimdl`, `generic8_m.swimdl`

Only filenames and sizes are available; the three formats have **not**
been parsed or associated with `@M00B`. In particular the string
`generic11` alone is **not** an identity witness for Model ID 11.

The absent filename in the extracted directory cannot prove that no
runtime-generated symlink, mount, namespace mapping or other alias exists.

## Research consequence

**Do not use `libOnDemandLoader.so` as evidence of a
`modelCamera.so → libObj.so` runtime alias.** A more relevant proof
would show the ELF dynamic loader's actual resolution of
`dlopen("modelCamera.so")`, the selected module, and the return value
of `dlsym("ModelCameraToInstance")` in a controlled read-only setting.

Nothing here resolves the five existing Camera Core blockers, proves
device execution, or changes the tracked 64 primary / 5 inferred / 5
unresolved relations. The user should not perform any camera writes,
mount operations or loader invocations on an actual device for this
audit.

**Reproducible metadata checks** on authorized local copies:

```sh
sha256sum libOnDemandLoader.so libObj.so
readelf -d libOnDemandLoader.so
readelf -Ws --wide libOnDemandLoader.so
readelf -d libObj.so
readelf -Ws --wide libObj.so
```
