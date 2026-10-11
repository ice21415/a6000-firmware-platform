# Phase 4.22 — First direct private-ELF registry keyflow replay

**Source:** user-provided private Sony A6000 firmware 3.21 `libObj.so`.
**SHA-256:** `8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`.
**Method:** bounded offline read-only ELF32 ARM/Thumb disassembly (`llvm-objdump --triple=thumbv7-none-eabi`), ELF relocation/symbol audit (`readelf`), and exact PIC constant/string dereference. No firmware bytes are committed. No camera connected or firmware executed.

## Confirmed result 1 — @M00B yields 11 and passes to IdSoTable::add

The original ELF's dynamic relocation binds PLT `0xdbc58` to `ModelIdSoTable::getInstance`, `0xdffb8` to `IdGenerator::Get(char const*)`, `0xdf58c` to `IdSoTable::add(int,char const*,char const*)`, and `0xdfbb8` to `strncmp`.

- `0x401f80`: call `ModelIdSoTable::getInstance`; `0x401f8e`: preserve returned table pointer in `r4`.
- `0x40208c–0x40208e`: PC-relative pointer resolves to `@M00B`.
- `0x402090`: invoke `IdGenerator::Get`.
- `0x12d670`: internally defined IdGenerator function; `0x12d678–0x12d67c` checks leading `@`.
- `0x12d70e–0x12d718`: compare first five characters against reserved `@MFFE` with `strncmp`; `@M00B` takes normal parsing path.
- `0x12d71a–0x12d744`: computes `(0 << 8) + (0 << 4) + 11 = 11`, returned in `r0` at `0x12d74c`.
- `0x40209c`: `mov r1,r0` preserves the IdGenerator result as second argument.
- `0x40209e`: `mov r0,r4` passes the singleton instance as `this`.
- `0x4020a0`: invokes `IdSoTable::add` with this ID and the configured `modelCamera.so`, `ModelCameraToInstance` strings (literals `0x4022e4`, `0x4022e8`).

This **resolves the static callsite key-return provenance** that prior Phase 4.19/4.21 notes marked UNKNOWN. It does not prove the runtime module loader successfully creates a ModelCamera instance.

## Confirmed result 2 — ModelManager record key comes from descriptor +8

- `0x7ec8b6`: helper `0x7ea930` returns the descriptor's `[r0+8]`.
- `0x7ec8be`: save numeric result in caller stack `[r7+0x20]`.
- `0x7ec90e`: restore the same word into `r1` before constructor call `0x7ec91c`.
- `0x7f1160`: record initializer writes `r1` to `record+0`.
- `0x7ec8ba`: registration owner `r4+0x88` identifies its tree field.
- `0x7ec94e–0x7ec954`: the registration tree field is passed into the insertion call.
- `0x7eb904`: ModelManager lookup computes its owner `r0+0x88`.

These instructions prove a *shared owner-relative registry layout*, but not that the two functions always act on the same **runtime ModelManager object**.

## Remaining identity gap

`ModelIdSoTable` (ID→library/factory configuration) and `ModelManager` (descriptor→record→event routing) have distinct object roles and storage layouts. The missing proof is not the hexadecimal ID parsing or the return-to-add callsite anymore. It is the **connection from the ModelIdSoTable registration for key 11 to the descriptor object referenced by ModelManager**, together with runtime owner identity, tree-node insertion/lookup equality, successful loader resolution and record `+0x1c` instance pointer provenance.

Accordingly the three new first-class static relations are:

- `registry.camera.return_key_to_add`
- `registry.modelmanager.descriptor_key_to_record`
- `registry.modelmanager.common_owner_tree_offset`

Graph: **60 primary / 5 static inferred / 5 unresolved = 70 tracked**. **Zero blockers are fully resolved** and runtime-verified/safe-to-invoke APIs remain **0 / 0**. Graph relation verification is *not* SDK completion percentage.

## Reproduction

Use a privately held exact SHA-matched ELF, never the public repository:

```sh
sha256sum /private/path/libObj.so
llvm-objdump -d --triple=thumbv7-none-eabi --start-address=0x40208c --stop-address=0x4020a4 /private/path/libObj.so
llvm-objdump -d --triple=thumbv7-none-eabi --start-address=0x12d670 --stop-address=0x12d756 /private/path/libObj.so
llvm-objdump -d --triple=thumbv7-none-eabi --start-address=0x7ec8a4 --stop-address=0x7ec960 /private/path/libObj.so
llvm-objdump -d --triple=thumbv7-none-eabi --start-address=0x7eb8fa --stop-address=0x7eb940 /private/path/libObj.so
```

No binary or raw decompiler export is included in this report. The graph generation implementation adds new Capstone instruction witnesses and PLT binding checks so the same static claims must reproduce on the author's private ELF. Public CI can validate contracts and synthetic tests but cannot independently redo private-ELF disassembly without a separately supplied authorized sample.
