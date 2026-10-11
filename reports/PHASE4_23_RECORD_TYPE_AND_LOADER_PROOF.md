# Phase 4.23 — IdSoTable Configuration vs ModelManager Runtime Record

**Primary evidence:** locally supplied private Sony A6000 FW 3.21 `libObj.so`.
**SHA-256:** `8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`.
**Technique:** read-only LLVM Thumb disassembly at exact ELF VMAs, existing PLT and Capstone evidence checks. No private ELF committed, no device access or firmware execution.

## Finding A — configuration table inserts a different record type

`IdSoTable::add(int,char const*,char const*)` at `0x7f08a0`:

- `0x7f08b0` invokes lookup helper `0x7f063c` to locate a matching key.
- `0x7f08e0` compares result against the end iterator and `0x7f08e4` conditionally skips insertion.
- The missing-key path moves the integer key `r5→r1`, library argument `r8→r2`, factory symbol `r6→r3` at `0x7f08e6..0x7f08ec`.
- `0x7f08ee` calls constructor `0x7f0394`; `0x7f08f6` inserts this node through `0x7f0888`.
- In `0x7f0394`, `0x7f03a4` writes the integer key to `node+4`, `0x7f03b2` writes a copied library-string payload pointer to `node+8`, and `0x7f03ba` writes a copied factory-string payload pointer to `node+0xc`. The string copy itself goes through helper `0x7f0308`.

This IdSoTable node is **not** the ModelManager's event-routing Record. That Record's `+8` is a state word; its `+0x1c` is an eventual model instance pointer. Using offsets alone to join these different types would create a false proof.

## Finding B — ModelManager descriptor lookup uses the same key-extraction convention

The wrapper beginning `0x7eb944` retains owner in `r4`, moves its descriptor argument into `r0` at `0x7eb94c`, invokes getter `0x7ea930` at `0x7eb94e` (which loads descriptor `+8`), forwards returned integer into `r1` at `0x7eb952`, and invokes ModelManager record tree lookup `0x7eb8fa` at `0x7eb956`.

This matches the earlier observation that registration at `0x7ec8b6` uses a descriptor `+8` key. The two callsites are statically consistent but **runtime descriptor and owner identity are UNKNOWN**.

## Finding C — state machine passes the same record argument into the Loader

At entry `0x7eac60`, `0x7eac62` copies the supplied Registry Record argument `r1` into preserved `r4`. It reads `record+8` at `0x7eac6e`.

Guarded state/event paths pass `r4` as Loader `r0`:

- `0x7eacb2: mov r0,r4`, `0x7eacb4: bl 0x7f11ca`
- `0x7ead8a: mov r0,r4`, `0x7ead8c: bl 0x7f11ca`

Inside Loader `0x7f11ca`, `0x7f11ce` moves received Record into `r4`. It resolves the library name at `record+0x10`, the factory symbol at `+0x14`, and `0x7f11f4` stores the factory return pointer into `record+0x1c`, **only if loader and factory paths are successful**. The forwarder branch at `0x7eaf8c/0x7eaf90` separately sends `r4` to `0x7f124a`, which loads `record+0x1c`.

This establishes an argument-consistent, **conditional static producer/consumer topology** for the Record instance pointer. It does not prove that the loader branch and the forwarder branch executed in one observed runtime lifecycle, nor that selected `modelCamera.so` resolves to the analyzed private ELF.

## First-class evidence relations

- `registry.camera.idso_duplicate_guard`
- `registry.camera.idso_node_constructor`
- `registry.modelmanager.descriptor_key_lookup`
- `registry.record.state_machine_loader`

Progress after this checkpoint: **64 PRIMARY_ELF_VERIFIED + 5 STATIC_INFERRED + 5 UNRESOLVED = 74 tracked static graph relations**. All five original end-to-end blockers remain unresolved; **0** runtime-verified APIs and **0** safe-to-invoke APIs.

## Independent reproduction using a privately retained file

```sh
sha256sum /private/path/libObj.so
llvm-objdump -d --triple=thumbv7-none-eabi --start-address=0x7f0394 --stop-address=0x7f03c0 /private/path/libObj.so
llvm-objdump -d --triple=thumbv7-none-eabi --start-address=0x7f08a0 --stop-address=0x7f0916 /private/path/libObj.so
llvm-objdump -d --triple=thumbv7-none-eabi --start-address=0x7eb944 --stop-address=0x7eb964 /private/path/libObj.so
llvm-objdump -d --triple=thumbv7-none-eabi --start-address=0x7eac60 --stop-address=0x7eacc0 /private/path/libObj.so
llvm-objdump -d --triple=thumbv7-none-eabi --start-address=0x7f11ca --stop-address=0x7f125e /private/path/libObj.so
```

Public CI verifies source code consistency and synthetic tests, not private firmware bytes. The added Capstone checks are available to reproduce on the matching privately held file.
