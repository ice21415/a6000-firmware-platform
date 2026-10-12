# Phase 4.26 — ModelManager provider-vtable origin for the IdSoTable pointer

**Study:** Sony A6000 firmware 3.21 `libObj.so` (authorized private ELF, SHA-256 `8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`).

**Method:** read-only `llvm-objdump --triple=thumbv7-none-eabi` at bounded Thumb code windows, `readelf -Ws/-rW` for shared library symbol identity, PC-relative constant inspection. The original ELF is not committed or redistributed; no code ran on the camera.

## New trace: bootstrap constructs a provider and passes the same pointer to ModelManager

The bootstrap initializer starting at `0x7ef254`:

1. `0x7ef268: bl 0x7ef1e4` returns a provider candidate pointer in `r0`; `0x7ef270: str r0,[r4,#0x14]` caches it in bootstrap `+0x14`.
2. Later, `0x7ef2f6` allocates `0xac` bytes for ModelManager; `0x7ef2fc` and `0x7ef2fe` load two constructor arguments, including provider from bootstrap `+0x14` to `r2`.
3. `0x7ef302: bl 0x7ec384` invokes the constructor, `0x7ef306` stores the constructed ModelManager pointer at bootstrap `+4`.
4. `0x7ec398: mov r5,r2` preserves the **same provider argument** in the constructor.

This is a bounded, direct interfunction *pointer-provenance* trace; provider dynamic type remains to be determined.

## New trace: virtual getter result initializes ModelManager+0x8

Within ModelManager constructor `0x7ec384`:

```text
0x7ec3b4  mov r0,r5       # provider this
0x7ec3b6  ldr r3,[r5]     # provider vptr
0x7ec3bc  str r5,[r4,#4]  # save provider pointer in ModelManager+4
0x7ec3be  ldr r3,[r3,#0x1c] # virtual method entry
0x7ec3c0  blx r3          # invoke virtual getter
0x7ec3c4  str r0,[r4,#8]  # ModelManager+8 = getter return
```

Additional slots `+0x20`, `+0x24`, `+0x28` populate ModelManager `+0xc`, `+0x10`, `+0x1c` (separate provider operations). The prior Phase 4.25 proof established that registration accessors `0x7eaae8` and `0x7eaaf6` read ModelManager `+8` as the IdSoTable lookup source. We now know **how the field is initialized**.

The provider creator `0x7ef1e4` includes an `AppConfig.so` name check; the static `0xe0354` PLT relocation binds to exported `initializeConfig`, and one indirect getter candidate corresponds to `getConfig`. These observations do not establish the provider's concrete vtable at `0x7ec3be`, nor the exact semantics of its virtual `+0x1c` method. Its target may depend on bootstrap configuration; do not treat all branches as a single concrete provider.

## Identity boundary that remains

The critical unresolved equality is:

```text
provider->vtable[+0x1c]()
      == ModelIdSoTable::getInstance() that accepted @M00B / key 11 ?
```

Only the left-hand getter invocation and storage to ModelManager `+8` are now verified. We **cannot** equate it to the right-hand singleton without resolving the provider's type/vtable and return implementation. A particular descriptor's key being 11 is also unproved. The missing concrete `modelCamera.so` file/link in the three original LZPT images does not establish a loader alias or complete runtime namespace inventory.

## Evidence classes and counts

New graph relations:

- `registry.modelmanager.provider_constructor_handoff`
- `registry.modelmanager.provider_vtable_to_idso_field`

**69 primary static / 5 inferred / 5 unresolved = 79 tracked** (previous 67/5/5=77). Neither of the five end-to-end blockers has been fully resolved. Runtime-verified APIs: 0; safe-to-invoke APIs: 0.

This is **87.34% of an evolving hand-curated relation list**, not total SDK completion and not evidence that the virtual call is safe at runtime.

## Exact offline replay

```sh
sha256sum /private/path/libObj.so
llvm-objdump -d --triple=thumbv7-none-eabi --start-address=0x7ef254 --stop-address=0x7ef308 /private/path/libObj.so
llvm-objdump -d --triple=thumbv7-none-eabi --start-address=0x7ec384 --stop-address=0x7ec434 /private/path/libObj.so
llvm-objdump -d --triple=thumbv7-none-eabi --start-address=0x7eaae8 --stop-address=0x7eab04 /private/path/libObj.so
```

GitHub Actions validates code and synthetic graph tests but cannot privately load the original ELF. The new `fwplatform/camera_core_chain.py` instruction witnesses require the matching private file for direct replay.

**Next static target:** classify provider instances and provider vtables reachable from `0x7ef1e4`; confirm whether `+0x1c` points to a getter of `ModelIdSoTable::getInstance`, without guessing based on a string match alone.
