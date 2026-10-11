# Phase 4.41 — im.elf has a concrete libObj loader fallback before appFw initialization

Sony A6000 firmware 3.21. Three read-only, SHA-pinned original ELFs:
`im.elf` f0f181426af4add55a8510c5441ff86c3121678fd1f7e0467152070e870d803a;
`libIMDB.so` 9ceb21092a4987ec782fd980818aee687cde649af0999608bd6c40e1f46a84ea;
`libObj.so` 8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a.
The separately stored machine-code/data witnesses are in `sdk/im_loader_alias_3_21.json`.

## Newly established direct code-to-name resolution

`im.elf` at `0xb430` dispatches record types **0x20000001**, **0x20000002**, **0x20000003** through function `0xb25c`. This is shown by the arithmetic range check `0xb460..0xb46a`.

That loader chooses between the row's logical module name (`row+0x10`) and a *hardcoded physical module path*:

- `0xb262` loads the row's logical name; `0xb266` reads the high 16 bits of its packed ID at `row+0x0e`.
- `0xb26a` loads PC-relative word at `0xb2c8` = **0xc395**. The ELF's allocated rodata at **0xc395** contains exact NUL-terminated ASCII **`/usr/lib/libObj.so`**.
- `0xb26c..0xb272` selects **the logical row name if upper half equals 0**, or **`/usr/lib/libObj.so` if upper half is nonzero**.
- `0xb276` loads dynamic-loader flags from global base 0x15484+0x20; `0xb278` calls the relocations-verified `dlopen` PLT 0x8f10.

This directly proves a **conditional loader-path aliasing mechanism** for certain generic IMDB descriptors. A logical name such as `libInfraInput.so` can cause an attempted `dlopen("/usr/lib/libObj.so", ...)` when its packed upper half is nonzero. It does **not** mean all logical names or `modelCamera.so` are aliases, or that a particular load succeeded.

In contrast, type **0x20000004** (the `appFw.so` and `subapp.so` entries) uses the other loader at `0xb1a8`: row99's nonzero upper half selects **`dlopen(NULL)` at 0xb1ec**, followed by guarded `dlsym(handle,"Application_System_Init")` and an indirect initializer call.

## ELF default loader flags: 0x101

The source configuration in the original `im.elf` at **0x153e4+0x14=0x153f8** has a file-initialized word **0x00000101**. At `0x9b70`, main calls its getter `0xa610`; at `0x9b74` it passes that return through setter `0xad2c` to the loader state at **0x15484+0x20=0x154a4**, which independently also starts with `0x101` in the ELF.

Under the firmware's glibc dynamic-linking convention, **0x101 = RTLD_LAZY | RTLD_GLOBAL**. Both generic fallback loader and appFw loader read the same state+0x20 field as `dlopen` flags. This supports a *possible* symbol visibility mechanism: if a prior row successfully loads libObj with the global scope flag, the later `dlopen(NULL)` lookup may be able to find its exported initializer.

This is **not proof** of actual process load order, symbol namespace contents, or a successful `dlsym` binding.

## Quantified IMDB rows

Direct enumeration from the separate original `libIMDB.so` descriptor array at **0xc0e8**, with 143 records and 44-byte stride:

- **31** rows of loader types 0x20000001/02/03 have **nonzero packed upper halfword**.
- **All 31** masks include target bit 0x1 (`default`).
- **All 31** precede the `appFw.so` row99 in the array, distributed among record groups **1:13**, **2:9**, **4:9**, and types **0x20000001:7**, **0x20000002:22**, **0x20000003:2**.
- Example row29 at **0xc5e4**: type 0x20000001, group 1, mask 0xffffffbf, packed ID 0x07fb007a, logical name `libInfraInput.so`, init symbol `infra_input_init`. Under the named loader condition it resolves to **`/usr/lib/libObj.so`** instead.
- Example row96 at **0xd168**: logical `libInfraCameraBackground.so`, type 0x20000003, packed ID 0x07fb0102, likewise a fallback candidate.

The compiled dispatcher is capable of walking these rows. Their position before row99 and flag compatibility do **not establish** that any one of them was executed successfully before row99 under actual device startup conditions. In particular, independent stage/group enable decisions remain conditional.

## Unresolved and scope

The original `libObj.so` has SONAME `libObj.so` and exports `Application_System_Init`; the generic loader's explicit path now explains one **plausible way it could become globally visible to im.elf** without appearing in its initial DT_NEEDED list. A definitive end-to-end conclusion still requires evidence of successful load, loader namespace/global binding and actual startup options, plus the unrelated Model ID 11 → ModelCamera registry identity and modelCamera.so resolution.

No camera communication, firmware modification or binary execution was performed. All findings are offline static and not safe-to-invoke API validation.

**Camera Core graph unchanged:** 74 directly ELF-verified of 84 evolving tracked relations; 5 inferred, 5 unresolved; zero runtime-verified APIs. The new cross-binary loader identity mechanism has its own SHA-pinned evidence file rather than inflating the core count.
