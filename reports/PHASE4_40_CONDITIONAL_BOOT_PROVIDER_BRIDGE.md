# Phase 4.40 — Conditional IMDB → initializer → ModelConfig provider → IdSoTable singleton bridge

Sources: original user-supplied **im.elf** SHA256 `f0f181426af4add55a8510c5441ff86c3121678fd1f7e0467152070e870d803a`; **libIMDB.so** SHA256 `9ceb21092a4987ec782fd980818aee687cde649af0999608bd6c40e1f46a84ea`; **libObj.so** SHA256 `8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`. All evidence comes from private, read-only original binaries; no firmware binaries committed or executed.

## Newly joined static facts

- `im.elf` option parser recognizes `target=` at `0xa7f0..0xa800`, stores its suffix pointer in global `0x153e4+0x10`. In the original ELF this pointer's initial value is zero. Main at `0x9b44..0x9b54` substitutes literal **default** at `0xc0af` if unset.
- Directly disassembled `libIMDB.so` export `IMDB_find_target_bit` assigns mask **0x1** to `default`; row99 for target ID 0x83 is `appFw.so`, mask `0xffffff9f`, while row100 `subapp.so` has mask `0x40` and is excluded by this mask. This statement is **conditional on the dispatcher actually processing ID 0x83 and selecting the row**, not runtime proof.
- `im.elf` sets parser bit **0x4000** when a compared argument begins with literal **cho** at `0xa860..0xa872`. This bit is forwarded `0xa982 -> 0x9b64..0x9b6c -> 0xaccc -> 0xad80`. A separate `cipa` option at `0xa8f4..0xa90a` can clear bits `0xc000`. Final argument order and real flag are **unknown**.
- If IMDB row99 is consumed by the dynamic-loader path at `im.elf 0xb1a8`, its nonzero packed high halfword makes the `dlopen` name argument **NULL**. The symbol-name field is **Application_System_Init**, passed to `dlsym`; a successful symbol lookup is followed by a guarded indirect call at `0xb22c`. The **0x4000** bit selects row+0x24 **AdjChkConfig.so** versus row+0x28 **AppConfig.so** as first argument.
- `libObj.so` exports `Application_System_Init` at Thumb symbol `0x7ed9f5`. If actually called with a nonnull string, it writes that string to BSS `0x010df828` at `0x7eda26..0x7eda36`; the null argument alone would instead use embedded AppConfig.so.
- `libObj.so` bootstrap selector at `0x7ef1e4` compares the BSS string to embedded **AppConfig.so** (literal VMA `0x00d87f27`, referenced by **both** comparisons at `0x7ef216` and `0x7ef22e`). Equal condition initializes AppConfig via PLT `0xe0354` (`initializeConfig`); non-equal condition initializes ModelConfig at `0x45f320`. For ModelConfig, the provider vtable slot +0x1c resolves to Thumb target `0x45ef28`, whose PLT call `0xdbc58` links via `R_ARM_JUMP_SLOT` at `0x0102ce88` to **ModelIdSoTable::getInstance**.

**Consequent conditional bridge**: If the dispatcher selects row99, finds the exported initializer, supplies **AdjChkConfig.so** after a final set 0x4000 flag, and the provider bootstrap uses its written selector string, ModelManager can receive the ModelConfig provider, whose slot +0x1c calls the same getter as the IdSoTable registration path. A clear flag instead sends **AppConfig.so**, which follows the alternate provider branch. Both are **static conditional implications**, **not** observed boot-time choices.

## Unresolved preconditions

1. Actual A6000 boot command line or target selection and final 0x4000 bit.
2. Actual descriptor row traversal and execution, including success of dlopen/dlsym. `im.elf` direct DT_NEEDED does not include libObj.so; loader process symbol visibility is unknown.
3. Bootstrap call lifetime and singleton pointer identity across any processes.
4. Concrete ModelManager descriptor key=11, registry record identity and the modelCamera.so loaded-module identity.

No hardware commands, firmware modifications, device execution or runtime pointer access. Zero runtime-verified or safe-to-invoke SDK APIs.

**Original Camera Core graph counts unchanged:** 74 primary static / 5 inferred / 5 unresolved = 84 tracked, because this cross-ELF conditional bridge is recorded separately and is not a previously unknown runtime Camera Core edge.
