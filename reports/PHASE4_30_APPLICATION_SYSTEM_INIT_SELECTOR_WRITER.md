# Phase 4.30 — BSS startup selector **writer** traced to exported Application_System_Init

**Private primary ELF:** Sony A6000 3.21 `libObj.so`, SHA-256 `8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`.

**Current decision:** The user-run Phase 4.29 WBI snapshot code fingerprint returned 3 UNMAPPED + 1 MISMATCH, **0/1 exact**, at the hypothesized `+0x40000000` bias. The sampled selector slot at `0x410df828` was EMPTY_OR_NUL, but cannot be equated to the runtime libObj BSS because the candidate ELF mapping failed. See `reports/PHASE4_29_WBI1_CODE_FINGERPRINT_RESULTS.md`. Do not promote this candidate load bias or treat it as a runtime branch observation.

## New evidence: exported initializer writes the selector BSS

Direct `llvm-objdump` disassembly of `Application_System_Init` (function ELF VMA `0x007ed9f4`; exported Thumb symbol `0x007ed9f5`) reveals a two-branch string copy:

```text
0x7ed9fa  mov   r5, r0          ; save external argument
...
0x7eda22  cbz   r5, 0x7eda2c   ; branch on caller-supplied null

# non-null external argument:
0x7eda24  ldr   r0,[pc,#0x48]  ; PC-relative BSS literal word
0x7eda26  mov   r1,r5          ; use actual external string as source
0x7eda28  add   r0,pc          ; destination = 0x010df828
0x7eda2a  b     0x7eda34

# null input:
0x7eda2c  ldr   r0,[pc,#0x44]  ; another PC-relative BSS literal
0x7eda2e  ldr   r1,[pc,#0x48]  ; static string literal reference
0x7eda30  add   r0,pc          ; destination = 0x010df828
0x7eda32  add   r1,pc          ; source = 0x00d87f27, literal AppConfig.so

# shared bounded copy:
0x7eda34  movs  r2,#0xff
0x7eda36  blx   0x000dce00    ; ARM PLT -> strncpy@GLIBC_2.4
```

The raw literal at `0x007eda78` is `0x0059a4f1`; the Thumb-PC value at `0x007eda32` is `0x007eda36`, thus `0x0059a4f1+0x007eda36 = 0x00d87f27`, which has the exact NUL-terminated ASCII `AppConfig.so`. Both destination calculations yield `0x010df828`:

- non-null: literal at `0x7eda70` = `0x008f1dfc`; PC `0x007eda2c` => `0x010df828`.
- null: literal at `0x7eda74` = `0x008f1df4`; PC `0x007eda34` => `0x010df828`.

ARM PLT at `0xdce00` addresses GOT `0x0102d428`, whose `R_ARM_JUMP_SLOT` relocation names `strncpy@GLIBC_2.4`. Thus the copy semantics are not deduced merely from argument shapes.

The subsequent startup call at `0x7ed984` passes the **same BSS address** to bootstrap:

```text
0x7ed98e  ldr r1,[pc,#0x54] ; 0x008f1e90 at 0x7ed9e4
0x7ed994  add r1,pc        ; PC=0x7ed998 -> r1=0x010df828
0x7ed996  bl  0x7ef254     ; bootstrap -> config provider selection
```

This is a new **writer → reader** chain that binds Phase 4.27's known BSS reader to a concrete initializer and explains the default value.

## What this establishes — and does NOT establish

- **Proved static:** `Application_System_Init(NULL)` selects static `AppConfig.so`; `Application_System_Init(nonnull)` copies the caller's byte string. Both use `strncpy` with count 255 into BSS `0x010df828`.
- **Proved static:** `0x7ed984` later forwards this same BSS pointer to the configuration/bootstrap initializer `0x7ef254`, which chooses the provider type based on text comparison.
- **Not proved:** whether exported `Application_System_Init` was called with null, which other module called it, what the device passed, when the BSS was read relative to writes, whether `strncpy` NUL termination was guaranteed for an unknown long input, and which provider branch the actual camera entered.
- **Not proved:** whether a particular ModelManager descriptor has numeric key 11, whether `modelCamera.so` exists as a resolved runtime alias to a concrete ELF, and whether the loaded ModelCamera instance was consumed.

**Graph delta:** add two conditional primary static relations `startup.application_init_default_appconfig` and `startup.application_init_explicit_selector`. New **74 primary / 5 inferred / 5 unresolved = 84 tracked**. All five end-to-end blockers remain open; runtime-verified and safe-to-invoke APIs: 0. This is ~88.1% of a project-defined growing static relation list, *not* SDK completion percentage.

## Safe caller search, no firmware execution

A new stdlib-only local ELF scanner `tools/scan_a6000_init_refs.py` inspects the user's extracted firmware tree for `Application_System_Init` and distinguishes a real **dynamic ELF undefined import** from the defining export or incidental literals. It does not execute, patch or write ELF contents.

```powershell
$py = ".\tools\fwtool-venv\Scripts\python.exe"
$root = ".\firmware-analysis\official-3.21-dat\firmware.tar_unpacked"
& $py ".\scan_a6000_init_refs.py" $root
```

Local dry run against the five accessible related private libraries plus glibc loader found **DYNAMIC_EXPORT only in libObj.so**, no matching dynamic imports in the limited uploaded set. This does not substitute for inspecting the user's full extracted firmware directory; user results are pending.

**Next proof target:** locate an imported symbol/callsite or dynamic literal in the full firmware's executable images and inspect the caller's actual argument. An ASCII string in a binary is only a *candidate*, not a call proof. If no static import is discovered, do not invent caller identity: indirect dispatch or a launcher not contained in the surveyed ELF set remains possible.
