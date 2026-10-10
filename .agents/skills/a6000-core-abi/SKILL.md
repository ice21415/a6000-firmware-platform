---
name: a6000-core-abi
description: "Use for reverse-engineering Sony A6000 firmware 3.21 libObj.so Camera core ABI with Capstone, Ghidra and source-backed evidence; especially 0x13200a, 0x42ac00 and 0x12d780. Use when asked to crack, trace, verify, or implement a Sony Camera core SDK API."
---

# A6000 Core ABI — primary ELF first

## Scope and hard limitations

Analyze **only an authorized, private, offline copy** of Sony ILCE-6000
firmware 3.21's `libObj.so`. The full file must have SHA-256:

`8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`

This is a reverse-engineering *research* workflow, **not** a camera
flash/patch guide. Do not run original firmware code, connect to a
camera, write to device storage, upload the proprietary ELF to
GitHub, or claim runtime-safe API use from static analysis alone.

The connected Codex workspace may return `BINARY_FILE` for the
original ELF. No Skill instruction can bypass this. When the binary is
not readable, do not pretend to have completed primary-opcode analysis.
Use preserved `model-camera-methods.txt` only as *secondary saved
instruction-text evidence*. An external published updater is not a
substitute for the exact SHA-pinned ELF.

## Execution order

1. **Check repo/branch**: continue PR #1 on
   `phase3/semantic-analysis`. Inspect current changes and CI before
   modifications. Never merge to main without explicit user request.
2. **Check primary-byte access**: find the user's already authorized
   local `libObj.so`; verify its complete SHA-256 *before* parsing or
   disassembly. Do not invent a path or silently override the pin.
3. **Analyze exactly two blockers first**:
   - `0x13200a` — action-payload getter; determine the true
     incoming register usage and provenance of returned `r0`.
   - `0x42ac00` — parameter lookup; determine whether it reads
     `r0/r1/r2/r3`, writes through `r2`, and returns status in
     `r0`.
   Run the existing bounded probe:

   ```powershell
   python -m fwplatform.cli sdk probe-core-abi --elf "C:\private\firmware\libObj.so" --json > "C:\private\a6000-core-abi.json"
   ```

   Use `--entry 0x42abcc --entry 0x42abdc` separately when the
   wrapper relation needs examination. Default target budget is
   384 bytes; a partial CFG is **not** complete function recovery.
4. **Decompile only ambiguous functions**: if real primary ELF data
   is available and Capstone alone leaves object layout or branching
   unclear, run the repo's existing local Ghidra integration (see
   `tools/run-ghidra-headless.ps1` and
   `ghidra-scripts/AnalyzeBinary.java`) in a **private project**.
   Inspect the target VMAs and concrete register/memory references,
   not just the decompiler's guessed parameter names. Keep exported
   firmware-derived source and opcode bytes private.
5. **Cross-check callers**: use the already saved
   `sdk/camera_3_21_request_abi_leads.json` and
   `sdk/camera_3_21_param_lookup_abi.json` as hypotheses to test,
   not as proofs of C++ type. Specifically, known saved callers pass
   wrapper pointer in `r0`, parameter ID in `r1`, output address
   in `r2`, and branch on zero `r0` result. Do **not** infer
   `r3` or a `ParamList*` return type until the actual callee
   body confirms it.
6. **Write a minimal ABI contract** for each independently resolved
   function, marking each field `PRIMARY_ELF_VERIFIED`,
   `SAVED_TEXT_ONLY` or `UNVERIFIED`. Required: ELF hash, address,
   return path, arg registers/types, output memory writes,
   error branches, object lifetime and initialization constraints.
   Without the full evidence set, keep `callable=false`.
7. **Add synthetic regression tests** and run GitHub CI for Python
   3.11 and 3.12. Never upload the private ELF to the public repo.
   Record actual tests separately from real binary analysis:
   4/4 CI success does **not** equal 4 fully verified APIs.

## Stop conditions (not an invitation to claim success)

- If the primary ELF is inaccessible, clearly report that blocker,
  identify the exact **missing original function-body evidence** and
  continue only with bounded, source-justified work.
- If a VMAs' provenance, instruction mode, import binding, ownership,
  return type, or control-flow completeness is unknown, say so.
- Do not create arbitrary progress percentages or promote static
  ABI leads to a functioning Sony SDK.
- Finish with the real commit SHA, CI status and the number of
  **fully verified callable core APIs**. Current research count is
  zero; do not change it without primary, caller and runtime proof.
