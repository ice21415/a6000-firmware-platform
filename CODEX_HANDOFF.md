# Codex Handoff — Sony A6000 Firmware 3.21 Core SDK

## Purpose

## Current continuation checkpoint (2026-10-09)

The old missing-primary-byte blocker below is historical and superseded.
Read `reports/CORE_PRIMARY_HELPER_AUDIT.md` and the current helper contracts.
Authenticated private libObj.so has been read with Capstone. ParamList::get
at ELF VMA 0x7edaca (Thumb-tagged symbol 0x7edacb, size 76) now has primary
loop/return evidence and a successful ASCII-path Ghidra run (exit 0).
It returns the first existing element matching words +4 and +8, or null.
The +0x0c payload word remains concretely untyped. ParamList destructor uses
a shared counter and element vptr +8 dispatch; borrowed-result semantics are
STATIC_INFERRED, not runtime validated. See `fwplatform/paramlist_snapshot.py`
for the strictly offline snapshot reader and `sdk/paramlist_3_21_candidate.hpp`
for candidate declarations. Next: resolve concrete element subclasses and
their deleting-destructor slots, mutations/copy-on-write and payload type mapping.
Callable/runtime-verified core API count remains zero. Private raw exports and
Ghidra projects are outside this public checkout.

Continue static reverse engineering of the Sony ILCE-6000 (A6000)
firmware 3.21 **core Camera SDK** in PR #1. This repository contains
the public-safe, evidence-gated analysis tooling and SDK candidate
fixtures built during previous ChatGPT sessions. This document
preserves the *material technical state* for Codex; it is **not**
a full transcript of ChatGPT messages or a substitute for the
original private firmware.

- Repository: `ice21415/a6000-firmware-platform`
- Working branch: `phase3/semantic-analysis`
- PR: <https://github.com/ice21415/a6000-firmware-platform/pull/1>
- Project Skill: `.agents/skills/a6000-core-abi/SKILL.md`
- Firmware ELF: `libObj.so`, 17,436,172 bytes; full-file SHA-256
  `8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`
- Core Camera APIs with full ABI and runtime callability verified: **0**
- PR / CI must remain evidence-based. Last reviewed state
  before this handoff had GitHub push+PR tests passing on 3.11 and 3.12.

## What actually exists

### Static evidence and tools

- `sdk/camera_3_21_request_abi_leads.json`,
  `fwplatform/request_abi.py`: original ARM AAPCS32 register-shape
  inferences for two `requestModelExecute` call entrypoints and the
  Event factory. Itanium mangling identifies three *explicit argument*
  types (`char const*, unsigned long, ParamList*`) but does not prove
  static/instance form or declared return type without register evidence.
- `ViewBase::requestModelExecute=0x12106e` appears instance-form
  `r0=this, r1=model name, r2=selector, r3=ParamList*`.
  `viewManagerIf::requestModelExecute=0x1250c0` appears static-form
  `r0=name, r1=selector, r2=ParamList*`; both feed unknown selector
  transform `0x12d780` and event factory PLT `0xdfbdc`.
- `AbstractUtilityManager::createRequestModelExecuteEvent=0x7f0b0c`
  constructs an Event with ID `0x11004003`. Its pointer-like return
  is inferred from allocation/constructor/r0 flow; declared C++
  return/lifetime/error semantics are NOT fully verified. The event
  consumer/ModelCamera binding is still unresolved.
- `viewUnified2.so` saved callsite `0x1a26e6` uses model/CAMERA
  selector `0x0f01`; a `ModelCamera::ActionGpSetSetting=0x4cfb9c`
  selector branch calls `pvt_ActionSetInit=0x4cf7a8` at `0x4cfe98`.
  Treat the cross-ELF/event-dispatch connection as a candidate,
  NOT a verified end-to-end runtime chain.
- `sdk/camera_3_21_action_payload_leads.json`,
  `fwplatform/action_payload_abi.py`: several action callers use
  `0x13200a` as an *opaque payload getter*; results are passed
  to wrapper `0x42abcc`. The result's declared C++ type is UNKNOWN,
  even though some consumers have `Invalid ParamList` branches.
- `sdk/camera_3_21_param_lookup_abi.json`,
  `fwplatform/param_lookup_abi.py`: `0x42ac00` sampled caller
  register roles appear `r0=local payload view`, `r1=parameter ID`,
  `r2=output address`, with zero-result branches accepting output.
  `r3`, exact C++ types and error contract are UNKNOWN.
  Nearby `0x42abdc` is a distinct unverified EasyMode lookup target.
- `fwplatform/private_thumb_research.py`,
  `fwplatform/core_abi_probe.py`: SHA-locked read-only ELF32 ARM
  Thumb probes, bounded CFG/call/literal/return and memory-operand
  observations, visited-byte fingerprints; output is *not* a
  completed function/type proof.
- `tests/test_core_abi_probe.py` and related ABI tests use
  *synthetic ELF and synthetic saved instructions*, not Sony bytes.
  Prior stored instruction-text matches are secondary evidence only.
- SDK / research docs: `sdk/README.md`, `ROADMAP.md`,
  `reports/CORE_CAMERA_API_INVESTIGATION.md` and PR timeline comments.

### Historical blocker (resolved locally; retained for provenance)

The ChatGPT-connected `a6000` Codex workspace can search/read **text**
and reports, but its `read_file` interface returned `BINARY_FILE`
when asked for the actual `libObj.so`. The original ELF is present
under a private firmware tree but **its machine bytes have not been
returned to ChatGPT**, so no exact primary-opcode reconstruction of
`0x13200a` or `0x42ac00` has yet happened in the ChatGPT sessions.

No Skill can bypass missing ELF read/terminal access. Codex must run
in an environment that has permission to read the private binary
and execute local analysis tools. If that is not available, say so
and avoid repeating saved caller evidence as a new breakthrough.

## Immediate Codex execution plan

1. Ensure this branch and `a6000-core-abi` Skill are present.
   Inspect git status; do not overwrite local uncommitted work.
2. Resolve the existing authorized private original `libObj.so`
   path. Verify full-file SHA against the hash above.
   Keep ELF and firmware-derived detailed output outside the
   public repository. Never put the binary, Ghidra project or
   raw opcode export into the public PR.
3. From the repository root on the local machine, run:

   ```powershell
   python -m fwplatform.cli sdk probe-core-abi --elf "C:\private\firmware\libObj.so" --json > "C:\private\core-abi-evidence.json"
   ```

   Defaults to **`0x13200a` and `0x42ac00`**.
   The private exact path is illustrative and must be replaced
   by the path verified on the local host.
4. Audit observed return paths, arguments actually dereferenced,
   whether `0x42ac00` writes through input `r2`,
   the status return use, any `r3` reads and branches.
   If needed, run additional bounded reads for `0x42abcc`
   and `0x42abdc`, or use the existing
   `tools/run-ghidra-headless.ps1` /
   `ghidra-scripts/AnalyzeBinary.java` in a local private
   Ghidra project.
5. Produce a short evidence table per target:
   verified raw ELF SHA; exact VMA; input registers;
   memory reads/writes; return path; object lifetime;
   `PRIMARY_ELF_VERIFIED / SAVED_TEXT_ONLY / UNVERIFIED`.
   Do not call a function 'ABI complete' without types and
   return/error/lifetime context. Do not claim device-callable APIs
   from offline disassembly alone.
6. Add focused code and synthetic tests. Run:
   `python -m unittest discover -s tests -v`.
   Commit and push to `phase3/semantic-analysis`, then
   check GitHub Actions CI on PR #1. Never merge to main
   without user instruction.

## Continuation instruction for Codex chat

> Use the project Skill `a6000-core-abi` and this
> `CODEX_HANDOFF.md`. Continue the existing A6000 3.21
> core API reverse engineering without rediscovering prior work.
> Start with the exact SHA-pinned private `libObj.so`
> and `0x13200a` / `0x42ac00` function bodies.
> Prioritize primary ELF opcode evidence and a genuinely
> verified ABI; no more broad callsite reports or guessed
> 'completed' APIs. Keep Sony binary private. Add tests and
> continue PR #1. Report blockers honestly.

## Security and evidence

This is a non-invasive static research project; do not provide
or run hardware flashing, bypass, exploitation or destructive
operations. Keep private binaries and trace exports private.
The handoff copies only technical context and file references
from previous chats; it does NOT automatically sync private
ChatGPT conversation transcripts or private file contents.
