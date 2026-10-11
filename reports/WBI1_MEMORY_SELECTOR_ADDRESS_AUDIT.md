# WBI1 memory-section metadata verification and bounded selector hypothesis

**2026-10-11, offline investigation.** Input: user-provided `inspect_a6000_wbi1.py` output for official Sony A6000 3.21 `0700_part_image/dev/nflasha5`, plus independently inspected privately supplied `libObj.so` (SHA-256 `8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`). No WBI image bytes or camera secrets are stored in this repository.

## Original WBI1 structure, per user read-only metadata scan

- Magic `WBI1`, expected version `0x20060224`.
- 1,164 memory sections; flags `0x9` (compressed bit set), sector size 512.
- Image size **42,293,120** bytes (`0x2855780`).
- First nonempty data sector at **`0x40000`**.
- Compressed payload **41,993,728** bytes (`0x280c600`).
- Section table begins at **`0x284c600`**, the exact payload end.
- 1,164 descriptions × 32 bytes = **37,248** bytes; table ends at **`0x2855780`**, exact image end.
- Sum of per-section packed sizes equals declared compressed payload.
- Total advertised uncompressed memory **172,998,656** bytes (~164.98 MiB).
- First twelve described sections use physical addresses around `0x80000000` and virtual addresses around `0x40000000` (e.g. section 0 physical `0x80028000`, virtual `0x40028000`).

**Consequence:** header, compressed data size and section table accounting agree exactly, supporting structural integrity. This does **not** prove every section decompresses or its checksum.

## Candidate runtime address mapping

The Phase 4.27 original ELF trace follows the bootstrap provider-selection argument to ELF **`.bss` VMA `0x010df828`**:

- `0x7ed98e` loads a PC-relative literal (raw little-endian `0x008f1e90`);
- `0x7ed994` adds to PC, yielding `0x010df828`;
- `0x7ed996` passes that pointer to configuration/bootstrap initialization.
- This ELF `.bss` is `0x010a88a8..0x010e2bd0` (NOBITS). It has **no static initialized bytes**.
- The WBI's first 12 **virtual** section addresses lie near `0x40000000`, so `0x40000000` is a **hypothetical** library load bias. The selector's candidate runtime address would then be `0x410df828`. The actual loader bias, snapshot provenance and whether this BSS block is included remain UNKNOWN.

The appropriate next experiment first checks *all 1,164 WBI section descriptors* for virtual/physical range containment of `0x010df828` and `0x410df828`. It **must not** assume a hit proves ELF→memory identity: other snapshots or unrelated memory may occupy a matching address.

A new **local-only downloadable Python script**, `probe_a6000_wbi1_selector.py`, does that metadata check using the already-provided `inspect_a6000_wbi1.py` parser. `--inspect` is optional: for a covered candidate address, it invokes `fwtool.sony.wbi.readWbi` to decompress **only the matched section, capped at 8 MiB per section**, and reports an exact, allowlisted NUL-terminated token (e.g. `AppConfig.so` or `ModelConfig.so`); unknown memory bytes are withheld. It does **not** write or execute the memory image. Eight synthetic metadata/probe unit tests pass locally; **the actual full WBI1 contents were not uploaded or decoded here**.

## Remaining interpretation constraints

- WBI1 contains warm-boot RAM sections, **not a CramFS directory**: a filename/symlink search of this partition is inapplicable.
- A `modelCamera.so` string found in RAM would be **insufficient** to prove a real file, `dlopen` success, an alias to `libObj.so` or ModelCamera instantiated runtime identity.
- The user's four original filesystem images `nflasha15,3,7,16` lack the filename/link in the selective scanner. Runtime mounts/aliases remain possible.
- No data herein resolves the startup provider branch or a concrete ModelManager descriptor key 11.

**No graph count promotion:** 72 primary ELF static / 5 inferred / 5 unresolved = 82 tracked. Five end-to-end blockers remain unresolved, zero runtime-verified/safe-to-invoke APIs.

No writes, camera access, mounting, firmware flash or in-camera command injection are needed for this research.
