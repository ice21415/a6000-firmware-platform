# Phase 4.48 — 649-ELF stage-event literal/import sweep points to `bootin.elf`

## Scope and provenance

This is a **user-run, read-only scan output** against Sony A6000 Firmware 3.21 unpacked path `0700_part_image/dev/nflasha15_unpacked_unpacked`, using `scan_a6000_stage_event_producers.py`. The report deliberately distinguishes **candidate discovery** from **direct ELF instruction proof**: `bootin.elf` has **not yet been uploaded or disassembled** in this stage.

Scanner totals as reported: **649** ELF files, **0** skipped due to size, **19** containing at least one exact relevant word in a 4-byte aligned position of an allocated PROGBITS section. Ranking: **2 HIGH**, **16 MEDIUM**, **1 LITERAL_ONLY**. A HIGH rank means co-occurrence of two stage-ID word constants and an imported `osal_snd_msg` symbol; it **does not certify code execution, literal references, or a send callsite**.

## Highest-priority previously unseen candidate: bootin.elf

`0700_part_image/dev/nflasha15_unpacked_unpacked/bin/bootin.elf`:

| Label | Original scanner's section VMA |
| --- | --- |
| stage event **0x00940036** | `.text+0x00009c28` (reported as text VMA) |
| stage event **0x00940037** | `.text+0x00009c30` |
| fixed UIPC destination **0x0094016a** | `.text+0x00009c50` |

Its undefined dynamic OSAL symbols include `osal_rcv_msg_tmo`, `osal_reg_sync_msg_queue_cb`, `osal_snd_msg`, and `osal_snd_sync_msg`.

The **only other** HIGH match is `bin/im.elf`, whose direct Thumb calls and literal references were separately verified earlier in Phase 4.43. `bootin.elf` is therefore the best next binary to inspect for a potentially independent publisher/dispatcher of stage events 0x940036 and 0x940037. Whether it actually **sends** those events, uses them to **receive/compare** events, or merely includes them in unrelated data remains unverified.

## Other findings and scanner caveats

- `libmpr.so` has **stage_036** at 0x75c994 but no matching **stage_037** in the scanner output. Previous direct analysis traced its 0x940036 constant in a formatting/logging path. That is not stage-event producer proof.
- `libObj.so` contains fixed-destination literal values and an independently proven `osal_snd_msg` sender helper, but no pair of 0x940036/037 word constants in this scan. Its message code is passed by caller; stage producer identity is still open.
- **`upm.ko`** holds four instances of fixed-destination 0x94016a, but appears LITERAL_ONLY because the scanner checks `.dynsym` undefined imports. An unstripped ET_REL kernel module normally uses `.symtab` and relocation records, so `imports=none` here is **not** a proven absence of OSAL calls. This is a secondary follow-up candidate, not a confirmed sender.
- The 16 other MEDIUM matches have fixed-destination or isolated stage literals with send API imports; the scan alone does not prioritize any over `bootin.elf` for **both** stage events.
- Exact-word scans cannot find computed event IDs, indirect or runtime-injected targets, or binaries missing valid ELF32 ARM section metadata. Further absence claims would be unwarranted.

## Immediate next verification

Obtain the original **`bootin.elf`** file from the already unpacked `nflasha15` partition and pin its SHA-256 before drawing instruction-level conclusions. Disassemble with ARM/Thumb mode and check:

1. **PC-relative xrefs** to 0x9c28, 0x9c30, and 0x9c50, including whether referenced as event-value operands, data/message-field writes, or comparison constants.
2. **PLT relocations** to `osal_snd_msg`, `osal_snd_sync_msg`, `osal_rcv_msg_tmo`, `osal_reg_sync_msg_queue_cb`.
3. **Call context and queue destinations**, in particular 0x94016a versus a dynamic 0x946xxx ID.
4. Any **programmed sequencing or success-check** between event 0x940036 and 0x940037, and whether this offers evidence for actual prior `libObj.so` loading.

Only then can earlier cross-ELF IPC hypotheses be narrowed from candidates to real control/data flow. Do not assert OSAL delivery, runtime boot choices or Camera Core event-consumer completion from the scan.

Previous principal static Camera Core accounting **unchanged**: 74 primary + 5 inferred + 5 unresolved = 84 tracked, 0 runtime-verified APIs. New structured scan record: `sdk/bootin_stage_event_scan_3_21.json`.
