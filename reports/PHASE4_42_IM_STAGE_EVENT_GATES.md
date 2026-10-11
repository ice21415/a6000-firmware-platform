# Phase 4.42 — IMDB stage markers, guarded stage traversal and the appFw event boundary

**Scope:** read-only static analysis of the exact user-uploaded Sony A6000 v3.21 original ELFs. `im-vendor-original.elf` SHA256 `f0f181426af4add55a8510c5441ff86c3121678fd1f7e0467152070e870d803a`, `libIMDB.so` SHA256 `9ceb21092a4987ec782fd980818aee687cde649af0999608bd6c40e1f46a84ea`, and independent `libObj.so` SHA256 `8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`. Original bytes are not committed.

## Major correction to prior '31 preceding records' interpretation

The 143-record IMDB table is not a linear unconditional startup playlist. **It has stage separator records** identified by first-word values 1..8. In the independently uploaded `libIMDB.so` array with 44-byte stride:

| Stage marker | Row index | ELF VMA |
|---|---:|---|
| 1 | 0 | `0xc0e8` |
| 2 | 9 | `0xc274` |
| 3 | 19 | `0xc42c` |
| 4 | 31 | `0xc63c` |
| 5 | 33 | `0xc694` |
| 6 | 94 | `0xd110` |
| 7 | 98 | `0xd1c0` |
| 8 | 101 | `0xd244` |
| End tag `0x28` | 143 | `0xd97c` |

The `im.elf` iterator `0xb63c..0xb6d4` invokes `IMDB_get_entries` at `0xb66a`, uses `mla` with stride `0x2c` at `0xb670`, checks the target mask at `0xb67c..0xb682`, group mask at `0xb684..0xb68a`, forwards the row's 16-bit ID to `0xb530` at `0xb69c..0xb69e`, and advances at `0xb6ae..0xb6b0`. Critically, `0xb6b4` stops the scan when the **row type equals r1 (requested stage marker)**, or when it reaches `0x28`. `0xb676` checks **r2** (gate), and skips dispatch when r2 is zero.

The facade at `0xb6e4` fixes r3=0xff (permitting the observed group values) then tail-jumps to the iterator. Thus passing r1=8 from the stage-7 marker executes the **stage 7→8 interval** containing row99 `appFw.so` and row100 `subapp.so`.

## Actual event handler accepts distinct event IDs

Handler `0xa06c` reads the event value from the message, and compares it with PC-relative 32-bit constants in its literal pool at `0xa308..0xa320`:

| Event | Literal address | Stage path |
|---|---|---|
| `0x940031` | `0xa308` | stop at marker 1; no interval rows |
| `0x940032` | `0xa30c` | skip to marker 1 (gate 0), then process to marker 2 (gate 1) |
| `0x940033` | `0xa310` | skip to marker 2, then process to 3 |
| `0x940034` | `0xa314` | skip to marker 3, then process to 4 |
| `0x940035` | `0xa318` | skip to marker 4, then process to 5 |
| `0x940036` | `0xa31c` | skip to marker 5, then process to 7 |
| `0x940037` | `0xa320` | skip to marker 7 at **`0xa11c`**, then process to marker 8 via **`0xa0a4`** |

For event `0x940037`, the first iterator call at `0xa11c` sets r0=0, r1=7, **r2=0**; the second receives r1=8 and **r2=1**. Since IMDB row99 is between markers 7 and 8, this is a **concrete executable route that can reach the appFw description** if this event arrives and the target mask selects that row. It is not runtime event delivery proof. Notably the handler can **skip directly** to marker 7 without first processing stages 1..6; no earlier `libObj.so` load is thereby guaranteed.

## Re-evaluated prior 31 conditional libObj loaders

Earlier Phase4.41 verified 31 rows with type `0x20000001/02/03`, nonzero packed high halfword (indicating `dlopen("/usr/lib/libObj.so", ...)` in `0xb25c`) and a mask matching default target bit `0x1`. Direct 44-byte row enumeration now partitions those **31 candidates** by the *stage intervals actually scanned*:

- **1** candidate: index **29**, in marker **3→4** interval (rows 19..30), which main calls with **r1=4** and gate bit **0x80000** (main `0x9c04..0x9c0e`), or event `0x940034`.
- **30** candidates: indices **34..96** (not all consecutive), in marker **5→7** interval (rows 33..97), reached by event `0x940036` and a gate=1 stage dispatch.
- **0** candidates of this category are in interval **7→8** (rows 98..100), where appFw row99 is.

The original `im.elf` source config has `global[0x153e4+0x0c]` = **`0x00000003`** as the file-initialized value. The four main-stage gates at `0xab60/0xab74/0xab88/0xab9c` test **0x20000/0x40000/0x80000/0x100000**, all zero in that file-initialized state; however, **the command-line parser can modify those bits**. The code cannot establish which gates are enabled for the actual camera startup.

**The critical correction:** the fact that 31 eligible rows *precede* `appFw.so` in the data table never proves they are executed first. A stage-7 event `0x940037` has a structurally reachable path to row99 even without evidence that earlier event `0x940036` ran or any conditional libObj dlopen succeeded. The Phase4.41 conclusion remains a **plausible linker visibility mechanism**, not a proven executed prerequisite.

## Evidence level and next target

New proof is actual **file-pinned machine-code program control flow** and **table segmentation**. It is not camera runtime. The next key evidence is the real source and ordering of events `0x940036` vs `0x940037` (other processes, launch service or event dispatch), plus success of `dlopen("/usr/lib/libObj.so",0x101)` and visibility of `Application_System_Init` from `dlopen(NULL)`. Those remain unknown and must not be inferred from handler existence.

The linked static conditional call chain previously established through `im.elf → libIMDB.so → libObj.so` continues to stand. Model ID11 → ModelCamera record/DSO linkage remains separate and unresolved.

No device access, firmware patch, execution or unsafe invocation. **Camera Core tracking remains 74 direct static / 5 inferred / 5 unresolved = 84**; zero runtime-verified and safe-to-invoke APIs. Phase4.42 evidence stored in `sdk/im_stage_dispatch_3_21.json`.
