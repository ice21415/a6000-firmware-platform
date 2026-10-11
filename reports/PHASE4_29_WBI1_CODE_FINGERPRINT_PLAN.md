# Phase 4.29 — WBI virtual-address coverage is not proof of libObj.so load bias

**Evidence date:** 2026-10-11. Sony A6000 Firmware 3.21. This report is based on a read-only WBI probe *run by the user* against original `nflasha5`, not on unseen private WBI contents. No firmware bytes or RAM snapshots committed.

## New user-provided WBI1 results

The user ran `probe_a6000_wbi1_selector.py` twice (second time `--inspect`). Both runs agreed:

```text
WBI1: 1,164 sections; file 42,293,120 bytes; declared memory 172,998,656 bytes
Integrity: payload_end=0x284c600, table_start=0x284c600,
           table_end=0x2855780, file_end=0x2855780; packed_sum=41,993,728
candidate ELF VMA 0x010df828 + bias 0x00000000 = 0x010df828 | virtual hits=0, physical hits=0
candidate ELF VMA 0x010df828 + bias 0x40000000 = 0x410df828 | virtual hits=1, physical hits=0
  VIRT section 32: 0x410c8000..0x411a8000 offset=0x17828 size=917,504
    known-string probe: UNKNOWN (not a known token; bytes withheld)
```

The original `libObj.so` ELF VMA `0x010df828` falls in `.bss` (NOBITS). Section coverage is **not** evidence that a specific address contains this library's BSS at the selected warm-boot snapshot time. The `0x40000000` delta is a **hypothetical load bias**; the WBI is a RAM-section serialization rather than a process loader map.

The `UNKNOWN` classification only says that the inspected bytes were not exactly a NUL-delimited allowlisted token (`AppConfig.so`, `ModelConfig.so`, etc.) at the selected location. It does not identify another provider branch. There may be an empty value, binary field, nonallowlisted string, unrelated memory, relocated address or memory from a different lifecycle point.

**No Blocker is resolved by this user result.**

## Stronger proposed offline experiment: multiple text fingerprints

A dedicated downloadable local script `check_a6000_wbi1_libobj_mapping.py` cross-compares the user's exact private `libObj.so` against WBI virtual memory, under a nominated candidate bias, at four distinct **ELF executable instruction** VMAs:

| Thumb code region | Original ELF VMA | Candidate WBI virtual VMA for bias +0x40000000 |
| --- | --- | --- |
| ModelManager constructor | `0x007ec384` | `0x407ec384` |
| Bootstrap initializer | `0x007ef254` | `0x407ef254` |
| ModelConfig getter | `0x0045ef28` | `0x4045ef28` |
| IdSoTable name accessor | `0x007eaae8` | `0x407eaae8` |

The script first confirms ELF32 ARM little-endian executable `PT_LOAD` mappings and pinned SHA-256 `8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`. It uses the previously provided local read-only WBI1 header/table parser. `--compare` decodes **only uniquely mapped WBI sections** from the existing `fwtool.sony.wbi` Python library, with a maximum of 8 MiB/section and 32 MiB total. It compares 48 bytes at each executable VMA (no raw memory or ELF bytes printed), and separately classifies any candidate BSS value without exposing unknown text or pointer values.

Local synthetic tests on the helper functions (four unit tests plus Python compile check) pass. **This is a proposed experiment; no output from the user's actual WBI+ELF code-fingerprint run exists yet.** Do not claim match, mismatch, module identity or conditional branch selection.

The local PowerShell invocation can use the user's already-downloaded scripts:

```powershell
$py = ".\tools\fwtool-venv\Scripts\python.exe"
$env:PYTHONPATH = (Resolve-Path ".\tools\fwtool-src").Path
$root = ".\firmware-analysis\official-3.21-dat"
$wbi = Join-Path $root "firmware.tar_unpacked\0700_part_image\dev\nflasha5"
$elf = Get-ChildItem ".\firmware-analysis" -Recurse -File -Filter "libObj.so" |
    Select-Object -First 1 -ExpandProperty FullName
& $py ".\check_a6000_wbi1_libobj_mapping.py" $wbi --elf $elf --compare
```

The downloaded `check_a6000_wbi1_libobj_mapping.py` and `inspect_a6000_wbi1.py` must be in the same folder. If the ELF hash differs, stop and reassess provenance instead of substituting unchecked bytes.

**Interpretation:** a match of two or more distinct file-backed instruction regions would strengthen, but not absolutely prove, that the WBI snapshot includes libObj text at the candidate address mapping. A mismatch/unmapped result would weaken the chosen bias and direct BSS inference. An exact BSS token (if independently observed) still requires boot-state and pointer provenance before selecting ModelConfig vs AppConfig and before promoting any runtime verification.

## Unchanged graph and safety constraints

**72 primary ELF static / 5 inferred / 5 unresolved = 82 tracked.** Five original end-to-end blockers still unresolved. Runtime verified: 0. Safe-to-invoke APIs: 0. All requested actions are read-only offline analysis; no camera commands, firmware modification, mounting, or flashing.
