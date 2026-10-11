# Follow-up: `nflasha5` is Sony WBI1, not a TPZL filesystem image

**2026-10-11 — evidence scope:** User ran the offline read-only `scan_a6000_lzpt_links.py` against `0700_part_image/dev/nflasha5` and received:

```text
[ERROR] nflasha5: expected TPZL, found b'WBI1'
```

This is a **format mismatch**, not evidence of a corrupt image, a missing firmware library, or a failed partition extraction.

## Supported format classification

The existing open-source Sony firmware tool has an explicit WBI parser:
[ma1co/fwtool.py — fwtool/sony/wbi.py](https://github.com/ma1co/fwtool.py/blob/master/fwtool/sony/wbi.py).
It declares:

- `WbiHeader.magic`: four ASCII bytes `WBI1`;
- version constant `0x20060224`;
- eleven header fields total (magic followed by ten little-endian 32-bit values);
- a `numSections` count, flags (bit 0 is compressed), sector size, compressed data size, resume vector and kernel-related metadata;
- per-section descriptors containing physical address, virtual address, compressed size, uncompressed size, flags and checksums.

The parser's `readWbi` yields memory chunks `(physicalAddr, virtualAddr, size, contents)` and decodes their LZ77 streams. It **does not** expose a directory tree or symlink inventory; consequently passing `nflasha5` to the LZPT/CramFS symlink scanner is conceptually invalid. The upstream CLI has a separate `unpackWbi` function which writes RAM sections as address-named `.dat` files; those files are *not* evidence of a `modelCamera.so` filesystem link.

## Five images: exact bounds on negative evidence

| Partition | Mount from Sony config | User-provided scan result | Interpretation |
| --- | --- | --- | --- |
| `nflasha15` | `/usr` | LZPT → filesystem; `/lib/libObj.so` present, 31 symlinks, no `modelCamera.so` match | Missing as stored file/symlink in that scanned FS |
| `nflasha3` | `/system` | LZPT → filesystem; 0 symlinks, no match | Same scoped negative evidence |
| `nflasha7` | `/rootfs` | LZPT → filesystem; 87 symlinks, no match | Same scoped negative evidence |
| `nflasha16` | `/android/system` | LZPT → filesystem; 53 symlinks, 10 camera-related files but no `modelCamera.so` match | Same scoped negative evidence |
| `nflasha5` | `/wbi` | `WBI1` magic detected; LZPT scanner rejected it | **Unsurveyed RAM-section contents**, not a negative directory inventory |

The lack of a stored `modelCamera.so` in the four scanned filesystems does not rule out runtime-generated filesystem mappings, symlinks, process namespaces, or runtime `dlopen` behavior. The warm boot image, even after memory-block decoding, is not a substitute for observing the dynamic loader's resolved pathname.

## Safe next step

Use a metadata-only local WBI1 parser (no decompression or writing), validate `WBI1` magic and basic header ranges, then locate and list section table entries (physical/virtual addresses and lengths) based on the upstream format. Do not mount images or execute any included code on the actual camera.

The separate ModelConfig provider-vtable identity work in Phase 4.27 remains conditional on the runtime startup selector; inspecting WBI metadata alone cannot promote it to runtime-proven.

**Static graph unchanged:** 72 SHA-pinned primary / 5 inferred / 5 unresolved = **82 tracked**. Five unresolved end-to-end blockers; zero runtime-verified/safe-to-invoke APIs.
