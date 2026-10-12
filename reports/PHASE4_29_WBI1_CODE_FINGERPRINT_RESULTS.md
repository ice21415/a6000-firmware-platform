# Phase 4.29 follow-up — WBI1 code fingerprint **rejects** the proposed +0x40000000 uniform libObj mapping

**2026-10-11, user-run read-only analysis.** This records actual output from `check_a6000_wbi1_libobj_mapping.py --compare` against privately held Sony A6000 3.21 `nflasha5` warm-boot image and the pinned `libObj.so` SHA-256 `8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a`.

## Observations (supplied by user; not independently reproduced with private WBI bytes)

```text
WBI sections=1,164; libObj.so SHA256=EXPECTED; candidate bias=0x40000000
  ModelManager ctor VMA 0x007ec384 => 0x407ec384: virtual hits=0
  Bootstrap init VMA 0x007ef254 => 0x407ef254: virtual hits=0
  ModelConfig getter VMA 0x0045ef28 => 0x4045ef28: virtual hits=1 (section 8)
  IdSoTable library accessor VMA 0x007eaae8 => 0x407eaae8: virtual hits=0
  ModelManager ctor 0x007ec384: UNMAPPED (virtual hits=0)
  Bootstrap init 0x007ef254: UNMAPPED (virtual hits=0)
  ModelConfig getter 0x0045ef28: MISMATCH (section 8)
  IdSoTable library accessor 0x007eaae8: UNMAPPED (virtual hits=0)
  Selector slot 0x410df828: EMPTY_OR_NUL (not a proven process/string identity)
Code fingerprint result: 0/1 exact among mapped/checked probes.
```

The WBI decompressor produced data for the sole mapped instruction probe and the 48-byte fingerprint was **not equal** to the same VMA's original ELF file bytes. The three remaining executable probes had no WBI virtual range coverage at candidate bias. The prior single `0x410df828` coverage hit was incidental with respect to ELF module mapping under this exact assumption.

**Interpretation:** A simple uniform `+0x40000000` mapping of this original ELF's `.text` into the serialized WBI virtual sections is **not supported** by these observations. More precisely, it fails the tested 48-byte ModelConfig getter fingerprint and has no section coverage for the other three code probes. This is **not** proof that `libObj.so` was absent from the device at all times: the warm-boot snapshot may omit or transform ranges, use different mappings, or capture a different process/lifecycle. It also is not a search over all possible load biases.

The tool's `EMPTY_OR_NUL` classification means the **sampled** 64-byte slice beginning at virtual `0x410df828` starts with NUL (per classifier). As mapping identity failed, that read does **not** show whether the actual startup selector at ELF BSS `0x010df828` was empty, what string it held, or whether the AppConfig vs ModelConfig branch was selected.

## Evidence classification and project decisions

1. **Hypothesis retired for now:** do not use `bias=0x40000000` in proof of the ModelIdSoTable branch, as a libObj RAM image, or as a ModelCamera runtime record.
2. Keep the Phase 4.27 **conditional** static proof: the ModelConfig provider's `vptr+0x1c` calls the same `ModelIdSoTable::getInstance` getter used by the `@M00B` registration path; actual branch selection and descriptor ID=11 identity remain UNKNOWN.
3. Do not infer `modelCamera.so -> libObj.so` alias from the lack of a filename, the WBI code mismatch, or an ELF factory export; `dlopen` success and actual resolved loaded module are still unknown.
4. Prefer **offline primary ELF analysis** of startup selector initialization/call-site provenance and descriptor key 11 before any broader WBI RAM search. If more memory testing is justified, require independent module identity validation first and limit decompression/read scope.

**No new graph relations and no blocker promotion:** 72 primary static / 5 static inferred / 5 unresolved = **82 tracked**; 5 end-to-end blockers remain open. No runtime-verified or safe-to-invoke APIs.

**Disclosure:** GitHub Actions uses synthetic tests and did not ingest the private WBI image, so it does **not** independently attest these user-supplied WBI observations. This report intentionally contains metadata and classification output only, not Sony firmware bytes or memory contents.
