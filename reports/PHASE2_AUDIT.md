# PHASE2_AUDIT

Generated: 2026-10-08T06:25:57.524816+00:00

## Implemented code paths

- v3 integrity migration and evidence archive: `fwplatform/migration_v3.py`
- v4 Ghidra provenance columns: `fwplatform/migration_v4.py`
- deterministic Ghidra export and Auto Analysis wrapper: `ghidra-scripts/AnalyzeBinary.java`, `tools/run-ghidra-headless.ps1`
- JSONL importer with run/hash provenance: `fwplatform/ghidra_importer.py`
- ELF DT_NEEDED and unique export linkage: `fwplatform/linkage.py`
- call graph queries: `fwplatform/cli.py` (`callers`, `callees`, `callsite`, `trace --depth`)

## Measured status

- Schema: `4`; quick check `ok`; FK errors `0`.
- Ghidra runs: `1`; CFG rows: `{'function': 135313, 'basic_block': 353, 'instruction': 2363, 'callsite': 400, 'cross_reference': 1497, 'unresolved_edge': 0}`; linkage: `{'module_dependency': 2084, 'resolved_import_xrefs': 569, 'dynamic_evidence': 707}`.
- CLI smoke query counts (`callers open`, `callsite 0x11250`, `xrefs ...0x11250`, trace seed): `{'callers_open': 10, 'callsite_0x11250': 1, 'xrefs_0x11250': 1, 'trace_seed_open': 1162}`.
- Regression test log: `PASS` (`reports/phase2-tests.txt`).
- Existing symbol index remains distinct from recovered CFG and semantic understanding.

## Not claimed

No firmware patch, NAND/WBI modification, bootloader change, or runtime safety claim was made. Unknown and candidate relations remain explicitly marked.