# CROSS_REFERENCE_COVERAGE

Counts come from SQLite rows, not symbol totals.

| Relation | Rows |
|---|---:|
| function | 135313 |
| basic_block | 353 |
| instruction | 2363 |
| callsite | 400 |
| cross_reference | 1497 |
| unresolved_edge | 0 |
| module_dependency | 2084 |
| resolved_import_xrefs | 569 |
| dynamic_evidence | 707 |

Verified callsites and cross-references retain Ghidra JSONL evidence IDs. Unresolved indirect edges are stored separately and are not counted as resolved targets.