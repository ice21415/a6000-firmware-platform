# SQLite 資料模型

schema 由 `database/migrations/001_initial.sql` 至 `004_ghidra_cfg.sql` 建立，
`PRAGMA user_version` 是 migration version。所有 analyzer 以 `(binary_id,
analyzer, analyzer_version, input_sha256)` 建立可重跑的 `analysis_run`。

主要 identity：

- `source_identity`：來源 hash/path/kind 的穩定 identity。
- `binary_identity`：binary SHA-256、大小、格式和架構 identity。
- `evidence.evidence_key`：source identity、locator、kind、excerpt hash 的非 nullable key。
- `evidence_archive`：合併 duplicate evidence 後保留原始 row 與 canonical ID。
- `module.identity_key`：binary hash + basename，或 research-only module name。

地址欄位刻意分離：ELF VMA、Ghidra image base、runtime VA、physical offset、WBI
offset、address space 不可互相覆寫。

CFG 表的關係是：`function -> basic_block -> instruction`，`callsite` 連接 caller/
callee，`cross_reference` 保存 binary/address pair，`unresolved_edge` 保存找不到
target 的候選關係。所有可驗證 relation 都應有 `source_evidence_id` 和 status。

可信度代碼：`VERIFIED_STATIC`、`VERIFIED_RUNTIME`、`INFERRED`、`CANDIDATE`、
`UNKNOWN`、`DISPROVEN`。原始 evidence 不可被後續推論覆寫。
