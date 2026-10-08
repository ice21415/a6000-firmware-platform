# SQLite 資料模型

schema 由 `database/migrations/001_initial.sql` 至 `006_ranges_evidence.sql` 建立，
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
callee，`cfg_edge` 保存明確 basic-block control flow，`cross_reference` 保存
binary/address pair，`function_body_range` 保存 Ghidra AddressSet 的不連續函式範圍，
`unresolved_edge` 保存找不到 target 的候選關係。

Phase 3 的 `semantic_node` 和 `semantic_edge` 是跨模組查詢層。它們以穩定 identity
連接 Binary、Module、Function、Message、JNI、Event 和 State，並保存 relation type、
address space、evidence、analyzer version、status 和 confidence。`osal_message`/
`message_flow` 保存 queue、command、payload、producer/consumer/callback；
`sdk_interface` 保存描述性 SDK 欄位，不代表可安全呼叫。

所有可驗證 relation 都應有 `source_evidence_id`/`evidence_id` 和 status。

Phase 3.1 的 `evidence_adapter_run` 保存 adapter 版本、輸入數量、checkpoint 和失敗
資訊；`research_observation` 保存來源 SHA-256、locator、binary/function identity、
address space、原始 status 和 derived relation。`semantic_node.provenance_kind` 與
`semantic_edge.provenance_kind` 用來區分 Ghidra-derived、imported research、ELF
dependency、synthetic fixture 和缺少 primary evidence；它不會把 derived edge 自動
提升為 VERIFIED。

可信度代碼：`VERIFIED_STATIC`、`VERIFIED_RUNTIME`、`INFERRED`、`CANDIDATE`、
`UNKNOWN`、`DISPROVEN`。原始 evidence 不可被後續推論覆寫。
