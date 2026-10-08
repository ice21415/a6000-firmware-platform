# Changelog

## Unreleased — Phase 3 semantic-analysis

- Phase 3.1：migration v6 新增函式不連續 body ranges、證據 adapter run/observation 與 graph provenance。
- Ghidra exporter/importer 改用 AddressSet body ranges；缺少 range 的 caller 保留 unresolved。
- GraphML 改用標準 key/data；加入 provenance gap validator。
- 新增私有 SyncAndroid/ModelCamera evidence adapter、`fw evidence`、`fw unresolved`、`fw sdk coverage` 和 Phase 3.1 reports。

- 新增 schema v5 Semantic Graph、CFG edge、OSAL message、JNI bridge 和 SDK evidence model；Phase 3.1 增加 migration v6 body range/provenance tables。
- 修正同名 ELF 的 SONAME/搜尋路徑解析；無法唯一判定的依賴與 symbol 會保存 unresolved edge。
- 修正 Ghidra callsite caller 必須由明確 function entry 和 code range 驗證，新增 JSONL complete marker、hash/record-count validation、rollback。
- 新增 OSAL/JNI fixture analyzer、保守 DEX inventory、跨模組 trace、protocol/state/API 查詢及 JSON/GraphML export。
- 新增 5 組 P0/P1/P2 synthetic regression tests；不包含原廠 firmware 或私人資料庫。

## 0.2.0-alpha — 2026-10-08

- 建立 allowlist 公開發布目錄。
- 加入繁體中文 README、架構、資料模型、重現性、AI context 和研究狀態文件。
- 排除本機 SQLite、firmware、Ghidra project、raw JSONL、manifest 和 private runtime data。
- 保留 Phase 2 工具、schema、mock、合成測試與清理後報告。
- 採用 MIT License；公開發布只包含 allowlist 內容，不包含原廠韌體或私人研究資料。
