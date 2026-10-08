# Changelog

## Unreleased — Phase 3 semantic-analysis

- 新增 schema v5 Semantic Graph、CFG edge、OSAL message、JNI bridge 和 SDK evidence model。
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
