# Changelog

## Unreleased — Phase 3 semantic-analysis

- Phase 3.14：由先前保存的 `libObj.so` 組語追回 `ViewBase::requestModelExecute` 前端與 `AbstractUtilityManager::createRequestModelExecuteEvent` 的靜態 event envelope：事件 `0x11004003`、可能包含 `ParamList`、參數鍵 7／8、入口與 callsite 位址。
- 新增 `sdk event-envelope [--saved-disassembly]`、保守的函式邊界／call-target／寄存器來源文字核對及 synthetic 測試。將 `0x12d780` 轉換、符號動態解析與事件投遞端明列 UNKNOWN；不宣稱 Sony ABI 或 runtime API 已完成。


- Phase 3.13：利用已保存的 REA/Ghidra UI 反編譯與獨立 Camera raw ELF/Capstone 區段，建立 `sdk rea-bridge` 跨 ELF selector 研究核對；區分 UI 地址 `0x1b2504→0x1a2504`、兩端 `0x0f01`、事件投遞未證實，以及靜態呼叫位置不等於 runtime 次數。
- 新增 REA metadata fixture、嚴格 saved UI pseudocode count 和 Thumb MOVW/BL byte decoder 的 synthetic 測試。沒有執行任何韌體、接觸設備或聲稱 Sony ABI 已完成。


- Phase 3.12：新增 `fw sdk research --verify-elf`，只讀原始私有 ELF，驗證 SHA-256、ELF32 ARM executable segment VMA、Thumb BL/B.W 直接分支與 LDRB.W/STRB.W byte displacement；失配非零退出，不執行任何 firmware code。另將 ModelCamera byte instruction immediate 與研究推論 object-root 調整量分開保存。
- 增加純合成 ELF32/Thumb 負位移和欄位立即數回歸測試；沒有假定報告可直接提供 Sony ABI、parameters、return values 或 runtime callability。


- Phase 3.11：在已連線 workspace 找到原本未定位的 Sony 3.21 Camera/Lens/Media 韌體 ELF；新增 14 個源自既有私有反組譯的 Camera 候選入口與 9 條報告層級直接呼叫／尾分支、6 筆 ModelCamera 欄位觀測、4 條 bounded selector 和 1 個 unresolved indirect dispatch。
- `fw sdk research --compare-db` 支援對私有 SQLite 索引做唯讀身份及 callsite FK 比對，不自動修改 DB 或提高 ABI 驗證狀態；新增缺失與重複 ELF 身分的回歸測試。
- `fw sdk research` 可純離線驗證指令目標與候選 ELF VMA 一致性、拒絕偽造的 ABI/VERIFIED/runtime 宣稱，並用 `--focus` 追蹤已記錄的 Camera call graph；回歸測試不分發韌體、沒有 live camera SDK 呼叫。


- Phase 3.10：新增 `sdk investigate` 對 Camera/Lens/Sensor/Media/UI/OSAL/Android/Networking 候選，交叉呈現有明確 FK 的 callsite、CFG/body range、OSAL、JNI 與 lifecycle 靜態證據。
- 新增 `sdk inspect --function-id`，可針對 Ghidra 自動命名或無 Camera 字樣的內部函式研究，保留跨二進位位址歧義、未知 ABI 及模組 state-machine-only 脈絡。
- 新增 `tests/test_core_api.py`（合成隔離、read-only、CLI、地址歧義、OSAL/JNI/狀態機），以及 Camera/Lens/Sensor/Media 研究缺口報告；沒有原廠韌體、實機 SDK 或 runtime 呼叫。
- Phase 3.9：ELF 匯入解析只接受已確定 DT_NEEDED 依賴的唯一 export 位址／版本候選，採 catalog fingerprint 重掃及失敗回滾；SDK discover/draft 可列出 incoming import evidence ID。
- Phase 3.8：強化 SDK ELF SHA／數值位址唯一性、匯出位址配對與重複候選審核，排除 SDK fixture 自我充當 ABI 證據。


- Phase 3.7：新增受限、可恢復的 `analyze ghidra-batch` 多 ELF 計畫與選擇性本機執行工具。
- 校驗 inventory SHA、避免危險來源路徑、限制分析批量與逾時；輸出保留在 firmware root 之外，不匯入 stale／截斷 JSONL。
- 新增 synthetic batch planner、mock headless 寫入、失敗隔離與 resume skip 測試，沒有將原廠 firmware 納入 CI。

- Phase 3.6：Ghidra function records 獨立保存來源 SHA 與 entry locator；不把 prototype 直接推定成 ABI。
- `fw sdk discover` 以 ELF export + binary identity 搜尋待審核 API，列出候選與證據缺口，不寫入 SDK。
- `fw sdk draft` 產出需人工確認、全部標 CANDIDATE 的 SDK fixture，保留 domain 搜尋提示而不自動確認語意。
- 新增 multi-ELF 同名函式、來源歸屬、受控查詢與 review-fixture roundtrip 的合成測試。

- Phase 3.5：加入純離線 `fw sdk mock --scenario`，以名稱空間隔離的命令與狀態轉移建立 deterministic tests；不觸及硬體。
- 強化 SDK `VERIFIED_STATIC` 合約，要求 primary evidence 同時支持 ELF SHA、function address、ABI 與 parameter/return layout。
- OSAL/JNI fixture 匯入改為整批 SQLite savepoint rollback；native role/function 綁定要求 ELF SHA，避免跨 binary name/address 誤配。
- 新增合成 mock、異常中斷回滾、跨 ELF native 歸屬與 ABI 不一致 regression tests。

- Phase 3.4：新增 offline SDK contracts 匯入、完整性稽核與 Camera/Lens/Sensor/Media/UI/OSAL/Android/Networking domain readiness matrix。
- 靜態狀態需函式與 ELF 身分唯一匹配，且來源 evidence 明確綁定相同 binary SHA-256 與 function address；不符時降級 CANDIDATE。
- CLI 新增 `fw sdk import --fixture` 和 `fw sdk audit`；SDK export 忽略單純的 CALLABLE_VALIDATED 資料庫旗標，不宣稱實機可執行。
- 新增 synthetic contract fixture 以及證據完整性、runtime 欄位拒絕、idempotence、rollback 測試。

- Phase 3.3：JNI semantic graph 以精確 DEX path 和 evidence ID 配對，修正 JNI registration module ID 誤作 binary ID 的風險。
- DEX parser 提供 bounded string/type/proto/method/class-def table 解析；class definition 和 method reference 分開記錄，不推定方法實作。
- DEX `research_observation` 採交易回滾，新增跨 DEX、防錯誤索引、重跑與部分匯入失敗的合成回歸測試。

- Phase 3.2：schema v7 保留 legacy DB identity 與 FK，移除衝突的 module dependency、OSAL queue、JNI bridge 唯一性約束，並補上 v6 upgrade tests。
- JNI bridge identity 綁定 native binary SHA、DEX path 與 address space，不再依相同虛擬位址覆寫其他韌體的對應。
- 增加 evidence-bound DEX string/candidate persistence、`fw analyze dex` 與 `fw query dex` 以及 CLI 回歸測試。
- Semantic graph stale node/edge cleanup、ELF `$ORIGIN` normalization、Ghidra completion identity validation 與回歸測試。


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
