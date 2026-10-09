# Roadmap

## Phase 2（已完成基礎版）

- 完成 evidence identity、v3 integrity migration 和 v4 Ghidra provenance。
- 建立單一 ARM/Thumb ELF 的 Ghidra CFG/XREF pipeline。
- 建立 ELF DT_NEEDED 與唯一 symbol resolution linkage。
- 提供可追溯的 CLI 與 audit reports。

## Phase 3（目前分支：semantic-analysis）

- migration v5–v6 Semantic Graph、CFG edge、OSAL message、JNI bridge、body ranges 和 SDK evidence schema。
- 修正同名 ELF DT_NEEDED 解析和 Ghidra caller 歸屬，歧義保留 unresolved edge。
- 提供 OSAL/JNI fixture analyzer、DEX inventory、跨模組 trace、state/protocol/API 查詢和 GraphML export。
- 以 synthetic fixtures 驗證完整性、namespace 分離、idempotence 和 rollback。

尚未宣稱完整還原 Sony 的 OSAL/JNI 協定或 Camera runtime 行為；需要更多有來源的
fixture、Ghidra multi-ELF runs 和實機觀測才能提升 verification status。

## Phase 3.1（目前開發中）

- 使用 migration v6 保存 Ghidra 不連續 body range、normalized research observation 和 adapter checkpoint。
- 已在私有 DB 副本驗證 targeted SyncAndroid/ModelCamera evidence ingestion、OSAL queue/message、JNI registration lookup、state transitions 和 provenance gaps。
- Receiver canonical function、message completion、Java native implementation、camera ready/first-shot 和 runtime verification 保持 UNKNOWN/CANDIDATE。

## Phase 3.2（公開靜態索引／資料完整性）

- schema v7 移除阻礙多命名空間 queue 和多 ELF JNI 的舊 UNIQUE 限制，保留資料列 ID 與外鍵。
- JNI bridge identity 加入 DEX、native binary fingerprint、address space；缺少 binary identity 者以來源 evidence 區隔。
- v6→v7 合成資料升級測試涵蓋 dependency/callsite identity 與 SQLite integrity。
- 新增 `fw analyze dex --path` 和 `fw query dex`，只將 DEX 字串與候選索引保存為有來源的研究觀測。
- 真實韌體、多 ELF Ghidra trace、訊息收發語意及 camera runtime 行為仍需獨立證據與驗證。

## Phase 3.3（DEX 結構索引／JNI 關係精確性）

- DEX parser 驗證 string/type/proto/method/class_def 表格邊界，保留 class definition 與 method reference 的區別。
- 新的 type/class/method-ref 觀測資料以原始 DEX SHA-256 作為來源，匯入採用 SQLite savepoint。
- JNI semantic edges 僅在 class/name/signature、DEX path 與證據 ID 全部吻合時建立。
- JNI 註冊關係的 binary provenance 取自函式所屬 binary，而非 module row ID。
- 合成測試涵蓋跨 DEX 重名、錯誤來源、外鍵完整性、invalid table references、idempotency 與 rollback。
- 仍無 method body 還原、原廠韌體實驗或實機 validation。

## Phase 3.4（離線核心 SDK 契約與驗證）

- 新增 SDK 合約 JSON fixture 匯入，明確定義 Camera、Lens、Sensor、Media、UI、OSAL、Android、Networking 領域。
- 靜態驗證須唯一解析 ELF SHA-256 + function address，且 primary evidence locator 必須指向同一個 binary/function。
- 含歧義或不完整證據的介面保留為 CANDIDATE，禁止由 fixture 宣稱 VERIFIED_RUNTIME/CALLABLE_VALIDATED。
- `fw sdk import`、`fw sdk audit`、`fw sdk coverage`、`fw sdk build` 支援離線介面索引、缺口報告與每領域可稽核矩陣。
- 即使資料庫欄位標為 CALLABLE_VALIDATED，SDK export 仍不推論實機可呼叫性；所有必需 API 分母 UNKNOWN。
- 合成回歸測試涵蓋多來源證據、身份歧義、介面匯入回滾、重入和不實 runtime claim。

核心逆向 SDK 的功能實作與實際 Sony camera firmware API 還原是兩個不同目標；
在沒有獨立實機/韌體原始證據時，不宣稱 Camera/Lens/Sensor/Media/OSAL 的真實 ABI 或 runtime readiness。

## Phase 3.5（SDK ABI 證據、模擬協定與交易安全）

- SDK `VERIFIED_STATIC` 現在需 ELF SHA-256、函式位址，以及 ABI、parameter/return layout 的同源獨立證據吻合；僅有函式位置不足以證明簽章。
- `fw sdk mock --scenario` 提供不接觸實機的明確 mock transition table、namespace-aware step replay 和非零錯誤退出碼。
- OSAL 與 JNI fixture 匯入用 SQLite savepoint 回滾，失敗不留下部分 queue、message、Java method、bridge 或證據列。
- native 函式解析需 binary SHA-256，不以全域 name/address 推斷關係；合成測試涵蓋重名 ELF。
- 本階段的協定 mock 是測試替身，並非已完成 Sony camera runtime SDK；真實核心介面驗證仍需合法且可追溯的二進位與行為證據。

## Phase 3.6（核心 SDK 符號審核佇列）

- Ghidra JSONL 每筆 function 增加獨立的 entry locator、ELF SHA-256 與 binary provenance evidence，僅證實靜態函式位置，不將自動推測的 prototype 視為 ABI。
- 新增 `fw sdk discover`，預設搜尋唯一 ELF export 對應的非自動命名函式；支援 exact binary SHA、名稱、domain 搜尋提示與受控 internal/generated 擴展。
- 新增 `fw sdk draft` 產生可匯入但全為 CANDIDATE 的人工審核清單；任何 domain/ABI/語意都不會由函式名稱直接轉正。
- 覆蓋合成多 binary 同名函式、無證據關係、函式定位、上限、重跑與草稿匯入回歸測試。
- 完整核心 API 仍需合法取得的多 ELF 程式碼證據與獨立 ABI、JNI、OSAL 及狀態機確認；symbol inventory 無法替代語意逆向。

## Phase 3.7（受控多 ELF Ghidra 覆蓋擴展）

- 新增 `fw analyze ghidra-batch`：預設僅規劃、選擇尚未成功匯入的 ELF，且以 manifest SHA-256、受限路徑與固定批量排程。
- 明確 `--execute` 才會使用本機 Ghidra PowerShell wrapper；獨立限制輸出與 project 目錄必須位於 firmware root 外。
- 每個檔案二次 SHA 驗證、清除上次輸出、完整 marker／原始 SHA 驗證；單一 Ghidra 作業失敗不阻斷其他靜態分析。
- 新增 synthetic binary、headless wrapper mock 和 resume/skip/failure regression tests；CI 不含真實 Sony 韌體，也不宣稱已掃描所有 ELF。
- 尚需在授權的本機研究副本中執行分析，並逐步驗證各 domain 的 ABI 與 API 語意。

## Phase 3.8（核心 SDK 函式身分與匯出位址精確性）

- SDK discover 必須符合同一 ELF 的 export 名稱和數值 VMA，避免同名不同位址被誤列成匯出 API。
- SDK import 將十六進位／十進位地址正規化並要求唯一函式入口；audit 會揭露既有合約中的數值地址歧義。
- 重複 ELF SHA-256 不是唯一的 binary 身分；候選搜尋保留歧義，SDK draft 去除重複合約並保留來源路徑。
- SDK fixture 自己不能成為獨立 ABI 驗證證據；舊資料中自我宣稱的 VERIFIED_STATIC 將被審核揭露、降級。
- 合成測試驗證誤配、地址別名、歧義、重複 hash 與候選匯入；不代表完成實機 API 語意或 ABI 逆向。

## Phase 3.9（跨 ELF 匯入符號的保守解析）

- `elf_linkage` 不再把與 `DT_NEEDED` 無關的全域同名匯出當成可證實的呼叫目標；未知依賴、版本不符和無效 import 位址保留 `unresolved_edge`。
- 同一 ELF 中相同符號名稱對應多個不同 VMA 時，保留 `ambiguous-export-entry`，不隨意選擇最後一筆。
- 已解析依賴中唯一匹配的 import/export 只建立 `CANDIDATE` cross reference；缺少 PLT/GOT、ELF loader interposition 與呼叫現場證據，不宣稱 runtime 實際綁定。
- Linkage checkpoint 加入 provider catalog fingerprint；export 或 binary metadata 變化會重新掃描並撤除過時的自動邊。單一 ELF 分析失敗以 SQLite savepoint 回滾。
- `sdk discover` 與 `sdk draft` 顯示由 `elf_dynamic` 證據支持的 incoming import 候選計數及 evidence ID，協助排列人工 ABI 審核優先順序，但不推論 runtime 綁定。
- 合成回歸測試涵蓋依賴範圍、匯出歧義、版本相容、缺失位址、catalog 更新與失敗交易。
- 此階段僅擴充跨模組靜態研究證據，不代表完成 Sony 核心 API 的實際 ABI、語意或實機呼叫驗證。

## 下一階段

- 擴充 Java/DEX/JNI、OSAL queue、message/event namespace 的真實 evidence fixture。
- 增加 indirect call candidate、jump table、vtable slot 和 unresolved edge 的合成 fixture。
- 強化跨 binary address-space、PLT/GOT、relocation 和 ABI 解析。
- 為描述性 SDK 建立 schema 驗證、mock protocol tests 和版本相容性檢查。

## 長期目標

- 完成 Camera、UI、Lens、Sensor、Media、Android、Networking 等 domain index。
- 建立可回復、可驗證的 modding framework adapter；任何實機 adapter 都必須另行審查。
- 支援公開資料來源的可重現分析，不把私人 firmware 納入 CI 或 release。
