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

## Phase 3.10（Camera／Lens／Sensor 核心 API 證據圖譜調查）

- 新增 `fw sdk investigate --domain Camera|Lens|Sensor|Media|UI|OSAL|Android|Networking`，依 ELF 匯出候選檢視具來源的直接 caller/callee、CFG、OSAL flow、JNI native 與 lifecycle 關係。
- 函式關係必須使用明確的 `function_id`，不把相同虛擬位址、符號文字、queue ID 或 state machine 名稱誤當成已證實的關係。
- 新增 `fw sdk inspect --function-id <db-id>`，可追蹤剝除名稱或 Ghidra 自動命名的確切函式，避免只依 Camera 等字串篩選遺漏內部核心候選。
- Camera state machine 列為脈絡資料，明確指出沒有 function-to-state、camera ready 或 first-shot-ready 的獨立證據。
- 輸出每個核心候選所需的 ABI、參數、呼叫、OSAL/JNI、執行語意之補證工作，支援私有 Ghidra／研究資料庫定向審查。
- 依舊僅為靜態分析工具：缺乏合法取得韌體與獨立 runtime 語意證據時不能宣稱 Sony 原廠 Camera／Lens／Sensor 的核心 API 已還原或能安全呼叫。

## Phase 3.11（Camera 靜態指令鏈與候選 SDK 合約）

- 在已連線研究工作區定位合法保存的 3.21 `libObj.so`、Lens、Media、OSAL 與其他 ELF，確認原先阻塞點不是缺少 ELF，而是缺少完整、可重複的 ABI 證據鏈。
- 根據既有 2026-10-07 的私有原始指令／vtable 核對，擴充 `sdk/camera_3_21_static_candidates.json` 至 14 個 Camera 入口候選，保留 SHA、ELF VMA、實際研究別名與來源檔案 basename。全部仍為 CANDIDATE／DESCRIPTIVE_ONLY，沒有虛構 ABI。
- 新增 `sdk/camera_3_21_static_callgraph.json`：九條有保存研究來源的 direct call/tail branch、六筆欄位觀測、四條 bounded normalized selector transition、一個無法唯一解析的間接指派。
- `--compare-db <private-copy.sqlite>` 以 SQLite read-only mode 交叉核對真正索引的 ELF SHA 唯一性、函式數值 VMA、明確 caller/callee ID；缺少／碰撞／不吻合一律不自動宣稱 ABI 已驗證。
- 新增唯讀 `fw sdk research` 與針對單一函式 `--focus` 的可稽核圖譜。驗證數值 VMA／指令目標一致、重複入口、偽造 ABI／runtime claim，以及證據檔名最小化；不把手工整理的報告當作公開獨立指令 byte 驗證。
- 從既有 IMDb phase-8 研究資料補記 `LensCommunicator_Init/Exit` 與 `infra_cameraProfile_init/exit` lifecycle 線索；descriptor offset 不得冒充 callback 函式 VMA。
- Camera 等核心的真正 ABI／Lens、Sensor、Media 硬體語意及可呼叫性仍需獨立反組譯、ABI 與裝置行為核對；完成度分母仍 UNKNOWN。

## Phase 3.12（獨立 ELF 指令核對）

- `fw sdk research --verify-elf <private-libObj.so>` 先以整檔 SHA-256 精確核對官方 3.21 ELF 身分，再透過 ELF32 little-endian ARM 執行段 VMA 檢查 Thumb-2 `BL`／`B.W` 分支 target 與 `LDRB.W`／`STRB.W` raw byte displacement。
- 從 ModelCamera 模型欄位的 **raw 指令 immediate** 分離由 register/dataflow 推得的 `+0x2680` object base；只能證明指令當下的直接運算元，不能由其推定整個 object root、calling convention 或硬體 ready。
- 不匹配的 ELF hash、分支 target、欄位 immediate 或多重 executable PT_LOAD mapping 均失敗或明確回報未通過；CI 使用合成 ARM ELF，從未出版／執行專有 Sony 原始韌體。
- 這是增加原始指令可重現核對的能力，尚未在連線 runtime 內直接執行私有 ELF verifier，因此不宣稱全部 Sony Camera ABI 已驗證。

## Phase 3.13（既存 REA/Ghidra 成功證據與跨 ELF selector 邊界）

- 經已連線研究工作區找回 `reverse-engineer-anything` 4.1.0／Ghidra 12.1.4 的實際 `viewUnified2.so` 反編譯紀錄；與先前失敗的 `libObj.so` 全檔 Ghidra timeout 明確分離。
- `setInitForRec` UI REA Ghidra VMA `0x1b2504` 對應 UI ELF `0x1a2504`（本 ELF 專用 `+0x10000`）。既存反編譯文本中有 20 處向 `model/CAMERA` 及 6 處向 `model/STILL_REC` 發送 `0x0f01` 的靜態程式位置，並非同次開機實際執行次數。
- 另核對 `libObj.so` 既存 raw ELF Capstone 位元組：`0x4cfe8a MOVW` 立即數為 `0x0f01`，`0x4cfe98 BL` 目標 `0x4cf7a8`。保留這是保存的 Camera 指令稽核，**不是**本輪完成的 Ghidra 全檔反編譯或新的整檔 SHA 驗證。
- 新增 `sdk/ui_camera_3_21_rea_bridge.json` 及 `fw sdk rea-bridge`，從私人保存的兩種原始分析產物唯讀重核 UI request／地址偏移／Thumb MOVW 與 BL，另有 synthetic 測試。跨 ELF 訊息轉換、事件隊列與接收映射未證實，所有 ABI／runtime callable 保留 UNKNOWN。
- 目前 ChatGPT session 的可列出 Skill 中沒有可即時執行的 REA/Ghidra 功能；本階段使用先前保存的成功 REA evidence 與已連線 Codex 工作區，並未重新啟動 live Ghidra session。

## Phase 3.14（UI→Camera 事件封裝層已定位，消費端仍未知）

- 新增 `sdk/camera_3_21_model_execute_envelope.json` 與 `fw sdk event-envelope`：用既有原始 ELF 的靜態組語報告，定位 `libObj.so` 中 `ViewBase::requestModelExecute` (`0x12106e`) 對 `IdGenerator::Get`、未知 `0x12d780` selector 轉換、`createRequestModelExecuteEvent` 與 `View::requestApplicationExecute` 的連續呼叫。
- 另定位同名 `AbstractUtilityManager::createRequestModelExecuteEvent` 實作入口候選 `0x7f0b0c`：建立事件 ID `0x11004003`、可選 `ParamList`、寫入 parameter keys `7`（model identifier）與 `8`（helper 轉換輸出）。這是有保存來源的 **event envelope 靜態線索**，不是完整 wire protocol／ABI。
- `fw sdk event-envelope --saved-disassembly ...` 逐個檢查組語文本中的 callsite、PLT 目標、寄存器來源與 Event 插入點；未附檔案時不得報為 opcode verified，並完全不碰 SQLite、實體相機或韌體執行。
- 仍需還原 `0x12d780` 與 `0x11004003` 的真實接收者、symbol relocation、app queue delivery、param extraction 與對應 `ModelCamera::ActionGpSetSetting`。**不能直接把事件 key 8 當成 `0x0f01`，也不能由相同符號名推定動態連結。**

## Phase 3.20（查參數的 register 角色與結果判斷已縮小）

- 針對 `0x42ac00` 找到跨 action 重複的呼叫慣例候選：`r0` 為 `0x42abcc` 包裝的堆疊內 payload view、`r1` 是數字參數 ID、`r2` 是 output pointer；`r3` 仍沒有可證的通用意義。
- `ActionExeAfRangeLimitDrive` 以 `0x3fe`／`0x3ff` 查詢，返回零時跳過 `Invalid ParamList`；`ActionObjectFocusPosDisplayEvent` 以 `0x1b8`／`0x1b9` 查詢，返回零時讀取堆疊 4-byte slot，再寫入 Camera `+0x200`、`+0x204`。
- `pvt_ActionSetInit` 的 `0x42abdc` 呼叫則以 `0x12000005` 為參數值、讀取輸出 slot，配合 `EasyMode ON` 比較：地址接近 `0x42ac00` 但**不能**推斷其為同一 C++ 函式或 ABI。
- 新增 `sdk/camera_3_21_param_lookup_abi.json`、`fwplatform/param_lookup_abi.py`、`sdk param-lookup`、合成測試；已核對 39 個保存的私有 ARM 組語文字位置，**不是重新掃原始 ELF 機器碼**。
- 接下來應先取得 `0x13200a`、`0x42abcc`、`0x42ac00`、`0x42abdc` 的原始 ELF 函式本體，查明完整 C++ 參數／回傳型別，不能由跨呼叫者 register 約束直接宣告安全可呼叫 API。

## Phase 3.19（還原 `0x13200a` Camera action payload 參數用途）

- `0x13200a` 雖無原始函式指令可讀，但保存的五個獨立 action 入口有**跨呼叫者資料流**：`0x4aea00`、`0x4bac78`、`0x4afc9c` 均從同一 getter 取得 `r0`，再以 `r1` 傳給共用 `0x42abcc` 包裝器。
- `ActionExeAfRangeLimitDrive=0x4bac78` 中，該包裝器產生的物件會送往 `0x42ac00` 查詢參數鍵 **`0x3fe`／`0x3ff`**，且兩處均有 `Invalid ParamList` 分支。這建立了「ParamList 相容解析用途」的**結構約束**，但尚不能推定 getter 的宣告返回型別就是 `ParamList*`。
- 另一個 action `0x4ae930` 把 getter 輸出交給 `0x44a284` 訊息建構；`pvt_ActionSetInit=0x4cf7a8` 也將傳入的 `r1` 交由相同 `0x42abcc` 包裝器。因此已由多個不同用途交叉確認 SetInit 第二引數為事件/參數 payload 類物件候選，非任意已知整數常數。
- 新增 `sdk/camera_3_21_action_payload_leads.json`、`fwplatform/action_payload_abi.py`、`fw sdk action-payload`、合成測試；36 處靜態保存組語位址核對必須全部對上。**未有新原始 ELF 指令或完整 ABI 驗證。**
- 最關鍵下一步：以原始 `libObj.so` 局部反組譯 `0x13200a`、`0x42abcc` 與 `0x42ac00`，確定 getter 來源、返回 C++ 型別、wrapper 轉換與 ParamList 生命週期；另外必須還原 `0x12d780` 與 UI→Camera 事件投遞。

## Phase 3.18（優先破解核心 API：具名 ABI 引數及 Camera action 內部呼叫）

- **ABI 具體推進**：`ViewBase::requestModelExecute` (`0x12106e`) 及 `viewManagerIf::requestModelExecute` (`0x1250c0`) 的 Itanium mangling 都給出顯式參數 `char const*, unsigned long, ParamList*`，但符號名不含 static 與 return type。由保存的 ARM 暫存器資料流判定前者成員式 `r0=this,r1=name,r2=selector,r3=ParamList*`，後者更像靜態式 `r0=name,r1=selector,r2=ParamList*`。
- **事件工廠 ABI 線索**：`AbstractUtilityManager::createRequestModelExecuteEvent` 的顯式參數 `int,unsigned long,ParamList*`；保存的 `operator new`→`Event` constructor→`r0` 返回資料流強烈支持返回建立的 `Event*`，但 C++ 宣告返回型別、owner/lifetime、動態連結仍未知。
- **實際 Camera 內部引數**：`ActionGpSetSetting` `0x4cfb9c` 從 `0x131fd2` 取 selector，對 `0x0f01` 成立時，於 `0x4cfe98` 帶 `r0` Camera this 候選、`r1` `0x13200a` 的返回值呼叫 `pvt_ActionSetInit=0x4cf7a8`。確認兩個暫存器來源和 callee 保存邏輯，但 `r1` 真正 C++ 型別仍 UNKNOWN。
- **跨 ELF 證據**：`viewUnified2.so` 在 `0x1a26e6` 發出 `model/CAMERA` selector `0x0f01` 的具名 callsite，暫存器配置符合前述成員函式形式；並非動態投遞鏈證明。
- 新增 `sdk/camera_3_21_request_abi_leads.json`、`fwplatform/request_abi.py`、`sdk request-abi` 及 synthetic ABI 回歸測試。這是「參數 ABI 候選」，**不是**可安全呼叫的 Sony Camera API；下一個真核心缺口是 `0x13200a` 輸出型別、`0x12d780` 內部指令、事件接收者和原始 ELF 驗證。

## Phase 3.17（ModelManager +0xa4 狀態閘門與共用 semaphore）

- 新核對 `libObj.so` 保存組語中的 `0x7eaa14`：讀取物件 `+0xa4`，將非零 word 正規化為 Boolean。上游 `0x7eeec8` 的 guard 未短路時又做 `EOR 1`，因此狀態零→queue gate 1、非零→gate 0；主事件迴圈在 gate 為零時才依保存的 `0x7ef188` 分支走向 `0x7eeefa`。不得把此欄位直接命名為 Camera READY。
- 將獨立的保存 `app-status-wait-chain.json` 中 `0x830451` semaphore 三條等待包裝器，`0x7f21e8→0x7f0aa0`、`0x7f2210→0x7f099c`、`0x7f2238→0x7f0aac`，明確標記為 **次級研究報告**，非今次重新驗證的 ELF opcode 或此特定 `0x11004003` 事件接收者。
- 五個 ModelManager 狀態 setter `0x7eb118` 呼叫點／狀態常數亦保留在次級報告；`0x7eaa68` 的 `0x40000/0x50000/0x70000` 鄰近比較不冒充同一個 C++ 入口。
- 新增 `fwplatform/app_sync_research.py`、`sdk/camera_3_21_app_status_sync.json`、`sdk app-sync` 和 synthetic 測試，可選獨立核對保存組語文字與次級 JSON。從已連線工作區核對 18/18 個指定指令文字位址；不修改裝置、韌體或 SQLite。
- 接下來要補的是原始二進位中 `0x7f21e8`、`0x7f2238` 及 `0x12d780` 的真正局部分析，尤其 `0x11004003` 事件的接收與 Camera dispatcher 完整鏈。

## Phase 3.16（Appframework 事件迴圈／投遞邊界）

- 從保存 `libObj.so` 指令找到 `application_thread_body=0x7eeee8`、queue guard `0x7eeec8`、dispatch `0x7eecac→0x7f21e8`、semaphore helper `0x7f2210→0x7f099c`。
- 兩個 loop 呼叫點 `0x7ef0d4`、`0x7ef16e`，以及 cleanup `0x7eecec` 均報告直呼 `0x7eecac`。
- 原始保存報告含 `app_event_pop`、`app_event_dispatch`、`app_event_cleanup` 重疊掃描範圍；改以六個具名入口分別檢查，不能把重複掃描行數當成多條獨立函式執行證據。
- 新增 `sdk/camera_3_21_application_event_loop.json`、`fwplatform/app_event_loop.py`、`fw sdk event-loop` 及合成測試，核對 26 個保存的 opcode-text 位置。沒有原始 ELF 位元組驗證、事件接收動態證據或 SQLite 寫入。
- **尚未完成：** 尚不能從事件建立端 `0x11004003` 證明消費者在此迴圈，未查明事件 key 7/8 到 `ModelCamera::ActionGpSetSetting` 的轉換路徑，完整 Camera ABI 仍未知。

## Phase 3.15（兩條 requestModelExecute 靜態入口交叉核對）

- 新增第二個 `viewManagerIf::requestModelExecute` `libObj.so` ELF VMA `0x1250c0` 的具名入口線索，與 `ViewBase::requestModelExecute=0x12106e` 比較；兩者的保存指令顯示同樣呼叫 `IdGenerator::Get@0xdffb8`、`0x12d780` selector helper 與 `createRequestModelExecuteEvent@0xdfbdc`。
- 兩條靜態路徑都將 model ID、helper output、ParamList 指標送往事件工廠的 r1/r2/r3，卻在最後以不同 target 投遞：`ViewBase` 經 imported `View::requestApplicationExecute@0xdb578`；`viewManagerIf` 走 `0x125084` 本機候選（其本體仍未掃到）。
- 新增 `sdk/camera_3_21_model_request_frontends.json`、`fw sdk request-frontends --saved-disassembly ...` 和 10 組合成測試，明確辨識兩種 frontend/receiver provenance，並核對保存指令的 33 個文字地址：連線的私有研究檔核對 **33/33 符合**。這是既存組語報告，不是本輪原始 ELF byte scan。
- 真正未解：`0x12d780` 指令本體、`0x125084` 實際投遞、`0x11004003` 消費端、Event 7/8 解碼、動態符號解析與 Camera 動作映射；API 數量／ABI 驗證不因此升級。

## Phase 3.15（另一個 request frontend ＋ 具 SHA 鎖定的本機局部 Thumb 研究）

- 從私人保存的原始 `libObj.so` 組語新增第二個入口：`viewManagerIf::requestModelExecute=0x1250c0`，呼叫相同 helper `0x12d780` 及相同事件工廠匯入 stub `0xdfbdc`；末端的 `0x125084` 仍屬語意未明的尾分支，不能冒充 Camera 消費端。
- `sdk event-envelope` 現在從同一份組語來源逐項檢查 2 個前端＋工廠共 50 處地址與寄存器／呼叫目標（16＋15＋19）；已透過連線工作區對原有保存文字做 50/50 直接核對，**不是重新驗證原始 ELF 機器碼或完成 50 個 API**。
- 新增 `fwplatform/private_thumb_research.py` 與 `fw sdk trace-selector --elf <private-libObj.so>`：強制 SHA-256、ELF32 ARM 唯一執行段映射與小範圍 Capstone Thumb CFG 工作量限制，可聚焦 `0x12d780`／`0x125084`，另外分開標示事件 `0x11004003` 的 raw word occurrences 與真正未查明的 consumer。
- 連線 workspace 讀取介面明確回覆 `BINARY_FILE`，沒有直接回傳 `libObj.so` 位元組；因此新的 Capstone local tracer **只經合成 ELF 單元測試**，沒有在此聊天中對私有 Sony ELF 執行。不可把 local tracer 的存在當成 helper 真正已還原。
- 下一步要由 private original ELF 窄範圍指令輸出確認 helper 轉換、外部符號的 dynamic relocation、`0x11004003` 事件的消費者與 UI→Camera 跨模組處理。ABI／return/error 與實機 callability 仍未驗證。

## 下一階段

- 擴充 Java/DEX/JNI、OSAL queue、message/event namespace 的真實 evidence fixture。
- 增加 indirect call candidate、jump table、vtable slot 和 unresolved edge 的合成 fixture。
- 強化跨 binary address-space、PLT/GOT、relocation 和 ABI 解析。
- 為描述性 SDK 建立 schema 驗證、mock protocol tests 和版本相容性檢查。

## 長期目標

- 完成 Camera、UI、Lens、Sensor、Media、Android、Networking 等 domain index。
- 建立可回復、可驗證的 modding framework adapter；任何實機 adapter 都必須另行審查。
- 支援公開資料來源的可重現分析，不把私人 firmware 納入 CI 或 release。
# Primary helper checkpoint — 2026-10-09

The two handoff target bodies have now been read from the authenticated private
ELF. See `reports/CORE_PRIMARY_HELPER_AUDIT.md`. Next review ParamList::get
at ELF VMA 0x7edaca, recover wrapper class identity, and repair targeted Ghidra
tail-call decompilation/logging. Runtime-safe SDK API count remains zero.
