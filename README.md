# A6000 Firmware Research Platform

最新核心 helper 原始 ELF 驗證：[研究稽核](reports/CORE_PRIMARY_HELPER_AUDIT.md)。
可用 `python -m fwplatform.cli sdk primary-contracts --json` 查詢描述性契約；
這些介面尚未通過實機驗證，不能當作可直接呼叫的相機 SDK。

這是一個獨立的 Sony ILCE-6000（A6000）韌體逆向工程研究平台，目標是把
inventory、靜態 ELF 分析、Ghidra CFG、跨模組 linkage、證據管理和描述性 SDK
集中到可重複執行的本機資料庫中。

本公開版本支援的研究樣本是官方 firmware 3.21。Repository 只包含自行撰寫的
工具、schema、Ghidra 腳本、合成測試與研究摘要；不包含 Sony firmware、解包映像、
NAND/WBI/bootloader 備份、私人 SQLite、原始反組譯 JSONL 或 runtime dump。

目前已完成的公開功能包括：

- SQLite migration v1–v7，以及 evidence identity、duplicate archive、semantic graph 和完整性檢查。
- 遞迴 inventory 與 ELF/DEX/ODEX/APK/script/resource/unknown classifier。
- Python ELF symbol/import/export/relocation index。
- Ghidra Headless Auto Analysis JSONL export；支援 ARM/Thumb、function、basic block、
  instruction、callsite、XREF、symbol、prototype 和 address-space provenance。
- Ghidra JSONL 增量匯入與 `analysis_run` checkpoint。
- ELF `DT_NEEDED` 和唯一 export/import resolution linkage。
- Phase 3/3.2 semantic graph migrations v5–v7，保存 Binary、Module、Function、CFG、OSAL、JNI、Event、State、body ranges 和 SDK interface 關係。
- SONAME/DT_NEEDED 搜尋路徑解析；同名 ELF、symbol 和缺失 caller 會保留 unresolved edge，不任意配對。
- OSAL protocol fixture analyzer、JNI/Java fixture analyzer、DEX 字串/class inventory 和 GraphML/JSON graph export。
- 私有研究資料的 allowlisted evidence adapter：可將 SyncAndroid OSAL/JNI 線索與 ModelCamera selector transitions 匯入副本資料庫；每筆資料保留來源 SHA-256、locator、原始 confidence 和 unresolved 缺口。
- `callers`、`callees`、`callsite`、`xrefs`、`trace --depth` 等 CLI 查詢。
- 描述性 SDK 和不寫入硬體的 modding-framework mock。

Phase 3.9 亦強化跨 ELF 匯入符號解析：只在已解析的 `DT_NEEDED` 依賴內
尋找唯一且版本相符的匯出候選，結果仍是 `CANDIDATE`；對重複位址、
未知依賴或版本歧義保留 unresolved edge。SDK candidate discovery 會附上有
來源的 incoming import 候選數量，方便後續人工分析 ABI。

尚未完成的部分包括 runtime 驗證、完整 JNI/Java registration、OSAL queue producer/
consumer、ioctl 參數結構、完整 indirect-call resolution，以及任何可部署到相機的
modding adapter。Phase 3 analyzer 需要明確 fixture 或本機證據，不能由名稱或同值 ID
自動補出關係。Ghidra 名稱不等於已確認的功能語意。

## Windows 安裝

需要 Python 3.11 或更新版本。從 repository 根目錄執行：

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Ghidra 是可選工具，不是 CI 必要條件。請在本機安裝受信任的 Ghidra 版本，並把安裝
路徑傳給 wrapper；不要把 Ghidra 安裝檔或 firmware 放進 repository。

## Inventory、SQLite 和 CLI

SQLite database 預設放在 `database/firmware.db`，但這個檔案被 `.gitignore` 排除。
第一次使用時，migration 會自動建立 schema：

```powershell
python -m fwplatform.cli --db database/firmware.db manifest build --root C:\path\to\private-workspace
python -m fwplatform.cli --db database/firmware.db coverage --json
python -m fwplatform.cli --db database/firmware.db query module libObj --json
python -m fwplatform.cli --db database/firmware.db unknowns --json
# sanitized ParamSet tree-helper caller metadata (static evidence only)
python -m fwplatform.cli sdk parameter-set-callers --json
```

## Ghidra Headless

以下流程只對本機已有且有權分析的 ELF 執行，不會上傳輸入檔：

```powershell
.\tools\run-ghidra-headless.ps1 `
  -GhidraRoot C:\path\to\ghidra_12.1.3_PUBLIC `
  -ProjectDir database\ghidra-projects `
  -ProjectName phase2-sample `
  -Binary C:\path\to\private-workspace\libSample.so `
  -Output reports\ghidra-sample.jsonl

python -m fwplatform.cli --db database/firmware.db analyze ghidra `
  --root C:\path\to\private-workspace `
  --binary C:\path\to\private-workspace\libSample.so `
  --jsonl reports\ghidra-sample.jsonl --json
```

`AnalyzeBinary.java` 會截斷舊 JSONL，輸出包含輸入 SHA-256、Ghidra program identity、
原始 ELF VMA、Ghidra image base、address space、ARM/Thumb mode 與來源證據。錯誤會
記錄到 `analysis_run`，不會被當作成功。

跨模組查詢範例：

```powershell
python -m fwplatform.cli --db database/firmware.db callers open --json
python -m fwplatform.cli --db database/firmware.db callees _init --json
python -m fwplatform.cli --db database/firmware.db callsite 0x11250 --json
python -m fwplatform.cli --db database/firmware.db xrefs libSample.so:0x11250 --json
python -m fwplatform.cli --db database/firmware.db trace open --depth 3 --json
python -m fwplatform.cli --db database/firmware.db trace SyncAndroid_act --cross-module --json
python -m fwplatform.cli --db database/firmware.db protocol queue 0x01554466 --json
python -m fwplatform.cli --db database/firmware.db state ModelCamera --json
python -m fwplatform.cli --db database/firmware.db query api Camera --json
python -m fwplatform.cli --db database/firmware.db analyze semantic --json
python -m fwplatform.cli --db database/firmware.db graph export --format graphml --output reports/semantic.graphml --json
```

OSAL 和 JNI 關係使用帶有明確 status、source 和 binary identity 的離線 fixture 匯入：

```powershell
python -m fwplatform.cli --db database/firmware.db analyze osal --fixture C:\path\osal.json --json
python -m fwplatform.cli --db database/firmware.db analyze jni --fixture C:\path\jni.json --json
python -m fwplatform.cli --db database/firmware.db reports --phase3 --json
```

## Phase 3.6：核心 API 候選發現與受控多 ELF 分析

新指令只從現有資料庫提供來源可追溯的 API 候選，並明確保留未知 ABI、
參數與相機 Runtime 語意。預設僅查詢非 Ghidra 自動命名的 ELF 匯出符號：

```powershell
python -m fwplatform.cli --db C:\private\firmware-copy.db sdk discover --domain Camera --limit 100 --json
python -m fwplatform.cli --db C:\private\firmware-copy.db sdk draft --name Lens --output C:\private\lens-review.json --json
```

Ghidra 受控批次的**預設為只產生計畫，不執行**；僅在本機合法取得 ELF
與 Ghidra 都準備好時，使用 `--execute` 明確啟動：

```powershell
python -m fwplatform.cli --db C:\private\firmware-copy.db analyze ghidra-batch --root C:\private\firmware --limit 5 --json
python -m fwplatform.cli --db C:\private\firmware-copy.db analyze ghidra-batch --root C:\private\firmware --limit 2 --execute --ghidra-root C:\tools\ghidra --project-dir C:\private\ghidra-projects --output-dir C:\private\ghidra-jsonl --json
```

每批有數量與逾時限制、ELF SHA-256 驗證及完整 JSONL 匯入檢查，
已完成且未改變的 ELF 預設跳過；output/project 目錄必須位於 firmware root
之外。此功能完全離線，不會寫入相機，也不代表完成整個 firmware 的 ABI、
OSAL/JNI 或相機控制協定還原。

核心 ParamList 的跨 ELF 證據可用 profile 指令重跑。它只保存精確
`.dynsym` import、`R_ARM_JUMP_SLOT`、PLT/GOT 和私有 Ghidra 的 metadata；
不會公開韌體 bytes，也不把 loader binding、C++ ownership 或 ABI 安全性
當成已確認：

```powershell
python -m fwplatform.cli sdk parameter-cross-elf-set --root C:\private\firmware-root --provider-elf C:\private\libObj.so --provider-sha256 8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a --json
```

公開的去識別化結果在
[`sdk/paramlist_cross_elf_3_21.json`](sdk/paramlist_cross_elf_3_21.json)，
其中 `runtime_verified` 和 `callable` 維持 `false`。

## Phase 3.10：Camera、Lens、Sensor 核心 API 靜態調查

`sdk investigate` 在本地證據資料庫中將 ELF 函式候選與**直接 function ID**
綁定的 caller/callee、Ghidra CFG/body range、OSAL producer/consumer、JNI native
bridge、lifecycle callback 交叉索引；Camera state machine 只提供**名稱搜尋脈絡**，
不會因為同名或同位址而宣稱某函式觸發了某狀態轉移：

```powershell
python -m fwplatform.cli --db C:\\private\\firmware-copy.db sdk investigate --domain Camera --limit 25 --json
python -m fwplatform.cli --db C:\\private\\firmware-copy.db sdk investigate --domain Lens --include-internal --limit 50 --json
python -m fwplatform.cli --db C:\\private\\firmware-copy.db sdk investigate --domain Sensor --json
python -m fwplatform.cli --db C:\\private\\firmware-copy.db sdk inspect --function-id 12345 --json
```

輸出列出每條關係的 source evidence ID、狀態、截斷旗標，以及 ABI、函式 body、
呼叫關係、OSAL/JNI 與 runtime 尚需的驗證。這是純唯讀調查，不載入相機 ELF，
不生成可呼叫 SDK、不把符號名稱推測升級成 Camera/Lens/Sensor 真實 API 語意。

## 測試和報告

CI 只使用合成資料：

```powershell
$env:PYTHONDONTWRITEBYTECODE = '1'
python -m unittest discover -s tests -v
python -m compileall -q fwplatform analyzers tests
```

本地資料庫報告可用：

```powershell
python -m fwplatform.cli --db database/firmware.db reports --phase2 --json
```

公開 release 中的 `reports/` 只保存清理後摘要，不保存 private database、manifest 或
raw Ghidra export。

## 安全與研究限制

這個專案不提供 NAND、WBI、loader、boot selector、開機設定或實機記憶體寫入功能。
不要在 issue、pull request、CI artifact 或 log 上傳 firmware binary、私人備份、序號、
token、SSH key 或完整反編譯輸出。任何未經實機驗證的介面只能作為描述性研究資料，
不可視為安全可呼叫 API。

私有證據匯入（不會將檔案複製到 repository）可使用：

```powershell
python -m fwplatform.cli --db C:\path\private-copy.db analyze evidence --root C:\path\private-research --profile targeted --json
python -m fwplatform.cli --db C:\path\private-copy.db protocol queue 0x01554466 --json
python -m fwplatform.cli --db C:\path\private-copy.db evidence SyncAndroid --json
python -m fwplatform.cli --db C:\path\private-copy.db reports --phase3-1 --json
```

## Phase 3.2：schema v7 與 DEX 靜態索引

Schema v7 修復舊版 `module_dependency`、`message_queue`、`jni_bridge` 的
legacy UNIQUE 限制，保留原有 ID、外鍵和索引；callsite identity 會依可驗證的
caller/address 資訊轉換，缺乏足夠資訊者維持 legacy identity。
請先備份私有 SQLite 資料庫並在副本中執行 migration，確認
`PRAGMA quick_check` 和 `PRAGMA foreign_key_check`，不要直接覆寫研究原始資料。

可以從合法取得的本機 DEX 檔案建立可查詢的字串索引：

```powershell
python -m fwplatform.cli --db database/firmware.db analyze dex --path C:\\path\\to\\classes.dex --json
python -m fwplatform.cli --db database/firmware.db query dex SyncAndroid --json
```

`dex_string` 僅表示字串表中的靜態字串；
`dex_descriptor_candidate` 和 `dex_signature_candidate` 仍為 CANDIDATE，
不代表 Java class/method 或 JNI bridge 已獲證實。此流程不會對相機寫入資料。

## Phase 3.3：DEX 結構化證據與 JNI 交叉驗證

`fw analyze dex` 現在會同時解析 DEX `type_ids`、`class_defs`、`proto_ids`
與 `method_ids`，並將結果記錄成可查詢的 `research_observation`：
`dex_type_id`、`dex_class_definition`、`dex_method_reference`。輸入的表格
邊界、型別索引及原型參照都會檢查，匯入中途失敗會回滾 SQLite 寫入。
例如：

```powershell
python -m fwplatform.cli --db database/firmware.db analyze dex --path C:\\path\\to\\classes.dex --json
python -m fwplatform.cli --db database/firmware.db query dex "Lcom/example/C;" --json
```

**證據邊界**：DEX `class_def` 證明此 DEX 含有一個 class definition；
`method_id` 只證明存在方法**引用**，不能證明方法有程式碼或 JNI
實作。JNI 語意圖譜只會在 method class/name/signature、DEX 路徑和
來源 evidence ID 同時符合時，建立 Java method 對應邊。解析字串時使用
UTF-8 replacement 作為保守索引，尚未實作完整的 DEX MUTF-8 語意。

## Phase 3.4：核心 SDK 描述性契約

已增加 `fw sdk import --fixture <file>`、`fw sdk audit`、`fw sdk coverage` 和
`fw sdk build` 工作流程，對 Camera、Lens、Sensor、Media、UI、OSAL、Android、
Networking 類別提供可稽核的 SDK contract inventory。

```powershell
python -m fwplatform.cli --db database/private-copy.sqlite sdk import --fixture sdk/contracts.example.json --json
python -m fwplatform.cli --db database/private-copy.sqlite sdk audit --json
python -m fwplatform.cli --db database/private-copy.sqlite sdk coverage --json
```

每筆宣稱 VERIFIED_STATIC 的 contract 都必須唯一對應 firmware ELF SHA-256 與
函式地址，且有獨立的來源 evidence 直接識別相同的 binary/function；無法驗證
時降為 CANDIDATE。離線 SDK export 不會由資料庫狀態欄位推論實機可呼叫性。
所需 SDK 核心 API 的總分母尚未建立，逆向完成度保持 UNKNOWN。
詳細規格請見 [sdk/README.md](sdk/README.md)。

### ParamList 查詢 helper 的 direct-call 索引

針對已授權的私有 `libObj.so`，可以用下列唯讀命令建立查詢 wrapper、
`ParamList::get` forwarder 及 payload getter 的 Thumb direct-call metadata：

```powershell
python -m fwplatform.cli sdk parameter-query-callers --elf C:\private\libObj.so --json
```

這個探針以 Capstone 驗證指令級 branch，只有當 callsite 落在一個明確 ELF
symbol range 內才回報 caller；其餘保持 `UNRESOLVED`，不使用最近函式推測。
結果只保存 ELF VMA、SHA-256、地址空間和可信度，不包含 firmware bytes，
也不代表 C++ ownership、runtime binding 或安全可呼叫性。摘要契約在
[`sdk/param_query_callers_3_21.json`](sdk/param_query_callers_3_21.json)，
核心契約以 `query_callsite_index` 連結它；runtime/callable 仍為 `false`。

### ParamList clear virtual dispatch evidence

The latest private primary-ELF checkpoint adds
`fwplatform/paramlist_virtual_dispatch_probe.py` and the sanitized contract
[`sdk/paramlist_virtual_dispatch_3_21.json`](sdk/paramlist_virtual_dispatch_3_21.json).
The read-only command is:

```powershell
python -m fwplatform.cli sdk paramlist-virtual-dispatch-audit --elf C:\private\libObj.so --json
```

It verifies the bounded clear-site `vptr + 0x08` call and exact destructor-slot
mapping for ten known ParamBase-family vtables from the SHA-pinned private ELF.
This is static evidence only; no runtime or callable API claim is made, and
the Ghidra cross-check is targeted `-noanalysis` metadata rather than complete
whole-program analysis.

### Camera EE-neutral primary evidence

The bounded Camera probe
[`fwplatform/camera_ee_neutral_probe.py`](fwplatform/camera_ee_neutral_probe.py)
checks the private SHA-pinned ELF at `0x443d14` and `0x4b1a20`. Its sanitized
contract is
[`sdk/camera_3_21_ee_neutral_3_21.json`](sdk/camera_3_21_ee_neutral_3_21.json),
and descriptive constants are in
[`sdk/camera_3_21_candidate.hpp`](sdk/camera_3_21_candidate.hpp). The sender's
unique PLT evidence identifies ObjMsg construction and
`MWF::ObjIf::IssueCommandAsync(void*, MWF::ObjMsg*)`; the command candidate
updates `this+0x2700`, writes `this+0x26fc = 1`, and passes the observed selector
values to later helpers. Receiver identity, completion semantics, event
namespace, runtime safety and callable status remain UNKNOWN/false.

Run it only against the authorized private ELF:

```powershell
python -m fwplatform.cli sdk camera-ee-neutral-audit --elf C:\private\libObj.so --json
```

The Ghidra `camera-ee-neutral` profile is a targeted `-noanalysis` metadata
cross-check and does not publish the raw project or export.

## 參與開發

請先閱讀 [CONTRIBUTING.md](CONTRIBUTING.md)、[SECURITY.md](SECURITY.md) 和
[docs/AI_PROJECT_CONTEXT.md](docs/AI_PROJECT_CONTEXT.md)。新的分析結果應附帶來源
SHA-256、address space、證據狀態、可重現命令和失敗情況；不要提交私人 firmware
或由原始 firmware 直接產生的大型輸出。
