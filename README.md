# A6000 Firmware Research Platform

這是一個獨立的 Sony ILCE-6000（A6000）韌體逆向工程研究平台，目標是把
inventory、靜態 ELF 分析、Ghidra CFG、跨模組 linkage、證據管理和描述性 SDK
集中到可重複執行的本機資料庫中。

本公開版本支援的研究樣本是官方 firmware 3.21。Repository 只包含自行撰寫的
工具、schema、Ghidra 腳本、合成測試與研究摘要；不包含 Sony firmware、解包映像、
NAND/WBI/bootloader 備份、私人 SQLite、原始反組譯 JSONL 或 runtime dump。

目前已完成的公開功能包括：

- SQLite migration v1–v4，以及 evidence identity、duplicate archive 和完整性檢查。
- 遞迴 inventory 與 ELF/DEX/ODEX/APK/script/resource/unknown classifier。
- Python ELF symbol/import/export/relocation index。
- Ghidra Headless Auto Analysis JSONL export；支援 ARM/Thumb、function、basic block、
  instruction、callsite、XREF、symbol、prototype 和 address-space provenance。
- Ghidra JSONL 增量匯入與 `analysis_run` checkpoint。
- ELF `DT_NEEDED` 和唯一 export/import resolution linkage。
- `callers`、`callees`、`callsite`、`xrefs`、`trace --depth` 等 CLI 查詢。
- 描述性 SDK 和不寫入硬體的 modding-framework mock。

尚未完成的部分包括 runtime 驗證、完整 JNI/Java registration、OSAL queue producer/
consumer、ioctl 參數結構、完整 indirect-call resolution，以及任何可部署到相機的
modding adapter。Ghidra 名稱不等於已確認的功能語意。

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
```

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

## 參與開發

請先閱讀 [CONTRIBUTING.md](CONTRIBUTING.md)、[SECURITY.md](SECURITY.md) 和
[docs/AI_PROJECT_CONTEXT.md](docs/AI_PROJECT_CONTEXT.md)。新的分析結果應附帶來源
SHA-256、address space、證據狀態、可重現命令和失敗情況；不要提交私人 firmware
或由原始 firmware 直接產生的大型輸出。
