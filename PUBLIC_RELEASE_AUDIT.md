# Public Release Audit

狀態：**公開前稽核完成；GitHub 發布已完成**  
稽核日期：2026-10-08  
預計 Repository：`https://github.com/ice21415/a6000-firmware-platform`

這份稽核針對 `a6000-firmware-platform-public` 這個獨立 allowlist 發布目錄。
原始研究工作目錄、原廠韌體和私人資料沒有被複製到這個目錄。檔案先完成本機
稽核，再以乾淨歷史建立 GitHub Repository；發布後核對結果見下方。

## 準備公開的檔案

發布目錄目前有 **61 個追蹤檔案，約 196 KB**。`git ls-files` 的實際分組如下：

| 分組 | 檔案數 | 內容 |
|---|---:|---|
| root | 10 | README、授權狀態、貢獻與安全文件、依賴宣告 |
| `.github` | 5 | CI、Issue templates、PR template |
| `fwplatform` | 14 | SQLite、inventory、importer、linkage、CLI、report 程式 |
| `analyzers` | 3 | ELF analyzer 與 runner |
| `database/migrations` | 4 | v1–v4 schema migration；沒有 populated database |
| `ghidra-scripts` | 1 | Headless `AnalyzeBinary.java` |
| `tools` | 2 | CLI entry 與 Ghidra wrapper |
| `tests` | 3 | 合成/離線測試 |
| `docs` | 6 | 架構、資料模型、重現性、研究狀態、AI 導覽、實作狀態 |
| `domains`、`protocols`、`sdk` | 4 | 描述性 catalog、協定與 SDK 摘要 |
| `modding-framework` | 3 | 離線 mock 與 manifest schema |
| `reports` | 6 | 五份已清理的 Phase 2 摘要及報告索引 |

`reports/` 中所有原始研究路徑已替換成 `<private-firmware-path>` 等標記；沒有放入
原始 JSONL、manifest、SQLite 或 Ghidra project。

## 明確排除的內容

- Sony 官方 firmware/update package、解包映像、NAND/WBI/bootloader/kernel 備份。
- 完整反組譯、反編譯、原始 Ghidra JSONL、記憶體快照與 runtime dump。
- 私人 `firmware.db`、database backups、相機連線資料、序號、網路資料、密碼、SSH key、token。
- 未確認有權重新散布的第三方原始碼、二進位檔與 Ghidra 安裝檔。

追蹤路徑檢查結果：禁止副檔名/資料夾 **0**；發布目錄沒有 firmware binary 或私人資料庫。

## 安全掃描

以下檢查在發布目錄執行，結果均以實際輸出為依據：

| 檢查 | 結果 |
|---|---|
| tracked forbidden paths/extensions | `FORBIDDEN_TRACKED_PATHS=0` |
| private key/token/password regex | `SECRET_PATTERN_HITS=0` |
| absolute user paths / SSH public key patterns | `ABSOLUTE_PATH_OR_KEY_HITS=0` |
| staging `git ls-files` | 61 paths，沒有禁止路徑 |

這些是本機文字與檔名掃描，不是第三方商業 DLP 或法律意見；大型 binary 和未提交的
上層工作目錄仍須由維護者在發布前再次人工確認。

## 授權檢查

維護者已確認使用 MIT；`LICENSE` 現在包含完整 MIT License 文字。專案自有程式碼的
作者/權利鏈仍應由維護者保留相關紀錄。`requirements.txt` 只有
`pyelftools>=0.31,<1`；本機安裝套件 metadata 為 pyelftools 0.33、`Public domain`，
但這不取代完整第三方授權稽核。Ghidra 是本機前置工具，不隨 repository 散布。

## 測試與可重現性

### 已通過

- `python -m compileall -q fwplatform analyzers tests`：通過。
- `python -m unittest discover -s tests -v`：**8 tests，8 OK**。
- 空 SQLite 的 CLI smoke：`python -m fwplatform.cli --db database/ci-test.sqlite coverage --json`：通過，空 inventory 正確回報 `UNKNOWN`/`null`，沒有捏造覆蓋率。
- 從本機 staging 建立 clean clone 後重跑 compileall、8 個 unittest 及空資料庫 CLI：均通過。
- README 的 Windows 安裝命令、離線測試命令和 Ghidra wrapper 用法已對照實際檔案位置檢查。

### 不在公開 CI 中執行

需要私人 firmware/ELF 和本機 Ghidra 的完整 inventory 或 Headless 分析不會成為公開 CI
必要條件。CI 只使用合成測試；不會上傳 Sony firmware，也不會產生 firmware artifact。

## 已有本機研究資料的核對摘要

以下數字來自未納入發布目錄的本機 `database/firmware.db`，用於核對報告內容；資料庫
本身沒有被複製：schema v4、`PRAGMA quick_check=ok`、`foreign_key_check` 0 rows。

| 項目 | 實際數量 |
|---|---:|
| binary | 37,838 |
| ELF symbol-indexed / Ghidra analyzed | 706 / 1 |
| function | 135,313 |
| basic_block / instruction / callsite | 353 / 2,363 / 400 |
| cross_reference | 1,497 |
| vtable | 560 |
| module_dependency | 2,084 |
| evidence / evidence_archive | 7,006 / 37,825 |
| lifecycle_callback | 846 |
| event_id / state_transition | 8 / 17 |

Headless smoke run 是一個 ARM/Thumb `libSyncAndroid.so`，Ghidra 12.1.3，JSONL 4,967
筆；資料庫匯入 353 basic blocks、2,363 instructions、400 callsites、928 Ghidra XREF
records。這些結果是靜態研究證據，不代表 runtime 或可安全部署的韌體 API。

## Git 工作樹與歷史

發布目錄由 allowlist 重新初始化 Git，沒有承接原始研究目錄的 history。初始本機提交
為 `fe6aa54 Prepare public release staging`；發布前 working tree clean。現在的
`origin` 指向預定公開 Repository，發布後 main 仍須保持 clean。

歷史檢查只涵蓋這個新 staging history；上層私人工作目錄的 history 不會被發布。

本機 `gh` 檢查：GitHub CLI 2.94.0，帳號 `ice21415` 已登入。

## 發布後核對

- Repository：<https://github.com/ice21415/a6000-firmware-platform>
- GitHub API：`private=false`、default branch `main`。
- 發布 commit：`1b701284482719e5e8a6527af131d83d74dadf69`。
- Tag：`v0.2.0-alpha` 指向上述 commit。
- GitHub page HEAD request：HTTP 200。
- 發布後未上傳任何原廠 firmware、私人 SQLite 或 runtime dump。

## 尚待人工確認的風險

1. 最終人工複核 `sdk/sdk-index.json`、`reports/*.md` 是否沒有不應公開的研究細節。
2. 確認 GitHub owner、repository visibility、tag 版本與發布說明。
3. GitHub Actions、Ghidra 版本與外部依賴的供應鏈政策仍需由維護者決定。

本稽核不宣稱任何未經實機驗證的韌體操作可安全使用。






