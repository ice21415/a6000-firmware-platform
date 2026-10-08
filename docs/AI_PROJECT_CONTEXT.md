# AI Project Context

## 專案邊界

這是 Sony ILCE-6000 firmware 3.21 的離線逆向研究平台，不是 Sony 官方專案，也不
是 boot optimization 或 raw transfer patch。AI 工具只能修改公開 source、schema、
synthetic tests 和文件；不要要求或提交私人 firmware。

## 程式碼入口

- `fwplatform/db.py`：SQLite connection、migration、evidence upsert。
- `fwplatform/inventory.py`：格式辨識、SHA-256、manifest checkpoint。
- `fwplatform/importer.py`：既有研究 JSON 的保守匯入。
- `fwplatform/migration_v3.py`：identity、evidence merge、partition/module repair。
- `fwplatform/migration_v4.py`：Ghidra provenance 欄位。
- `fwplatform/ghidra_importer.py`：JSONL validation、CFG/XREF import、failure checkpoint。
- `fwplatform/linkage.py`：DT_NEEDED、unique import/export graph。
- `fwplatform/cli.py`：inventory、分析、查詢和報告命令。
- `fwplatform/phase2_reports.py`：從 SQLite 產生 audit files。

## Ghidra pipeline

1. Wrapper 計算 input SHA-256、讀取 Ghidra version、清除舊輸出。
2. `analyzeHeadless` 使用 Auto Analysis 載入單一 ELF。
3. `AnalyzeBinary.java` 輸出 metadata、functions、ARM/Thumb instructions、basic blocks、
   callsites、XREF 和 symbols；輸出 JSONL 不追加舊 run。
4. Importer 驗證 hash、program identity 和 JSONL metadata，寫入 `analysis_run`、
   `evidence` 和 CFG tables。
5. 同一輸入與 analyzer version 可增量重跑；錯誤會保留 FAILED checkpoint。

## 已驗證成果

本地 Phase 2 audit 已驗證一個 ARM/Thumb ELF 的實際 headless execution、CFG、XREF、
call graph query 和 repeated import。公開版只保留 sanitized report，不包含 raw export。

## 未解決問題

完整 JNI/Java、OSAL queue、message namespace、indirect-call resolution、ioctl layout、
runtime validation 和任何 device deployment 都是 UNKNOWN 或 PARTIAL。不要從 function
name、同值 numeric ID 或 symbol index 推導完整功能。

## CLI

```text
fw manifest build --root <private-workspace>
fw coverage --json
fw analyze elf --root <private-workspace> --limit 1
fw analyze ghidra --root <private-workspace> --binary <elf> --jsonl <output>
fw analyze linkage --root <private-workspace>
fw callers <function>
fw callees <function>
fw callsite <address>
fw xrefs <binary>:<address>
fw trace <function> --depth 3
```

## 下一步

優先新增 synthetic fixtures 和 schema tests，接著處理 Java/JNI、OSAL、event/message
namespace 的 evidence model；任何實機研究都必須另行保留、不得自動同步到公開目錄。
