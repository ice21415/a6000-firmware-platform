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
- `fwplatform/migration_v4.py`、`fwplatform/migration_v6.py`：Ghidra provenance、函式 body range、研究證據 adapter schema。
- `fwplatform/ghidra_importer.py`：JSONL validation、CFG/XREF import、failure checkpoint。
- `fwplatform/linkage.py`：SONAME、DT_NEEDED、loader search path、unique import/export graph 和 unresolved edges。
- `fwplatform/semantic_graph.py`：typed node/edge materialization、cross-module traversal、JSON/GraphML export。
- `fwplatform/osal.py`、`fwplatform/jni.py`：evidence-bound OSAL/JNI fixture import。
- `fwplatform/evidence_ingestion.py`：allowlisted、可重跑的 SyncAndroid/Camera historical evidence adapters；來源 hash、locator 和原始 status 會保留。
- `fwplatform/phase3_1_reports.py`：從 SQLite 產生 Phase 3.1 稽核與 coverage 報告。
- `analyzers/dex_analyzer.py`：對 DEX header/string/type/proto/method/class_def tables 做邊界檢查與保守解析；method_id 僅是引用。
- `fwplatform/dex_index.py`：將 DEX 表格的靜態結構觀測存入 SQLite，確保 SHA-256 與解析位元組一致，異常時 rollback。
- `fwplatform/cli.py`：inventory、分析、protocol/state/API/semantic graph 查詢和報告命令。
- `database/migrations/005_semantic_graph.sql`、`006_ranges_evidence.sql`、`007_identity_repairs.sql`、`fwplatform/migration_v5.py`、`migration_v6.py`、`migration_v7.py`：Phase 3.1–3.3 schema。
- `fwplatform/phase2_reports.py`：從 SQLite 產生 audit files。

## Ghidra pipeline

1. Wrapper 計算 input SHA-256、讀取 Ghidra version、清除舊輸出。
2. `analyzeHeadless` 使用 Auto Analysis 載入單一 ELF。
3. `AnalyzeBinary.java` 輸出 metadata、functions、ARM/Thumb instructions、basic blocks、
   CFG edges、callsites、XREF 和 symbols；輸出 JSONL 有 complete marker，不追加舊 run。
4. Importer 驗證 binary hash、program identity、record count 和 complete marker，使用
   transaction/savepoint 寫入 `analysis_run`、`evidence`、CFG tables；失敗會 rollback。
5. 同一輸入與 analyzer version 可增量重跑；錯誤會保留 FAILED checkpoint。

## 已驗證成果

本地 Phase 2 audit 已驗證一個 ARM/Thumb ELF 的實際 headless execution、CFG、XREF、
call graph query 和 repeated import。公開版只保留 sanitized report，不包含 raw export。

## 未解決問題

Phase 3.1 已可在私有 DB 副本匯入 SyncAndroid/ModelCamera 的選定研究檔案；receiver
function identity、Java body 的執行期含義、message completion、camera ready/first-shot
條件仍是 UNKNOWN 或 CANDIDATE。不要從 function name、同值 numeric ID 或 symbol index
推導完整功能。

## CLI

```text
fw manifest build --root <private-workspace>
fw coverage --json
fw analyze elf --root <private-workspace> --limit 1
fw analyze ghidra --root <private-workspace> --binary <elf> --jsonl <output>
fw analyze linkage --root <private-workspace>
fw analyze osal --fixture <osal.json>
fw analyze jni --fixture <jni.json>
fw analyze dex --path <local.dex>
fw query dex <name-or-descriptor>
fw analyze semantic
fw callers <function>
fw callees <function>
fw callsite <address>
fw xrefs <binary>:<address>
fw trace <function> --depth 3
fw trace <function> --cross-module --depth 3
fw protocol queue <queue-id>
fw state <state-machine>
fw query api <name>
fw evidence <relation-or-id> --json
fw unresolved --json
fw coverage --domain camera_core --json
fw sdk coverage --json
fw analyze evidence --root <private-research-root> --profile targeted --json
fw graph export --format graphml --output <graphml>
```

## 下一步

優先擴充真實證據 adapter 的 locator/ABI 驗證、受控 multi-ELF Ghidra checkpoint、事件
與狀態機關係及 SDK evidence schema；任何實機研究都必須另行保留、不得自動同步到公開目錄。
# Primary helper continuation (2026-10-09)

Read `reports/CORE_PRIMARY_HELPER_AUDIT.md` before repeating the handoff's
missing-byte conclusion. Real private SHA-pinned libObj.so was read with Capstone.
`fwplatform/elf_plt.py` resolves interworking PLT relocations;
`fwplatform/primary_contracts.py` validates the additive descriptive SDK fixture.
Targeted Ghidra instructions agree after image-base mapping, but tail-call
decompilation is rejected and process exit 1 remains an environment limitation.
No runtime/callable interface was validated. Next callee: ELF VMA 0x7edaca.
