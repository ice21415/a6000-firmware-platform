# 平台架構

```text
private firmware / public synthetic fixtures
              |
       inventory + SHA-256
              |
       SQLite migrations v1-v4
              |
  evidence / binary / module identity
              |
  Python ELF index ---- Ghidra Headless JSONL
              |                    |
              +---- CFG / XREF / callsite
              |
       ELF linkage graph
              |
       CLI + audit reports + descriptive SDK
```

`fwplatform/db.py` 是 SQLite 入口；migration data repair 位於
`fwplatform/migration_v3.py` 和 `fwplatform/migration_v4.py`。Inventory 只保存檔案
metadata 和 hash，不把 input firmware 複製到 release。

`analyzers/` 處理 Python ELF symbol/linkage index。`ghidra-scripts/AnalyzeBinary.java`
和 `tools/run-ghidra-headless.ps1` 產生 deterministic JSONL，
`fwplatform/ghidra_importer.py` 將 function、block、instruction、callsite 和 XREF
寫入 SQLite。Ghidra 名稱與語意保持分離。

`fwplatform/linkage.py` 解析 DT_NEEDED 和唯一 export/import match。模組依賴、事件、
message、JNI、state machine 和 domain 關係都必須保留 evidence status；無法確認時
使用 UNKNOWN、CANDIDATE 或 unresolved edge。

`modding-framework/` 目前只包含 firmware-hash、dependency、conflict、transaction 和
rollback 的 offline mock，沒有 device writer。
