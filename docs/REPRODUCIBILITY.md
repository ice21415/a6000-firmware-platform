# 可重現性

公開 CI 不需要 Sony firmware。使用合成資料可以執行：

```powershell
python -m unittest discover -s tests -v
python -m compileall -q fwplatform analyzers tests
```

建立空資料庫並驗證 migration：

```powershell
python -c "from pathlib import Path; from fwplatform.db import Database; d=Database(Path('database/test.sqlite')); print(d.migrate()); d.close()"
```

要分析本機 ELF，必須由使用者自行取得有權分析的輸入，將 workspace root 和 binary
path 傳給 Ghidra wrapper，再把 JSONL 匯入 SQLite。輸入 hash、Ghidra version、program
identity、image base 和 address space 會寫入 evidence/analysis_run。

不應把 firmware、私人 SQLite、Ghidra project 或 raw JSONL 放入 Git。重跑相同 hash
和 analyzer version 應跳過已完成工作；相同 JSONL 重複匯入不應增加 canonical rows。
