# 研究狀態

資料來源是本地 Phase 2/3 SQLite audit；公開版只包含 schema、analyzer、synthetic fixture
和清理後報告，不包含 populated database。

| 區域 | 狀態 | 證據邊界 |
|---|---|---|
| Inventory/schema | IMPLEMENTED | migrations、synthetic tests、SQLite integrity check |
| Python ELF index | IMPLEMENTED | symbol/import/export/relocation rows；不是完整語意逆向 |
| Ghidra single-ELF pipeline | IMPLEMENTED | ARM/Thumb sample、JSONL、CFG/XREF、增量匯入 |
| Cross-ELF linkage | PARTIAL | SONAME/search path 與唯一 export/import match；ambiguous match 保留 |
| Function semantics | UNKNOWN/PARTIAL | 名稱和 prototype 不能代替語意證明 |
| Semantic graph | IMPLEMENTED_WITH_GAPS | migration v5–v7、typed nodes/edges、GraphML、provenance validator；JNI 配對需精確 DEX path 與 evidence ID |
| JNI/Java bridge | PARTIAL | explicit fixture import；缺失 registration/body 保留 UNKNOWN |
| OSAL queue/message | PARTIAL | explicit fixture import；需要更多原始 producer/consumer 證據 |
| DEX inventory | INDEXED ONLY | header/string/type/proto/class_def/method_id 靜態結構；method_id 為引用，不宣稱 method body 或 JNI 實作 |
| Runtime behavior | UNKNOWN | 公開 CI 不連接相機 |
| Modding adapter | MOCK ONLY | 沒有 NAND/WBI/bootloader/device write path |

已知 blocker 是兩個 ELF section table 越界輸入；錯誤會保存到 `analysis_run`，不會
中止其他工作。公開版不宣稱任何 firmware patch 或實機安全性。
