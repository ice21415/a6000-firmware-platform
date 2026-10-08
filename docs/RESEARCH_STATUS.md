# 研究狀態

資料來源是本地 Phase 2 SQLite audit；公開版不包含該資料庫。

| 區域 | 狀態 | 證據邊界 |
|---|---|---|
| Inventory/schema | IMPLEMENTED | migrations、synthetic tests、SQLite integrity check |
| Python ELF index | IMPLEMENTED | symbol/import/export/relocation rows；不是完整語意逆向 |
| Ghidra single-ELF pipeline | IMPLEMENTED | ARM/Thumb sample、JSONL、CFG/XREF、增量匯入 |
| Cross-ELF linkage | PARTIAL | DT_NEEDED 與唯一 export/import match；ambiguous match 保留 |
| Function semantics | UNKNOWN/PARTIAL | 名稱和 prototype 不能代替語意證明 |
| JNI/Java bridge | UNKNOWN | 尚未建立可公開、可驗證的完整 fixture |
| OSAL queue/message | UNKNOWN | 需要額外證據和 namespace 分離 |
| Runtime behavior | UNKNOWN | 公開 CI 不連接相機 |
| Modding adapter | MOCK ONLY | 沒有 NAND/WBI/bootloader/device write path |

已知 blocker 是兩個 ELF section table 越界輸入；錯誤會保存到 `analysis_run`，不會
中止其他工作。公開版不宣稱任何 firmware patch 或實機安全性。
