## 變更內容

<!-- 說明實際改變、資料模型影響和證據來源。 -->

## 驗證

- [ ] `python -m unittest discover -s tests -v`
- [ ] `python -m compileall -q fwplatform analyzers tests`
- [ ] 新增 migration 時已測試重跑與 foreign-key integrity
- [ ] 沒有加入 firmware、私人資料庫、raw disassembly 或 secrets
- [ ] UNKNOWN/CANDIDATE 關係沒有被改寫成 VERIFIED

## 研究安全

- [ ] 沒有 NAND/WBI/bootloader/device write path
- [ ] 若使用輸入檔，已提供 hash、授權和可重現步驟
