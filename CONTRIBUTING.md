# 貢獻指南

歡迎提交 parser、schema、CLI、測試、文件和不依賴私人 firmware 的 analyzer 改進。

提交前請：

1. 使用合成 fixture 或公開且有明確授權的輸入。
2. 執行 `python -m unittest discover -s tests -v` 和 `python -m compileall -q fwplatform analyzers tests`。
3. 為新的資料表、欄位和 evidence relation 加入 migration、idempotency 測試和 rollback 說明。
4. 保留 UNKNOWN/CANDIDATE 狀態，不要把名稱或數值猜測成已確認語意。
5. 在 diff 中說明來源 hash、address space 和任何 blocker。

禁止提交 Sony firmware、更新包、NAND/WBI/loader/kernel 備份、私人資料庫、完整 raw
反組譯輸出、memory dump 或裝置憑證。這個專案目前仍在 license confirmation 階段；
在 LICENSE 被正式選定前，請不要將程式碼重新散布到其他專案。
