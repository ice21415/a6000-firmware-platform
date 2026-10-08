# Roadmap

## Phase 2（已完成基礎版）

- 完成 evidence identity、v3 integrity migration 和 v4 Ghidra provenance。
- 建立單一 ARM/Thumb ELF 的 Ghidra CFG/XREF pipeline。
- 建立 ELF DT_NEEDED 與唯一 symbol resolution linkage。
- 提供可追溯的 CLI 與 audit reports。

## Phase 3（目前分支：semantic-analysis）

- migration v5–v6 Semantic Graph、CFG edge、OSAL message、JNI bridge、body ranges 和 SDK evidence schema。
- 修正同名 ELF DT_NEEDED 解析和 Ghidra caller 歸屬，歧義保留 unresolved edge。
- 提供 OSAL/JNI fixture analyzer、DEX inventory、跨模組 trace、state/protocol/API 查詢和 GraphML export。
- 以 synthetic fixtures 驗證完整性、namespace 分離、idempotence 和 rollback。

尚未宣稱完整還原 Sony 的 OSAL/JNI 協定或 Camera runtime 行為；需要更多有來源的
fixture、Ghidra multi-ELF runs 和實機觀測才能提升 verification status。

## Phase 3.1（目前開發中）

- 使用 migration v6 保存 Ghidra 不連續 body range、normalized research observation 和 adapter checkpoint。
- 已在私有 DB 副本驗證 targeted SyncAndroid/ModelCamera evidence ingestion、OSAL queue/message、JNI registration lookup、state transitions 和 provenance gaps。
- Receiver canonical function、message completion、Java native implementation、camera ready/first-shot 和 runtime verification 保持 UNKNOWN/CANDIDATE。

## 下一階段

- 擴充 Java/DEX/JNI、OSAL queue、message/event namespace 的真實 evidence fixture。
- 增加 indirect call candidate、jump table、vtable slot 和 unresolved edge 的合成 fixture。
- 強化跨 binary address-space、PLT/GOT、relocation 和 ABI 解析。
- 為描述性 SDK 建立 schema 驗證、mock protocol tests 和版本相容性檢查。

## 長期目標

- 完成 Camera、UI、Lens、Sensor、Media、Android、Networking 等 domain index。
- 建立可回復、可驗證的 modding framework adapter；任何實機 adapter 都必須另行審查。
- 支援公開資料來源的可重現分析，不把私人 firmware 納入 CI 或 release。
