# Roadmap

## Phase 2（目前）

- 完成 evidence identity、v3 integrity migration 和 v4 Ghidra provenance。
- 建立單一 ARM/Thumb ELF 的 Ghidra CFG/XREF pipeline。
- 建立 ELF DT_NEEDED 與唯一 symbol resolution linkage。
- 提供可追溯的 CLI 與 audit reports。

## 下一階段

- 將 Java/DEX/JNI、OSAL queue、message/event namespace 匯入同一 provenance model。
- 增加 indirect call candidate、jump table、vtable slot 和 unresolved edge 的合成 fixture。
- 強化跨 binary address-space、PLT/GOT、relocation 和 ABI 解析。
- 為描述性 SDK 建立 schema 驗證、mock protocol tests 和版本相容性檢查。

## 長期目標

- 完成 Camera、UI、Lens、Sensor、Media、Android、Networking 等 domain index。
- 建立可回復、可驗證的 modding framework adapter；任何實機 adapter 都必須另行審查。
- 支援公開資料來源的可重現分析，不把私人 firmware 納入 CI 或 release。
