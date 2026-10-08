from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .db import Database, utc_now


def _count(db: Database, sql: str, args: list[Any] | None = None) -> int:
    return int(db.connection.execute(sql, args or []).fetchone()[0])


def phase3_metrics(db: Database) -> dict[str, Any]:
    return {
        "schema_version": int(db.connection.execute("PRAGMA user_version").fetchone()[0]),
        "semantic_nodes": _count(db, "SELECT COUNT(*) FROM semantic_node"),
        "semantic_edges": _count(db, "SELECT COUNT(*) FROM semantic_edge"),
        "semantic_verified_edges": _count(db, "SELECT COUNT(*) FROM semantic_edge WHERE status IN ('VERIFIED_STATIC','VERIFIED_RUNTIME')"),
        "cfg_edges": _count(db, "SELECT COUNT(*) FROM cfg_edge"),
        "osal_queues": _count(db, "SELECT COUNT(*) FROM message_queue"),
        "osal_messages": _count(db, "SELECT COUNT(*) FROM osal_message"),
        "osal_flows": _count(db, "SELECT COUNT(*) FROM message_flow"),
        "jni_bridges": _count(db, "SELECT COUNT(*) FROM jni_bridge"),
        "java_methods": _count(db, "SELECT COUNT(*) FROM java_method"),
        "state_machines": _count(db, "SELECT COUNT(*) FROM state_machine"),
        "state_transitions": _count(db, "SELECT COUNT(*) FROM state_transition"),
        "sdk_documented": _count(db, "SELECT COUNT(*) FROM sdk_interface"),
        "sdk_runtime_verified": _count(db, "SELECT COUNT(*) FROM sdk_interface WHERE verification_status='VERIFIED_RUNTIME'"),
        "unresolved_edges": _count(db, "SELECT COUNT(*) FROM unresolved_edge"),
        "analysis_runs": [dict(row) for row in db.query("SELECT analyzer,status,COUNT(*) AS rows FROM analysis_run GROUP BY analyzer,status ORDER BY analyzer,status")],
        "denominators": {
            "semantic_nodes": "rows materialized from supported entity tables in the current database",
            "semantic_edges": "typed relations materialized from supported relation tables",
            "cfg_edges": "explicit Ghidra cfg_edge records; no estimate for unanalyzed binaries",
            "osal_protocol": "explicit OSAL fixture/message rows only; unobserved queues are UNKNOWN",
            "jni": "explicit Java/JNI inventory rows only; missing DEX/registration evidence is UNKNOWN",
            "sdk_callable": "UNKNOWN until independent runtime validation exists",
        },
    }


def _write(path: Path, title: str, body: str) -> str:
    path.write_text(f"# {title}\n\nGenerated: {utc_now()}\n\n{body}\n", encoding="utf-8")
    return str(path)


def write_phase3_reports(db: Database, output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    metrics = phase3_metrics(db)
    table = "\n".join(f"| {key} | {value if not isinstance(value, list) else len(value)} |" for key, value in metrics.items() if key not in {"denominators", "analysis_runs"})
    outputs = {
        "PHASE3_AUDIT.md": _write(output_dir / "PHASE3_AUDIT.md", "PHASE3_AUDIT", "本報告由 SQLite 目前資料產生；symbol index、CFG、語意理解、runtime 驗證和 SDK 可呼叫性分開計算。\n\n| 指標 | 數量 |\n|---|---:|\n" + table + "\n\n不存在合理分母的 coverage 會保留 UNKNOWN，不以 binary 或 symbol 數量推估語意完成度。"),
        "SEMANTIC_GRAPH_REPORT.md": _write(output_dir / "SEMANTIC_GRAPH_REPORT.md", "SEMANTIC_GRAPH_REPORT", f"Semantic nodes: **{metrics['semantic_nodes']}** ；edges: **{metrics['semantic_edges']}** ；verified edges: **{metrics['semantic_verified_edges']}**。\n\n關係包含 CALLS、CONTROL_FLOW、REFERENCES、DEPENDS_ON、OSAL message、JNI bridge、event 和 state transition；未知 target 保留在 unresolved_edge。"),
        "OSAL_PROTOCOL_REPORT.md": _write(output_dir / "OSAL_PROTOCOL_REPORT.md", "OSAL_PROTOCOL_REPORT", f"Queues: **{metrics['osal_queues']}**；messages: **{metrics['osal_messages']}**；flows: **{metrics['osal_flows']}**。\n\n只有明確 fixture/原始證據中的 producer、consumer、command、payload、callback 和 status 才會寫入；相同數值不會跨 namespace 自動連結。"),
        "JNI_BRIDGE_REPORT.md": _write(output_dir / "JNI_BRIDGE_REPORT.md", "JNI_BRIDGE_REPORT", f"Java methods: **{metrics['java_methods']}**；JNI bridges: **{metrics['jni_bridges']}**。\n\nNative function 只有在 binary identity、address/name 唯一匹配時才建立關聯；方法 body 或 RegisterNatives 缺失時標示 UNKNOWN/CANDIDATE。"),
        "STATE_MACHINE_REPORT.md": _write(output_dir / "STATE_MACHINE_REPORT.md", "STATE_MACHINE_REPORT", f"State machines: **{metrics['state_machines']}**；transitions: **{metrics['state_transitions']}**。\n\nState、event namespace、action 和硬體完成條件保持分離；UI unmute 不會被自動宣稱為 camera ready。"),
        "SDK_COVERAGE_REPORT.md": _write(output_dir / "SDK_COVERAGE_REPORT.md", "SDK_COVERAGE_REPORT", f"Documented interfaces: **{metrics['sdk_documented']}**；runtime verified: **{metrics['sdk_runtime_verified']}**。\n\nIndexed symbols are not SDK APIs. `sdk_interface` 的 verification_status、runtime_safety、evidence references 和 mock status 分開保存；可呼叫性在沒有 runtime validation 時為 UNKNOWN。"),
    }
    (output_dir / "phase3-metrics.json").write_text(json.dumps(metrics, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return {"output_dir": str(output_dir), "files": list(outputs.values()), "metrics": metrics}
