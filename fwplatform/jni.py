from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .db import Database, sha256_file

STATUSES = {"VERIFIED_STATIC", "VERIFIED_RUNTIME", "INFERRED", "CANDIDATE", "UNKNOWN", "DISPROVEN"}


def _status(value: Any) -> str:
    raw = value.get("status") if isinstance(value, dict) else value
    text = str(raw or "UNKNOWN").upper()
    return text if text in STATUSES else "UNKNOWN"


def _function(db: Database, ref: Any) -> int | None:
    if not isinstance(ref, dict):
        return None
    args: list[Any] = []
    clauses: list[str] = []
    if ref.get("binary_sha256"):
        clauses.append("lower(b.sha256)=?"); args.append(str(ref["binary_sha256"]).lower())
    if ref.get("address") is not None:
        address = str(ref["address"])
        try: address = hex(int(address, 0))
        except ValueError: pass
        clauses.append("f.address=?"); args.append(address)
    if ref.get("name"):
        clauses.append("f.name=?"); args.append(str(ref["name"]))
    if not clauses:
        return None
    rows = db.query("SELECT f.id FROM function f LEFT JOIN binary b ON b.id=f.binary_id WHERE " + " AND ".join(clauses) + " ORDER BY f.id", args)
    return int(rows[0][0]) if len(rows) == 1 else None


def _module(db: Database, ref: Any) -> int | None:
    if not isinstance(ref, dict) or not ref.get("name"):
        return None
    name = str(ref["name"]); sha = str(ref.get("binary_sha256") or "").lower()
    rows = db.query("SELECT m.id FROM module m LEFT JOIN binary b ON b.id=m.binary_id WHERE m.name=? AND (?='' OR lower(b.sha256)=?) ORDER BY m.id", [name, sha, sha])
    return int(rows[0][0]) if len(rows) == 1 else None


def _unresolved(db: Database, identity: str, relation: str, reason: str,
                source_type: str = "jni_bridge", source_id: int | None = None,
                evidence_id: int | None = None, status: str = "CANDIDATE") -> None:
    db.upsert("unresolved_edge", {"identity_key": identity, "from_type": source_type,
        "from_id": source_id, "to_type": "unknown", "to_id": None,
        "relation": relation, "reason": reason, "status": status,
        "source_evidence_id": evidence_id}, ("identity_key",))


def import_jni_fixture(db: Database, fixture: Path) -> dict[str, Any]:
    """Import explicit Java/JNI registration observations from a fixture.

    The fixture can be produced from DEX/ODEX or a static RegisterNatives
    extraction. Missing native entries remain UNKNOWN/CANDIDATE and are never
    linked by a similar name alone.
    """
    fixture = fixture.resolve()
    payload = json.loads(fixture.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("JNI fixture must be a JSON object")
    evidence_id = db.evidence(str(fixture), sha256_file(fixture), "jni_fixture", "document",
                               json.dumps(payload, ensure_ascii=False, sort_keys=True), _status(payload),
                               {"analyzer": "jni_bridge", "schema": payload.get("schema", 1)},
                               evidence_type="jni_bridge", status_basis="explicit_fixture_status")
    counts = {"java_methods": 0, "jni_bridges": 0, "resolved_native": 0, "unresolved": 0, "evidence_id": evidence_id}
    java_ids: dict[tuple[str, str, str, str], int] = {}
    for method in payload.get("java_methods", []):
        if not isinstance(method, dict):
            continue
        class_name = str(method.get("class_name") or ""); name = str(method.get("method_name") or ""); signature = str(method.get("signature") or "")
        if not class_name or not name or not signature:
            continue
        dex_path = str(method.get("dex_path") or "")
        identity = f"java:{class_name}:{name}:{signature}:{dex_path}"
        row_id = db.upsert("java_method", {"class_name": class_name, "method_name": name, "signature": signature,
            "dex_path": dex_path, "status": _status(method), "source_evidence_id": evidence_id,
            "identity_key": identity, "namespace": method.get("namespace"), "analyzer_version": "jni_bridge:1"}, ("identity_key",))
        java_ids[(class_name, name, signature, dex_path)] = row_id
        counts["java_methods"] += 1
    for bridge in payload.get("jni_methods", payload.get("bridges", [])):
        if not isinstance(bridge, dict):
            continue
        class_name = str(bridge.get("class_name") or ""); name = str(bridge.get("method_name") or ""); signature = str(bridge.get("signature") or "")
        dex_path = str(bridge.get("dex_path") or "")
        java_key = (class_name, name, signature, dex_path)
        if java_key not in java_ids:
            counts["unresolved"] += 1
        native = bridge.get("native") or bridge.get("native_entry") or {}
        native_id = _function(db, native)
        module_id = _module(db, bridge.get("module"))
        status = _status(bridge)
        if native_id is not None:
            counts["resolved_native"] += 1
        elif native:
            counts["unresolved"] += 1
            status = "CANDIDATE" if status == "VERIFIED_STATIC" else status
        identity = f"jni:{class_name}:{name}:{signature}:{native.get('address') if isinstance(native, dict) else native}"
        bridge_id = db.upsert("jni_bridge", {"class_name": class_name, "method_name": name, "signature": signature,
            "native_entry": str(native.get("address") if isinstance(native, dict) else native or ""),
            "module_id": module_id, "status": status, "source_evidence_id": evidence_id,
            "identity_key": identity, "native_function_id": native_id,
            "address_space": bridge.get("address_space"), "analyzer_version": "jni_bridge:1"}, ("identity_key",))
        if java_key not in java_ids:
            _unresolved(db, f"{identity}:java", "JNI_BRIDGE",
                        f"Java method was not present in fixture: {class_name}.{name}{signature}",
                        source_id=bridge_id, evidence_id=evidence_id, status="CANDIDATE")
        if native_id is None:
            _unresolved(db, f"{identity}:native", "JNI_NATIVE_ENTRY",
                        "Native function reference was missing or not uniquely resolved",
                        source_id=bridge_id, evidence_id=evidence_id, status="CANDIDATE")
        counts["jni_bridges"] += 1
    db.commit()
    return counts
