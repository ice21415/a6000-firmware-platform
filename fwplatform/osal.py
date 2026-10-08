from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .db import Database, sha256_file, utc_now

STATUSES = {"VERIFIED_STATIC", "VERIFIED_RUNTIME", "INFERRED", "CANDIDATE", "UNKNOWN", "DISPROVEN"}


def _status(value: Any) -> str:
    raw = value.get("status") if isinstance(value, dict) else value
    text = str(raw or "UNKNOWN").upper()
    return text if text in STATUSES else "UNKNOWN"


def _evidence(db: Database, fixture: Path, payload: dict[str, Any]) -> int:
    return db.evidence(str(fixture), sha256_file(fixture), "osal_fixture", "document",
                       json.dumps(payload, ensure_ascii=False, sort_keys=True), _status(payload),
                       {"analyzer": "osal_protocol", "schema": payload.get("schema", 1)},
                       evidence_type="osal_protocol", status_basis="explicit_fixture_status")


def _module(db: Database, ref: Any) -> int | None:
    if not isinstance(ref, dict):
        return None
    name = ref.get("module") or ref.get("name")
    sha = str(ref.get("binary_sha256") or "").lower()
    rows = db.query("SELECT m.id FROM module m LEFT JOIN binary b ON b.id=m.binary_id WHERE m.name=? AND (?='' OR lower(b.sha256)=?) ORDER BY m.id", [name, sha, sha]) if name else []
    return int(rows[0][0]) if len(rows) == 1 else None


def _function(db: Database, ref: Any) -> int | None:
    if not isinstance(ref, dict):
        return None
    sha = str(ref.get("binary_sha256") or "").lower()
    address = ref.get("address")
    name = ref.get("name")
    clauses: list[str] = []
    args: list[Any] = []
    if sha:
        clauses.append("lower(b.sha256)=?"); args.append(sha)
    if address is not None:
        text = str(address)
        try: text = hex(int(text, 0))
        except ValueError: pass
        clauses.append("f.address=?"); args.append(text)
    if name:
        clauses.append("f.name=?"); args.append(str(name))
    if not clauses:
        return None
    rows = db.query("SELECT f.id FROM function f LEFT JOIN binary b ON b.id=f.binary_id WHERE " + " AND ".join(clauses) + " ORDER BY f.id", args)
    return int(rows[0][0]) if len(rows) == 1 else None


def _message_id(db: Database, ref: Any, evidence_id: int) -> int | None:
    if not isinstance(ref, dict) or ref.get("value") is None:
        return None
    namespace = str(ref.get("namespace") or "unknown")
    value = str(ref.get("value"))
    name = str(ref.get("name") or "")
    identity = f"message-id:{namespace}:{value}:{name}"
    return db.upsert("message_id", {"namespace": namespace, "value": value, "name": name or None,
        "description": ref.get("description"), "status": _status(ref), "source_evidence_id": evidence_id,
        "identity_key": identity, "command_kind": ref.get("command_kind"),
        "payload_layout": json.dumps(ref.get("payload_layout"), ensure_ascii=False, sort_keys=True) if ref.get("payload_layout") is not None else None}, ("identity_key",))


def _unresolved(db: Database, identity: str, relation: str, reason: str, evidence_id: int) -> None:
    db.upsert("unresolved_edge", {"identity_key": identity, "from_type": "message_queue", "from_id": None,
        "to_type": "function", "to_id": None, "relation": relation, "reason": reason,
        "status": "CANDIDATE", "source_evidence_id": evidence_id}, ("identity_key",))


def import_osal_fixture(db: Database, fixture: Path) -> dict[str, Any]:
    """Import an explicit OSAL protocol fixture without inventing endpoints."""
    fixture = fixture.resolve()
    payload = json.loads(fixture.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("queue"), dict):
        raise ValueError("OSAL fixture requires an object and a queue object")
    evidence_id = _evidence(db, fixture, payload)
    queue = payload["queue"]
    namespace = str(queue.get("namespace") or "unknown")
    value = str(queue.get("value") or queue.get("address") or "")
    if not value:
        raise ValueError("OSAL queue requires namespace and value/address")
    queue_key = f"queue:{namespace}:{value}:{queue.get('name') or ''}"
    queue_id = db.upsert("message_queue", {"module_id": _module(db, queue.get("module")),
        "name": queue.get("name"), "address": value, "direction": queue.get("direction"),
        "status": _status(queue), "source_evidence_id": evidence_id, "identity_key": queue_key,
        "namespace": namespace, "queue_value": value, "semantics": queue.get("semantics"),
        "callback_function_id": _function(db, queue.get("callback")), "address_space": queue.get("address_space"),
        "analyzer_version": "osal_protocol:1"}, ("identity_key",))
    counts = {"queue": 1, "messages": 0, "flows": 0, "unresolved": 0, "evidence_id": evidence_id, "queue_id": queue_id}
    for item in payload.get("messages", []):
        if not isinstance(item, dict):
            continue
        command_id = _message_id(db, item.get("command") or item.get("message"), evidence_id)
        reply_id = _message_id(db, item.get("reply"), evidence_id)
        command_ref = item.get("command") or item.get("message") or {}
        identity = f"osal:{queue_key}:{command_ref.get('namespace','unknown')}:{command_ref.get('value','')}:{item.get('direction','')}"
        producer_id = _function(db, item.get("producer")); consumer_id = _function(db, item.get("consumer")); callback_id = _function(db, item.get("callback"))
        row_id = db.upsert("osal_message", {"queue_id": queue_id, "message_id": command_id,
            "direction": item.get("direction"), "semantics": item.get("semantics"),
            "payload_layout": json.dumps(item.get("payload"), ensure_ascii=False, sort_keys=True) if item.get("payload") is not None else None,
            "reply_message_id": reply_id, "timeout_ms": item.get("timeout_ms"), "producer_function_id": producer_id,
            "consumer_function_id": consumer_id, "callback_function_id": callback_id,
            "status": _status(item), "source_evidence_id": evidence_id, "analyzer_version": "osal_protocol:1",
            "identity_key": identity, "metadata_json": json.dumps(item, ensure_ascii=False, sort_keys=True)}, ("identity_key",))
        counts["messages"] += 1
        for role, function_id in (("producer", producer_id), ("consumer", consumer_id), ("callback", callback_id)):
            ref = item.get(role)
            # An omitted role is absence of a relationship, not a NULL
            # endpoint.  Materialising it as a flow made every async message
            # look as if it had three endpoints and polluted the graph.
            if not ref:
                continue
            module_id = _module(db, ref)
            if function_id is None and module_id is None:
                counts["unresolved"] += 1
                _unresolved(db, f"{identity}:{role}", f"osal_{role}", f"endpoint {role} is not uniquely identified", evidence_id)
                continue
            flow_key = f"flow:{row_id}:{role}:{module_id or 0}:{function_id or 0}"
            db.upsert("message_flow", {"osal_message_id": row_id, "role": role, "module_id": module_id,
                "function_id": function_id, "status": _status(item), "source_evidence_id": evidence_id,
                "identity_key": flow_key, "metadata_json": json.dumps(ref or {}, sort_keys=True)}, ("identity_key",))
            counts["flows"] += 1
    db.commit()
    return counts
