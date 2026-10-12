from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from .constants import STATUSES
from .db import Database, sha256_file

LOG = logging.getLogger(__name__)


def normalize_path(value: str, root: Path) -> str:
    value = value.replace("\\", "/")
    root_text = root.resolve().as_posix().rstrip("/")
    if value.startswith(root_text + "/"):
        value = value[len(root_text) + 1 :]
    while value.startswith("./"):
        value = value[2:]
    return value


def _status(payload: Any, filename: str = "") -> str:
    # Confidence is derived only from an explicit status field. Filenames and
    # arbitrary prose may describe a candidate, but cannot promote evidence.
    raw = None
    if isinstance(payload, dict):
        raw = payload.get("evidence_status") or payload.get("status")
    if isinstance(raw, str):
        upper = raw.upper()
        if "DISPROVEN" in upper:
            return "DISPROVEN"
        if "RUNTIME" in upper:
            return "VERIFIED_RUNTIME"
        if "STATIC" in upper or "VERIFIED" in upper:
            return "VERIFIED_STATIC"
        if "INFERRED" in upper:
            return "INFERRED"
        if "CANDIDATE" in upper:
            return "CANDIDATE"
    return "UNKNOWN"


def _binary_id(db: Database, path: str | None, root: Path) -> int | None:
    if not path:
        return None
    normalized = normalize_path(path, root)
    row = db.connection.execute("SELECT id FROM binary WHERE path=?", (normalized,)).fetchone()
    if row:
        return int(row[0])
    rows = db.connection.execute("SELECT id FROM binary WHERE path LIKE ? ORDER BY length(path)", (f"%{Path(normalized).as_posix()}",)).fetchall()
    return int(rows[0][0]) if len(rows) == 1 else None


def _evidence_status(db: Database, evidence_id: int) -> str:
    row = db.connection.execute("SELECT status FROM evidence WHERE id=?", (evidence_id,)).fetchone()
    return str(row[0]) if row and row[0] in STATUSES else "UNKNOWN"


def _module(db: Database, name: str, binary_id: int | None = None, domain: str | None = None,
            status: str = "UNKNOWN", evidence_id: int | None = None) -> int:
    status = status if status in STATUSES else "UNKNOWN"
    if binary_id:
        row = db.connection.execute("SELECT sha256 FROM binary WHERE id=?", (binary_id,)).fetchone()
        identity_key = f"binary-sha256:{row[0]}:{name}" if row else f"binary-id:{binary_id}:{name}"
    else:
        identity_key = f"research:{name}"
    return db.upsert("module", {"name": name, "binary_id": binary_id, "description": None,
        "identity_key": identity_key,
        "domain": domain, "status": status, "confidence_id": db.confidence_id(status),
        "source_evidence_id": evidence_id}, ("identity_key",))


def _function(db: Database, binary_id: int | None, module_id: int | None, name: str,
              address: Any, size: Any = None, evidence_id: int | None = None,
              status: str = "VERIFIED_STATIC", origin: str = "research_index") -> int:
    address = str(address) if address is not None else None
    if address and not address.startswith("0x"):
        try:
            address = hex(int(address, 0))
        except ValueError:
            pass
    identity_key = f"function:{binary_id or 0}:{module_id or 0}:{address or ''}:{name or ''}"
    existing = db.connection.execute("SELECT id FROM function WHERE binary_id IS ? AND address IS ? AND name IS ? LIMIT 1",
                                     (binary_id, address, name)).fetchone()
    values = {"binary_id": binary_id, "module_id": module_id, "name": name,
        "identity_key": identity_key,
        "address": address, "size": int(size) if str(size or "").isdigit() else None,
        "calling_convention": None, "thumb_mode": None, "vma": address, "runtime_va": None,
        "physical_offset": None, "wbi_offset": None, "status": status,
        "confidence_id": db.confidence_id(status), "source_evidence_id": evidence_id,
        "generated_name": 0, "origin": origin}
    if existing:
        # A legacy row can have an equivalent address/name but a pre-v3 key
        # built from a different module identity. Preserve its occupied key
        # rather than violating the new unique index; the row itself remains
        # the canonical function referenced by existing relations.
        key_owner = db.connection.execute("SELECT id FROM function WHERE identity_key=? AND id<>? LIMIT 1",
                                          (identity_key, existing[0])).fetchone()
        effective_key = identity_key if key_owner is None else db.connection.execute(
            "SELECT identity_key FROM function WHERE id=?", (existing[0],)).fetchone()[0]
        db.connection.execute("UPDATE function SET module_id=?,identity_key=?,size=?,status=?,confidence_id=?,source_evidence_id=?,origin=? WHERE id=?",
                              (module_id, effective_key, values["size"], status, values["confidence_id"], evidence_id, origin, existing[0]))
        return int(existing[0])
    return db.upsert("function", values, ("identity_key",))


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
        return json.load(handle)


def _evidence_for(db: Database, path: Path, root: Path, payload: Any) -> int:
    rel = normalize_path(str(path), root)
    digest = sha256_file(path)
    status = _status(payload, path.name)
    excerpt = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))[:1000]
    basis = "explicit_status_field" if isinstance(payload, dict) and (payload.get("status") or payload.get("evidence_status")) else "no_explicit_status"
    return db.evidence(rel, digest, "existing_research_json", "document", excerpt, status,
                       {"payload_type": type(payload).__name__}, evidence_type="research_json", status_basis=basis)


def _import_imdb(db: Database, payload: list[Any], evidence_id: int) -> int:
    count = 0
    status = _evidence_status(db, evidence_id)
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("library") or f"IMDB:{entry.get('index', count)}")
        module_id = _module(db, name, None, "camera_core", status, evidence_id)
        callbacks = entry.get("lifecycle_callbacks") or {}
        for phase in ("init", "exit", "suspend", "resume", "inactivate", "activate"):
            callback = callbacks.get(phase) or ""
            function_id = _function(db, None, module_id, callback, callback, evidence_id=evidence_id) if callback else None
            callback_key = f"{module_id}|{phase}|{function_id or 0}"
            db.upsert("lifecycle_callback", {"module_id": module_id, "name": phase,
                "callback_key": callback_key,
                "function_id": function_id, "phase": phase, "status": status,
                "source_evidence_id": evidence_id}, ("callback_key",))
        identity_key = f"imdb:{entry.get('index', count)}:{entry.get('address')}"
        db.upsert("data_structure", {"binary_id": None, "name": f"IMDBEntry[{entry.get('index', count)}]",
            "identity_key": identity_key,
            "base_address": entry.get("address"), "field_offset": None, "field_name": "raw_words",
            "field_type": "uint32[]", "width": len(entry.get("words") or []) * 4,
            "status": status, "source_evidence_id": evidence_id}, ("identity_key",))
        count += 1
    return count


def _import_vtables(db: Database, path: Path, root: Path, payload: dict[str, Any], evidence_id: int) -> int:
    binary_id = _binary_id(db, payload.get("input"), root)
    module_name = Path(str(payload.get("input") or path.stem)).name
    domain = "display_ui" if "view" in path.name.lower() else "camera_core"
    status = _evidence_status(db, evidence_id)
    module_id = _module(db, module_name, binary_id, domain, status, evidence_id)
    count = 0
    for cls in payload.get("classes", []):
        class_name = str(cls.get("rtti_name") or cls.get("name") or "unknown")
        table_address = cls.get("vtable_header") or cls.get("address")
        for method in cls.get("methods", []):
            address = method.get("address") or method.get("pointer")
            symbol = method.get("symbol") or None
            db.upsert("vtable", {"binary_id": binary_id, "class_name": class_name,
                "address": table_address, "slot": method.get("slot"), "slot_address": method.get("slot_address"),
                "target_address": address, "symbol": symbol, "imported": int(bool(method.get("imported"))),
                "status": status, "confidence_id": db.confidence_id(status),
                "source_evidence_id": evidence_id}, ("binary_id", "class_name", "slot_address"))
            if address and not method.get("imported"):
                _function(db, binary_id, module_id, symbol or f"{class_name}::slot_{method.get('slot')}", address,
                          evidence_id=evidence_id, status=status, origin="vtable_candidate")
            count += 1
    return count


def _import_elf_inventory(db: Database, payload: list[Any], root: Path, evidence_id: int) -> int:
    count = 0
    status = _evidence_status(db, evidence_id)
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        binary_id = _binary_id(db, entry.get("path"), root)
        module_name = Path(str(entry.get("path") or "unknown")).name
        module_id = _module(db, module_name, binary_id, None, status, evidence_id)
        for symbol in entry.get("symbols", []):
            if not isinstance(symbol, dict) or not symbol.get("name"):
                continue
            address = symbol.get("address")
            db.upsert("symbol", {"binary_id": binary_id, "name": symbol["name"], "address": str(address) if address is not None else None,
                "size": symbol.get("size"), "type": symbol.get("type"), "binding": None,
                "section": symbol.get("section"), "status": status}, ("binary_id", "name", "address"))
            if symbol.get("type") == "STT_FUNC" and address not in (None, "0x0", "0"):
                _function(db, binary_id, module_id, symbol["name"], address, symbol.get("size"), evidence_id, status, "symbol_index")
                count += 1
        for string in entry.get("strings", []):
            if isinstance(string, dict) and string.get("text"):
                db.upsert("resource", {"binary_id": binary_id, "path": f"{string.get('address')}:{string.get('text')}",
                    "resource_type": "string", "description": string.get("text"), "status": status,
                    "source_evidence_id": evidence_id}, ("binary_id", "path"))
    return count


def _import_state_transitions(db: Database, payload: dict[str, Any], root: Path, evidence_id: int) -> int:
    binary_id = _binary_id(db, payload.get("input"), root)
    status = _evidence_status(db, evidence_id)
    module_id = _module(db, Path(str(payload.get("input") or "libObj.so")).name, binary_id, "camera_core", status, evidence_id)
    machine_id = db.upsert("state_machine", {"name": "ModelCamera.selector_dispatch", "module_id": module_id,
        "description": "Static selector evaluation from camera-state-transitions.json", "status": status,
        "source_evidence_id": evidence_id}, ("name",))
    states: dict[str, int] = {}
    for value in payload.get("states", []):
        states[str(value)] = db.upsert("state", {"machine_id": machine_id, "value": str(value), "name": f"state_{value}",
            "description": None, "status": status, "source_evidence_id": evidence_id}, ("machine_id", "value", "name"))
    count = 0
    for transition in payload.get("transitions_and_focus_actions", []):
        selector = str(transition.get("selector"))
        event_identity = f"camera_selector|{selector}|selector_{selector}"
        event_id = db.upsert("event_id", {"namespace": "camera_selector", "value": selector, "name": f"selector_{selector}",
            "identity_key": event_identity,
            "description": "Selector observed in static state dispatcher", "status": status, "source_evidence_id": evidence_id},
            ("identity_key",))
        transition_identity = f"{machine_id}|{states.get(str(transition.get('state'))) or 0}|{event_id}|{states.get(str(transition.get('next_state'))) or 0}|{transition.get('action')}"
        db.upsert("state_transition", {"machine_id": machine_id, "from_state_id": states.get(str(transition.get("state"))),
            "identity_key": transition_identity,
            "event_id": event_id, "to_state_id": states.get(str(transition.get("next_state"))), "action": str(transition.get("action")),
            "status": status, "source_evidence_id": evidence_id},
            ("identity_key",))
        count += 1
    return count


def _import_generic_functions(db: Database, path: Path, payload: Any, evidence_id: int) -> int:
    if not isinstance(payload, list):
        return 0
    module_id = _module(db, path.stem, None, None, "CANDIDATE", evidence_id)
    count = 0
    for row in payload:
        if isinstance(row, dict) and "address" in row:
            _function(db, None, module_id, str(row.get("name") or f"generated_{row.get('address')}"),
                      row.get("address"), row.get("size"), evidence_id, "CANDIDATE", "candidate")
            count += 1
    return count


def import_existing(db: Database, root: Path) -> dict[str, int]:
    root = root.resolve()
    stats = {"json_files": 0, "evidence": 0, "imdb_entries": 0, "functions": 0, "vtables": 0, "transitions": 0, "errors": 0}
    research = root / "firmware-analysis"
    for path in research.rglob("*.json"):
        stats["json_files"] += 1
        try:
            payload = _read_json(path)
            evidence_id = _evidence_for(db, path, root, payload)
            stats["evidence"] += 1
            name = path.name.lower()
            if name == "imdb-entries.json" and isinstance(payload, list):
                stats["imdb_entries"] += _import_imdb(db, payload, evidence_id)
            elif name.endswith("vtables.json") and isinstance(payload, dict):
                stats["vtables"] += _import_vtables(db, path, root, payload, evidence_id)
            elif name == "elf-inventory.json" and isinstance(payload, list):
                stats["functions"] += _import_elf_inventory(db, payload, root, evidence_id)
            elif name == "camera-state-transitions.json" and isinstance(payload, dict):
                stats["transitions"] += _import_state_transitions(db, payload, root, evidence_id)
            elif name in {"shoot-ready-symbols.json", "shoot-ready-targets.json"}:
                stats["functions"] += _import_generic_functions(db, path, payload, evidence_id)
            if isinstance(payload, dict) and payload.get("root_cause_status"):
                for key, value in (payload.get("root_cause_status") or {}).items():
                    key_lower = str(key).lower()
                    status = ("VERIFIED_RUNTIME" if "safe_proven" in key_lower else
                              "INFERRED" if "confirmed" in key_lower else
                              "CANDIDATE" if any(token in key_lower for token in ("not_proven", "unsafe", "candidate")) else
                              _status(value, path.name))
                    db.upsert("hypothesis", {"subject_type": "research_json", "subject_id": evidence_id,
                        "statement": f"{key}: {value}", "status": status, "confidence_id": db.confidence_id(status),
                        "source_evidence_id": evidence_id}, ("subject_type", "subject_id", "statement"))
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            stats["errors"] += 1
            LOG.warning("research import failed for %s: %s", path, exc)
    _deduplicate_nullable_keys(db)
    db.commit()
    return stats


def _deduplicate_nullable_keys(db: Database) -> None:
    """Repair legacy NULL-key rows so repeated imports stay idempotent."""
    for table, key in (("lifecycle_callback", "module_id,name"), ("data_structure", "name,base_address")):
        groups = db.query(f"SELECT {key}, MIN(id) AS keep_id, COUNT(*) AS n FROM {table} GROUP BY {key} HAVING n>1")
        for group in groups:
            where = " AND ".join(f"{column.strip()} IS ?" for column in key.split(","))
            args = [group[column.strip()] for column in key.split(",")]
            db.connection.execute(f"DELETE FROM {table} WHERE {where} AND id<>?", args + [group["keep_id"]])
    groups = db.query("""SELECT module_id,name,address,MIN(id) AS keep_id,COUNT(*) AS n
                         FROM function WHERE binary_id IS NULL
                         GROUP BY module_id,name,address HAVING n>1""")
    for group in groups:
        db.connection.execute("DELETE FROM function WHERE binary_id IS NULL AND module_id IS ? AND name IS ? AND address IS ? AND id<>?",
                              (group["module_id"], group["name"], group["address"], group["keep_id"]))
    groups = db.query("SELECT namespace,value,MIN(id) AS keep_id,COUNT(*) AS n FROM event_id GROUP BY namespace,value HAVING n>1")
    for group in groups:
        duplicate_ids = [row[0] for row in db.connection.execute("SELECT id FROM event_id WHERE namespace=? AND value=? AND id<>?", (group["namespace"], group["value"], group["keep_id"]))]
        for duplicate_id in duplicate_ids:
            db.connection.execute("UPDATE OR IGNORE state_transition SET event_id=? WHERE event_id=?", (group["keep_id"], duplicate_id))
            db.connection.execute("UPDATE OR IGNORE event_producer SET event_id=? WHERE event_id=?", (group["keep_id"], duplicate_id))
            db.connection.execute("UPDATE OR IGNORE event_consumer SET event_id=? WHERE event_id=?", (group["keep_id"], duplicate_id))
            db.connection.execute("DELETE FROM state_transition WHERE event_id=?", (duplicate_id,))
            db.connection.execute("DELETE FROM event_producer WHERE event_id=?", (duplicate_id,))
            db.connection.execute("DELETE FROM event_consumer WHERE event_id=?", (duplicate_id,))
            db.connection.execute("DELETE FROM event_id WHERE id=?", (duplicate_id,))
