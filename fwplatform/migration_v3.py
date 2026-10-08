from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}


def _add_column(conn: sqlite3.Connection, table: str, name: str, definition: str) -> None:
    if name not in _columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


def _identity_key(source_path: str | None, source_sha256: str | None, kind: str | None) -> str:
    if source_sha256:
        return f"sha256:{source_sha256.lower()}:{kind or 'unknown'}"
    return f"path:{source_path or ''}:{kind or 'unknown'}"


def _explicit_status(old_status: str | None, excerpt: str | None) -> tuple[str, str]:
    """Conservative legacy conversion; do not infer status from arbitrary text."""
    text = (excerpt or "").lstrip()
    match = re.match(r'^\{\s*"status"\s*:\s*"([^"]*)"', text, re.IGNORECASE)
    if match:
        raw = match.group(1).upper()
        if "DISPROVEN" in raw:
            return "DISPROVEN", "explicit_top_level_status"
        if "RUNTIME" in raw:
            return "VERIFIED_RUNTIME", "explicit_top_level_status"
        if "STATIC" in raw or "VERIFIED" in raw:
            return "VERIFIED_STATIC", "explicit_top_level_status"
        if "INFERRED" in raw:
            return "INFERRED", "explicit_top_level_status"
        if "CANDIDATE" in raw:
            return "CANDIDATE", "explicit_top_level_status"
    return "UNKNOWN", "legacy_text_not_explicit"


def _evidence_key(source_identity_id: int, locator_key: str, kind: str, excerpt: str) -> str:
    digest = hashlib.sha256(excerpt.encode("utf-8", "replace")).hexdigest()
    return f"{source_identity_id}|{kind}|{locator_key}|{digest}"


def _backfill_source_identities(conn: sqlite3.Connection) -> None:
    rows = conn.execute("SELECT id,source_path,source_sha256,kind FROM evidence").fetchall()
    for row in rows:
        key = _identity_key(row[1], row[2], row[3])
        conn.execute("INSERT OR IGNORE INTO source_identity(identity_key,source_path,source_sha256,kind,first_seen_at,metadata_json) VALUES(?,?,?,?,?,?)",
                     (key, row[1], row[2], row[3], _now(), "{}"))
        source_id = conn.execute("SELECT id FROM source_identity WHERE identity_key=?", (key,)).fetchone()[0]
        conn.execute("UPDATE evidence SET source_identity_id=? WHERE id=?", (source_id, row[0]))


def _backfill_binary_identities(conn: sqlite3.Connection) -> None:
    rows = conn.execute("SELECT id,sha256,size,format,arch,endian FROM binary").fetchall()
    for row in rows:
        key = f"sha256:{str(row[1]).lower()}:{int(row[2])}:{row[3]}"
        conn.execute("INSERT OR IGNORE INTO binary_identity(identity_key,sha256,size,format,arch,endian,first_seen_at,metadata_json) VALUES(?,?,?,?,?,?,?,?)",
                     (key, row[1], row[2], row[3], row[4], row[5], _now(), "{}"))
        identity_id = conn.execute("SELECT id FROM binary_identity WHERE identity_key=?", (key,)).fetchone()[0]
        conn.execute("UPDATE binary SET binary_identity_id=? WHERE id=?", (identity_id, row[0]))


def _merge_evidence(conn: sqlite3.Connection) -> None:
    if "evidence_key" in _columns(conn, "evidence"):
        return
    conn.execute("DROP TABLE IF EXISTS evidence_v3")
    conn.execute("""CREATE TABLE evidence_v3 (
        id INTEGER PRIMARY KEY, source_path TEXT NOT NULL, source_sha256 TEXT,
        kind TEXT, locator TEXT, locator_key TEXT NOT NULL, excerpt TEXT,
        evidence_key TEXT NOT NULL UNIQUE, evidence_type TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'UNKNOWN', status_basis TEXT NOT NULL,
        confidence_id INTEGER REFERENCES confidence(id), created_at TEXT NOT NULL,
        metadata_json TEXT, source_identity_id INTEGER REFERENCES source_identity(id)
    )""")
    rows = conn.execute("SELECT id,source_path,source_sha256,kind,locator,excerpt,status,confidence_id,created_at,metadata_json,source_identity_id FROM evidence ORDER BY id").fetchall()
    canonical: dict[str, tuple[Any, ...]] = {}
    mapping: dict[int, int] = {}
    for row in rows:
        source_id = row[10]
        if source_id is None:
            key = _identity_key(row[1], row[2], row[3])
            conn.execute("INSERT OR IGNORE INTO source_identity(identity_key,source_path,source_sha256,kind,first_seen_at,metadata_json) VALUES(?,?,?,?,?,?)",
                         (key, row[1], row[2], row[3], _now(), "{}"))
            source_id = conn.execute("SELECT id FROM source_identity WHERE identity_key=?", (key,)).fetchone()[0]
        locator_key = row[4] or "document"
        kind = row[3] or "unknown"
        excerpt = row[5] or ""
        ekey = _evidence_key(int(source_id), locator_key, kind, excerpt)
        status, basis = _explicit_status(row[6], excerpt)
        if ekey not in canonical:
            canonical[ekey] = (row[0], row[1], row[2], kind, row[4], locator_key, excerpt, ekey, kind,
                               status, basis, row[7], row[8] or _now(), row[9], source_id)
            mapping[int(row[0])] = int(row[0])
        else:
            mapping[int(row[0])] = int(canonical[ekey][0])
    conn.executemany("""INSERT INTO evidence_v3(id,source_path,source_sha256,kind,locator,locator_key,excerpt,evidence_key,evidence_type,status,status_basis,confidence_id,created_at,metadata_json,source_identity_id)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", list(canonical.values()))
    for row in rows:
        old_id, canonical_id = int(row[0]), mapping[int(row[0])]
        if old_id == canonical_id:
            continue
        conn.execute("INSERT OR IGNORE INTO evidence_archive(old_id,canonical_id,source_path,source_sha256,kind,locator,excerpt,old_status,confidence_id,created_at,metadata_json,merged_at,merge_reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                     (old_id, canonical_id, row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9], _now(), "duplicate_evidence_key"))
    conn.execute("CREATE TEMP TABLE evidence_map(old_id INTEGER PRIMARY KEY,canonical_id INTEGER NOT NULL)")
    conn.executemany("INSERT INTO evidence_map(old_id,canonical_id) VALUES(?,?)", mapping.items())
    # Existing schema uses source_evidence_id without declaring every FK. Update
    # all such columns uniformly so no relationship silently points at a removed id.
    for table_row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall():
        table = str(table_row[0])
        if table in {"evidence", "evidence_v3", "evidence_archive", "evidence_map"}:
            continue
        if "source_evidence_id" in _columns(conn, table):
            conn.execute(f"UPDATE {table} SET source_evidence_id=(SELECT canonical_id FROM evidence_map WHERE old_id={table}.source_evidence_id) WHERE source_evidence_id IN (SELECT old_id FROM evidence_map)")
    conn.execute("DROP TABLE evidence")
    conn.execute("ALTER TABLE evidence_v3 RENAME TO evidence")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_status ON evidence(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_evidence_source_identity ON evidence(source_identity_id)")
    conn.execute("DROP TABLE evidence_map")


def _rebuild_modules(conn: sqlite3.Connection) -> None:
    if "identity_key" in _columns(conn, "module"):
        return
    rows = conn.execute("SELECT m.id,m.name,m.binary_id,m.description,m.domain,m.status,m.confidence_id,m.source_evidence_id,b.sha256 FROM module m LEFT JOIN binary b ON b.id=m.binary_id ORDER BY m.id").fetchall()
    conn.execute("DROP INDEX IF EXISTS idx_module_domain")
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute("DROP TABLE IF EXISTS module_v3")
    conn.execute("""CREATE TABLE module_v3 (
      id INTEGER PRIMARY KEY, name TEXT NOT NULL, identity_key TEXT NOT NULL UNIQUE,
      binary_id INTEGER REFERENCES binary(id), description TEXT, domain TEXT,
      status TEXT NOT NULL DEFAULT 'UNKNOWN', confidence_id INTEGER REFERENCES confidence(id),
      source_evidence_id INTEGER
    )""")
    used: set[str] = set()
    for row in rows:
        # Match the importer identity for research-only modules.  The old
        # name-only UNIQUE key did not distinguish source, but a stable
        # research:<name> identity lets the first post-migration import reuse
        # the preserved module row instead of creating a duplicate graph.
        key = f"binary-sha256:{row[8]}:{row[1]}" if row[8] else f"research:{row[1]}"
        if key in used:
            key = f"{key}:module-{row[0]}"
        used.add(key)
        conn.execute("INSERT INTO module_v3(id,name,identity_key,binary_id,description,domain,status,confidence_id,source_evidence_id) VALUES(?,?,?,?,?,?,?,?,?)",
                     (row[0],row[1],key,row[2],row[3],row[4],row[5],row[6],row[7]))
    conn.execute("DROP TABLE module")
    conn.execute("ALTER TABLE module_v3 RENAME TO module")
    conn.execute("CREATE INDEX idx_module_domain ON module(domain)")
    conn.execute("PRAGMA foreign_keys=ON")


def _backfill_classification(conn: sqlite3.Connection) -> None:
    for row in conn.execute("SELECT id,path,format,metadata_json FROM partition ORDER BY id").fetchall():
        path = str(row[1] or "").lower().replace("\\", "/")
        kind = "extracted_directory"
        source_type = "legacy_path_classifier"
        if any(token in path for token in ("backup", "chunk", "part-")):
            kind, source_type = "backup_chunk", "legacy_path_classifier"
        elif path.endswith((".mtd", ".nand", ".img")) and "unpacked" not in path:
            kind, source_type = "physical_nand", "file_image"
        identity = f"{kind}:{path or row[0]}"
        if conn.execute("SELECT 1 FROM partition WHERE identity_key=? LIMIT 1", (identity,)).fetchone():
            identity = f"{identity}:legacy-{row[0]}"
        conn.execute("UPDATE partition SET partition_kind=?,source_type=?,identity_key=? WHERE id=?", (kind,source_type,identity,row[0]))
    for row in conn.execute("SELECT id,binary_id,status FROM function").fetchall():
        origin = "symbol_index" if row[1] is not None and row[2] == "VERIFIED_STATIC" else "candidate"
        conn.execute("UPDATE function SET origin=? WHERE id=?", (origin,row[0]))
    for table, column, expression in (
        ("lifecycle_callback", "callback_key", "printf('%s|%s|%s',module_id,name,coalesce(function_id,0))"),
        ("data_structure", "identity_key", "printf('%s|%s|%s',coalesce(binary_id,0),name,coalesce(base_address,''))"),
        ("event_id", "identity_key", "printf('%s|%s|%s',coalesce(namespace,''),coalesce(value,''),coalesce(name,''))"),
        ("state_transition", "identity_key", "printf('%s|%s|%s|%s|%s',coalesce(machine_id,0),coalesce(from_state_id,0),coalesce(event_id,0),coalesce(to_state_id,0),coalesce(action,''))"),
        ("function", "identity_key", "printf('function:%s:%s:%s:%s',coalesce(binary_id,0),coalesce(module_id,0),coalesce(address,''),coalesce(name,''))"),
    ):
        if column not in _columns(conn, table):
            continue
        conn.execute(f"UPDATE {table} SET {column}={expression} WHERE {column} IS NULL OR {column}=''" )
        duplicates = conn.execute(f"SELECT {column},MIN(id) FROM {table} WHERE {column} IS NOT NULL GROUP BY {column} HAVING COUNT(*)>1").fetchall()
        for key, keep_id in duplicates:
            if table == "function":
                for child_row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall():
                    child = str(child_row[0])
                    if "function_id" in _columns(conn, child):
                        conn.execute(f"UPDATE OR IGNORE {child} SET function_id=? WHERE function_id IN (SELECT id FROM function WHERE {column}=? AND id<>?)", (keep_id, key, keep_id))
            conn.execute(f"DELETE FROM {table} WHERE {column}=? AND id<>?", (key, keep_id))
        conn.execute(f"CREATE UNIQUE INDEX IF NOT EXISTS idx_{table}_{column} ON {table}({column})")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_partition_identity ON partition(identity_key)")


def apply_v3(conn: sqlite3.Connection) -> None:
    """Apply data-aware v3 changes; each operation is safe to resume."""
    _add_column(conn, "binary", "binary_identity_id", "INTEGER REFERENCES binary_identity(id)")
    _add_column(conn, "binary", "inventory_status", "TEXT NOT NULL DEFAULT 'UNQUEUED'")
    _add_column(conn, "binary", "inventory_run_id", "INTEGER")
    _add_column(conn, "partition", "partition_kind", "TEXT NOT NULL DEFAULT 'unknown'")
    _add_column(conn, "partition", "identity_key", "TEXT")
    _add_column(conn, "partition", "source_type", "TEXT")
    _add_column(conn, "function", "origin", "TEXT NOT NULL DEFAULT 'legacy_unknown'")
    _add_column(conn, "function", "analysis_run_id", "INTEGER")
    _add_column(conn, "function", "identity_key", "TEXT")
    _add_column(conn, "lifecycle_callback", "callback_key", "TEXT")
    _add_column(conn, "data_structure", "identity_key", "TEXT")
    _add_column(conn, "event_id", "identity_key", "TEXT")
    _add_column(conn, "state_transition", "identity_key", "TEXT")
    _add_column(conn, "evidence", "source_identity_id", "INTEGER")
    _backfill_source_identities(conn)
    _backfill_binary_identities(conn)
    conn.execute("UPDATE binary SET inventory_status=CASE WHEN analysis_status IS NULL OR analysis_status='UNQUEUED' THEN 'INVENTORIED' ELSE 'INVENTORIED' END WHERE inventory_status='UNQUEUED'")
    _merge_evidence(conn)
    _rebuild_modules(conn)
    _backfill_classification(conn)
