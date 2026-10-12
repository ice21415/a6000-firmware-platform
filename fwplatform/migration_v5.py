from __future__ import annotations

import sqlite3


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}


def _add_column(conn: sqlite3.Connection, table: str, name: str, definition: str) -> None:
    if name not in _columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


def apply_v5(conn: sqlite3.Connection) -> None:
    """Add stable identities and provenance used by Phase 3 analyzers."""
    additions = (
        ("module_dependency", "identity_key", "TEXT"),
        ("module_dependency", "dependency_name", "TEXT"),
        ("module_dependency", "target_soname", "TEXT"),
        ("module_dependency", "search_rule", "TEXT"),
        ("module_dependency", "analyzer_version", "TEXT"),
        ("module_dependency", "metadata_json", "TEXT"),
        ("callsite", "caller_entry", "TEXT"),
        ("callsite", "target_address_space", "TEXT"),
        ("callsite", "caller_resolution", "TEXT"),
        ("callsite", "analyzer_version", "TEXT"),
        ("import_export", "version", "TEXT"),
        ("import_export", "identity_key", "TEXT"),
        ("import_export", "analyzer_version", "TEXT"),
        ("message_queue", "identity_key", "TEXT"),
        ("message_queue", "namespace", "TEXT"),
        ("message_queue", "queue_value", "TEXT"),
        ("message_queue", "semantics", "TEXT"),
        ("message_queue", "callback_function_id", "INTEGER"),
        ("message_queue", "address_space", "TEXT"),
        ("message_queue", "analyzer_version", "TEXT"),
        ("message_id", "identity_key", "TEXT"),
        ("message_id", "command_kind", "TEXT"),
        ("message_id", "payload_layout", "TEXT"),
        ("jni_bridge", "identity_key", "TEXT"),
        ("jni_bridge", "native_function_id", "INTEGER"),
        ("jni_bridge", "address_space", "TEXT"),
        ("jni_bridge", "analyzer_version", "TEXT"),
        ("java_method", "identity_key", "TEXT"),
        ("java_method", "namespace", "TEXT"),
        ("java_method", "analyzer_version", "TEXT"),
        ("analysis_run", "run_key", "TEXT"),
        ("analysis_run", "jsonl_sha256", "TEXT"),
        ("analysis_run", "record_count", "INTEGER"),
        ("analysis_run", "integrity_status", "TEXT"),
        ("binary", "candidate_load_paths", "TEXT"),
    )
    for table, name, definition in additions:
        _add_column(conn, table, name, definition)

    seen: set[str] = set()
    rows = conn.execute("SELECT id,from_module_id,to_module_id,kind,dependency_name FROM module_dependency ORDER BY id").fetchall()
    for row in rows:
        key = f"dependency:{row[1]}:{row[2] or 0}:{row[3] or 'unknown'}:{row[4] or ''}"
        if key in seen:
            key = f"{key}:legacy-{row[0]}"
        seen.add(key)
        conn.execute("UPDATE module_dependency SET identity_key=? WHERE id=? AND (identity_key IS NULL OR identity_key='')", (key, row[0]))
    seen = set()
    rows = conn.execute("SELECT id,binary_id,name,direction,address FROM import_export ORDER BY id").fetchall()
    for row in rows:
        key = f"import-export:{row[1] or 0}:{row[3] or ''}:{row[2] or ''}:{row[4] or ''}"
        if key in seen:
            key = f"{key}:legacy-{row[0]}"
        seen.add(key)
        conn.execute("UPDATE import_export SET identity_key=? WHERE id=? AND (identity_key IS NULL OR identity_key='')", (key, row[0]))
    seen = set()
    rows = conn.execute("SELECT id,module_id,name,address FROM message_queue ORDER BY id").fetchall()
    for row in rows:
        key = f"queue:{row[1] or 0}:{row[2] or ''}:{row[3] or ''}"
        if key in seen:
            key = f"{key}:legacy-{row[0]}"
        seen.add(key)
        conn.execute("UPDATE message_queue SET identity_key=? WHERE id=? AND (identity_key IS NULL OR identity_key='')", (key, row[0]))
    seen = set()
    rows = conn.execute("SELECT id,namespace,value,name FROM message_id ORDER BY id").fetchall()
    for row in rows:
        key = f"message-id:{row[1] or ''}:{row[2] or ''}:{row[3] or ''}"
        if key in seen:
            key = f"{key}:legacy-{row[0]}"
        seen.add(key)
        conn.execute("UPDATE message_id SET identity_key=? WHERE id=? AND (identity_key IS NULL OR identity_key='')", (key, row[0]))
    seen = set()
    rows = conn.execute("SELECT id,class_name,method_name,signature,native_entry FROM jni_bridge ORDER BY id").fetchall()
    for row in rows:
        key = f"jni:{row[1] or ''}:{row[2] or ''}:{row[3] or ''}:{row[4] or ''}"
        if key in seen:
            key = f"{key}:legacy-{row[0]}"
        seen.add(key)
        conn.execute("UPDATE jni_bridge SET identity_key=? WHERE id=? AND (identity_key IS NULL OR identity_key='')", (key, row[0]))
    seen = set()
    rows = conn.execute("SELECT id,class_name,method_name,signature,dex_path FROM java_method ORDER BY id").fetchall()
    for row in rows:
        key = f"java:{row[1] or ''}:{row[2] or ''}:{row[3] or ''}:{row[4] or ''}"
        if key in seen:
            key = f"{key}:legacy-{row[0]}"
        seen.add(key)
        conn.execute("UPDATE java_method SET identity_key=? WHERE id=? AND (identity_key IS NULL OR identity_key='')", (key, row[0]))
    rows = conn.execute("SELECT id,caller_id,address,target FROM callsite ORDER BY id").fetchall()
    for row in rows:
        binary_id = conn.execute("SELECT binary_id FROM function WHERE id=?", (row[1],)).fetchone()
        key = f"callsite:{binary_id[0] if binary_id else 0}:{row[2] or ''}:{row[3] or ''}:{row[1] or 0}"
        conn.execute("UPDATE callsite SET identity_key=COALESCE(identity_key,?),caller_entry=COALESCE(caller_entry,(SELECT address FROM function WHERE id=?)) WHERE id=?", (key, row[1], row[0]))
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_module_dependency_identity ON module_dependency(identity_key)")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_import_export_identity ON import_export(identity_key)")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_message_queue_identity ON message_queue(identity_key)")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_message_id_identity ON message_id(identity_key)")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_jni_bridge_identity ON jni_bridge(identity_key)")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_java_method_identity ON java_method(identity_key)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_callsite_caller_entry ON callsite(caller_entry,address_space)")
