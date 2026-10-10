from __future__ import annotations

import sqlite3


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}


def _add_column(conn: sqlite3.Connection, table: str, name: str, definition: str) -> None:
    if name not in _columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


def apply_v6(conn: sqlite3.Connection) -> None:
    """Add address-range ownership and evidence-ingestion provenance."""
    for table, name, definition in (
        ("cfg_edge", "source_instruction_id", "INTEGER REFERENCES instruction(id)"),
        ("cfg_edge", "target_instruction_id", "INTEGER REFERENCES instruction(id)"),
        ("cfg_edge", "source_instruction_address", "TEXT"),
        ("semantic_node", "provenance_kind", "TEXT"),
        ("semantic_edge", "provenance_kind", "TEXT"),
        ("jni_bridge", "direction", "TEXT"),
        ("jni_bridge", "registration_function_id", "INTEGER REFERENCES function(id)"),
        ("jni_bridge", "method_lookup_address", "TEXT"),
    ):
        _add_column(conn, table, name, definition)
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_function_body_range_identity ON function_body_range(identity_key)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cfg_edge_source_instruction ON cfg_edge(source_instruction_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_jni_bridge_direction ON jni_bridge(direction)")
