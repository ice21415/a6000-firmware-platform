from __future__ import annotations

import sqlite3


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}


def _add_column(conn: sqlite3.Connection, table: str, name: str, definition: str) -> None:
    if name not in _columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


def apply_v4(conn: sqlite3.Connection) -> None:
    """Add address-space/run provenance for Ghidra CFG observations."""
    for table, name, definition in (
        ("binary", "ghidra_program_identity", "TEXT"),
        ("binary", "ghidra_image_base", "TEXT"),
        ("binary", "ghidra_address_space", "TEXT"),
        ("function", "prototype", "TEXT"),
        ("function", "address_space", "TEXT"),
        ("function", "analysis_run_id", "INTEGER"),
        ("basic_block", "binary_id", "INTEGER REFERENCES binary(id)"),
        ("basic_block", "address_space", "TEXT"),
        ("basic_block", "analysis_run_id", "INTEGER"),
        ("instruction", "binary_id", "INTEGER REFERENCES binary(id)"),
        ("instruction", "address_space", "TEXT"),
        ("instruction", "analysis_run_id", "INTEGER"),
        ("instruction", "source_evidence_id", "INTEGER"),
        ("callsite", "identity_key", "TEXT"),
        ("callsite", "address_space", "TEXT"),
        ("callsite", "analysis_run_id", "INTEGER"),
        ("cross_reference", "from_address_space", "TEXT"),
        ("cross_reference", "to_address_space", "TEXT"),
        ("cross_reference", "analysis_run_id", "INTEGER"),
        ("unresolved_edge", "identity_key", "TEXT"),
    ):
        _add_column(conn, table, name, definition)
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_callsite_identity ON callsite(identity_key)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_instruction_binary_address ON instruction(binary_id,address)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_basic_block_binary_start ON basic_block(binary_id,start_vma)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_xref_from_address ON cross_reference(from_binary_id,from_address)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_xref_to_address ON cross_reference(to_binary_id,to_address)")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_unresolved_edge_identity ON unresolved_edge(identity_key)")
