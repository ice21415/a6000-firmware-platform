from __future__ import annotations

import sqlite3


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _rebuild_without_legacy_unique(conn: sqlite3.Connection, table: str) -> None:
    """Preserve row IDs, column defaults, FKs and explicit indexes, but drop v1 UNIQUE tuples.

    This is run only with foreign_keys disabled by Database.migrate(). Existing
    references to these row IDs (including OSAL messages) remain valid.
    """
    columns = conn.execute(f"PRAGMA table_info({_quote(table)})").fetchall()
    references = {str(fk[3]): fk for fk in conn.execute(f"PRAGMA foreign_key_list({_quote(table)})")}
    indexes = [row[0] for row in conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name=? AND sql IS NOT NULL",
        (table,),
    ).fetchall()]
    definitions: list[str] = []
    names: list[str] = []
    for column in columns:
        _, name, data_type, not_null, default, primary_key = column
        name = str(name)
        names.append(_quote(name))
        definition = f"{_quote(name)} {data_type or 'TEXT'}"
        if primary_key:
            definition += " PRIMARY KEY"
        if not_null:
            definition += " NOT NULL"
        if default is not None:
            definition += f" DEFAULT {default}"
        if name in references:
            fk = references[name]
            definition += f" REFERENCES {_quote(str(fk[2]))}({_quote(str(fk[4]))})"
            if fk[5] and fk[5] != "NO ACTION":
                definition += f" ON UPDATE {fk[5]}"
            if fk[6] and fk[6] != "NO ACTION":
                definition += f" ON DELETE {fk[6]}"
        definitions.append(definition)
    temp = table + "_v7"
    conn.execute(f"CREATE TABLE {_quote(temp)} ({', '.join(definitions)})")
    columns_sql = ", ".join(names)
    conn.execute(f"INSERT INTO {_quote(temp)} ({columns_sql}) SELECT {columns_sql} FROM {_quote(table)}")
    conn.execute(f"DROP TABLE {_quote(table)}")
    conn.execute(f"ALTER TABLE {_quote(temp)} RENAME TO {_quote(table)}")
    for statement in indexes:
        conn.execute(statement)


def _unique_identity(conn: sqlite3.Connection, table: str, candidates: list[tuple[int, str]]) -> None:
    # Clear all old identities first so an upgrade cannot hit a transient
    # UNIQUE conflict when two historical keys are reordered.
    for row_id, _ in candidates:
        conn.execute(f"UPDATE {_quote(table)} SET identity_key=? WHERE id=?",
                     (f"migration-v7-pending:{table}:{row_id}", row_id))
    used: set[str] = set()
    for row_id, desired in candidates:
        key = desired if desired not in used else f"legacy:{table}:{row_id}"
        used.add(key)
        conn.execute(f"UPDATE {_quote(table)} SET identity_key=? WHERE id=?", (key, row_id))


def apply_v7(conn: sqlite3.Connection) -> None:
    """Repair v1 constraints, preserve historic IDs, and align analyzer identities.

    Historical evidence without a known dependency/DEX identity is kept under
    a distinct legacy key rather than guessing a relationship.
    """
    if conn.execute("PRAGMA foreign_keys").fetchone()[0] != 0:
        raise RuntimeError("schema v7 rebuild requires foreign_keys=OFF")
    if not any(str(c[1]) == "dex_path" for c in conn.execute("PRAGMA table_info(jni_bridge)")):
        conn.execute("ALTER TABLE jni_bridge ADD COLUMN dex_path TEXT")
    for table in ("module_dependency", "message_queue", "jni_bridge"):
        _rebuild_without_legacy_unique(conn, table)

    dependencies = []
    for row in conn.execute("SELECT id,from_module_id,dependency_name,kind FROM module_dependency ORDER BY id"):
        ident = (f"dependency:{row[1]}:{row[2]}" if row[3] == "DT_NEEDED" and row[2]
                 else f"legacy:module_dependency:{row[0]}")
        dependencies.append((int(row[0]), ident))
    _unique_identity(conn, "module_dependency", dependencies)

    queues = []
    for row in conn.execute("SELECT id,namespace,queue_value,address,name FROM message_queue ORDER BY id"):
        value = row[2] or row[3]
        ident = (f"queue:{row[1] or 'unknown'}:{value}:{row[4] or ''}" if value
                 else f"legacy:message_queue:{row[0]}")
        queues.append((int(row[0]), ident))
    _unique_identity(conn, "message_queue", queues)

    bridges = []
    for row in conn.execute("""SELECT j.id,j.class_name,j.method_name,j.signature,
            j.dex_path,j.native_entry,j.address_space,COALESCE(bf.sha256,bm.sha256)
            FROM jni_bridge j
            LEFT JOIN function f ON f.id=j.native_function_id
            LEFT JOIN binary bf ON bf.id=f.binary_id
            LEFT JOIN module m ON m.id=j.module_id
            LEFT JOIN binary bm ON bm.id=m.binary_id ORDER BY j.id"""):
        if row[7]:
            ident = f"jni:{row[1] or ''}:{row[2] or ''}:{row[3] or ''}:{row[4] or ''}:{str(row[7]).lower()}:{row[5] or ''}:{row[6] or ''}"
        else:
            ident = f"legacy:jni_bridge:{row[0]}"
        bridges.append((int(row[0]), ident))
    _unique_identity(conn, "jni_bridge", bridges)

    # v4/v5 rows used a shorter callsite identity than the v6 importer.
    # Reuse canonical keys only where ownership and callsite location are known.
    sites = []
    for row in conn.execute("""SELECT c.id,c.caller_entry,c.address,c.target,c.kind,
            f.binary_id,f.address FROM callsite c LEFT JOIN function f ON f.id=c.caller_id ORDER BY c.id"""):
        entry = row[1] or row[6]
        if row[5] is not None and entry and row[2]:
            ident = f"callsite:{row[5]}:{entry}:{row[2]}:{row[3] or ''}:{row[4] or 'call'}"
            conn.execute("UPDATE callsite SET caller_entry=COALESCE(caller_entry,?) WHERE id=?", (entry, row[0]))
        else:
            ident = f"legacy:callsite:{row[0]}"
        sites.append((int(row[0]), ident))
    _unique_identity(conn, "callsite", sites)

    errors = conn.execute("PRAGMA foreign_key_check").fetchall()
    if errors:
        raise ValueError(f"schema v7 foreign key validation failed ({len(errors)} violations)")
