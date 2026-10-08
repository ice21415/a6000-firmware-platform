from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from . import __version__
from .constants import STATUSES


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Database:
    """SQLite store with idempotent migrations and small typed helpers."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA journal_mode=WAL")

    def close(self) -> None:
        self.connection.close()

    def migrate(self, migrations_dir: Path | None = None) -> int:
        if migrations_dir is None:
            migrations_dir = Path(__file__).resolve().parents[1] / "database" / "migrations"
        self.connection.execute("CREATE TABLE IF NOT EXISTS schema_migration (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL, tool_version TEXT NOT NULL)")
        current = int(self.connection.execute("PRAGMA user_version").fetchone()[0])
        migrations = sorted(migrations_dir.glob("*.sql"))
        for migration in migrations:
            try:
                version = int(migration.stem.split("_", 1)[0])
            except ValueError:
                continue
            if version <= current:
                continue
            script = migration.read_text(encoding="utf-8")
            if version == 3:
                # v3 rebuilds the module/evidence tables while preserving row
                # IDs. SQLite only accepts this pragma outside a transaction;
                # foreign_key_check is run by the caller before promotion.
                self.connection.commit()
                self.connection.execute("PRAGMA foreign_keys=OFF")
            # The migration table is also created by 001; this outer transaction
            # makes partial schema creation recoverable on the next run.
            try:
                with self.connection:
                    self.connection.executescript(script)
                    if version == 3:
                        from .migration_v3 import apply_v3
                        apply_v3(self.connection)
                    elif version == 4:
                        from .migration_v4 import apply_v4
                        apply_v4(self.connection)
                    self.connection.execute(
                        "INSERT OR REPLACE INTO schema_migration(version, applied_at, tool_version) VALUES(?,?,?)",
                        (version, utc_now(), __version__),
                    )
                    self.connection.execute(f"PRAGMA user_version={version}")
            finally:
                if version == 3:
                    self.connection.commit()
                    self.connection.execute("PRAGMA foreign_keys=ON")
            current = version
        self.seed_confidence()
        return current

    def seed_confidence(self) -> None:
        descriptions = {
            "VERIFIED_STATIC": "Direct instruction, disassembly, or file-format evidence.",
            "VERIFIED_RUNTIME": "Observed in a runtime trace or on-device experiment.",
            "INFERRED": "Supported by multiple evidence items but not completely confirmed.",
            "CANDIDATE": "Plausible candidate awaiting a discriminating test.",
            "UNKNOWN": "No reliable interpretation is currently available.",
            "DISPROVEN": "A prior claim was contradicted by evidence.",
        }
        with self.connection:
            for ordinal, code in enumerate(STATUSES, 1):
                self.connection.execute(
                    "INSERT OR IGNORE INTO confidence(code,description,ordinal) VALUES(?,?,?)",
                    (code, descriptions[code], ordinal),
                )

    def confidence_id(self, status: str) -> int:
        row = self.connection.execute("SELECT id FROM confidence WHERE code=?", (status,)).fetchone()
        if not row:
            raise ValueError(f"invalid evidence status: {status}")
        return int(row[0])

    def insert(self, table: str, values: dict[str, Any], conflict: str = "IGNORE") -> int:
        if not values:
            raise ValueError("cannot insert empty row")
        keys = list(values)
        placeholders = ",".join("?" for _ in keys)
        sql = f"INSERT OR {conflict} INTO {table} ({','.join(keys)}) VALUES ({placeholders})"
        cur = self.connection.execute(sql, [values[k] for k in keys])
        if cur.lastrowid:
            return int(cur.lastrowid)
        where = " AND ".join(f"{k} IS ?" for k in keys)
        row = self.connection.execute(f"SELECT id FROM {table} WHERE {where} LIMIT 1", [values[k] for k in keys]).fetchone()
        return int(row[0]) if row else 0

    def upsert(self, table: str, values: dict[str, Any], conflict_columns: Iterable[str]) -> int:
        keys = list(values)
        update_keys = [key for key in keys if key not in conflict_columns]
        placeholders = ",".join("?" for _ in keys)
        conflict = ",".join(conflict_columns)
        updates = ",".join(f"{key}=excluded.{key}" for key in update_keys)
        sql = f"INSERT INTO {table} ({','.join(keys)}) VALUES ({placeholders}) ON CONFLICT({conflict}) DO UPDATE SET {updates}" if updates else f"INSERT OR IGNORE INTO {table} ({','.join(keys)}) VALUES ({placeholders})"
        self.connection.execute(sql, [values[k] for k in keys])
        # sqlite's lastrowid is undefined for ON CONFLICT DO UPDATE and may
        # retain the id of an unrelated table. Always resolve the row through
        # its declared conflict key so foreign keys remain valid on re-import.
        where = " AND ".join(f"{k} IS ?" for k in conflict_columns)
        row = self.connection.execute(f"SELECT id FROM {table} WHERE {where} LIMIT 1", [values[k] for k in conflict_columns]).fetchone()
        return int(row[0]) if row else 0

    def evidence(self, source_path: str, source_sha256: str | None, kind: str,
                 locator: str | None, excerpt: str | None, status: str,
                 metadata: dict[str, Any] | None = None,
                 evidence_type: str | None = None,
                 status_basis: str = "explicit_parser") -> int:
        status = status if status in STATUSES else "UNKNOWN"
        locator_key = locator or "document"
        identity_key = (f"sha256:{source_sha256.lower()}:{kind or 'unknown'}" if source_sha256
                        else f"path:{source_path}:{kind or 'unknown'}")
        self.connection.execute("INSERT OR IGNORE INTO source_identity(identity_key,source_path,source_sha256,kind,first_seen_at,metadata_json) VALUES(?,?,?,?,?,?)",
                               (identity_key, source_path, source_sha256, kind, utc_now(), "{}"))
        source_identity_id = self.connection.execute("SELECT id FROM source_identity WHERE identity_key=?", (identity_key,)).fetchone()[0]
        excerpt_text = excerpt or ""
        excerpt_hash = hashlib.sha256(excerpt_text.encode("utf-8", "replace")).hexdigest()
        evidence_key = f"{source_identity_id}|{kind or 'unknown'}|{locator_key}|{excerpt_hash}"
        return self.upsert("evidence", {
            "source_path": source_path,
            "source_sha256": source_sha256,
            "kind": kind,
            "locator": locator,
            "locator_key": locator_key,
            "excerpt": excerpt_text,
            "evidence_key": evidence_key,
            "evidence_type": evidence_type or kind or "unknown",
            "status": status,
            "status_basis": status_basis,
            "confidence_id": self.confidence_id(status),
            "created_at": utc_now(),
            "metadata_json": json.dumps(metadata or {}, ensure_ascii=False, sort_keys=True),
            "source_identity_id": source_identity_id,
        }, ("evidence_key",))

    def query(self, sql: str, args: Iterable[Any] = ()) -> list[sqlite3.Row]:
        return list(self.connection.execute(sql, list(args)).fetchall())

    def commit(self) -> None:
        self.connection.commit()
