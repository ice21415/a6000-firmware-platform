"""Read-only comparison between report-only Camera SDK leads and local SQLite indexes.

Never migrates databases, writes firmware, or treats an imported row as proof
of callable ABI. Exact ELF identity and numeric VMA uniqueness are required.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import quote


def _number(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    try:
        n = int(str(value).strip(), 0)
    except ValueError:
        return None
    return n if n > 0 else None


def crosscheck_camera_database(
    db_path: Path, sha: str, functions: dict[str, dict[str, Any]],
    calls: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compare exact binary and function identities without ever mutating DB."""
    path = db_path.resolve()
    if not path.is_file():
        raise FileNotFoundError(f"research database does not exist: {path}")
    uri = "file:" + quote(path.as_posix(), safe="/:") + "?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA query_only=ON")
        binaries = list(conn.execute("SELECT id FROM binary WHERE lower(sha256)=? ORDER BY id", (sha,)))
        identity = ("UNIQUE_ELF_SHA" if len(binaries) == 1
                    else "ELF_SHA_NOT_INDEXED" if not binaries else "AMBIGUOUS_ELF_SHA")
        entry_rows: dict[int, list[sqlite3.Row]] = {}
        if len(binaries) == 1:
            for row in conn.execute(
                "SELECT id,address,name,source_evidence_id FROM function WHERE binary_id=? ORDER BY id",
                (binaries[0]["id"],),
            ):
                numeric = _number(row["address"])
                if numeric is not None:
                    entry_rows.setdefault(numeric, []).append(row)
        matches: dict[str, dict[str, Any]] = {}
        for name, candidate in functions.items():
            addr = _number(candidate["address"])
            owners = entry_rows.get(addr, []) if addr is not None else []
            status = ("BINARY_IDENTITY_UNRESOLVED" if len(binaries) != 1 else
                      "ENTRY_NOT_INDEXED" if not owners else
                      "AMBIGUOUS_ENTRY" if len(owners) != 1 else "UNIQUE_INDEXED_ENTRY")
            matches[name] = {
                "name": name, "address": candidate["address"], "status": status,
                "function_id": int(owners[0]["id"]) if len(owners) == 1 else None,
                "index_source_evidence_id": owners[0]["source_evidence_id"] if len(owners) == 1 else None,
                "abi_verified": False,
            }
        call_matches: list[dict[str, Any]] = []
        for edge in calls:
            caller = matches[edge["caller"]]["function_id"]
            callee = matches[edge["callee"]]["function_id"]
            if caller is None or callee is None:
                status = "ENTRY_UNRESOLVED"
                call_rows: list[sqlite3.Row] = []
            else:
                call_rows = list(conn.execute(
                    "SELECT id,caller_id,callee_id,address,source_evidence_id,status "
                    "FROM callsite WHERE caller_id=? ORDER BY id", (caller,),
                ))
                call_rows = [x for x in call_rows if _number(x["address"]) == _number(edge["callsite"])]
                status = ("CALLSITE_NOT_INDEXED" if not call_rows else
                          "AMBIGUOUS_CALLSITE" if len(call_rows) != 1 else
                          "CALLEE_ID_MISMATCH" if call_rows[0]["callee_id"] != callee else
                          "INDEXED_TARGET_ID_MATCH")
            call_matches.append({
                "caller": edge["caller"], "callee": edge["callee"],
                "callsite": edge["callsite"], "status": status,
                "callsite_id": int(call_rows[0]["id"]) if len(call_rows) == 1 else None,
                "callsite_evidence_id": call_rows[0]["source_evidence_id"] if len(call_rows) == 1 else None,
                "independent_abi_verified": False,
            })
        return {
            "status": "READ_ONLY_INDEX_CROSSCHECK",
            "database": str(path),
            "binary_identity": identity,
            "binary_match_count": len(binaries),
            "entries": list(matches.values()),
            "calls": call_matches,
            "unique_indexed_function_entries": sum(
                x["status"] == "UNIQUE_INDEXED_ENTRY" for x in matches.values()),
            "indexed_matching_callee_ids": sum(
                x["status"] == "INDEXED_TARGET_ID_MATCH" for x in call_matches),
            "note": "DB function/callsite rows are indexing evidence, not verified ABI or device callability.",
        }
    finally:
        conn.close()
