from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from posixpath import normpath
from typing import Any

from . import __version__
from .db import Database, utc_now

LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class ElfMetadata:
    needed: tuple[str, ...] = ()
    soname: str | None = None
    rpath: tuple[str, ...] = ()
    runpath: tuple[str, ...] = ()
    parse_error: str | None = None


def _module(db: Database, binary_id: int) -> int:
    row = db.connection.execute("SELECT sha256,path FROM binary WHERE id=?", (binary_id,)).fetchone()
    if not row:
        raise ValueError(f"binary {binary_id} missing")
    name = Path(str(row[1])).name
    key = f"binary-sha256:{row[0]}:{name}"
    return db.upsert("module", {"name": name, "identity_key": key, "binary_id": binary_id,
        "description": "ELF linkage observations", "domain": None, "status": "VERIFIED_STATIC",
        "confidence_id": db.confidence_id("VERIFIED_STATIC"), "source_evidence_id": None}, ("identity_key",))


def _elf_metadata(path: Path) -> ElfMetadata:
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError as exc:
        return ElfMetadata(parse_error=f"pyelftools unavailable: {exc}")
    try:
        with path.open("rb") as handle:
            elf = ELFFile(handle)
            needed: list[str] = []
            soname: str | None = None
            rpath: list[str] = []
            runpath: list[str] = []
            dynamic = elf.get_section_by_name(".dynamic")
            if dynamic is not None:
                for tag in dynamic.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        needed.append(str(tag.needed))
                    elif tag.entry.d_tag == "DT_SONAME":
                        soname = str(tag.soname)
                    elif tag.entry.d_tag == "DT_RPATH":
                        rpath.extend(str(tag.rpath).split(":"))
                    elif tag.entry.d_tag == "DT_RUNPATH":
                        runpath.extend(str(tag.runpath).split(":"))
            return ElfMetadata(tuple(dict.fromkeys(needed)), soname, tuple(rpath), tuple(runpath))
    except Exception as exc:  # noqa: BLE001 - malformed ELF is an isolated input
        return ElfMetadata(parse_error=str(exc))


def _path_key(path: str) -> str:
    return normpath(PurePosixPath(path.replace("\\", "/")).as_posix())


def _candidate_search_dirs(requester: str, metadata: ElfMetadata, root: Path) -> set[str]:
    requester_parent = PurePosixPath(_path_key(requester)).parent
    result = {requester_parent.as_posix(), "."}
    for raw in (*metadata.runpath, *metadata.rpath):
        # ORIGIN substitution already anchors the directory at requester_parent.
        origin_expanded = "$ORIGIN" in raw or "${ORIGIN}" in raw
        value = raw.replace("${ORIGIN}", requester_parent.as_posix()).replace("$ORIGIN", requester_parent.as_posix())
        value = value.replace("${LIB}", "lib").replace("$LIB", "lib")
        path = PurePosixPath(value) if value else requester_parent
        if not path.is_absolute() and not origin_expanded:
            path = requester_parent / path
        result.add(_path_key(path.as_posix()).lstrip("/"))
    result.add(root.as_posix())
    return result


def _resolve_needed(requester: str, needed: str, metadata: ElfMetadata,
                   candidates: list[dict[str, Any]], root: Path) -> tuple[int | None, list[int], str]:
    name = Path(needed).name
    soname_matches = [row for row in candidates if row.get("soname") == needed or row.get("soname") == name]
    basename_matches = [row for row in candidates if Path(str(row["path"])).name == name]
    pool = soname_matches or basename_matches
    unique: dict[int, dict[str, Any]] = {int(row["id"]): row for row in pool}
    if len(unique) <= 1:
        only = next(iter(unique), None)
        return only, list(unique), "exact-soname" if soname_matches else "unique-basename"
    search_dirs = _candidate_search_dirs(requester, metadata, root)
    searched = {int(row["id"]): row for row in unique.values()
                if PurePosixPath(_path_key(str(row["path"]))).parent.as_posix() in search_dirs}
    if len(searched) == 1:
        only = next(iter(searched))
        return only, list(unique), "loader-search-path"
    return None, sorted(unique), "ambiguous-soname-or-basename"


def _record_unresolved(db: Database, *, identity: str, from_type: str, from_id: int | None,
                       relation: str, reason: str, candidates: list[int], evidence_id: int) -> None:
    db.upsert("unresolved_edge", {"identity_key": identity, "from_type": from_type, "from_id": from_id,
        "to_type": "binary", "to_id": None, "relation": relation, "reason": reason,
        "status": "CANDIDATE", "source_evidence_id": evidence_id}, ("identity_key",))
    db.connection.execute("UPDATE unresolved_edge SET reason=? WHERE identity_key=?",
                          (json.dumps({"reason": reason, "candidate_binary_ids": candidates}, sort_keys=True), identity))


def _export_index(db: Database) -> dict[tuple[str, str | None], list[dict[str, Any]]]:
    result: dict[tuple[str, str | None], list[dict[str, Any]]] = {}
    for row in db.query("SELECT binary_id,name,address,version FROM import_export WHERE direction='export' AND name IS NOT NULL AND name<>''"):
        result.setdefault((str(row[1]), str(row[3]) if row[3] else None), []).append(dict(row))
    return result


def analyze_linkage(db: Database, root: Path, limit: int | None = None) -> dict[str, int]:
    """Resolve ELF dependencies without basename-based guessing.

    A dependency is promoted only when SONAME/search-path evidence identifies a
    single binary. Ambiguous and missing targets remain unresolved edges with
    their candidate identity set.
    """
    root = root.resolve()
    rows = db.query("SELECT id,path,sha256 FROM binary WHERE format='elf_executable_or_shared_library' ORDER BY id")
    rows = rows[:limit] if limit else rows
    stats = {"binaries": 0, "parsed": 0, "failed": 0, "skipped": 0, "needed": 0,
             "unresolved_dependencies": 0, "ambiguous_dependencies": 0, "resolved_symbols": 0,
             "ambiguous_symbols": 0, "unresolved_symbols": 0}
    candidates: list[dict[str, Any]] = []
    for candidate in db.query("SELECT id,path,sha256 FROM binary WHERE format='elf_executable_or_shared_library' ORDER BY id"):
        path = root / str(candidate[1])
        metadata = _elf_metadata(path) if path.is_file() else ElfMetadata(parse_error="file missing")
        candidates.append({"id": int(candidate[0]), "path": str(candidate[1]), "sha256": str(candidate[2]),
                           "soname": metadata.soname, "metadata": metadata})
    exports = _export_index(db)
    for row in rows:
        stats["binaries"] += 1
        binary_id, rel, digest = int(row[0]), str(row[1]), str(row[2])
        prior = db.connection.execute("SELECT id,status FROM analysis_run WHERE binary_id=? AND analyzer='elf_linkage' AND analyzer_version=? AND input_sha256=?",
                                      (binary_id, __version__, digest)).fetchone()
        if prior and prior["status"] == "COMPLETE":
            stats["skipped"] += 1
            continue
        run_id = db.upsert("analysis_run", {"binary_id": binary_id, "analyzer": "elf_linkage",
            "analyzer_version": __version__, "input_sha256": digest, "started_at": utc_now(),
            "completed_at": None, "status": "RUNNING", "checkpoint": "dynamic", "error_text": None,
            "metadata_json": json.dumps({"path": rel, "resolver": "soname-search-path-v3"}, sort_keys=True)},
            ("binary_id", "analyzer", "analyzer_version", "input_sha256"))
        path = root / rel
        try:
            metadata = _elf_metadata(path)
            if metadata.parse_error:
                raise ValueError(metadata.parse_error)
            stats["parsed"] += 1
            module_id = _module(db, binary_id)
            evidence_excerpt = json.dumps({"binary": rel, "needed": metadata.needed, "soname": metadata.soname,
                                            "rpath": metadata.rpath, "runpath": metadata.runpath}, sort_keys=True)
            evidence_id = db.evidence(rel, digest, "elf_dynamic", "DT_NEEDED", evidence_excerpt,
                                      "VERIFIED_STATIC", {"parser": "pyelftools", "resolver": "soname-search-path-v3"},
                                      evidence_type="elf_dynamic", status_basis="dynamic_tag")
            resolved_dependencies: set[int] = set()
            for needed_name in metadata.needed:
                target_binary, candidate_ids, rule = _resolve_needed(rel, needed_name, metadata, candidates, root)
                identity = f"dependency:{module_id}:{needed_name}"
                if target_binary is None:
                    stats["unresolved_dependencies"] += 1
                    if len(candidate_ids) > 1:
                        stats["ambiguous_dependencies"] += 1
                    _record_unresolved(db, identity=identity, from_type="module", from_id=module_id,
                                       relation="DT_NEEDED", reason=f"{rule}:{needed_name}", candidates=candidate_ids,
                                       evidence_id=evidence_id)
                    continue
                target_module = _module(db, target_binary)
                resolved_dependencies.add(target_binary)
                target_soname = next((str(c["soname"]) for c in candidates if int(c["id"]) == target_binary and c.get("soname")), None)
                db.upsert("module_dependency", {"from_module_id": module_id, "to_module_id": target_module,
                    "kind": "DT_NEEDED", "status": "VERIFIED_STATIC", "source_evidence_id": evidence_id,
                    "identity_key": identity, "dependency_name": needed_name, "target_soname": target_soname,
                    "search_rule": rule, "analyzer_version": __version__,
                    "metadata_json": json.dumps({"candidate_binary_ids": candidate_ids}, sort_keys=True)}, ("identity_key",))
                stats["needed"] += 1
            imports = db.query("SELECT name,address,version FROM import_export WHERE binary_id=? AND direction='import' AND name<>''", [binary_id])
            for symbol_row in imports:
                name, version = str(symbol_row[0]), str(symbol_row[2]) if symbol_row[2] else None
                dependency_exports = [item for item in exports.get((name, version), []) if int(item["binary_id"]) in resolved_dependencies]
                if not dependency_exports and version is not None:
                    dependency_exports = [item for item in exports.get((name, None), []) if int(item["binary_id"]) in resolved_dependencies]
                if not dependency_exports:
                    dependency_exports = exports.get((name, version), []) or exports.get((name, None), [])
                unique = {int(item["binary_id"]): item for item in dependency_exports}
                source_address = str(symbol_row[1])
                identity = f"symbol:{binary_id}:{source_address}:{name}:{version or ''}"
                if len(unique) != 1 or source_address in {"0", "0x0", "None"}:
                    stats["unresolved_symbols"] += 1
                    if len(unique) > 1:
                        stats["ambiguous_symbols"] += 1
                    _record_unresolved(db, identity=identity, from_type="binary", from_id=binary_id,
                                       relation="import_symbol", reason=f"ambiguous-or-unresolved:{name}",
                                       candidates=sorted(unique), evidence_id=evidence_id)
                    continue
                target_binary, target = next(iter(unique.items()))
                db.upsert("cross_reference", {"from_binary_id": binary_id, "from_address": source_address,
                    "to_binary_id": target_binary, "to_address": str(target["address"]), "kind": "resolved_import",
                    "status": "VERIFIED_STATIC", "source_evidence_id": evidence_id},
                    ("from_binary_id", "from_address", "to_binary_id", "to_address", "kind"))
                stats["resolved_symbols"] += 1
            db.connection.execute("UPDATE binary SET candidate_load_paths=? WHERE id=?",
                                  (json.dumps({"soname": metadata.soname, "rpath": metadata.rpath, "runpath": metadata.runpath}, sort_keys=True), binary_id))
            db.connection.execute("UPDATE analysis_run SET completed_at=?,status='COMPLETE',checkpoint=?,error_text=NULL WHERE id=?",
                                  (utc_now(), "imports-resolved", run_id))
        except Exception as exc:  # noqa: BLE001 - one corrupt ELF must not stop the batch
            stats["failed"] += 1
            LOG.warning("linkage failed for %s: %s", rel, exc)
            db.connection.execute("UPDATE analysis_run SET completed_at=?,status='FAILED',checkpoint=?,error_text=? WHERE id=?",
                                  (utc_now(), "error", str(exc), run_id))
    db.commit()
    return stats
