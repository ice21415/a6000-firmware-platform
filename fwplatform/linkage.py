from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from . import __version__
from .db import Database, sha256_file, utc_now

LOG = logging.getLogger(__name__)


def _module(db: Database, binary_id: int) -> int:
    row = db.connection.execute("SELECT sha256,path FROM binary WHERE id=?", (binary_id,)).fetchone()
    if not row:
        raise ValueError(f"binary {binary_id} missing")
    name = Path(str(row[1])).name
    key = f"binary-sha256:{row[0]}:{name}"
    return db.upsert("module", {"name": name, "identity_key": key, "binary_id": binary_id,
        "description": "ELF linkage observations", "domain": None, "status": "VERIFIED_STATIC",
        "confidence_id": db.confidence_id("VERIFIED_STATIC"), "source_evidence_id": None}, ("identity_key",))


def _elf_needed(path: Path) -> tuple[list[str], str | None]:
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return [], None
    with path.open("rb") as handle:
        elf = ELFFile(handle)
        needed: list[str] = []
        soname: str | None = None
        dynamic = elf.get_section_by_name(".dynamic")
        if dynamic is not None:
            for tag in dynamic.iter_tags():
                if tag.entry.d_tag == "DT_NEEDED":
                    needed.append(str(tag.needed))
                elif tag.entry.d_tag == "DT_SONAME":
                    soname = str(tag.soname)
        return needed, soname


def analyze_linkage(db: Database, root: Path, limit: int | None = None) -> dict[str, int]:
    """Resolve ELF DT_NEEDED edges and unambiguous exported symbols.

    This is a static linker graph.  It never treats a same-named symbol as a
    relation unless there is exactly one export candidate in the inventory.
    """
    root = root.resolve()
    rows = db.query("SELECT id,path,sha256 FROM binary WHERE format='elf_executable_or_shared_library' ORDER BY id")
    rows = rows[:limit] if limit else rows
    stats = {"binaries": 0, "parsed": 0, "failed": 0, "skipped": 0, "needed": 0, "resolved_symbols": 0, "ambiguous_symbols": 0}
    names: dict[str, list[int]] = {}
    for row in db.query("SELECT binary_id,name FROM import_export WHERE direction='export' AND name IS NOT NULL AND name<>''"):
        names.setdefault(str(row[1]), []).append(int(row[0]))
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
            "metadata_json": json.dumps({"path": rel}, sort_keys=True)},
            ("binary_id", "analyzer", "analyzer_version", "input_sha256"))
        path = root / rel
        try:
            needed, soname = _elf_needed(path)
            stats["parsed"] += 1
            module_id = _module(db, binary_id)
            evidence_excerpt = json.dumps({"binary": rel, "needed": needed, "soname": soname}, sort_keys=True)
            evidence_id = db.evidence(rel, digest, "elf_dynamic", "DT_NEEDED", evidence_excerpt,
                                      "VERIFIED_STATIC", {"parser": "pyelftools"}, evidence_type="elf_dynamic",
                                      status_basis="dynamic_tag")
            by_basename: dict[str, int] = {}
            for candidate in db.query("SELECT id,path FROM binary WHERE format='elf_executable_or_shared_library'"):
                by_basename[Path(str(candidate[1])).name] = int(candidate[0])
            for needed_name in needed:
                target_binary = by_basename.get(Path(needed_name).name)
                if target_binary is None:
                    continue
                target_module = _module(db, target_binary)
                db.upsert("module_dependency", {"from_module_id": module_id, "to_module_id": target_module,
                    "kind": "DT_NEEDED", "status": "VERIFIED_STATIC", "source_evidence_id": evidence_id},
                    ("from_module_id", "to_module_id", "kind"))
                stats["needed"] += 1
            for symbol_row in db.query("SELECT name,address FROM import_export WHERE binary_id=? AND direction='import' AND name<>''", [binary_id]):
                candidates = names.get(str(symbol_row[0]), [])
                if len(candidates) != 1:
                    if len(candidates) > 1:
                        stats["ambiguous_symbols"] += 1
                    continue
                target_binary = candidates[0]
                target = db.connection.execute("SELECT address FROM import_export WHERE binary_id=? AND direction='export' AND name=? ORDER BY id LIMIT 1",
                                               (target_binary, symbol_row[0])).fetchone()
                if target is None or str(symbol_row[1]) in {"0", "0x0", "None"}:
                    continue
                db.upsert("cross_reference", {"from_binary_id": binary_id, "from_address": str(symbol_row[1]),
                    "to_binary_id": target_binary, "to_address": str(target[0]), "kind": "resolved_import",
                    "status": "VERIFIED_STATIC", "source_evidence_id": evidence_id},
                    ("from_binary_id", "from_address", "to_binary_id", "to_address", "kind"))
                stats["resolved_symbols"] += 1
            db.connection.execute("UPDATE analysis_run SET completed_at=?,status='COMPLETE',checkpoint=?,error_text=NULL WHERE id=?",
                                  (utc_now(), "imports-resolved", run_id))
        except Exception as exc:  # noqa: BLE001 - one corrupt ELF must not stop the batch
            stats["failed"] += 1
            LOG.warning("linkage failed for %s: %s", rel, exc)
            db.connection.execute("UPDATE analysis_run SET completed_at=?,status='FAILED',checkpoint=?,error_text=? WHERE id=?",
                                  (utc_now(), "error", str(exc), run_id))
    db.commit()
    return stats
