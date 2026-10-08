from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from fwplatform import __version__
from fwplatform.db import Database, utc_now
from .elf_analyzer import analyze_elf

LOG = logging.getLogger(__name__)


def run_elf_batch(db: Database, root: Path, limit: int | None = None) -> dict[str, int]:
    rows = db.query("SELECT id,path,sha256 FROM binary WHERE format='elf_executable_or_shared_library' ORDER BY id")
    stats = {"queued": 0, "skipped": 0, "complete": 0, "failed": 0, "functions": 0, "imports": 0, "exports": 0}
    for row in rows[:limit] if limit else rows:
        stats["queued"] += 1
        binary_id, rel, digest = int(row["id"]), str(row["path"]), str(row["sha256"])
        prior = db.connection.execute("SELECT status FROM analysis_run WHERE binary_id=? AND analyzer=? AND analyzer_version=? AND input_sha256=?",
                                      (binary_id, "python_elf_index", __version__, digest)).fetchone()
        if prior and prior["status"] == "COMPLETE":
            stats["skipped"] += 1
            continue
        run_id = db.upsert("analysis_run", {"binary_id": binary_id, "analyzer": "python_elf_index",
            "analyzer_version": __version__, "input_sha256": digest, "started_at": utc_now(),
            "completed_at": None, "status": "RUNNING", "checkpoint": "header", "error_text": None,
            "metadata_json": "{}"}, ("binary_id", "analyzer", "analyzer_version", "input_sha256"))
        try:
            result = analyze_elf(root / rel)
            identity_key = f"binary-sha256:{digest}:{Path(rel).name}"
            existing_module = db.connection.execute("SELECT id FROM module WHERE identity_key=?", (identity_key,)).fetchone()
            if existing_module:
                module_id = int(existing_module[0])
            else:
                module_id = db.upsert("module", {"name": Path(rel).name, "binary_id": binary_id, "description": "ELF symbol/linkage index",
                    "identity_key": identity_key,
                    "domain": None, "status": "VERIFIED_STATIC", "confidence_id": db.confidence_id("VERIFIED_STATIC"),
                    "source_evidence_id": None}, ("identity_key",))
            for symbol in result["symbols"]:
                db.upsert("symbol", {"binary_id": binary_id, "name": symbol["name"], "address": symbol["address"],
                    "size": symbol["size"], "type": symbol["type"], "binding": symbol["bind"], "section": symbol["section"],
                    "status": "VERIFIED_STATIC"}, ("binary_id", "name", "address"))
            for func in result["functions"]:
                function_key = f"function:{binary_id}:{module_id}:{func['address']}:{func['name']}"
                existing_function = db.connection.execute("SELECT id FROM function WHERE binary_id IS ? AND address IS ? AND name IS ? LIMIT 1",
                                                           (binary_id, func["address"], func["name"])).fetchone()
                function_values = {"binary_id": binary_id, "module_id": module_id, "name": func["name"],
                    "identity_key": function_key,
                    "address": func["address"], "size": func["size"], "calling_convention": None, "thumb_mode": None,
                    "vma": func["address"], "runtime_va": None, "physical_offset": None, "wbi_offset": None,
                    "status": "VERIFIED_STATIC", "confidence_id": db.confidence_id("VERIFIED_STATIC"),
                    "source_evidence_id": None, "generated_name": 0, "origin": "elf_symbol_index",
                    "analysis_run_id": run_id}
                if existing_function:
                    db.connection.execute("UPDATE function SET module_id=?,identity_key=?,origin=?,analysis_run_id=?,status=?,confidence_id=? WHERE id=?",
                                          (module_id, function_key, "elf_symbol_index", run_id, "VERIFIED_STATIC", db.confidence_id("VERIFIED_STATIC"), existing_function[0]))
                else:
                    db.upsert("function", function_values, ("identity_key",))
            for direction, key in (("import", "imports"), ("export", "exports")):
                for symbol in result[key]:
                    db.upsert("import_export", {"binary_id": binary_id, "name": symbol["name"], "direction": direction,
                        "address": symbol["address"], "library": None, "status": "VERIFIED_STATIC", "source_evidence_id": None},
                        ("binary_id", "name", "direction", "address"))
            for relocation in result["relocations"]:
                db.upsert("relocation", {"binary_id": binary_id, "offset": relocation["offset"], "type": relocation["type"],
                    "symbol": str(relocation["symbol_index"]), "addend": None, "status": "VERIFIED_STATIC"},
                    ("binary_id", "offset", "type", "symbol"))
            db.connection.execute("UPDATE binary SET analysis_status='ANALYZED_ELF_SYMBOLS' WHERE id=?", (binary_id,))
            db.connection.execute("UPDATE analysis_run SET completed_at=?,status='COMPLETE',checkpoint=?,metadata_json=? WHERE id=?",
                                  (utc_now(), "symbols-linkage", json.dumps({"functions": len(result["functions"])}), run_id))
            stats["complete"] += 1; stats["functions"] += len(result["functions"])
            stats["imports"] += len(result["imports"]); stats["exports"] += len(result["exports"])
        except Exception as exc:  # noqa: BLE001 - continue batch and retain blocker
            stats["failed"] += 1
            LOG.warning("ELF analysis failed for %s: %s", rel, exc)
            db.connection.execute("UPDATE analysis_run SET completed_at=?,status='FAILED',checkpoint=?,error_text=? WHERE id=?",
                                  (utc_now(), "error", str(exc), run_id))
    db.commit()
    return stats
