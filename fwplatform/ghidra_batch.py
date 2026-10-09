"""Bounded, resumable, offline Ghidra batch analysis of inventoried ELF files."""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .db import Database, sha256_file
from .ghidra_importer import import_ghidra_jsonl


MAX_BATCH = 30
MAX_TIMEOUT = 21600


def plan_ghidra_batch(
    db: Database, root: Path, *, limit: int = 5, force: bool = False,
) -> dict[str, Any]:
    """Select a bounded set of ELF files, without invoking any external tool.

    Always verify real file hashes against the inventory, and reject unsafe
    manifest paths. Successful prior imports of identical hashes are skipped.
    """
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_BATCH:
        raise ValueError(f"Ghidra batch limit must be between 1 and {MAX_BATCH}")
    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"Ghidra batch input root is not a directory: {root}")
    rows = db.query("""SELECT id,path,sha256 FROM binary
        WHERE format='elf_executable_or_shared_library' ORDER BY id""")
    selected: list[dict[str, Any]] = []
    skipped = {
        "completed": 0, "unavailable": 0, "unsafe_path": 0,
        "invalid_hash": 0, "hash_mismatch": 0,
    }
    eligible_remaining = 0
    for record in rows:
        bid = int(record["id"])
        rel = str(record["path"] or "").replace("\\", "/")
        digest = str(record["sha256"] or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            skipped["invalid_hash"] += 1
            continue
        if not force and db.connection.execute("""SELECT 1 FROM analysis_run
            WHERE binary_id=? AND analyzer='ghidra_headless'
              AND input_sha256=? AND status='COMPLETE'
              AND integrity_status='VALIDATED' LIMIT 1""", (bid, digest)).fetchone():
            skipped["completed"] += 1
            continue
        if not rel or Path(rel).is_absolute() or ".." in Path(rel).parts or ":" in rel:
            skipped["unsafe_path"] += 1
            continue
        path = (root / rel).resolve()
        if not path.is_relative_to(root):
            skipped["unsafe_path"] += 1
            continue
        if not path.is_file():
            skipped["unavailable"] += 1
            continue
        if len(selected) >= limit:
            eligible_remaining += 1
            continue
        if sha256_file(path) != digest:
            skipped["hash_mismatch"] += 1
            continue
        selected.append({
            "binary_id": bid, "relative_path": rel,
            "binary_sha256": digest, "file_path": str(path),
        })
    return {
        "status": "PLANNED", "input_root": str(root),
        "total_inventory_elfs": len(rows),
        "selected_count": len(selected), "eligible_remaining_estimate": eligible_remaining,
        "skipped": skipped, "force": force,
        "selected": selected,
        "camera_hardware_access": False,
        "rule": "This is a controlled offline ELF analysis batch, not firmware API verification.",
    }


def _invoke_wrapper(
    ps_executable: str, script: Path, *, ghidra_root: Path,
    project_dir: Path, binary: Path, output: Path, digest: str, timeout: int,
) -> None:
    command = [
        ps_executable, "-NoProfile", "-NonInteractive", "-File", str(script),
        "-GhidraRoot", str(ghidra_root), "-ProjectDir", str(project_dir),
        "-ProjectName", f"fw-{digest[:16]}",
        "-Binary", str(binary), "-Output", str(output),
        "-RunId", f"ghidra-{digest}",
    ]
    subprocess.run(command, check=True, timeout=timeout, capture_output=True, text=True)


def run_ghidra_batch(
    db: Database, root: Path, *, output_dir: Path, ghidra_root: Path,
    project_dir: Path, limit: int = 5, force: bool = False,
    timeout: int = 3600,
) -> dict[str, Any]:
    """Execute explicitly requested, bounded Ghidra jobs on local ELF copies.

    Never connects to, patches, or invokes a camera device. Each successfully
    completed JSONL is validated by the existing importer before DB promotion.
    Failed jobs are isolated and reported, not marked as analyzed.
    """
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 60 <= timeout <= MAX_TIMEOUT:
        raise ValueError(f"Ghidra batch timeout must be between 60 and {MAX_TIMEOUT} seconds")
    ghidra_root = ghidra_root.resolve()
    if not (ghidra_root / "support" / "analyzeHeadless.bat").is_file():
        raise ValueError("Ghidra batch requires a local Ghidra support/analyzeHeadless.bat")
    script = Path(__file__).resolve().parents[1] / "tools" / "run-ghidra-headless.ps1"
    if not script.is_file():
        raise ValueError("Ghidra wrapper script is missing")
    executable = shutil.which("pwsh") or shutil.which("powershell")
    if executable is None:
        raise ValueError("Ghidra batch requires pwsh or powershell on the local host")

    plan = plan_ghidra_batch(db, root, limit=limit, force=force)
    output_dir = output_dir.resolve()
    project_dir = project_dir.resolve()
    # Analysis artifacts must not be written under the input firmware root.
    # This also prevents unintended manifest self-ingestion on later scans.
    if output_dir.is_relative_to(Path(plan["input_root"])):
        raise ValueError("Ghidra output directory must be outside the input root")
    if project_dir.is_relative_to(Path(plan["input_root"])):
        raise ValueError("Ghidra project directory must be outside the input root")
    output_dir.mkdir(parents=True, exist_ok=True)
    project_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    for item in plan["selected"]:
        digest = item["binary_sha256"]
        binary = Path(item["file_path"])
        output = output_dir / f"ghidra-{item['binary_id']}-{digest[:16]}.jsonl"
        try:
            # Revalidate immediately before execution to avoid stale manifest.
            if sha256_file(binary) != digest:
                raise ValueError("binary changed before Ghidra execution")
            _invoke_wrapper(executable, script, ghidra_root=ghidra_root,
                            project_dir=project_dir, binary=binary, output=output,
                            digest=digest, timeout=timeout)
            if sha256_file(binary) != digest:
                raise ValueError("binary changed during Ghidra execution")
            if not output.is_file():
                raise ValueError("Ghidra batch produced no JSONL output")
            stats = import_ghidra_jsonl(db, root, binary, output)
            results.append({
                "binary_id": item["binary_id"], "relative_path": item["relative_path"],
                "status": "COMPLETE", "counts": stats,
            })
        except Exception as exc:
            # Keep batch jobs isolated: a malformed file or importer exception
            # must not cause later unrelated ELF analyses to be skipped.
            results.append({
                "binary_id": item["binary_id"], "relative_path": item["relative_path"],
                "status": "FAILED", "error_type": type(exc).__name__,
            })
    return {
        "status": "COMPLETE" if all(item["status"] == "COMPLETE" for item in results)
                 else "PARTIAL_FAILURE",
        "jobs": len(results),
        "successful": sum(item["status"] == "COMPLETE" for item in results),
        "failed": sum(item["status"] == "FAILED" for item in results),
        "skipped": plan["skipped"], "eligible_remaining_estimate": plan["eligible_remaining_estimate"],
        "results": results, "camera_hardware_access": False,
    }
