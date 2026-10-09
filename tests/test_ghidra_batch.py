from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fwplatform.cli import main
from fwplatform.db import Database, sha256_file, utc_now
from fwplatform.ghidra_batch import plan_ghidra_batch, run_ghidra_batch


class GhidraBatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "firmware"
        self.root.mkdir()
        self.db = Database(self.base / "analysis.sqlite")
        self.assertEqual(self.db.migrate(), 7)
        self.elfs = []
        for i in range(2):
            elf = self.root / f"lib{i}.so"
            elf.write_bytes(b"synthetic-offline-elf" + bytes([i]))
            digest = sha256_file(elf)
            bid = self.db.upsert("binary", {
                "path": elf.name, "sha256": digest, "size": elf.stat().st_size,
                "format": "elf_executable_or_shared_library",
            }, ("path",))
            self.elfs.append((bid, elf, digest))
        self.db.commit()

    def tearDown(self) -> None:
        self.db.close()
        self.temp.cleanup()

    def test_plan_skips_completed_and_does_not_modify_database(self) -> None:
        first_id, _, first_sha = self.elfs[0]
        self.db.upsert("analysis_run", {
            "binary_id": first_id, "analyzer": "ghidra_headless",
            "analyzer_version": "ghidra:mock", "input_sha256": first_sha,
            "status": "COMPLETE", "integrity_status": "VALIDATED",
            "started_at": utc_now(),
        }, ("binary_id", "analyzer", "analyzer_version", "input_sha256"))
        self.db.commit()
        plan = plan_ghidra_batch(self.db, self.root, limit=1)
        self.assertEqual(plan["selected_count"], 1)
        self.assertEqual(plan["skipped"]["completed"], 1)
        self.assertEqual(plan["selected"][0]["binary_id"], self.elfs[1][0])
        force = plan_ghidra_batch(self.db, self.root, limit=1, force=True)
        self.assertEqual(force["selected"][0]["binary_id"], first_id)
        self.assertEqual(self.db.connection.execute("SELECT COUNT(*) FROM analysis_run").fetchone()[0], 1)

    def test_modified_file_is_not_runnable(self) -> None:
        self.elfs[0][1].write_bytes(b"tampered")
        plan = plan_ghidra_batch(self.db, self.root, limit=2)
        self.assertEqual(plan["selected_count"], 1)
        self.assertEqual(plan["skipped"]["hash_mismatch"], 1)
        with self.assertRaises(ValueError):
            plan_ghidra_batch(self.db, self.root, limit=0)

    def test_plan_ignores_traversal_and_missing_paths(self) -> None:
        self.db.upsert("binary", {
            "path": "../escape.so", "sha256": "a" * 64,
            "format": "elf_executable_or_shared_library",
        }, ("path",))
        self.db.upsert("binary", {
            "path": "missing.so", "sha256": "b" * 64,
            "format": "elf_executable_or_shared_library",
        }, ("path",))
        self.db.commit()
        plan = plan_ghidra_batch(self.db, self.root, limit=3)
        self.assertEqual(plan["skipped"]["unsafe_path"], 1)
        self.assertEqual(plan["skipped"]["unavailable"], 1)

    def test_execution_imports_validated_jsonl_and_resumes(self) -> None:
        ghidra = self.base / "ghidra"
        (ghidra / "support").mkdir(parents=True)
        (ghidra / "support" / "analyzeHeadless.bat").touch()
        projects = self.base / "projects"
        outputs = self.base / "outputs"

        def fake_invoke(_, script, *, ghidra_root, project_dir, binary, output, digest, timeout):
            records = [
                {"kind": "metadata", "run_id": f"ghidra-{digest}",
                 "binary_sha256": digest, "analyzer_version": "mock",
                 "program_identity": {"address_space": "ram"}},
                {"kind": "function", "entry_vma": "0x100",
                 "name": "Camera_capture", "body_bytes": 8},
            ]
            records.append({
                "kind": "complete", "run_id": f"ghidra-{digest}",
                "binary_sha256": digest, "export_status": "complete",
                "record_count": len(records),
            })
            output.write_text("\n".join(json.dumps(x) for x in records) + "\n", encoding="utf-8")

        with patch("fwplatform.ghidra_batch.shutil.which", return_value="pwsh"), \
             patch("fwplatform.ghidra_batch._invoke_wrapper", side_effect=fake_invoke):
            result = run_ghidra_batch(self.db, self.root, output_dir=outputs,
                                      ghidra_root=ghidra, project_dir=projects, limit=2)
        self.assertEqual(result["status"], "COMPLETE")
        self.assertEqual(result["successful"], 2)
        self.assertEqual(self.db.connection.execute(
            "SELECT COUNT(*) FROM function WHERE source_evidence_id IS NOT NULL"
        ).fetchone()[0], 2)
        resumed = plan_ghidra_batch(self.db, self.root, limit=2)
        self.assertEqual(resumed["selected_count"], 0)
        self.assertEqual(resumed["skipped"]["completed"], 2)
        self.assertEqual(self.db.connection.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_plan_cli_never_requires_executable(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["--db", str(self.base / "analysis.sqlite"),
                                   "analyze", "ghidra-batch", "--root",
                                   str(self.root), "--limit", "1", "--json"]), 0)
        self.assertEqual(json.loads(output.getvalue())["selected_count"], 1)


if __name__ == "__main__":
    unittest.main()
