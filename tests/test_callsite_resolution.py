from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fwplatform.db import Database, sha256_file
from fwplatform.ghidra_importer import import_ghidra_jsonl


class CallsiteResolutionTests(unittest.TestCase):
    def test_caller_resolution_updates_original_callsite_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary, jsonl = root / "sample.so", root / "export.jsonl"
            binary.write_bytes(b"synthetic")
            digest = sha256_file(binary)
            db = Database(root / "test.sqlite")
            self.assertEqual(db.migrate(), 7)
            db.connection.execute(
                "INSERT INTO binary(path,sha256,size,format,analysis_status,metadata_json) VALUES(?,?,?,?,?,?)",
                (binary.name, digest, binary.stat().st_size,
                 "elf_executable_or_shared_library", "INVENTORIED", "{}"),
            )
            db.commit()

            def ingest(run_id: str, with_ranges: bool) -> None:
                records = [
                    {"kind": "metadata", "run_id": run_id,
                     "binary_sha256": digest, "analyzer_version": "12.1.3",
                     "program_identity": {"address_space": "ram"}},
                    {"kind": "function", "entry_vma": "0x100",
                     "name": "caller", "body_bytes": 16},
                    {"kind": "function", "entry_vma": "0x300",
                     "name": "callee", "body_bytes": 16},
                ]
                if with_ranges:
                    records.append({"kind": "function_body_range", "function_entry": "0x100",
                                    "start_vma": "0x180", "end_vma": "0x190",
                                    "address_space": "ram"})
                records.append({"kind": "callsite", "function_entry": "0x100",
                                "from_address": "0x185", "to_address": "0x300",
                                "callee_entry": "0x300", "relation_kind": "direct_call"})
                records.append({"kind": "complete", "run_id": run_id,
                                "binary_sha256": digest, "record_count": len(records),
                                "export_status": "complete"})
                jsonl.write_text("\n".join(json.dumps(item) for item in records) + "\n",
                                 encoding="utf-8")
                import_ghidra_jsonl(db, root, binary, jsonl)

            ingest("no-range", False)
            first = db.connection.execute(
                "SELECT id,caller_id,identity_key FROM callsite"
            ).fetchone()
            self.assertIsNone(first["caller_id"])
            ingest("range-recovered", True)
            second = db.connection.execute(
                "SELECT id,caller_id,identity_key FROM callsite"
            ).fetchone()
            self.assertEqual(second["id"], first["id"])
            self.assertEqual(second["identity_key"], first["identity_key"])
            self.assertIsNotNone(second["caller_id"])
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM callsite").fetchone()[0], 1)
            self.assertEqual(db.connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            db.close()


if __name__ == "__main__":
    unittest.main()
