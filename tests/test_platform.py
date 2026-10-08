from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fwplatform.cli import main
from fwplatform.db import Database
from fwplatform.inventory import classify, parse_elf_header
from fwplatform.inventory import build_manifest
from fwplatform.importer import _status
from fwplatform.ghidra_importer import import_ghidra_jsonl
from fwplatform.db import sha256_file
from fwplatform.importer import import_existing


class PlatformTests(unittest.TestCase):
    def test_migrations_and_status_seed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db = Database(Path(directory) / "test.db")
            self.assertEqual(db.migrate(), 6)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM confidence").fetchone()[0], 6)
            self.assertEqual(db.connection.execute("PRAGMA user_version").fetchone()[0], 6)
            self.assertEqual(db.connection.execute("PRAGMA quick_check").fetchone()[0], "ok")
            self.assertEqual(len(db.connection.execute("PRAGMA foreign_key_check").fetchall()), 0)
            db.close()

    def test_evidence_identity_is_idempotent_and_status_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db = Database(Path(directory) / "test.db")
            db.migrate()
            first = db.evidence("research.json", "a" * 64, "research_json", "document", '{"text":"STATIC"}', "UNKNOWN")
            second = db.evidence("research.json", "a" * 64, "research_json", "document", '{"text":"STATIC"}', "UNKNOWN")
            self.assertEqual(first, second)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0], 1)
            self.assertEqual(_status({"text": "VERIFIED_STATIC prose"}), "UNKNOWN")
            self.assertEqual(_status({"status": "VERIFIED_STATIC"}), "VERIFIED_STATIC")
            db.close()

    def test_ghidra_input_failure_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "sample.so"
            binary.write_bytes(b"sample")
            bad = root / "bad.jsonl"
            bad.write_text("not-json\n", encoding="utf-8")
            db = Database(root / "test.db")
            db.migrate()
            db.connection.execute("INSERT INTO binary(path,sha256,size,format,analysis_status,metadata_json) VALUES(?,?,?,?,?,?)",
                                  ("sample.so", sha256_file(binary), binary.stat().st_size, "elf_executable_or_shared_library", "INVENTORIED", "{}"))
            db.commit()
            with self.assertRaises(ValueError):
                import_ghidra_jsonl(db, root, binary, bad)
            self.assertEqual(db.connection.execute("SELECT status FROM analysis_run WHERE analyzer='ghidra_headless'").fetchone()[0], "FAILED")
            db.close()

    def test_existing_json_import_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            research = root / "firmware-analysis"
            research.mkdir()
            (research / "sample.json").write_text(json.dumps({"status": "CANDIDATE", "value": 1}), encoding="utf-8")
            db = Database(root / "test.db")
            db.migrate()
            first = import_existing(db, root)
            count1 = db.connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
            second = import_existing(db, root)
            count2 = db.connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0]
            self.assertEqual(first["errors"], 0)
            self.assertEqual(second["errors"], 0)
            self.assertEqual(count1, count2)
            db.close()

    def test_classifier_and_elf(self) -> None:
        self.assertEqual(classify(Path("x.dex"), b"dex\n035\0").format, "dex")
        self.assertEqual(classify(Path("lib.so"), b"\x7fELF\x01\x01\x01" + b"\0" * 57).format, "elf_executable_or_shared_library")

    def test_cli_query_empty_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "test.db"
            self.assertEqual(main(["--db", str(db_path), "coverage", "--json"]), 0)

    def test_manifest_checkpoint_reuses_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "input"
            root.mkdir()
            (root / "sample.dex").write_bytes(b"dex\n035\0")
            (root / "opaque.bin").write_bytes(b"opaque")
            db = Database(Path(directory) / "test.db")
            db.migrate()
            first = build_manifest(db, root)
            db.connection.execute("UPDATE binary SET analysis_status='ANALYZED_GHIDRA' WHERE path='sample.dex'")
            db.commit()
            second = build_manifest(db, root)
            self.assertEqual(first["files"], 2)
            self.assertEqual(second["hashed"], 0)
            self.assertEqual(second["reused"], 2)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM binary").fetchone()[0], 2)
            self.assertEqual(db.connection.execute("SELECT analysis_status FROM binary WHERE path='sample.dex'").fetchone()[0], "ANALYZED_GHIDRA")
            db.close()

    def test_manifest_parse_error_does_not_lower_analyzer_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "input"
            root.mkdir()
            malformed = root / "malformed.so"
            malformed.write_bytes(b"\\x7fELF\\x01\\x01\\x01" + b"\\0" * 57)
            db = Database(Path(directory) / "test.db")
            db.migrate()
            build_manifest(db, root)
            db.connection.execute("UPDATE binary SET analysis_status='ANALYZED_GHIDRA' WHERE path='malformed.so'")
            db.commit()
            build_manifest(db, root)
            status = db.connection.execute("SELECT analysis_status FROM binary WHERE path='malformed.so'").fetchone()[0]
            self.assertEqual(status, "ANALYZED_GHIDRA")
            db.close()


if __name__ == "__main__":
    unittest.main()
