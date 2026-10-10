from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from fwplatform.cli import main
from fwplatform.db import Database


class DexIndexTests(unittest.TestCase):
    @staticmethod
    def _sample(path: Path) -> None:
        # Synthetic DEX header and string table; no camera firmware is needed.
        data = bytearray(0x90)
        data[:8] = b"dex\n035\0"
        data[0x20:0x24] = (0x90).to_bytes(4, "little")
        data[0x24:0x28] = (0x70).to_bytes(4, "little")
        data[0x28:0x2C] = (0x12345678).to_bytes(4, "little")
        data[0x38:0x3C] = (1).to_bytes(4, "little")
        data[0x3C:0x40] = (0x70).to_bytes(4, "little")
        data[0x70:0x74] = (0x74).to_bytes(4, "little")
        data[0x74:0x7D] = b"\x08Lcom/X;\0"
        path.write_bytes(data)

    def test_cli_dex_analysis_is_idempotent_and_queryable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db_path, dex = root / "test.sqlite", root / "classes.dex"
            self._sample(dex)
            for _ in range(2):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(main(["--db", str(db_path), "analyze", "dex",
                                           "--path", str(dex), "--json"]), 0)
                result = json.loads(output.getvalue())
                self.assertEqual(result["semantic_status"], "INDEXED_ONLY")
                self.assertEqual(result["descriptor_candidates"], 1)
                self.assertEqual(result["strings"], 1)
                self.assertEqual(result["observations"], 2)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["--db", str(db_path), "query", "dex", "Lcom/X;", "--json"]), 0)
            found = json.loads(output.getvalue())
            self.assertEqual(len(found), 2)
            self.assertEqual({row["status"] for row in found}, {"CANDIDATE", "VERIFIED_STATIC"})
            db = Database(db_path)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM evidence_adapter_run").fetchone()[0], 1)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM research_observation").fetchone()[0], 2)
            self.assertEqual(db.connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            db.close()

    def test_invalid_dex_does_not_create_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db_path, dex = root / "test.sqlite", root / "invalid.dex"
            dex.write_bytes(b"not-a-dex")
            with self.assertRaises(ValueError):
                main(["--db", str(db_path), "analyze", "dex", "--path", str(dex)])
            db = Database(db_path)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM research_observation").fetchone()[0], 0)
            db.close()


if __name__ == "__main__":
    unittest.main()
