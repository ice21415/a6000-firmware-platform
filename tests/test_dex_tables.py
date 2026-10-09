from __future__ import annotations

import contextlib
import io
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from analyzers.dex_analyzer import analyze_dex
from fwplatform.cli import main
from fwplatform.db import Database
from fwplatform.dex_index import index_dex


def synthetic_structured_dex(path: Path) -> bytes:
    """Build minimal DEX tables containing a defined and an external class."""
    strings = ["Lcom/example/C;", "V", "run", "Lcom/example/Other;"]
    data = bytearray(0xC8)
    data[:8] = b"dex\n035\0"
    struct.pack_into("<I", data, 0x24, 0x70)  # header_size
    struct.pack_into("<I", data, 0x28, 0x12345678)
    for offset, size, table_offset in (
        (0x38, len(strings), 0x70),
        (0x40, 3, 0x80),
        (0x48, 1, 0x8C),
        (0x58, 2, 0x98),
        (0x60, 1, 0xA8),
    ):
        struct.pack_into("<II", data, offset, size, table_offset)
    for index, string in enumerate(strings):
        struct.pack_into("<I", data, 0x70 + index * 4, len(data))
        data.extend(bytes([len(string)]) + string.encode("ascii") + b"\0")
    for index, string_index in enumerate((0, 1, 3)):
        struct.pack_into("<I", data, 0x80 + index * 4, string_index)
    struct.pack_into("<III", data, 0x8C, 1, 1, 0)  # shorty V, return V, no parameters
    struct.pack_into("<HHI", data, 0x98, 0, 0, 2)  # defined class C.run:()V
    struct.pack_into("<HHI", data, 0xA0, 2, 0, 2)  # external Other.run:()V reference
    struct.pack_into("<II", data, 0xA8, 0, 1)  # class_def for C, public
    struct.pack_into("<I", data, 0x20, len(data))
    path.write_bytes(data)
    return bytes(data)


class DexStructureTests(unittest.TestCase):
    def test_distinguishes_defined_class_from_external_method_reference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dex, sqlite = root / "classes.dex", root / "study.sqlite"
            synthetic_structured_dex(dex)
            parsed = analyze_dex(dex)
            self.assertEqual(parsed["type_descriptors"], [
                "Lcom/example/C;", "V", "Lcom/example/Other;",
            ])
            self.assertEqual(len(parsed["defined_classes"]), 1)
            self.assertEqual(parsed["defined_classes"][0]["descriptor"], "Lcom/example/C;")
            self.assertEqual([x["signature"] for x in parsed["method_references"]], ["()V", "()V"])
            self.assertEqual([x["class_defined_in_dex"] for x in parsed["method_references"]], [True, False])

            for _ in range(2):
                # Explicit lifecycle ensures no SQLite handle persists between runs.
                db = Database(sqlite)
                db.migrate()
                result = index_dex(db, dex)
                self.assertEqual(result["type_ids"], 3)
                self.assertEqual(result["class_defs"], 1)
                self.assertEqual(result["method_references"], 2)
                self.assertEqual(result["observations"], 12)
                db.close()
            result_text = io.StringIO()
            with contextlib.redirect_stdout(result_text):
                self.assertEqual(main(["--db", str(sqlite), "query", "dex", "run", "--json"]), 0)
            matches = json.loads(result_text.getvalue())
            self.assertEqual(sum(x["observation_type"] == "dex_method_reference" for x in matches), 2)
            self.assertTrue(all(x["status"] == "VERIFIED_STATIC" for x in matches))
            db = Database(sqlite)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM research_observation").fetchone()[0], 12)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM evidence_adapter_run").fetchone()[0], 1)
            self.assertEqual(db.connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            # No method implementation or JNI mapping is automatically inferred.
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM java_method").fetchone()[0], 0)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM jni_bridge").fetchone()[0], 0)
            db.close()

    def test_bad_table_indexes_fail_before_persisting_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dex = root / "broken.dex"
            original = synthetic_structured_dex(dex)
            for offset, format_, invalid in ((0x9A, "<H", 99), (0x58, "<I", 999)):
                data = bytearray(original)
                struct.pack_into(format_, data, offset, invalid)
                dex.write_bytes(data)
                with self.assertRaises(ValueError):
                    analyze_dex(dex)
            db = Database(root / "empty.sqlite")
            db.migrate()
            with self.assertRaises(ValueError):
                index_dex(db, dex)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0], 0)
            db.close()

    def test_index_transaction_rolls_back_partial_observations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dex = root / "classes.dex"
            synthetic_structured_dex(dex)
            db = Database(root / "study.sqlite")
            db.migrate()
            original = db.upsert
            written = 0

            def fail_during_insert(table, values, conflict_columns):
                nonlocal written
                if table == "research_observation":
                    written += 1
                    if written == 3:
                        raise RuntimeError("synthetic interrupted index")
                return original(table, values, conflict_columns)

            with patch.object(db, "upsert", side_effect=fail_during_insert):
                with self.assertRaisesRegex(RuntimeError, "synthetic interrupted"):
                    index_dex(db, dex)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0], 0)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM evidence_adapter_run").fetchone()[0], 0)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM research_observation").fetchone()[0], 0)
            self.assertEqual(db.connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            db.close()


if __name__ == "__main__":
    unittest.main()
