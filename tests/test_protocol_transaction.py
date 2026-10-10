from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fwplatform.db import Database
from fwplatform.jni import import_jni_fixture
from fwplatform.osal import import_osal_fixture


class ProtocolFixtureTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = Database(self.root / "protocol.sqlite")
        self.assertEqual(self.db.migrate(), 7)

    def tearDown(self) -> None:
        self.db.close()
        self.temp.cleanup()

    def _fixture(self, name: str, payload: dict) -> Path:
        path = self.root / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_osal_failed_import_does_not_leave_queue_evidence_or_messages(self) -> None:
        path = self._fixture("osal.json", {
            "status": "VERIFIED_STATIC",
            "queue": {"namespace": "osal-mock", "value": "0x42", "name": "ready"},
            "messages": [{
                "command": {"namespace": "osal-mock", "value": "0x2", "name": "advance"},
                "status": "VERIFIED_STATIC", "direction": "request",
            }],
        })
        real_upsert = self.db.upsert

        def interrupt(table, values, conflict_columns):
            if table == "osal_message":
                raise RuntimeError("synthetic interruption")
            return real_upsert(table, values, conflict_columns)

        with patch.object(self.db, "upsert", side_effect=interrupt):
            with self.assertRaisesRegex(RuntimeError, "synthetic interruption"):
                import_osal_fixture(self.db, path)
        for table in ("evidence", "message_queue", "message_id", "osal_message", "message_flow"):
            self.assertEqual(self.db.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], 0, table)
        self.assertEqual(self.db.connection.execute("PRAGMA foreign_key_check").fetchall(), [])
        self.assertEqual(import_osal_fixture(self.db, path)["messages"], 1)

    def test_jni_failed_import_cannot_leave_orphan_java_or_native_bridge(self) -> None:
        path = self._fixture("jni.json", {
            "status": "VERIFIED_STATIC",
            "java_methods": [{
                "class_name": "com.example.C", "method_name": "run",
                "signature": "()V", "dex_path": "classes.dex",
            }],
            "jni_methods": [{
                "class_name": "com.example.C", "method_name": "run",
                "signature": "()V", "dex_path": "classes.dex",
                "native": {"binary_sha256": "d" * 64, "address": "0x1234"},
            }],
        })
        real_upsert = self.db.upsert

        def interrupt(table, values, conflict_columns):
            if table == "jni_bridge":
                raise RuntimeError("synthetic interruption")
            return real_upsert(table, values, conflict_columns)

        with patch.object(self.db, "upsert", side_effect=interrupt):
            with self.assertRaisesRegex(RuntimeError, "synthetic interruption"):
                import_jni_fixture(self.db, path)
        for table in ("evidence", "java_method", "jni_bridge", "unresolved_edge"):
            self.assertEqual(self.db.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], 0, table)
        self.assertEqual(self.db.connection.execute("PRAGMA foreign_key_check").fetchall(), [])
        self.assertEqual(import_jni_fixture(self.db, path)["jni_bridges"], 1)
        self.assertEqual(self.db.connection.execute("SELECT COUNT(*) FROM jni_bridge").fetchone()[0], 1)

    def test_osal_missing_queue_identity_is_fully_rolled_back(self) -> None:
        path = self._fixture("malformed-osal.json", {
            "queue": {"namespace": "osal-mock"}, "messages": [],
        })
        with self.assertRaises(ValueError):
            import_osal_fixture(self.db, path)
        self.assertEqual(self.db.connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
