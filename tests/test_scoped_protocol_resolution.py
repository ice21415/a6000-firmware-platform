from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fwplatform.db import Database
from fwplatform.jni import import_jni_fixture
from fwplatform.osal import import_osal_fixture


class ProvenanceScopedResolutionTests(unittest.TestCase):
    def test_jni_and_osal_never_guess_function_from_unscoped_address(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db = Database(root / "study.sqlite")
            self.assertEqual(db.migrate(), 7)
            names = ("first.so", "second.so")
            for i, name in enumerate(names):
                binary_id = db.upsert("binary", {
                    "path": name, "sha256": str(i+1) * 64, "size": 16,
                    "format": "elf_executable_or_shared_library",
                }, ("path",))
                db.upsert("function", {
                    "identity_key": f"fn:{name}:0x100", "binary_id": binary_id,
                    "name": "same_name", "address": "0x100",
                }, ("identity_key",))
            db.commit()

            jni = root / "jni.json"
            jni.write_text(json.dumps({
                "java_methods": [{
                    "class_name": "com.example.C", "method_name": "call",
                    "signature": "()V", "dex_path": "classes.dex",
                }],
                "jni_methods": [{
                    "class_name": "com.example.C", "method_name": "call",
                    "signature": "()V", "dex_path": "classes.dex",
                    "native": {"name": "same_name", "address": "0x100"},
                    "status": "VERIFIED_STATIC",
                }],
            }), encoding="utf-8")
            out = import_jni_fixture(db, jni)
            self.assertEqual(out["resolved_native"], 0)
            self.assertEqual(db.connection.execute(
                "SELECT native_function_id FROM jni_bridge"
            ).fetchone()[0], None)

            osal = root / "osal.json"
            osal.write_text(json.dumps({
                "queue": {"namespace": "mock", "value": "0x11", "name": "queue"},
                "messages": [{
                    "command": {"namespace": "mock", "value": "0x42", "name": "push"},
                    "producer": {"name": "same_name", "address": "0x100"},
                    "status": "VERIFIED_STATIC",
                }],
            }), encoding="utf-8")
            out = import_osal_fixture(db, osal)
            self.assertEqual(out["unresolved"], 1)
            self.assertEqual(db.connection.execute(
                "SELECT producer_function_id FROM osal_message"
            ).fetchone()[0], None)
            self.assertEqual(db.connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            db.close()


if __name__ == "__main__":
    unittest.main()
