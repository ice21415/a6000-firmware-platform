from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from fwplatform.db import Database
from fwplatform.jni import import_jni_fixture
from fwplatform.osal import import_osal_fixture


class IdentityUpgradeTests(unittest.TestCase):
    def test_v6_upgrade_keeps_rows_and_reconciles_analyzer_identities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            historical = root / "old-migrations"
            historical.mkdir()
            migrations = Path(__file__).resolve().parents[1] / "database" / "migrations"
            for script in migrations.glob("*.sql"):
                if int(script.name.split("_", 1)[0]) <= 6:
                    shutil.copyfile(script, historical / script.name)

            db = Database(root / "history.sqlite")
            self.assertEqual(db.migrate(historical), 6)
            binaries = []
            modules = []
            for index in range(1, 4):
                digest = str(index) * 64
                bid = db.upsert("binary", {
                    "path": f"lib{index}.so", "sha256": digest, "size": 100,
                    "format": "elf_executable_or_shared_library", "analysis_status": "INVENTORIED",
                }, ("path",))
                mid = db.upsert("module", {
                    "name": f"lib{index}.so", "identity_key": f"fixture:module:{index}",
                    "binary_id": bid, "status": "VERIFIED_STATIC",
                }, ("identity_key",))
                binaries.append((bid, digest))
                modules.append(mid)
            funcs = []
            for index in (0, 1):
                fid = db.upsert("function", {
                    "binary_id": binaries[index][0], "module_id": modules[index],
                    "identity_key": f"fixture:fn:{index}", "name": "nativeRun",
                    "address": "0x100", "status": "VERIFIED_STATIC",
                }, ("identity_key",))
                funcs.append(fid)
            dep_id = db.upsert("module_dependency", {
                "from_module_id": modules[0], "to_module_id": modules[1],
                "kind": "DT_NEEDED", "dependency_name": "lib2.so",
                "identity_key": f"dependency:{modules[0]}:{modules[1]}:DT_NEEDED:lib2.so",
            }, ("identity_key",))
            queue_id = db.upsert("message_queue", {
                "module_id": modules[0], "name": "work", "address": "0x7",
                "namespace": "alpha", "queue_value": "0x7",
                "identity_key": "queue:legacy:test",
            }, ("identity_key",))
            bridge_id = db.upsert("jni_bridge", {
                "class_name": "com.example.Run", "method_name": "run",
                "signature": "()V", "native_entry": "0x100", "module_id": modules[0],
                "native_function_id": funcs[0], "identity_key": "jni:legacy:test",
            }, ("identity_key",))
            site_id = db.upsert("callsite", {
                "caller_id": funcs[0], "address": "0x105", "target": "0x200",
                "kind": "call", "identity_key": "callsite:legacy:test",
            }, ("identity_key",))
            db.commit()

            self.assertEqual(db.migrate(), 7)
            self.assertEqual(db.connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(db.connection.execute("PRAGMA quick_check").fetchone()[0], "ok")
            for table, row_id in (("module_dependency", dep_id), ("message_queue", queue_id),
                                  ("jni_bridge", bridge_id), ("callsite", site_id)):
                self.assertEqual(db.connection.execute(f"SELECT id FROM {table} WHERE id=?", (row_id,)).fetchone()[0], row_id)
            self.assertEqual(db.connection.execute(
                "SELECT identity_key FROM callsite WHERE id=?", (site_id,)
            ).fetchone()[0], f"callsite:{binaries[0][0]}:0x100:0x105:0x200:call")

            # Old dependency must be updated, not duplicated or rejected by a
            # now-obsolete UNIQUE(from_module_id,to_module_id,kind) constraint.
            same_id = db.upsert("module_dependency", {
                "from_module_id": modules[0], "to_module_id": modules[2],
                "kind": "DT_NEEDED", "dependency_name": "lib2.so",
                "identity_key": f"dependency:{modules[0]}:lib2.so",
            }, ("identity_key",))
            self.assertEqual(same_id, dep_id)
            self.assertEqual(db.connection.execute(
                "SELECT to_module_id FROM module_dependency WHERE id=?", (dep_id,)
            ).fetchone()[0], modules[2])

            # Identical queue value, module and name may be different protocols.
            second = db.upsert("message_queue", {
                "module_id": modules[0], "name": "work", "address": "0x7",
                "namespace": "beta", "queue_value": "0x7",
                "identity_key": "queue:beta:0x7:work",
            }, ("identity_key",))
            self.assertNotEqual(second, queue_id)

            # Repeated native virtual address across two distinct ELFs must
            # not rewrite the first firmware's JNI mapping.
            fixture = root / "jni.json"
            for index in (0, 1):
                fixture.write_text(json.dumps({
                    "status": "VERIFIED_STATIC",
                    "java_methods": [{
                        "class_name": "com.example.Run", "method_name": "run",
                        "signature": "()V", "dex_path": f"classes{index}.dex",
                    }],
                    "jni_methods": [{
                        "class_name": "com.example.Run", "method_name": "run",
                        "signature": "()V", "dex_path": f"classes{index}.dex",
                        "native": {"binary_sha256": binaries[index][1], "address": "0x100"},
                        "status": "VERIFIED_STATIC",
                    }],
                }), encoding="utf-8")
                self.assertEqual(import_jni_fixture(db, fixture)["resolved_native"], 1)
                self.assertEqual(import_jni_fixture(db, fixture)["resolved_native"], 1)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM jni_bridge").fetchone()[0], 3)
            for index in (0, 1):
                self.assertEqual(db.connection.execute(
                    "SELECT native_function_id FROM jni_bridge WHERE dex_path=?",
                    (f"classes{index}.dex",),
                ).fetchone()[0], funcs[index])
            self.assertEqual(db.connection.execute(
                "SELECT native_function_id FROM jni_bridge WHERE id=?", (bridge_id,)
            ).fetchone()[0], funcs[0])
            self.assertEqual(db.connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            db.close()

    def test_namespaced_osal_fixtures_have_independent_queue_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db = Database(root / "test.sqlite")
            self.assertEqual(db.migrate(), 7)
            for namespace in ("alpha", "beta"):
                fixture = root / (namespace + ".json")
                fixture.write_text(json.dumps({
                    "status": "VERIFIED_STATIC",
                    "queue": {"namespace": namespace, "value": "0x7", "name": "work"},
                    "messages": [],
                }), encoding="utf-8")
                self.assertEqual(import_osal_fixture(db, fixture)["queue"], 1)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM message_queue").fetchone()[0], 2)
            db.close()


if __name__ == "__main__":
    unittest.main()
