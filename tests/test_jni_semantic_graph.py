from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fwplatform.db import Database
from fwplatform.semantic_graph import sync_semantic_graph


class JniSemanticGraphTests(unittest.TestCase):
    def test_bridge_requires_exact_dex_and_matching_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db = Database(Path(directory) / "test.sqlite")
            self.assertEqual(db.migrate(), 7)
            evidences = [
                db.evidence(f"fixture-{i}.json", str(i) * 64, "jni_fixture", "document",
                            f"fixture-{i}", "VERIFIED_STATIC")
                for i in (1, 2)
            ]
            for i, evidence_id in enumerate(evidences):
                db.upsert("java_method", {
                    "identity_key": f"java:com.example.C:run:()V:classes{i}.dex",
                    "class_name": "com.example.C", "method_name": "run",
                    "signature": "()V", "dex_path": f"classes{i}.dex",
                    "source_evidence_id": evidence_id, "status": "VERIFIED_STATIC",
                }, ("identity_key",))
            db.upsert("jni_bridge", {
                "identity_key": "fixture:bridge:valid",
                "class_name": "com.example.C", "method_name": "run",
                "signature": "()V", "dex_path": "classes0.dex",
                "native_entry": "0x100", "status": "VERIFIED_STATIC",
                "source_evidence_id": evidences[0],
            }, ("identity_key",))
            db.upsert("jni_bridge", {
                "identity_key": "fixture:bridge:wrong-evidence",
                "class_name": "com.example.C", "method_name": "run",
                "signature": "()V", "dex_path": "classes0.dex",
                "native_entry": "0x200", "status": "CANDIDATE",
                "source_evidence_id": evidences[1],
            }, ("identity_key",))
            db.commit()
            sync_semantic_graph(db)
            rows = db.query("""SELECT src.identity_key AS bridge, dst.identity_key AS java,
                e.metadata_json AS metadata FROM semantic_edge e
                JOIN semantic_node src ON src.id=e.source_node_id
                JOIN semantic_node dst ON dst.id=e.target_node_id
                WHERE e.relation_type='JNI_BRIDGE' AND src.node_type='JNIEntry'
                  AND dst.node_type='JavaMethod'""")
            self.assertEqual(len(rows), 1)
            self.assertIn("fixture:bridge:valid", rows[0]["bridge"])
            self.assertIn("classes0.dex", rows[0]["java"])
            self.assertEqual(db.connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            db.close()

    def test_registration_edges_reference_binary_not_module_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db = Database(Path(directory) / "test.sqlite")
            self.assertEqual(db.migrate(), 7)
            binary = db.upsert("binary", {
                "path": "sample.so", "sha256": "c" * 64, "size": 8,
                "format": "elf_executable_or_shared_library",
            }, ("path",))
            # Force the module PK to differ from its associated binary PK.
            db.upsert("module", {"name": "placeholder", "identity_key": "placeholder"}, ("identity_key",))
            module = db.upsert("module", {
                "name": "sample.so", "identity_key": "fixture:sample", "binary_id": binary,
            }, ("identity_key",))
            self.assertNotEqual(binary, module)
            function = db.upsert("function", {
                "binary_id": binary, "module_id": module, "name": "JNI_OnLoad",
                "address": "0x100", "identity_key": "fn:registration",
            }, ("identity_key",))
            evidence = db.evidence("fixture.json", "d" * 64, "jni_fixture", "document",
                                   "registration", "VERIFIED_STATIC")
            db.upsert("jni_bridge", {
                "identity_key": "fixture:registered:JNI",
                "class_name": "com.example.C", "method_name": "run",
                "signature": "()V", "native_entry": "0x200",
                "module_id": module, "registration_function_id": function,
                "method_lookup_address": "0x110", "source_evidence_id": evidence,
                "status": "VERIFIED_STATIC",
            }, ("identity_key",))
            db.commit()
            sync_semantic_graph(db)
            edges = db.query("""SELECT source_binary_id FROM semantic_edge
                WHERE relation_type='REGISTERS_CALLBACK'""")
            self.assertEqual(len(edges), 1)
            self.assertEqual(edges[0]["source_binary_id"], binary)
            self.assertEqual(db.connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            db.close()


if __name__ == "__main__":
    unittest.main()
