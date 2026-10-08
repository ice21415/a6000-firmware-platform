from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch

from fwplatform.db import Database, sha256_file
from analyzers.dex_analyzer import analyze_dex
from fwplatform.ghidra_importer import import_ghidra_jsonl
from fwplatform.jni import import_jni_fixture
from fwplatform.linkage import ElfMetadata, analyze_linkage
from fwplatform.osal import import_osal_fixture
from fwplatform.evidence_ingestion import ingest_research_evidence
from fwplatform.semantic_graph import export_graph, sync_semantic_graph, validate_graph_provenance
from fwplatform.sdk import build_sdk_index


class Phase3Tests(unittest.TestCase):
    def _db(self, root: Path) -> Database:
        db = Database(root / "test.db")
        self.assertEqual(db.migrate(), 6)
        return db

    def test_ghidra_explicit_caller_and_cfg_are_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); binary = root / "sample.so"; binary.write_bytes(b"sample-elf")
            digest = sha256_file(binary); jsonl = root / "sample.jsonl"
            records = [
                {"kind": "metadata", "run_id": "run-1", "binary_sha256": digest, "analyzer_version": "12.1.3", "program_identity": {"image_base": "0x10000", "address_space": "ram"}},
                {"kind": "function", "entry_vma": "0x100", "name": "caller", "prototype": "void caller(void)", "body_bytes": 32},
                {"kind": "function", "entry_vma": "0x300", "name": "callee", "prototype": "void callee(void)", "body_bytes": 16},
                {"kind": "function_body_range", "function_entry": "0x100", "start_vma": "0x100", "end_vma": "0x110", "address_space": "ram"},
                {"kind": "function_body_range", "function_entry": "0x100", "start_vma": "0x180", "end_vma": "0x190", "address_space": "ram"},
                {"kind": "function_body_range", "function_entry": "0x300", "start_vma": "0x300", "end_vma": "0x310", "address_space": "ram"},
                {"kind": "instruction", "function_entry": "0x100", "address": "0x102", "mnemonic": "bl", "mode": "Thumb"},
                {"kind": "callsite", "function_entry": "0x100", "from_address": "0x102", "to_address": "0x300", "callee_entry": "0x300", "relation_kind": "direct_call", "status": "VERIFIED_STATIC"},
                {"kind": "callsite", "function_entry": "0x100", "from_address": "0x185", "to_address": "0x300", "callee_entry": "0x300", "relation_kind": "direct_call", "status": "VERIFIED_STATIC"},
                {"kind": "callsite", "from_address": "0x250", "to_address": "0x300", "callee_entry": "0x300", "relation_kind": "indirect_call", "status": "CANDIDATE"},
                {"kind": "basic_block", "function_entry": "0x100", "start_vma": "0x100", "end_vma": "0x110"},
                {"kind": "basic_block", "function_entry": "0x100", "start_vma": "0x110", "end_vma": "0x120"},
                {"kind": "cfg_edge", "function_entry": "0x100", "from_address": "0x100", "to_address": "0x110", "edge_kind": "fallthrough"},
            ]
            records.append({"kind": "complete", "run_id": "run-1", "binary_sha256": digest, "record_count": len(records), "export_status": "complete"})
            jsonl.write_text("\n".join(json.dumps(row) for row in records) + "\n", encoding="utf-8")
            db = self._db(root)
            db.connection.execute("INSERT INTO binary(path,sha256,size,format,analysis_status,metadata_json) VALUES(?,?,?,?,?,?)", ("sample.so", digest, binary.stat().st_size, "elf_executable_or_shared_library", "INVENTORIED", "{}"))
            db.commit()
            first = import_ghidra_jsonl(db, root, binary, jsonl)
            second = import_ghidra_jsonl(db, root, binary, jsonl)
            self.assertEqual(first["callsites"], 3); self.assertEqual(second["callsites"], 3)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM cfg_edge").fetchone()[0], 1)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM function_body_range").fetchone()[0], 3)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM callsite WHERE caller_id IS NULL").fetchone()[0], 1)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM unresolved_edge WHERE relation='callsite_caller'").fetchone()[0], 1)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM callsite WHERE caller_id IS NOT NULL AND address='0x185'").fetchone()[0], 1)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM analysis_run WHERE status='COMPLETE'").fetchone()[0], 1)
            db.close()

    def test_truncated_export_rolls_back_partial_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); binary = root / "sample.so"; binary.write_bytes(b"sample")
            digest = sha256_file(binary); jsonl = root / "truncated.jsonl"
            jsonl.write_text(json.dumps({"kind": "metadata", "binary_sha256": digest, "program_identity": {}}) + "\n", encoding="utf-8")
            db = self._db(root)
            db.connection.execute("INSERT INTO binary(path,sha256,size,format,analysis_status,metadata_json) VALUES(?,?,?,?,?,?)", ("sample.so", digest, binary.stat().st_size, "elf_executable_or_shared_library", "INVENTORIED", "{}")); db.commit()
            with self.assertRaises(ValueError): import_ghidra_jsonl(db, root, binary, jsonl)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM function").fetchone()[0], 0)
            self.assertEqual(db.connection.execute("SELECT status FROM analysis_run WHERE analyzer='ghidra_headless'").fetchone()[0], "FAILED")
            db.close()

    def test_linkage_does_not_choose_ambiguous_basename(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "app").mkdir(); (root / "a").mkdir(); (root / "b").mkdir()
            for rel in ("app/main.so", "a/libdep.so", "b/libdep.so"): (root / rel).write_bytes(rel.encode())
            db = self._db(root)
            for rel in ("app/main.so", "a/libdep.so", "b/libdep.so"):
                p = root / rel; db.connection.execute("INSERT INTO binary(path,sha256,size,format,analysis_status,metadata_json) VALUES(?,?,?,?,?,?)", (rel, sha256_file(p), p.stat().st_size, "elf_executable_or_shared_library", "INVENTORIED", "{}"))
            db.commit()
            def fake(path: Path) -> ElfMetadata:
                return ElfMetadata(needed=("libdep.so",), soname="main" if path.name == "main.so" else "libdep.so") if path.name == "main.so" else ElfMetadata(soname="libdep.so")
            with patch("fwplatform.linkage._elf_metadata", side_effect=fake):
                result = analyze_linkage(db, root)
            self.assertEqual(result["needed"], 0); self.assertEqual(result["ambiguous_dependencies"], 1)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM module_dependency").fetchone()[0], 0)
            row = db.connection.execute("SELECT reason FROM unresolved_edge WHERE relation='DT_NEEDED'").fetchone()
            self.assertIsNotNone(row); self.assertIn("candidate_binary_ids", row[0])
            db.close()

    def test_osal_fixture_and_jni_fixture_are_evidence_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); binary = root / "libSyncAndroid.so"; binary.write_bytes(b"native")
            db = self._db(root); digest = sha256_file(binary)
            db.connection.execute("INSERT INTO binary(path,sha256,size,format,analysis_status,metadata_json) VALUES(?,?,?,?,?,?)", (binary.name, digest, binary.stat().st_size, "elf_executable_or_shared_library", "INVENTORIED", "{}"))
            bid = db.connection.execute("SELECT id FROM binary").fetchone()[0]
            mid = db.upsert("module", {"name": binary.name, "identity_key": f"binary-sha256:{digest}:{binary.name}", "binary_id": bid, "status": "VERIFIED_STATIC", "confidence_id": db.confidence_id("VERIFIED_STATIC")}, ("identity_key",))
            fid = db.upsert("function", {"binary_id": bid, "module_id": mid, "name": "SyncAndroid_act", "identity_key": f"function:{bid}:0x100:SyncAndroid_act", "address": "0x100", "status": "VERIFIED_STATIC", "confidence_id": db.confidence_id("VERIFIED_STATIC")}, ("identity_key",)); db.commit()
            osal = root / "osal.json"; osal.write_text(json.dumps({"schema": 1, "status": "VERIFIED_STATIC", "queue": {"namespace": "osal", "value": "0x01554466", "name": "SyncAndroid", "module": {"name": binary.name, "binary_sha256": digest}}, "messages": [{"command": {"namespace": "syncandroid", "value": "0x72", "name": "Resume", "status": "VERIFIED_STATIC"}, "producer": {"binary_sha256": digest, "address": "0x100", "name": "SyncAndroid_act"}, "direction": "async", "semantics": "resume", "status": "VERIFIED_STATIC"}]}), encoding="utf-8")
            first = import_osal_fixture(db, osal); second = import_osal_fixture(db, osal)
            self.assertEqual(first["messages"], 1); self.assertEqual(second["messages"], 1); self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM osal_message").fetchone()[0], 1)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM message_flow WHERE function_id IS NULL AND module_id IS NULL").fetchone()[0], 0)
            jni = root / "jni.json"; jni.write_text(json.dumps({"status": "VERIFIED_STATIC", "java_methods": [{"class_name": "com.android.server.SyncAndroidService", "method_name": "Resume", "signature": "(I)V", "dex_path": "classes.dex", "status": "VERIFIED_STATIC"}], "jni_methods": [{"class_name": "com.android.server.SyncAndroidService", "method_name": "Resume", "signature": "(I)V", "dex_path": "classes.dex", "native": {"binary_sha256": digest, "address": "0x100", "name": "SyncAndroid_act"}, "status": "VERIFIED_STATIC"}]}), encoding="utf-8")
            result = import_jni_fixture(db, jni); self.assertEqual(result["resolved_native"], 1); self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM jni_bridge").fetchone()[0], 1)
            graph = sync_semantic_graph(db); self.assertGreaterEqual(graph["nodes"], 5); self.assertGreaterEqual(graph["edges"], 1)
            out = root / "graph.graphml"; exported = export_graph(db, out, "graphml"); self.assertGreater(exported["nodes"], 0); self.assertTrue(out.read_text(encoding="utf-8").startswith("<?xml"))
            xml = ET.parse(out); ns = {"g": "http://graphml.graphdrawing.org/xmlns"}
            self.assertGreater(len(xml.findall("g:key", ns)), 0); self.assertGreater(len(xml.findall(".//g:data", ns)), 0)
            self.assertEqual(validate_graph_provenance(db)["counts"]["missing_evidence"], 0)
            sdk = build_sdk_index(db, root / "sdk.json"); self.assertIsNone(sdk["coverage"]["callable_validated_interfaces"]); self.assertEqual(sdk["coverage"]["sdk_documented_interfaces"], 0)
            db.close()

    def test_event_namespaces_and_graph_depth_remain_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db = self._db(Path(directory))
            e1 = db.upsert("event_id", {"namespace": "model", "value": "0x10", "name": "Ready", "identity_key": "model|0x10|Ready", "status": "VERIFIED_STATIC", "source_evidence_id": None}, ("identity_key",))
            e2 = db.upsert("event_id", {"namespace": "ui", "value": "0x10", "name": "Ready", "identity_key": "ui|0x10|Ready", "status": "CANDIDATE", "source_evidence_id": None}, ("identity_key",))
            self.assertNotEqual(e1, e2); result = sync_semantic_graph(db); self.assertGreaterEqual(result["nodes"], 2)
            self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM semantic_node WHERE node_type='EventID'").fetchone()[0], 2); db.close()

    def test_jni_missing_endpoints_are_unresolved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            db = self._db(root)
            fixture = root / "jni-missing.json"
            fixture.write_text(json.dumps({"status": "VERIFIED_STATIC", "jni_methods": [{
                "class_name": "com.example.Missing", "method_name": "run", "signature": "()V",
                "status": "VERIFIED_STATIC", "native": {"address": "0x404"}
            }]}), encoding="utf-8")
            result = import_jni_fixture(db, fixture)
            self.assertGreaterEqual(result["unresolved"], 2)
            relations = {row[0] for row in db.connection.execute("SELECT relation FROM unresolved_edge")}
            self.assertIn("JNI_BRIDGE", relations)
            self.assertIn("JNI_NATIVE_ENTRY", relations)
            db.close()

    def test_research_adapter_is_idempotent_and_preserves_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); research = root / "firmware-analysis" / "boot-static-analysis"; research.mkdir(parents=True)
            (research / "sync-android-queue-constant-hits.json").write_text(json.dumps({"constant": "0x01554466", "hits": [{"path": "libSyncAndroid.so", "file_offset": "0x2208"}]}), encoding="utf-8")
            (research / "camera-state-transitions.json").write_text(json.dumps({"status": "STATIC SELECTOR EVALUATION; NO CAMERA EXECUTION", "sha256": "a" * 64, "transitions_and_focus_actions": [{"state": 0, "selector": "0x1", "next_state": 1}]}), encoding="utf-8")
            db = self._db(root)
            first = ingest_research_evidence(db, root); count1 = db.connection.execute("SELECT COUNT(*) FROM research_observation").fetchone()[0]
            second = ingest_research_evidence(db, root); count2 = db.connection.execute("SELECT COUNT(*) FROM research_observation").fetchone()[0]
            self.assertEqual(first["adapters"]["camera-state"]["status"], "COMPLETE"); self.assertEqual(second["adapters"]["camera-state"]["status"], "COMPLETE")
            self.assertEqual(count1, count2); self.assertEqual(db.connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0], 2)
            self.assertEqual(db.connection.execute("SELECT status FROM research_observation WHERE observation_type='state_transition'").fetchone()[0], "VERIFIED_STATIC")
            db.close()

    def test_dex_inventory_is_conservative(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); dex = root / "classes.dex"; data = bytearray(0x90)
            data[:8] = b"dex\n035\0"; data[0x20:0x24] = (0x90).to_bytes(4, "little"); data[0x24:0x28] = (0x70).to_bytes(4, "little"); data[0x28:0x2C] = (0x12345678).to_bytes(4, "little")
            data[0x38:0x3C] = (1).to_bytes(4, "little"); data[0x3C:0x40] = (0x70).to_bytes(4, "little"); data[0x70:0x74] = (0x74).to_bytes(4, "little"); data[0x74:0x7D] = (5).to_bytes(1, "little") + b"Lcom/X;\0"
            dex.write_bytes(data)
            result = analyze_dex(dex); self.assertEqual(result["format"], "dex"); self.assertIn("Lcom/X;", result["class_descriptors"]); self.assertEqual(result["semantic_status"], "INDEXED_ONLY")


if __name__ == "__main__":
    unittest.main()
