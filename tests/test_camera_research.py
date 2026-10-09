"""Offline ModelCamera report-graph validation and SDK candidate regression tests."""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from fwplatform.camera_research import inspect_camera_research
from fwplatform.cli import main
from fwplatform.db import Database
from fwplatform.sdk_contracts import import_sdk_contracts


ROOT = Path(__file__).resolve().parent.parent
CATALOG = ROOT / "sdk" / "camera_3_21_static_candidates.json"
GRAPH = ROOT / "sdk" / "camera_3_21_static_callgraph.json"


class CameraResearchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        self.graph = json.loads(GRAPH.read_text(encoding="utf-8"))
        self.cat_path = self.root / "candidates.json"
        self.graph_path = self.root / "graph.json"
        self._save()

    def tearDown(self):
        self.tmp.cleanup()

    def _save(self):
        self.cat_path.write_text(json.dumps(self.catalog), encoding="utf-8")
        self.graph_path.write_text(json.dumps(self.graph), encoding="utf-8")

    def _inspect(self, focus=""):
        self._save()
        return inspect_camera_research(self.cat_path, self.graph_path, focus=focus)

    def test_saved_research_graph_contains_real_addressed_candidates_but_no_abi(self):
        result = self._inspect()
        self.assertEqual(result["status"], "RESEARCH_GRAPH_INTERNALLY_CONSISTENT")
        self.assertEqual(result["catalog_candidate_count"], 14)
        self.assertEqual(result["reported_direct_branch_count"], 9)
        self.assertEqual(result["reported_byte_field_observation_count"], 6)
        self.assertEqual(result["reported_normalized_selector_count"], 4)
        self.assertEqual(result["reported_unresolved_indirect_count"], 1)
        self.assertFalse(result["validation"]["independent_instruction_bytes_checked"])
        self.assertFalse(result["validation"]["independent_abi_verified"])
        self.assertFalse(result["validation"]["live_device_behavior_verified"])
        self.assertIsNone(result["callable_camera_apis"])
        self.assertTrue(all(not f["runtime_callable"] and f["abi_status"] == "UNKNOWN"
                            for f in result["functions"]))

    def test_focus_traverses_direct_call_chain_not_unresolved_indirect(self):
        name = "ModelCamera::ActionGpSetSetting"
        result = self._inspect(focus=name)
        names = {row["name"] for row in result["functions"]}
        self.assertIn("ModelCamera::pvt_ActionSetInit", names)
        self.assertIn("ModelCamera::pvt_ExeEENeutralCmd", names)
        self.assertIn("ModelCamera::EE_neutral_sender_candidate", names)
        self.assertIn("ModelCamera::prepare_setter_candidate", names)
        self.assertNotIn("ModelCamera::PrepON", names)
        self.assertEqual(result["unresolved_external"][0]["resolved_target"], None)
        self.assertTrue(all(x["proof_level"] == "REPORTED_STATIC_INSTRUCTION_NOT_PUBLICLY_REVALIDATED"
                            for x in result["static_calls"]))
        with self.assertRaisesRegex(ValueError, "not in the research catalog"):
            self._inspect(focus="ModelCamera::nonexistent")

    def test_forged_abi_or_runtime_promotion_is_rejected(self):
        self.catalog["interfaces"][0]["abi"] = "AAPCS"
        with self.assertRaisesRegex(ValueError, "verified ABI"):
            self._inspect()
        self.catalog["interfaces"][0]["abi"] = None
        self.catalog["interfaces"][0]["verification_status"] = "VERIFIED_STATIC"
        with self.assertRaisesRegex(ValueError, "promoted"):
            self._inspect()
        self.catalog["interfaces"][0]["verification_status"] = "CANDIDATE"
        self.graph["verified_static_api_count"] = 1
        with self.assertRaisesRegex(ValueError, "callable camera"):
            self._inspect()

    def test_wrong_target_vma_and_inconsistent_branch_kind_are_rejected(self):
        self.graph["static_calls"][0]["instruction"] = "bl #0x400"
        with self.assertRaisesRegex(ValueError, "branch target"):
            self._inspect()
        self.graph = json.loads(GRAPH.read_text(encoding="utf-8"))
        self.graph["static_calls"][0]["kind"] = "TAIL_BRANCH"
        with self.assertRaisesRegex(ValueError, "edge kind"):
            self._inspect()
        self.graph = json.loads(GRAPH.read_text(encoding="utf-8"))
        self.graph["static_calls"][0]["callsite"] = "0x1"
        with self.assertRaisesRegex(ValueError, "precedes"):
            self._inspect()

    def test_numeric_address_collision_cross_binary_and_missing_report_scope(self):
        self.catalog["interfaces"][1]["address"] = self.catalog["interfaces"][0]["address"]
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self._inspect()
        self.catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        self.catalog["interfaces"][1]["binary_sha256"] = "e" * 64
        with self.assertRaisesRegex(ValueError, "ELF identity"):
            self._inspect()
        self.catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        self.graph["proof_policy"] = "VERIFIED_STATIC"
        with self.assertRaisesRegex(ValueError, "report-only"):
            self._inspect()

    def test_reject_unverified_artifact_path_and_false_selector_assertions(self):
        self.graph["static_calls"][0]["source_artifact"] = "C:/private/raw-disassembly.txt"
        with self.assertRaisesRegex(ValueError, "basename"):
            self._inspect()
        self.graph = json.loads(GRAPH.read_text(encoding="utf-8"))
        self.graph["normalized_selector_routes"][0]["status"] = "VERIFIED_RUNTIME"
        with self.assertRaisesRegex(ValueError, "not observed live"):
            self._inspect()

    def test_pure_cli_does_not_create_or_migrate_sqlite(self):
        dbfile = self.root / "must-not-create.sqlite"
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = main(["--db", str(dbfile), "sdk", "research",
                       "--catalog", str(self.cat_path), "--graph", str(self.graph_path),
                       "--focus", "ModelCamera::PrepON", "--json"])
        self.assertEqual(rc, 0)
        self.assertFalse(dbfile.exists())
        result = json.loads(out.getvalue())
        self.assertEqual(result["focus"], "ModelCamera::PrepON")
        self.assertEqual(result["catalog_candidate_count"], 14)
        self.assertEqual(len(result["static_calls"]), 1)

    def test_offline_sdk_import_resolves_entries_but_never_promotes_abi(self):
        database = Database(self.root / "sdk.sqlite")
        try:
            self.assertEqual(database.migrate(), 7)
            sha = self.graph["binary_sha256"]
            bid = database.upsert("binary", {
                "path": "synthetic-libObj.so", "sha256": sha,
                "size": 17436172, "format": "elf_executable_or_shared_library",
            }, ("path",))
            for i, entry in enumerate(self.catalog["interfaces"]):
                database.upsert("function", {
                    "binary_id": bid, "identity_key": f"synthetic:{i}",
                    "name": entry["name"], "address": entry["address"],
                    "status": "CANDIDATE",
                }, ("identity_key",))
            database.commit()
            imported = import_sdk_contracts(database, self.cat_path)
            self.assertEqual(imported["interfaces"], 14)
            self.assertEqual(imported["function_resolved"], 14)
            self.assertEqual(imported["verified_static"], 0)
            self.assertEqual(database.connection.execute(
                "SELECT COUNT(*) FROM sdk_interface WHERE verification_status='CANDIDATE'"
            ).fetchone()[0], 14)
            self.assertEqual(database.connection.execute(
                "SELECT COUNT(*) FROM sdk_interface WHERE abi IS NOT NULL"
            ).fetchone()[0], 0)
        finally:
            database.close()

    def test_readonly_private_db_crosscheck_matches_only_indexed_function_ids(self):
        db_path = self.root / "private-copy.sqlite"
        db = Database(db_path)
        try:
            db.migrate()
            binary = db.upsert("binary", {
                "path": "synthetic-libObj.so", "sha256": self.graph["binary_sha256"],
                "size": 100, "format": "elf_executable_or_shared_library",
            }, ("path",))
            lookup = {}
            for i, candidate in enumerate(self.catalog["interfaces"]):
                lookup[candidate["name"]] = db.upsert("function", {
                    "binary_id": binary, "identity_key": f"crosscheck:{i}",
                    "address": candidate["address"], "name": candidate["name"],
                }, ("identity_key",))
            first = self.graph["static_calls"][0]
            db.upsert("callsite", {
                "identity_key": "synthetic:camera:callsite", 
                "caller_id": lookup[first["caller"]],
                "callee_id": lookup[first["callee"]],
                "address": first["callsite"],
                "target": self.catalog["interfaces"][2]["address"],
                "kind": "call",
            }, ("identity_key",))
            db.commit()
        finally:
            db.close()
        before = db_path.stat().st_mtime_ns
        self._save()
        report = inspect_camera_research(self.cat_path, self.graph_path,
                                         compare_db=db_path)
        proof = report["database_crosscheck"]
        self.assertEqual(proof["status"], "READ_ONLY_INDEX_CROSSCHECK")
        self.assertEqual(proof["binary_identity"], "UNIQUE_ELF_SHA")
        self.assertEqual(proof["unique_indexed_function_entries"], 14)
        self.assertEqual(proof["indexed_matching_callee_ids"], 1)
        self.assertTrue(all(not row["abi_verified"] for row in proof["entries"]))
        self.assertTrue(all(not row["independent_abi_verified"] for row in proof["calls"]))
        self.assertEqual(db_path.stat().st_mtime_ns, before)

    def test_readonly_crosscheck_detects_missing_and_ambiguous_binary(self):
        missing_db = self.root / "absent.sqlite"
        with self.assertRaises(FileNotFoundError):
            self._inspect_db(missing_db)
        self.assertFalse(missing_db.exists())
        existing = self.root / "ambiguous.sqlite"
        db = Database(existing)
        try:
            db.migrate()
            for i in range(2):
                db.upsert("binary", {
                    "path": f"clone{i}.so", "sha256": self.graph["binary_sha256"],
                    "size": 123, "format": "elf_executable_or_shared_library",
                }, ("path",))
            db.commit()
        finally:
            db.close()
        report = self._inspect_db(existing)
        cross = report["database_crosscheck"]
        self.assertEqual(cross["binary_identity"], "AMBIGUOUS_ELF_SHA")
        self.assertEqual(cross["binary_match_count"], 2)
        self.assertEqual(cross["unique_indexed_function_entries"], 0)
        self.assertEqual(cross["indexed_matching_callee_ids"], 0)

    def _inspect_db(self, path: Path):
        self._save()
        return inspect_camera_research(self.cat_path, self.graph_path,
                                       compare_db=path)

    def test_non_scalar_field_is_rejected_with_validation_error(self):
        self.graph["field_observations"][0]["observed_value"] = {"value": 1}
        with self.assertRaisesRegex(ValueError, "field value"):
            self._inspect()

    def test_lens_and_camera_profile_lifecycle_leads_are_not_callable_functions(self):
        leads = json.loads((ROOT / "sdk" / "core_3_21_lifecycle_research_leads.json"
                            ).read_text(encoding="utf-8"))
        self.assertEqual(leads["schema_version"], 1)
        self.assertEqual(leads["function_abi_verified_count"], 0)
        self.assertEqual(leads["lifecycle_callback_abi_verified_count"], 0)
        self.assertEqual({x["domain"] for x in leads["entries"]}, {"Lens", "Camera"})
        lens = next(x for x in leads["entries"] if x["domain"] == "Lens")
        self.assertEqual(lens["callbacks"]["init"], "LensCommunicator_Init")
        self.assertEqual(lens["callbacks"]["exit"], "LensCommunicator_Exit")
        self.assertEqual(lens["imdb_entry_index"], 131)
        for item in leads["entries"]:
            self.assertIsNone(item["binary_sha256"])
            self.assertIsNone(item["function_entries"])
            self.assertIsNone(item["abi"])
            self.assertEqual(item["verification_status"], "RESEARCH_LEAD")
            self.assertFalse(item["runtime_callable"])
        self.assertEqual({x["domain"] for x in leads["unresolved_domain_targets"]},
                         {"Sensor", "Media", "OSAL"})


if __name__ == "__main__":
    unittest.main()
