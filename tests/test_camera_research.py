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


if __name__ == "__main__":
    unittest.main()
