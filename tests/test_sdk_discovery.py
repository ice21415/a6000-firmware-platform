from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from fwplatform.cli import main
from fwplatform.db import Database
from fwplatform.sdk_discovery import discover_sdk_candidates
from fwplatform.sdk_review import draft_sdk_review
from fwplatform.sdk_contracts import import_sdk_contracts


class SdkDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = Database(self.root / "evidence.sqlite")
        self.assertEqual(self.db.migrate(), 7)
        self.digest = "a" * 64
        self.other_digest = "b" * 64
        for idx, sha in enumerate((self.digest, self.other_digest)):
            bid = self.db.upsert("binary", {
                "path": f"lib{idx}.so", "sha256": sha, "size": 100,
                "format": "elf_executable_or_shared_library",
            }, ("path",))
            fn = self.db.upsert("function", {
                "binary_id": bid, "identity_key": f"function:{idx}:0x100",
                "name": "Camera_capture", "address": "0x100",
                "prototype": "int Camera_capture(void)",
                "status": "VERIFIED_STATIC",
            }, ("identity_key",))
            self.db.upsert("import_export", {
                "binary_id": bid, "name": "Camera_capture", "direction": "export",
                "address": "0x100", "status": "VERIFIED_STATIC",
            }, ("binary_id", "name", "direction", "address"))
            if idx == 0:
                eid = self.db.evidence("synthetic.jsonl", "c" * 64,
                                       "ghidra_function_entry", "function:0x100",
                                       json.dumps({"binary_sha256": sha, "function_entry": "0x100",
                                                   "prototype_text": "int Camera_capture(void)"}),
                                       "VERIFIED_STATIC", {"binary_sha256": sha})
                self.db.connection.execute("UPDATE function SET source_evidence_id=? WHERE id=?",
                                           (eid, fn))
        self.db.upsert("function", {
            "binary_id": 1, "identity_key": "internal:0x200",
            "name": "Lens_focus", "address": "0x200",
        }, ("identity_key",))
        self.db.upsert("function", {
            "binary_id": 1, "identity_key": "generated:0x300",
            "name": "FUN_300", "address": "0x300", "generated_name": 1,
        }, ("identity_key",))
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def test_export_only_is_evidence_bound_but_never_semantically_verified(self):
        result = discover_sdk_candidates(self.db, name="Camera", limit=20)
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertEqual(result["returned"], 2)
        self.assertTrue(result["core_api_total_unknown"])
        self.assertEqual(result["verified_sdk_apis_discovered"], 0)
        by_sha = {item["binary_sha256"]: item for item in result["candidates"]}
        self.assertTrue(by_sha[self.digest]["entry_location_evidence_valid"])
        self.assertFalse(by_sha[self.other_digest]["entry_location_evidence_valid"])
        self.assertEqual(by_sha[self.digest]["identity_evidence_id"] is not None, True)
        self.assertEqual(by_sha[self.digest]["domain_search_hints"], ["Camera"])
        for candidate in result["candidates"]:
            self.assertEqual(candidate["api_status"], "UNVERIFIED_CANDIDATE")
            self.assertEqual(candidate["abi_status"], "UNKNOWN")
            self.assertFalse(candidate["runtime_callable"])
        self.assertEqual(self.db.connection.execute("SELECT COUNT(*) FROM sdk_interface").fetchone()[0], 0)

    def test_internal_and_generated_candidates_are_explicitly_opt_in(self):
        self.assertEqual(discover_sdk_candidates(self.db, name="Lens")["returned"], 0)
        internal = discover_sdk_candidates(self.db, name="Lens", include_internal=True)
        self.assertEqual(internal["returned"], 1)
        self.assertEqual(internal["candidates"][0]["domain_search_hints"], ["Lens"])
        no_generated = discover_sdk_candidates(self.db, name="FUN_", include_internal=True)
        self.assertEqual(no_generated["returned"], 0)
        generated = discover_sdk_candidates(self.db, name="FUN_", include_internal=True,
                                            include_generated=True)
        self.assertEqual(generated["returned"], 1)

    def test_binary_scope_domain_filter_and_limit_are_exact(self):
        one = discover_sdk_candidates(self.db, binary_sha256=self.digest, domain="Camera")
        self.assertEqual(one["returned"], 1)
        self.assertEqual(one["candidates"][0]["binary_sha256"], self.digest)
        clipped = discover_sdk_candidates(self.db, name="Camera", limit=1)
        self.assertEqual(clipped["returned"], 1)
        self.assertTrue(clipped["more_candidates_possible"])
        with self.assertRaises(ValueError):
            discover_sdk_candidates(self.db, limit=0)
        with self.assertRaises(ValueError):
            discover_sdk_candidates(self.db, binary_sha256="not-a-hash")

    def test_draft_roundtrip_is_explicit_candidate_not_verified_sdk(self):
        output = self.root / "review.json"
        result = draft_sdk_review(self.db, output, name="Camera", limit=10)
        self.assertEqual(result["status"], "REVIEW_ONLY")
        self.assertEqual(result["interfaces"], 2)
        draft = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(draft["automatically_verified_api_count"], 0)
        self.assertEqual({item["domain"] for item in draft["interfaces"]}, {"Other"})
        self.assertEqual({item["verification_status"] for item in draft["interfaces"]}, {"CANDIDATE"})
        self.assertTrue(all(item["abi"] is None for item in draft["interfaces"]))
        self.assertEqual(len([item for item in draft["interfaces"]
                              if "source_evidence_id" in item]), 1)
        imported = import_sdk_contracts(self.db, output)
        self.assertEqual(imported["interfaces"], 2)
        self.assertEqual(imported["verified_static"], 0)
        self.assertEqual(self.db.connection.execute(
            "SELECT COUNT(*) FROM sdk_interface WHERE verification_status='VERIFIED_STATIC'"
        ).fetchone()[0], 0)

    def test_cli_discover_is_read_only(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["--db", str(self.root / "evidence.sqlite"), "sdk",
                                   "discover", "--domain", "Camera",
                                   "--binary-sha256", self.digest, "--json"]), 0)
        result = json.loads(output.getvalue())
        self.assertEqual(result["returned"], 1)
        self.assertEqual(self.db.connection.execute("SELECT COUNT(*) FROM sdk_interface").fetchone()[0], 0)
        self.assertEqual(self.db.connection.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_export_name_alone_cannot_bind_wrong_function_address(self):
        binary_id = self.db.connection.execute(
            "SELECT id FROM binary WHERE sha256=?", (self.digest,)
        ).fetchone()[0]
        self.db.upsert("function", {
            "binary_id": binary_id, "identity_key": "decoy:0x400",
            "name": "Camera_capture", "address": "0x400",
        }, ("identity_key",))
        self.db.connection.execute(
            "UPDATE import_export SET address='0x0100' WHERE binary_id=? AND name='Camera_capture'",
            (binary_id,),
        )
        self.db.commit()
        result = discover_sdk_candidates(self.db, name="Camera_capture", limit=20)
        self.assertEqual(result["returned"], 2)
        self.assertEqual({x["address"] for x in result["candidates"]}, {"0x100"})
        self.assertTrue(result["candidates"][0]["unique_function_entry"])

    def test_duplicate_numeric_function_entry_disables_location_proof(self):
        binary_id = self.db.connection.execute(
            "SELECT id FROM binary WHERE sha256=?", (self.digest,)
        ).fetchone()[0]
        self.db.upsert("function", {
            "binary_id": binary_id, "identity_key": "ambiguous:0x0100",
            "name": "Camera_capture_alias", "address": "0x0100",
        }, ("identity_key",))
        self.db.commit()
        result = discover_sdk_candidates(self.db, binary_sha256=self.digest)
        self.assertEqual(result["returned"], 1)
        self.assertFalse(result["candidates"][0]["unique_function_entry"])
        self.assertFalse(result["candidates"][0]["entry_location_evidence_valid"])
        self.assertIsNone(result["candidates"][0]["identity_evidence_id"])

    def test_duplicate_binary_digest_is_not_a_unique_sdk_identity(self):
        duplicate_bid = self.db.upsert("binary", {
            "path": "duplicate.so", "sha256": self.digest, "size": 100,
            "format": "elf_executable_or_shared_library",
        }, ("path",))
        self.db.upsert("function", {
            "binary_id": duplicate_bid, "identity_key": "duplicated:0x100",
            "name": "Camera_capture", "address": "0x100",
        }, ("identity_key",))
        self.db.upsert("import_export", {
            "binary_id": duplicate_bid, "name": "Camera_capture",
            "direction": "export", "address": "0x100",
        }, ("binary_id", "name", "direction", "address"))
        self.db.commit()
        candidates = discover_sdk_candidates(self.db, binary_sha256=self.digest)
        self.assertEqual(candidates["returned"], 2)
        self.assertTrue(all(not item["unique_binary_identity"]
                            for item in candidates["candidates"]))
        self.assertTrue(all(not item["entry_location_evidence_valid"]
                            for item in candidates["candidates"]))
        output = self.root / "duplicate-review.json"
        result = draft_sdk_review(self.db, output, binary_sha256=self.digest)
        self.assertEqual(result["interfaces"], 1)
        self.assertEqual(result["duplicate_candidates_collapsed"], 1)
        payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(len(payload["interfaces"]), 1)
        self.assertEqual(len(payload["interfaces"][0]["review"]["candidate_binary_paths"]), 2)
        self.assertNotIn("source_evidence_id", payload["interfaces"][0])
        self.assertEqual(import_sdk_contracts(self.db, output)["interfaces"], 1)

    def test_discovery_reports_import_evidence_without_runtime_promotion(self):
        camera_bid = self.db.connection.execute(
            "SELECT id FROM binary WHERE sha256=?", (self.digest,)
        ).fetchone()[0]
        imported_bid = self.db.connection.execute(
            "SELECT id FROM binary WHERE sha256=?", (self.other_digest,)
        ).fetchone()[0]
        evidence = self.db.evidence(
            "synthetic-dynamic.so", "d" * 64, "elf_dynamic", "DT_NEEDED",
            json.dumps({"needed": ["lib0.so"]}), "VERIFIED_STATIC",
        )
        self.db.upsert("cross_reference", {
            "from_binary_id": imported_bid, "from_address": "0x400",
            "to_binary_id": camera_bid, "to_address": "0x0100",
            "kind": "resolved_import", "status": "CANDIDATE",
            "source_evidence_id": evidence,
        }, ("from_binary_id", "from_address", "to_binary_id", "to_address", "kind"))
        # A manually added link with no dynamic ELF evidence must not inflate
        # the count of machine-indexed provider candidates.
        self.db.upsert("cross_reference", {
            "from_binary_id": imported_bid, "from_address": "0x500",
            "to_binary_id": camera_bid, "to_address": "0x100",
            "kind": "resolved_import", "status": "VERIFIED_STATIC",
        }, ("from_binary_id", "from_address", "to_binary_id", "to_address", "kind"))
        self.db.commit()
        found = discover_sdk_candidates(self.db, binary_sha256=self.digest)
        self.assertEqual(found["returned"], 1)
        entry = found["candidates"][0]
        self.assertEqual(entry["incoming_static_import_candidates"], 1)
        self.assertEqual(entry["incoming_importing_binary_count"], 1)
        self.assertEqual(entry["incoming_import_evidence_ids"], [evidence])
        self.assertFalse(entry["runtime_import_binding_verified"])
        self.assertFalse(entry["runtime_callable"])
        output = self.root / "import-evidence-review.json"
        draft_sdk_review(self.db, output, binary_sha256=self.digest)
        review = json.loads(output.read_text(encoding="utf-8"))["interfaces"][0]["review"]
        self.assertEqual(review["incoming_static_import_candidates"], 1)
        self.assertFalse(review["runtime_import_binding_verified"])


if __name__ == "__main__":
    unittest.main()
