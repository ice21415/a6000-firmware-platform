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


if __name__ == "__main__":
    unittest.main()
