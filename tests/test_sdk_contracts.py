from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from fwplatform.cli import main
from fwplatform.db import Database
from fwplatform.sdk import build_sdk_index
from fwplatform.sdk_contracts import audit_sdk_contracts, import_sdk_contracts


class OfflineSdkContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = Database(self.root / "sdk.sqlite")
        self.assertEqual(self.db.migrate(), 7)

    def tearDown(self) -> None:
        self.db.close()
        self.temp.cleanup()

    def _fixture(self, entries: list[dict], name: str = "interfaces.json") -> Path:
        file = self.root / name
        file.write_text(json.dumps({
            "schema_version": 1, "firmware_version": "3.21", "interfaces": entries,
        }), encoding="utf-8")
        return file

    def _function_with_evidence(self) -> tuple[str, int, int]:
        digest = "a" * 64
        binary_id = self.db.upsert("binary", {
            "path": "study.so", "sha256": digest, "size": 8,
            "format": "elf_executable_or_shared_library",
        }, ("path",))
        module_id = self.db.upsert("module", {
            "identity_key": "module:study.so", "name": "study.so", "binary_id": binary_id,
        }, ("identity_key",))
        function_id = self.db.upsert("function", {
            "identity_key": "function:study.so:0x100", "name": "study_get",
            "module_id": module_id, "binary_id": binary_id, "address": "0x100",
        }, ("identity_key",))
        evidence_id = self.db.evidence(
            "synthetic-ghidra.jsonl", "c" * 64, "ghidra_jsonl", "function[0]",
            json.dumps({"binary_sha256": digest, "function_entry": "0x100",
                        "prototype": "int study_get(void)"}), "VERIFIED_STATIC",
        )
        self.db.commit()
        return digest, function_id, evidence_id

    def test_import_resolves_exact_function_and_audits_static_contract(self) -> None:
        digest, function_id, evidence_id = self._function_with_evidence()
        fixture = self._fixture([{
            "name": "study_get", "domain": "Camera", "binary_sha256": digest,
            "address": "0x100", "abi": "AAPCS",
            "parameter_layout": {"args": []},
            "return_semantics": {"type": "int"},
            "verification_status": "VERIFIED_STATIC",
            "source_evidence_id": evidence_id,
        }])
        first = import_sdk_contracts(self.db, fixture)
        second = import_sdk_contracts(self.db, fixture)
        self.assertEqual(first["verified_static"], 1)
        self.assertEqual(second["function_resolved"], 1)
        self.assertEqual(self.db.connection.execute("SELECT COUNT(*) FROM sdk_interface").fetchone()[0], 1)
        self.assertEqual(self.db.connection.execute("SELECT function_id FROM sdk_interface").fetchone()[0], function_id)
        audit = audit_sdk_contracts(self.db)
        self.assertEqual(audit["static_contract_complete"], 1)
        self.assertEqual(audit["unresolved_or_incomplete"], 0)
        self.assertIsNone(audit["runtime_callable_validated"])
        self.assertEqual(audit["domain_matrix"]["Camera"]["documented"], 1)
        self.assertEqual(audit["domain_matrix"]["Camera"]["static_contract_complete"], 1)
        self.assertIsNone(audit["domain_matrix"]["Camera"]["required_api_denominator"])
        self.assertIsNone(audit["domain_matrix"]["Lens"]["core_reverse_engineering_complete"])
        sdk = build_sdk_index(self.db, self.root / "sdk.json")
        self.assertEqual(sdk["coverage"]["static_contract_complete"], 1)
        self.assertIsNone(sdk["coverage"]["callable_validated_interfaces"])
        self.assertTrue((self.root / "sdk.json").exists())

    def test_unrelated_static_evidence_cannot_promote_sdk_contract(self) -> None:
        digest, _, _ = self._function_with_evidence()
        unrelated = self.db.evidence(
            "wrong-firmware-ghidra.jsonl", "e" * 64, "ghidra_jsonl", "function[0]",
            json.dumps({"binary_sha256": "b" * 64, "function_entry": "0x100"}),
            "VERIFIED_STATIC",
        )
        self.db.commit()
        fixture = self._fixture([{
            "name": "study_get", "domain": "Camera", "binary_sha256": digest,
            "address": "0x100", "abi": "AAPCS", "parameter_layout": [],
            "return_semantics": "int", "verification_status": "VERIFIED_STATIC",
            "source_evidence_id": unrelated,
        }])
        result = import_sdk_contracts(self.db, fixture)
        self.assertEqual(result["downgraded"], 1)
        self.assertEqual(result["verified_static"], 0)
        self.assertEqual(audit_sdk_contracts(self.db)["static_contract_complete"], 0)

    def test_incomplete_static_claim_is_downgraded_not_guessed(self) -> None:
        digest, _, _ = self._function_with_evidence()
        fixture = self._fixture([{
            "name": "unknown_camera_entry", "domain": "Camera",
            "binary_sha256": digest, "address": "0x200",
            "verification_status": "VERIFIED_STATIC",
        }])
        result = import_sdk_contracts(self.db, fixture)
        self.assertEqual(result["downgraded"], 1)
        self.assertEqual(result["unresolved"], 1)
        row = self.db.connection.execute(
            "SELECT verification_status,runtime_safety,function_id FROM sdk_interface"
        ).fetchone()
        self.assertEqual(row["verification_status"], "CANDIDATE")
        self.assertEqual(row["runtime_safety"], "DESCRIPTIVE_ONLY")
        self.assertIsNone(row["function_id"])
        audit = audit_sdk_contracts(self.db)
        self.assertIn("UNRESOLVED_FUNCTION", audit["records"][0]["issues"])

    def test_rejects_runtime_claim_and_undeclared_binary(self) -> None:
        for field in (
            {"verification_status": "VERIFIED_RUNTIME"},
            {"runtime_safety": "CALLABLE_VALIDATED"},
            {"address": "0x100"},
        ):
            fixture = self._fixture([{"name": "unsafe", "domain": "Lens", **field}])
            with self.assertRaises(ValueError):
                import_sdk_contracts(self.db, fixture)
        self.assertEqual(self.db.connection.execute("SELECT COUNT(*) FROM sdk_interface").fetchone()[0], 0)
        self.assertEqual(self.db.connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0], 0)

    def test_unknown_primary_evidence_rolls_back_entire_batch(self) -> None:
        fixture = self._fixture([
            {"name": "safe_candidate", "domain": "Media"},
            {"name": "missing_evidence", "domain": "Sensor", "source_evidence_id": 999999},
        ])
        with self.assertRaisesRegex(ValueError, "does not exist"):
            import_sdk_contracts(self.db, fixture)
        self.assertEqual(self.db.connection.execute("SELECT COUNT(*) FROM sdk_interface").fetchone()[0], 0)
        self.assertEqual(self.db.connection.execute("SELECT COUNT(*) FROM evidence").fetchone()[0], 0)
        self.assertEqual(self.db.connection.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_malicious_runtime_flags_do_not_authorize_execution(self) -> None:
        _, function_id, evidence_id = self._function_with_evidence()
        binary_id = self.db.connection.execute("SELECT binary_id FROM function WHERE id=?", (function_id,)).fetchone()[0]
        self.db.upsert("sdk_interface", {
            "identity_key": "injected:runtime", "name": "unsafe_firmware_call", "domain": "Sensor",
            "binary_id": binary_id, "function_id": function_id, "address": "0x100",
            "abi": "AAPCS", "parameter_layout": "[]", "return_semantics": "int",
            "verification_status": "VERIFIED_RUNTIME", "runtime_safety": "CALLABLE_VALIDATED",
            "source_evidence_id": evidence_id,
        }, ("identity_key",))
        self.db.commit()
        audit = audit_sdk_contracts(self.db)
        self.assertIn("UNSUPPORTED_RUNTIME_SAFETY_CLAIM", audit["records"][0]["issues"])
        self.assertIn("RUNTIME_CLAIM_REQUIRES_INDEPENDENT_VALIDATION", audit["records"][0]["issues"])
        exported = build_sdk_index(self.db, self.root / "index.json")
        self.assertIsNone(exported["coverage"]["callable_validated_interfaces"])

    def test_cli_import_and_audit(self) -> None:
        fixture = self._fixture([{"name": "display_state", "domain": "UI"}])
        self.db.close()
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(main([
                    "--db", str(self.root / "sdk.sqlite"), "sdk",
                    "import", "--fixture", str(fixture), "--json",
                ]), 0)
            self.assertEqual(json.loads(out.getvalue())["interfaces"], 1)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(main([
                    "--db", str(self.root / "sdk.sqlite"), "sdk", "audit", "--json",
                ]), 0)
            self.assertEqual(json.loads(out.getvalue())["unresolved_or_incomplete"], 1)
        finally:
            self.db = Database(self.root / "sdk.sqlite")


if __name__ == "__main__":
    unittest.main()
