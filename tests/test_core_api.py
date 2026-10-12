"""Core Camera/Lens/Sensor API review is evidence-only and read-only."""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from fwplatform.cli import main
from fwplatform.core_api import investigate_core_apis
from fwplatform.db import Database


class CoreApiInvestigationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.dbfile = self.root / "research.sqlite"
        self.db = Database(self.dbfile)
        self.assertEqual(self.db.migrate(), 7)
        self.camera_sha, self.lens_sha = "a" * 64, "b" * 64
        self.binaries = {}
        self.functions = {}
        for name, sha in (("Camera_capture", self.camera_sha),
                          ("Lens_focus", self.lens_sha)):
            binary = self.db.upsert("binary", {
                "path": name + ".so", "sha256": sha, "size": 42,
                "format": "elf_executable_or_shared_library",
            }, ("path",))
            module = self.db.upsert("module", {
                "name": name + ".so", "identity_key": "module:" + name,
                "binary_id": binary,
            }, ("identity_key",))
            function = self.db.upsert("function", {
                "binary_id": binary, "module_id": module,
                "name": name, "identity_key": "function:" + name,
                "address": "0x100",
            }, ("identity_key",))
            self.db.upsert("import_export", {
                "binary_id": binary, "name": name, "address": "0x100",
                "direction": "export", "status": "VERIFIED_STATIC",
            }, ("binary_id", "name", "direction", "address"))
            self.binaries[name], self.functions[name] = binary, function
        evidence = self.db.evidence(
            "synthetic-camera-ghidra.jsonl", "c" * 64, "ghidra_function_entry",
            "function:0x100", json.dumps({
                "binary_sha256": self.camera_sha, "function_entry": "0x100",
            }), "VERIFIED_STATIC",
        )
        self.db.connection.execute(
            "UPDATE function SET source_evidence_id=? WHERE id=?",
            (evidence, self.functions["Camera_capture"]),
        )
        self.callsite_evidence = self.db.evidence(
            "synthetic-callsite.jsonl", "d" * 64, "ghidra_jsonl",
            "callsite:0x220", "{}", "VERIFIED_STATIC",
        )
        self.db.commit()

    def tearDown(self) -> None:
        self.db.close()
        self.temp.cleanup()

    def _call(self, address: str = "0x220") -> None:
        self.db.upsert("callsite", {
            "identity_key": "call:" + address,
            "caller_id": self.functions["Lens_focus"],
            "callee_id": self.functions["Camera_capture"],
            "address": address, "target": "0x100", "kind": "call",
            "status": "VERIFIED_STATIC",
            "source_evidence_id": self.callsite_evidence,
            "caller_resolution": "EXPLICIT_AND_BODY_RANGE_VALID",
        }, ("identity_key",))
        self.db.commit()

    def _camera(self, **options):
        return investigate_core_apis(self.db, domain="Camera", **options)

    def test_camera_callgraph_evidence_and_unknown_semantics(self) -> None:
        self._call()
        changes = self.db.connection.total_changes
        result = self._camera()
        self.assertEqual(self.db.connection.total_changes, changes)
        self.assertTrue(result["read_only"])
        self.assertFalse(result["hardware_access"])
        self.assertEqual(result["indexed_candidates"], 1)
        row = result["investigations"][0]
        self.assertEqual(row["candidate"]["symbol_name"], "Camera_capture")
        self.assertTrue(row["candidate"]["entry_location_evidence_valid"])
        call = row["incoming_calls"]["rows"][0]
        self.assertEqual(call["peer_function_name"], "Lens_focus")
        self.assertEqual(call["peer_binary_sha256"], self.lens_sha)
        self.assertEqual(call["evidence_id"], self.callsite_evidence)
        self.assertEqual(call["relationship"], "direct_function_id")
        self.assertFalse(call["semantic_proof"])
        self.assertFalse(row["abi_verified"])
        self.assertFalse(row["runtime_callable"])
        self.assertIsNone(result["core_api_completion"])

    def test_osal_and_jni_require_explicit_function_ids(self) -> None:
        camera = self.functions["Camera_capture"]
        queue = self.db.upsert("message_queue", {
            "identity_key": "queue:camera:test", "namespace": "Camera",
            "queue_value": "0x100", "name": "camera_queue",
        }, ("identity_key",))
        msg = self.db.upsert("osal_message", {
            "identity_key": "osal:camera:test", "queue_id": queue,
        }, ("identity_key",))
        # Same address in the Lens ELF is unrelated: one direct FK identifies
        # a Camera function, while a similar name/address proves nothing else.
        evidence = self.db.evidence(
            "synthetic-osal.json", "e" * 64, "osal_fixture",
            "document", "{}", "CANDIDATE",
        )
        self.db.upsert("message_flow", {
            "identity_key": "flow:camera:producer", "osal_message_id": msg,
            "function_id": camera, "role": "producer",
            "source_evidence_id": evidence, "status": "CANDIDATE",
        }, ("identity_key",))
        self.db.upsert("jni_bridge", {
            "identity_key": "jni:camera:method", "class_name": "Lcamera/C;",
            "method_name": "capture", "signature": "()V", "dex_path": "classes.dex",
            "native_function_id": camera, "status": "CANDIDATE",
            "source_evidence_id": evidence,
        }, ("identity_key",))
        self.db.commit()
        row = self._camera()["investigations"][0]
        self.assertEqual(row["osal_function_roles"]["shown"], 1)
        self.assertEqual(row["osal_function_roles"]["rows"][0]["queue_namespace"], "Camera")
        self.assertEqual(row["osal_function_roles"]["rows"][0]["role"], "producer")
        self.assertEqual(row["jni_native_bridges"]["shown"], 1)
        self.assertFalse(row["jni_native_bridges"]["rows"][0]["runtime_registration_verified"])
        lens = investigate_core_apis(self.db, domain="Lens")["investigations"][0]
        self.assertEqual(lens["osal_function_roles"]["shown"], 0)
        self.assertEqual(lens["jni_native_bridges"]["shown"], 0)

    def test_camera_state_names_are_not_bound_to_function(self) -> None:
        machine = self.db.upsert("state_machine", {
            "name": "ModelCamera.selector", "status": "CANDIDATE",
        }, ("name",))
        self.db.upsert("state_transition", {
            "identity_key": "transition:camera:test", "machine_id": machine,
            "status": "CANDIDATE", "action": "synthetic_not_ready",
        }, ("identity_key",))
        self.db.commit()
        result = self._camera()
        context = result["state_machine_context"]
        self.assertEqual(context["scope"], "lexical_machine_name_only")
        self.assertEqual(context["machines"][0]["transitions"], 1)
        self.assertFalse(context["function_to_state_link_verified"])
        self.assertFalse(context["camera_ready_or_first_shot_verified"])
        self.assertNotIn("state_machine", result["investigations"][0])

    def test_relation_limit_marks_truncation_and_preserves_source(self) -> None:
        self._call("0x220")
        self._call("0x224")
        row = self._camera(relation_limit=1)["investigations"][0]
        relations = row["incoming_calls"]
        self.assertEqual(relations["shown"], 1)
        self.assertTrue(relations["truncated"])
        self.assertEqual(relations["rows"][0]["callsite_address"], "0x220")

    def test_unknown_domain_invalid_bounds_and_empty_candidates(self) -> None:
        with self.assertRaises(ValueError):
            investigate_core_apis(self.db, domain="Other")
        with self.assertRaises(ValueError):
            self._camera(limit=0)
        with self.assertRaises(ValueError):
            self._camera(relation_limit=0)
        with self.assertRaises(ValueError):
            self._camera(relation_limit=13)
        result = investigate_core_apis(self.db, domain="Sensor")
        self.assertEqual(result["indexed_candidates"], 0)
        self.assertEqual(result["investigations"], [])
        self.assertIsNone(result["runtime_callable_apis"])

    def test_cli_investigate_camera_is_descriptive(self) -> None:
        self.db.close()
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(main([
                "--db", str(self.dbfile), "sdk", "investigate",
                "--domain", "Camera", "--limit", "10",
                "--relation-limit", "2", "--json",
            ]), 0)
        result = json.loads(stdout.getvalue())
        self.assertEqual(result["domain"], "Camera")
        self.assertEqual(result["status"], "STATIC_RESEARCH_ONLY")
        self.assertEqual(result["indexed_candidates"], 1)
        self.assertIsNone(result["runtime_callable_apis"])
        self.db = Database(self.dbfile)

    def test_inspect_exact_generated_function_without_lexical_domain(self) -> None:
        from fwplatform.function_inspection import inspect_function
        bid = self.binaries["Camera_capture"]
        original_module = self.db.connection.execute(
            "SELECT module_id FROM function WHERE id=?",
            (self.functions["Camera_capture"],),
        ).fetchone()[0]
        fid = self.db.upsert("function", {
            "binary_id": bid, "module_id": original_module,
            "identity_key": "function:generated:0x900",
            "name": "FUN_00000900", "address": "0x900",
            "generated_name": 1, "prototype": "void FUN_00000900(void)",
        }, ("identity_key",))
        self.db.upsert("state_machine", {
            "name": "ModelCamera.selector_dispatch",
            "module_id": original_module, "status": "CANDIDATE",
        }, ("name",))
        self.db.commit()
        changes = self.db.connection.total_changes
        record = inspect_function(self.db, function_id=fid)
        self.assertEqual(self.db.connection.total_changes, changes)
        self.assertTrue(record["function"]["generated_name"])
        self.assertEqual(record["function"]["raw_prototype_unverified"],
                         "void FUN_00000900(void)")
        self.assertFalse(record["function"]["location_evidence_valid"])
        self.assertEqual(record["function"]["abi_status"], "UNKNOWN")
        self.assertFalse(record["function"]["runtime_callable"])
        context = record["module_state_machine_context"]
        self.assertEqual(context["scope"], "module_id_only_not_function_transition_proof")
        self.assertEqual(context["rows"][0]["name"], "ModelCamera.selector_dispatch")
        self.assertFalse(context["function_to_state_link_verified"])
        self.assertEqual(self._camera()["indexed_candidates"], 1)

    def test_inspect_same_numeric_entry_downgrades_identity(self) -> None:
        from fwplatform.function_inspection import inspect_function
        fid = self.functions["Camera_capture"]
        self.db.upsert("function", {
            "binary_id": self.binaries["Camera_capture"],
            "identity_key": "function:alias:0x0100",
            "name": "FUN_alias", "address": "0x0100",
        }, ("identity_key",))
        self.db.commit()
        row = inspect_function(self.db, function_id=fid)
        self.assertFalse(row["function"]["identity_unique"])
        self.assertFalse(row["function"]["location_evidence_valid"])
        self.assertIsNone(row["function"]["location_evidence_id"])

    def test_inspect_invalid_ids_and_cli_response(self) -> None:
        from fwplatform.function_inspection import inspect_function
        with self.assertRaises(ValueError):
            inspect_function(self.db, function_id=0)
        with self.assertRaises(ValueError):
            inspect_function(self.db, function_id=999999)
        with self.assertRaises(ValueError):
            inspect_function(self.db, function_id=self.functions["Camera_capture"],
                             relation_limit=0)
        camera_id = self.functions["Camera_capture"]
        self.db.close()
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            self.assertEqual(main([
                "--db", str(self.dbfile), "sdk", "inspect",
                "--function-id", str(camera_id), "--json",
            ]), 0)
        result = json.loads(captured.getvalue())
        self.assertEqual(result["function"]["id"], camera_id)
        self.assertTrue(result["function"]["location_evidence_valid"])
        self.assertEqual(result["function"]["abi_status"], "UNKNOWN")
        self.db = Database(self.dbfile)


if __name__ == "__main__":
    unittest.main()
