"""Conservative multi-ELF import-provider resolution regression tests."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fwplatform.db import Database, sha256_file
from fwplatform.linkage import ElfMetadata, analyze_linkage


class LinkageResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.db = Database(self.root / "linkage.sqlite")
        self.db.migrate()
        self.binaries = {}
        for name in ("main.so", "libprovider.so", "libother.so"):
            file = self.root / name
            file.write_bytes(("synthetic-" + name).encode())
            self.binaries[name] = self.db.upsert("binary", {
                "path": name, "sha256": sha256_file(file), "size": file.stat().st_size,
                "format": "elf_executable_or_shared_library",
            }, ("path",))
        self.db.commit()

    def tearDown(self) -> None:
        self.db.close()
        self.temp.cleanup()

    def _add(self, binary: str, direction: str, address: str,
             version: str | None = None, name: str = "Camera_capture") -> None:
        self.db.upsert("import_export", {
            "binary_id": self.binaries[binary], "name": name, "direction": direction,
            "address": address, "version": version, "status": "VERIFIED_STATIC",
        }, ("binary_id", "name", "direction", "address"))
        self.db.commit()

    def _analyze(self, needed: tuple[str, ...]) -> dict[str, int]:
        def metadata(path: Path) -> ElfMetadata:
            if path.name == "main.so":
                return ElfMetadata(needed=needed, soname="main.so")
            return ElfMetadata(soname=path.name)
        with patch("fwplatform.linkage._elf_metadata", side_effect=metadata):
            return analyze_linkage(self.db, self.root)

    def _unresolved_reason(self) -> dict:
        rows = self.db.query("SELECT reason FROM unresolved_edge WHERE relation='import_symbol'")
        self.assertEqual(len(rows), 1)
        return json.loads(rows[0]["reason"])

    def test_unrelated_global_export_is_not_dependency(self) -> None:
        self._add("main.so", "import", "0x200")
        self._add("libother.so", "export", "0x120")
        stats = self._analyze(("libmissing.so",))
        self.assertEqual(stats["resolved_symbols"], 0)
        self.assertEqual(stats["unresolved_symbols"], 1)
        self.assertEqual(self.db.query("SELECT id FROM cross_reference WHERE kind='resolved_import'"), [])
        self.assertEqual(self._unresolved_reason()["reason"],
                         "no-resolved-dependency:Camera_capture")

    def test_distinct_export_addresses_same_binary_are_ambiguous(self) -> None:
        self._add("main.so", "import", "0x200")
        self._add("libprovider.so", "export", "0x100")
        self._add("libprovider.so", "export", "0x300")
        stats = self._analyze(("libprovider.so",))
        self.assertEqual(stats["needed"], 1)
        self.assertEqual(stats["ambiguous_symbols"], 1)
        self.assertEqual(stats["resolved_symbols"], 0)
        unresolved = self._unresolved_reason()
        self.assertEqual(unresolved["reason"], "ambiguous-export-entry:Camera_capture")
        self.assertEqual(unresolved["candidate_binary_ids"], [self.binaries["libprovider.so"]])

    def test_unique_dependent_export_is_only_candidate_binding(self) -> None:
        self._add("main.so", "import", "0x200")
        self._add("libprovider.so", "export", "0x0100")
        self._add("libother.so", "export", "0x500")
        stats = self._analyze(("libprovider.so",))
        self.assertEqual(stats["resolved_symbols"], 1)
        refs = self.db.query("SELECT from_binary_id,to_binary_id,to_address,status "
                             "FROM cross_reference WHERE kind='resolved_import'")
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["from_binary_id"], self.binaries["main.so"])
        self.assertEqual(refs[0]["to_binary_id"], self.binaries["libprovider.so"])
        self.assertEqual(refs[0]["to_address"], "0x0100")
        self.assertEqual(refs[0]["status"], "CANDIDATE")

    def test_versioned_import_does_not_fall_back_to_unversioned_export(self) -> None:
        self._add("main.so", "import", "0x200", version="ABI_2")
        self._add("libprovider.so", "export", "0x100")
        stats = self._analyze(("libprovider.so",))
        self.assertEqual(stats["resolved_symbols"], 0)
        self.assertEqual(self._unresolved_reason()["reason"],
                         "no-matching-dependent-export:Camera_capture")

    def test_zero_import_entry_is_unresolved(self) -> None:
        self._add("main.so", "import", "0x0")
        self._add("libprovider.so", "export", "0x100")
        stats = self._analyze(("libprovider.so",))
        self.assertEqual(stats["resolved_symbols"], 0)
        self.assertEqual(self._unresolved_reason()["reason"],
                         "no-import-address:Camera_capture")

    def test_catalog_change_recomputes_and_removes_stale_link(self) -> None:
        self._add("main.so", "import", "0x200")
        self._add("libprovider.so", "export", "0x100")
        self.assertEqual(self._analyze(("libprovider.so",))["resolved_symbols"], 1)
        self.assertEqual(self._analyze(("libprovider.so",))["skipped"], 3)
        # Same requester hash, but a newly discovered second provider VMA
        # must invalidate the checkpoint and revoke the old candidate link.
        self._add("libprovider.so", "export", "0x300")
        refreshed = self._analyze(("libprovider.so",))
        self.assertEqual(refreshed["resolved_symbols"], 0)
        self.assertEqual(refreshed["ambiguous_symbols"], 1)
        self.assertEqual(self.db.query(
            "SELECT id FROM cross_reference WHERE kind='resolved_import'"), [])
        self.assertEqual(self._unresolved_reason()["reason"],
                         "ambiguous-export-entry:Camera_capture")
        self.db.connection.execute(
            "DELETE FROM import_export WHERE binary_id=? AND address=?",
            (self.binaries["libprovider.so"], "0x300"),
        )
        self.db.commit()
        resolved = self._analyze(("libprovider.so",))
        self.assertEqual(resolved["resolved_symbols"], 1)
        self.assertEqual(self.db.query(
            "SELECT id FROM unresolved_edge WHERE relation='import_symbol'"), [])

    def test_failure_rolls_back_partial_links_and_keeps_failed_checkpoint(self) -> None:
        self._add("main.so", "import", "0x200")
        self._add("main.so", "import", "0x240", name="Camera_open")
        self._add("libprovider.so", "export", "0x100")
        self._add("libprovider.so", "export", "0x140", name="Camera_open")
        from fwplatform import linkage

        def metadata(path: Path) -> ElfMetadata:
            if path.name == "main.so":
                return ElfMetadata(needed=("libprovider.so",), soname="main.so")
            return ElfMetadata(soname=path.name)

        real_resolver = linkage._resolve_import_provider
        calls = 0

        def interrupted(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("synthetic resolver failure")
            return real_resolver(*args)

        with patch("fwplatform.linkage._elf_metadata", side_effect=metadata), patch(
            "fwplatform.linkage._resolve_import_provider", side_effect=interrupted
        ):
            stats = analyze_linkage(self.db, self.root)
        self.assertEqual(stats["failed"], 1)
        self.assertEqual(self.db.query(
            "SELECT id FROM cross_reference WHERE kind='resolved_import'"), [])
        failed = self.db.query(
            "SELECT status FROM analysis_run WHERE analyzer='elf_linkage' "
            "AND binary_id=?", (self.binaries["main.so"],)
        )
        self.assertEqual([x["status"] for x in failed], ["FAILED"])
        recovered = self._analyze(("libprovider.so",))
        self.assertEqual(recovered["resolved_symbols"], 2)
        self.assertEqual(len(self.db.query(
            "SELECT id FROM cross_reference WHERE kind='resolved_import'")), 2)


if __name__ == "__main__":
    unittest.main()
