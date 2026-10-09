"""Synthetic AAPCS32 request prototype tests; no vendor ELF/opcode assets."""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from fwplatform.cli import main
from fwplatform.request_abi import (
    EXPECTED_ABI, REGISTER_SITES, UI_SITES,
    audit_request_abi, demangle_aapcs_parameter_types,
)


ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "sdk" / "camera_3_21_request_abi_leads.json"


def synthetic_libobj(entries=None):
    contents = ["FILE synthetic/no-camera-binary.so"]
    for addr, (name, _, _, _) in EXPECTED_ABI.items():
        symbol = next(x["symbol"] for x in
                      json.loads(FIXTURE.read_text())["entrypoints"]
                      if x["entry_vma"] == addr)
        contents.append(f"ENTRY {addr} {symbol}")
        for vma, op in REGISTER_SITES[addr]:
            if entries and vma in entries:
                op = entries[vma]
            contents.append(f"{vma}: {op}")
        contents.append("")
    return "\n".join(contents) + "\n"


def synthetic_view(changes=None):
    items = ["FILE synthetic/viewUnified2.so"]
    for vma, op in UI_SITES:
        items.append(f"{vma}: {(changes or {}).get(vma, op)}")
    return "\n".join(items) + "\n"


class RequestParameterABITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.fixture = self.dir / "request-abi.json"
        self.libobj = self.dir / "saved-libobj.txt"
        self.view = self.dir / "saved-view.txt"
        self.libobj.write_text(synthetic_libobj(), encoding="utf-8")
        self.view.write_text(synthetic_view(), encoding="utf-8")
        self._save()

    def tearDown(self):
        self.tmp.cleanup()

    def _save(self):
        self.fixture.write_text(json.dumps(self.data), encoding="utf-8")

    def _audit(self, obj=True, view=True):
        self._save()
        return audit_request_abi(
            self.fixture, saved_libobj=self.libobj if obj else None,
            saved_view=self.view if view else None,
        )

    def test_mangling_reveals_three_parameters_not_static_or_return_type(self):
        a = demangle_aapcs_parameter_types(
            "_ZN8ViewBase19requestModelExecuteEPKcmP9ParamList")
        b = demangle_aapcs_parameter_types(
            "_ZN13viewManagerIf19requestModelExecuteEPKcmP9ParamList")
        c = demangle_aapcs_parameter_types(
            "_ZN22AbstractUtilityManager30createRequestModelExecuteEventEimP9ParamList")
        self.assertEqual(a, ("ViewBase::requestModelExecute",
                             ("char const*", "unsigned long", "ParamList*")))
        self.assertEqual(b, ("viewManagerIf::requestModelExecute",
                             ("char const*", "unsigned long", "ParamList*")))
        self.assertEqual(c, ("AbstractUtilityManager::createRequestModelExecuteEvent",
                             ("int", "unsigned long", "ParamList*")))
        for malformed in ["_ZN8ViewBase19requestModelExecuteEX",
                          "_ZN9ViewBase19requestModelExecuteEPKcmP9ParamList",
                          "_ZN8ViewBase19requestModelExecuteEPKcmP8ParamList",
                          "requestModelExecuteEPKcmP9ParamList",
                          "_ZN8ViewBase19requestModelExecuteEPKcmP9ParamListR"]:
            with self.subTest(value=malformed):
                with self.assertRaises(ValueError):
                    demangle_aapcs_parameter_types(malformed)

    def test_scoped_static_vs_member_register_mapping_and_factory_event_result(self):
        result = self._audit()
        self.assertEqual(result["status"], "TWO_SAVED_ELF_TEXT_CHECKS_MATCH")
        self.assertEqual(result["saved_libobj_register_sites_checked"],
                         sum(len(v) for v in REGISTER_SITES.values()))
        self.assertEqual(result["saved_view_ui_sites_checked"], len(UI_SITES))
        self.assertEqual(len(result["entrypoint_parameter_prototypes"]), 3)
        instance, static, factory = result["entrypoint_parameter_prototypes"]
        self.assertEqual(instance["method_form"], "INSTANCE_METHOD_CANDIDATE")
        self.assertEqual(instance["register_mapping"]["r0"], "ViewBase* this")
        self.assertEqual(instance["register_mapping"]["r3"], "ParamList* params")
        self.assertEqual(static["method_form"], "STATIC_METHOD_CANDIDATE")
        self.assertEqual(static["register_mapping"]["r0"], "char const* model_name")
        self.assertEqual(static["register_mapping"]["r2"], "ParamList* params")
        self.assertNotIn("r3", static["register_mapping"])
        self.assertEqual(factory["register_mapping"]["r3"], "ParamList* params")
        self.assertEqual(result["factory_event_pointer_return_static_inference"],
                         "Event* allocation/constructor/r0 return")
        self.assertFalse(result["factory_return_abi_verified"])
        self.assertFalse(result["selector_transform_0x12d780_verified"])
        self.assertFalse(result["actual_elf_bytes_redecoded"])
        self.assertEqual(result["sony_camera_core_api_abi_completed"], 0)
        self.assertTrue(all(not x["return_type_verified"] for x in result["entrypoint_parameter_prototypes"]))

    def test_missing_saved_files_returns_candidate_only(self):
        result = self._audit(obj=False, view=False)
        self.assertEqual(result["status"], "STATIC_PROTOTYPE_CANDIDATES_ONLY")
        self.assertIsNone(result["saved_libobj_register_sites_checked"])
        self.assertIsNone(result["saved_view_ui_sites_checked"])
        self.assertFalse(result["actual_elf_bytes_redecoded"])
        self.assertEqual(self._audit(obj=True, view=False)["status"],
                         "ONE_SAVED_ELF_TEXT_CHECK_MATCH")
        self.assertEqual(self._audit(obj=False, view=True)["status"],
                         "ONE_SAVED_ELF_TEXT_CHECK_MATCH")

    def test_static_entry_drops_original_r3_and_passes_original_r2_as_paramlist(self):
        self.libobj.write_text(synthetic_libobj({
            "0x1250e8": "mov      r3, r6",
        }))
        with self.assertRaisesRegex(ValueError, "0x1250e8"):
            self._audit(view=False)
        self.libobj.write_text(synthetic_libobj({
            "0x1250c0": "mov      r3, r0",
        }))
        with self.assertRaisesRegex(ValueError, "0x1250c0"):
            self._audit(view=False)

    def test_member_entry_helper_uses_name_selector_and_preserves_original_r3(self):
        for vma, changed in [("0x121086", "mov      r1, r8"),
                             ("0x12108a", "mov      r0, sl"),
                             ("0x121092", "mov      r3, r5")]:
            self.libobj.write_text(synthetic_libobj({vma: changed}))
            with self.subTest(vma=vma), self.assertRaisesRegex(ValueError, vma):
                self._audit(view=False)

    def test_derived_factory_pointer_requires_constructor_and_r0_return_flow(self):
        for vma, changed in [("0x7f0b1a", "blx      #0xdead ; _Znwj"),
                             ("0x7f0b26", "blx      #0xdead ; _ZN5EventC1Emhh"),
                             ("0x7f0b64", "mov      r0, r5"),
                             ("0x7f0b66", "bx       r4")]:
            self.libobj.write_text(synthetic_libobj({vma: changed}))
            with self.subTest(vma=vma), self.assertRaisesRegex(ValueError, vma):
                self._audit(view=False)

    def test_ui_cross_elf_model_camera_o_f01_and_param_registers(self):
        for vma, changed in [("0x1a26de", "movw     r2, #0xf02"),
                             ("0x1a26e2", "model/STILL_REC"),
                             ("0x1a26e4", "mov      r3, r5"),
                             ("0x1a26e6", "blx      #0xeb614 ; _ZN8ViewBase19requestModelExecuteEPKcmP9ParamList")]:
            self.view.write_text(synthetic_view({vma: changed}))
            with self.subTest(vma=vma), self.assertRaisesRegex(ValueError, vma):
                self._audit(obj=False)

    def test_do_not_promote_return_type_or_callable_camera_abi(self):
        self.data["entrypoints"][1]["method_form"] = "INSTANCE_METHOD_CANDIDATE"
        with self.assertRaisesRegex(ValueError, "parameter ABI evidence"):
            self._audit(obj=False, view=False)
        self.data = json.loads(FIXTURE.read_text())
        self.data["entrypoints"][2]["return_type_verified"] = True
        with self.assertRaisesRegex(ValueError, "parameter ABI evidence"):
            self._audit(obj=False, view=False)
        self.data = json.loads(FIXTURE.read_text())
        self.data["callable_camera_api_count"] = 1
        with self.assertRaisesRegex(ValueError, "noncallable"):
            self._audit(obj=False, view=False)

    def test_ambiguous_view_saved_file_rejected(self):
        self.view.write_text(synthetic_view()
            + "0x1a26e6: blx      #0xeb610 ; _ZN8ViewBase19requestModelExecuteEPKcmP9ParamList\n")
        with self.assertRaisesRegex(ValueError, "ambiguous UI"):
            self._audit(obj=False)

    def test_cli_keeps_sqlite_unmodified(self):
        db = self.dir / "should-not-exist.sqlite"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            rc = main([
                "--db", str(db), "sdk", "request-abi",
                "--fixture", str(self.fixture),
                "--saved-libobj", str(self.libobj), "--saved-view",
                str(self.view), "--json",
            ])
        self.assertEqual(rc, 0)
        self.assertFalse(db.exists())
        result = json.loads(output.getvalue())
        self.assertEqual(result["status"], "TWO_SAVED_ELF_TEXT_CHECKS_MATCH")
        self.assertEqual(result["sony_camera_core_api_abi_completed"], 0)


if __name__ == "__main__":
    unittest.main()
