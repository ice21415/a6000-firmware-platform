"""Synthetic checks for the private ParamBase family probe."""
import unittest
import json
from pathlib import Path

from fwplatform.param_family_probe import (
    PARAM_FAMILY_TARGETS,
    validate_param_family_contract,
    _target_symbol,
    _vma_symbol,
)
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


class ParamFamilyProbeTests(unittest.TestCase):
    def test_profile_covers_all_discovered_parambase_names(self) -> None:
        names = {item['name'] for item in PARAM_FAMILY_TARGETS}
        self.assertEqual(names, {
            'PrmBool', 'PrmNumber', 'PrmString', 'PrmPoint',
            'PrmDimension', 'PrmStruct', 'PrmSet', 'PrmObjMsg',
            'PrmCntInfoList', 'PrmNumberList',
        })

    def _contract(self) -> dict:
        return {
            "binary_sha256": EXPECTED_LIBOBJ_SHA,
            "address_space": "ELF_VMA",
            "runtime_verified": False,
            "callable": False,
            "types": [{
                "name": "SyntheticParam",
                "verification": "PRIMARY_ELF_VERIFIED",
                "vtable": {"address_space": "ELF_VMA"},
                "runtime_verified": False,
                "callable": False,
            }],
        }

    def test_public_contract_is_static_only(self) -> None:
        result = validate_param_family_contract(self._contract())
        self.assertTrue(result["valid"])
        self.assertEqual(result["type_count"], 1)

    def test_runtime_claim_is_rejected(self) -> None:
        contract = self._contract()
        contract["runtime_verified"] = True
        result = validate_param_family_contract(contract)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])

    def test_missing_address_space_is_not_filled_in(self) -> None:
        contract = self._contract()
        del contract["types"][0]["vtable"]["address_space"]
        result = validate_param_family_contract(contract)
        self.assertFalse(result["valid"])
        self.assertIn("missing_vtable_address_space:SyntheticParam", result["errors"])

    def test_thumb_symbol_identity_is_normalized_for_lookup(self) -> None:
        symbols = {"_ZN3Foo3barEv": (0x1001, 8)}
        self.assertEqual(_vma_symbol(symbols, "_ZN3Foo3barEv"), 0x1000)
        self.assertEqual(_target_symbol(symbols, 0x1001), "_ZN3Foo3barEv")

    def test_ambiguous_target_does_not_choose_a_symbol(self) -> None:
        symbols = {"first": (0x2001, 4), "second": (0x2000, 4)}
        self.assertIsNone(_target_symbol(symbols, 0x2001))

    def test_checked_in_family_contract_preserves_ehabi_lifecycle_metadata(self) -> None:
        path = Path(__file__).resolve().parents[1] / "sdk/parameter_types_lifetime_3_21.json"
        contract = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(len(contract["types"]), 10)
        for item in contract["types"]:
            unwind = item.get("exception_unwind")
            self.assertIsInstance(unwind, dict, item["name"])
            self.assertEqual(unwind["status"], "PRIMARY_ELF_VERIFIED")
            self.assertEqual(unwind["format"], "ARM EHABI .ARM.exidx metadata")
            targets = unwind["targets"]
            for role, key in (
                ("constructor", "constructor"),
                ("clone", "clone_candidate"),
                ("nondeleting_destructor", "nondeleting_destructor"),
                ("deleting_destructor", "deleting_destructor"),
            ):
                if item.get(key) is None:
                    continue
                self.assertIn(role, targets, f"{item['name']}:{role}")
                self.assertEqual(targets[role]["entry_vma"], str(item[key]).split(maxsplit=1)[0])
                self.assertEqual(targets[role]["address_space"], "ELF_VMA")
                self.assertEqual(targets[role]["status"], "PRIMARY_ELF_VERIFIED")

    def test_exception_metadata_cannot_be_promoted_to_runtime(self) -> None:
        contract = self._contract()
        contract["types"][0]["exception_unwind"] = {
            "status": "PRIMARY_ELF_VERIFIED",
            "format": "ARM EHABI .ARM.exidx metadata",
            "targets": {
                "constructor": {
                    "entry_vma": "0x1000",
                    "status": "PRIMARY_ELF_VERIFIED",
                    "address_space": "ELF_VMA",
                }
            },
        }
        contract["types"][0]["runtime_verified"] = True
        result = validate_param_family_contract(contract)
        self.assertFalse(result["valid"])
        self.assertIn("unsafe_type_claim:SyntheticParam", result["errors"])


if __name__ == "__main__":
    unittest.main()
