"""Synthetic checks for the private ParamBase family probe."""
import unittest

from fwplatform.param_family_probe import (
    validate_param_family_contract,
    _target_symbol,
    _vma_symbol,
)
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


class ParamFamilyProbeTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
