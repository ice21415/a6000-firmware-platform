import unittest

from fwplatform.camera_loader_dataflow import validate_loader_dataflow


class LoaderDataflowContractTests(unittest.TestCase):
    @staticmethod
    def valid_result():
        facts = [
            ("0x7f11d6", "ldr", "r0, [r0, #0x10]"),
            ("0x7f11d8", "blx", "#0xe0cec"),
            ("0x7f11dc", "str", "r0, [r4, #0x18]"),
            ("0x7f11e2", "ldr", "r1, [r4, #0x14]"),
            ("0x7f11e6", "blx", "#0xdfed0"),
            ("0x7f11ee", "ldr", "r0, [r4]"),
            ("0x7f11f0", "ldr", "r1, [r4, #0x20]"),
            ("0x7f11f2", "blx", "r3"),
            ("0x7f11f4", "str", "r0, [r4, #0x1c]"),
            ("0x7f116c", "str", "r1, [r0, #0x14]"),
            ("0x7f1176", "str", "r1, [r0, #0x20]"),
            ("0x7ec91c", "bl", "#0x7f1156"),
        ]
        return {
            "status": "PRIMARY_ELF_STATIC_DATAFLOW",
            "address_space": "ELF_VMA",
            "runtime_loader_identity": "UNKNOWN",
            "internal_helpers": {
                "loader": {"entry_vma": "0xe0cec", "address_space": "ELF_VMA", "instruction_mode": "ARM", "instructions": [{"mnemonic": "add", "operands": "ip, pc, #1"}, {"mnemonic": "add", "operands": "ip, ip, #1"}, {"mnemonic": "ldr", "operands": "pc, [ip, #1]!"}]},
                "symbol_resolver": {"entry_vma": "0xdfed0", "address_space": "ELF_VMA", "instruction_mode": "ARM", "instructions": [{"mnemonic": "add", "operands": "ip, pc, #1"}, {"mnemonic": "add", "operands": "ip, ip, #1"}, {"mnemonic": "ldr", "operands": "pc, [ip, #1]!"}]},
            },
            "veneer_bindings": {
                "dlopen": {"elf_sha256": "8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a", "binding_status": "PRIMARY_ELF_VERIFIED", "dynamic_symbol": "dlopen", "relocation_type": 22},
                "dlsym": {"elf_sha256": "8e8a937aed23c2783e7bbee8a4afa2fb4bcd897606f190b17dccadd207d05b6a", "binding_status": "PRIMARY_ELF_VERIFIED", "dynamic_symbol": "dlsym", "relocation_type": 22},
            },
            "facts": [
                {"instruction_vma": a, "mnemonic": m, "operands": o,
                 "address_space": "ELF_VMA", "verification": "PRIMARY_ELF_VERIFIED"}
                for a, m, o in facts
            ],
        }

    def test_static_result_keeps_runtime_identity_unknown(self):
        result = self.valid_result()
        self.assertEqual(validate_loader_dataflow(result), [])

    def test_runtime_identity_promotion_is_rejected(self):
        result = self.valid_result()
        result["runtime_loader_identity"] = "VERIFIED_RUNTIME"
        self.assertIn("runtime identity was improperly promoted", validate_loader_dataflow(result))

    def test_incomplete_fact_set_is_rejected(self):
        result = self.valid_result()
        result["facts"] = []
        self.assertIn("incomplete instruction fact set", validate_loader_dataflow(result))

    def test_empty_facts_cannot_be_used_as_static_evidence(self):
        result = self.valid_result()
        result["facts"] = [{}] * 12
        errors = validate_loader_dataflow(result)
        self.assertTrue(any("empty" in error for error in errors))

    def test_wrong_operand_is_rejected(self):
        result = self.valid_result()
        result["facts"][0]["operands"] = "r0, [r1]"
        self.assertIn("instruction operand mismatch 0x7f11d6", validate_loader_dataflow(result))

    def test_missing_helper_binding_evidence_is_rejected(self):
        result = self.valid_result()
        result.pop("veneer_bindings")
        self.assertIn("missing veneer binding evidence", validate_loader_dataflow(result))


if __name__ == "__main__":
    unittest.main()
