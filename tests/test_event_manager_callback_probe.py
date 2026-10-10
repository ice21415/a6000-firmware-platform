import unittest

from fwplatform.event_manager_callback_probe import validate_event_manager_callback


class EventManagerCallbackContractTests(unittest.TestCase):
    @staticmethod
    def valid_result():
        return {
            "status": "PRIMARY_ELF_RELOCATION_STATIC",
            "address_space": "ELF_VMA",
            "slot_vma": "0x1031894",
            "stored_thumb_value": "0x7eeb25",
            "callback_entry_vma": "0x7eeb24",
            "relocation": "R_ARM_RELATIVE",
            "consumer_callsite": "0x7ef9ce",
            "verification": "STATIC_INFERRED",
            "runtime_verified": False,
            "instructions": [{"instruction_vma": "0x7eeb24", "mnemonic": "push", "operands": "{r3, r4, r7, lr}"}],
        }

    def test_relocation_target_stays_static_inferred(self):
        result = self.valid_result()
        self.assertEqual(validate_event_manager_callback(result), [])

    def test_model_consumer_promotion_is_rejected(self):
        result = self.valid_result()
        result["verification"] = "PRIMARY_ELF_VERIFIED"
        self.assertIn("verification_promotion", validate_event_manager_callback(result))

    def test_empty_instruction_evidence_is_rejected(self):
        result = self.valid_result()
        result["instructions"] = []
        self.assertIn("missing callback instruction evidence", validate_event_manager_callback(result))

    def test_wrong_relocated_word_is_rejected(self):
        result = self.valid_result()
        result["stored_thumb_value"] = "0x7eeb24"
        self.assertIn("stored callback pointer", validate_event_manager_callback(result))


if __name__ == "__main__":
    unittest.main()
