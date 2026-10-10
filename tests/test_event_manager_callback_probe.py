import unittest

from fwplatform.event_manager_callback_probe import validate_event_manager_callback


class EventManagerCallbackContractTests(unittest.TestCase):
    def test_relocation_target_stays_static_inferred(self):
        result = {
            "address_space": "ELF_VMA",
            "verification": "STATIC_INFERRED",
            "callback_entry_vma": "0x7eeb24",
            "runtime_verified": False,
        }
        self.assertEqual(validate_event_manager_callback(result), [])

    def test_model_consumer_promotion_is_rejected(self):
        result = {
            "address_space": "ELF_VMA",
            "verification": "PRIMARY_ELF_VERIFIED",
            "callback_entry_vma": "0x7eeb24",
            "runtime_verified": False,
        }
        self.assertIn("verification_promotion", validate_event_manager_callback(result))


if __name__ == "__main__":
    unittest.main()
