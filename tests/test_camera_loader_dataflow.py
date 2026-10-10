import unittest

from fwplatform.camera_loader_dataflow import validate_loader_dataflow


class LoaderDataflowContractTests(unittest.TestCase):
    def test_static_result_keeps_runtime_identity_unknown(self):
        result = {
            "status": "PRIMARY_ELF_STATIC_DATAFLOW",
            "address_space": "ELF_VMA",
            "runtime_loader_identity": "UNKNOWN",
            "facts": [{}] * 10,
        }
        self.assertEqual(validate_loader_dataflow(result), [])

    def test_runtime_identity_promotion_is_rejected(self):
        result = {
            "status": "PRIMARY_ELF_STATIC_DATAFLOW",
            "address_space": "ELF_VMA",
            "runtime_loader_identity": "VERIFIED_RUNTIME",
            "facts": [{}] * 10,
        }
        self.assertIn("runtime identity was improperly promoted", validate_loader_dataflow(result))

    def test_incomplete_fact_set_is_rejected(self):
        result = {
            "status": "PRIMARY_ELF_STATIC_DATAFLOW",
            "address_space": "ELF_VMA",
            "runtime_loader_identity": "UNKNOWN",
            "facts": [],
        }
        self.assertIn("incomplete instruction fact set", validate_loader_dataflow(result))


if __name__ == "__main__":
    unittest.main()
