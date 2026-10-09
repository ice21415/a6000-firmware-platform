"""Public metadata validation; contains no Sony bytes or decompiler output."""
import copy
import json
from pathlib import Path
import unittest

from fwplatform.primary_contracts import validate_primary_contracts


class PrimaryContractTests(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).resolve().parents[1] / "sdk/core_3_21_primary_helper_contracts.json"
        self.contract = json.loads(path.read_text(encoding="utf-8"))

    def test_descriptive_contracts_never_grant_callability(self):
        self.assertEqual(validate_primary_contracts(self.contract)["callable_interfaces"], 0)

    def test_param_family_factory_keeps_tag_mapping_descriptive(self):
        factory = next(item for item in self.contract["interfaces"]
                       if item["name"] == "param_family_factory_candidate")
        self.assertEqual(factory["entry"], "0x42acd4")
        self.assertFalse(factory["safe_to_call"])
        self.assertEqual(
            {branch["discriminator"] for branch in factory["branches"]},
            {1, 3, 5},
        )
        self.assertTrue(factory["declared_return_type"].startswith("UNKNOWN"))
        helpers = {item["name"]: item for item in self.contract["interfaces"]}
        self.assertEqual(helpers["discriminator_five_lookup_forwarder"]["entry"], "0x120970")
        self.assertEqual(helpers["discriminator_three_lookup_forwarder"]["entry"], "0xfe9be")
        self.assertEqual(helpers["bool_payload_word_getter"]["entry"], "0x120968")
        self.assertEqual(helpers["point_payload_word_0c_getter"]["entry"], "0xfe9ae")
        self.assertEqual(helpers["point_payload_word_10_getter"]["entry"], "0xfe9b6")

    def test_static_status_cannot_enable_runtime(self):
        for field in ("runtime_verified", "callable"):
            doc = copy.deepcopy(self.contract)
            doc[field] = True
            with self.assertRaises(ValueError):
                validate_primary_contracts(doc)

    def test_identity_address_and_evidence_fail_closed(self):
        for field, value in (("binary_sha256", "0" * 64), ("address_space", "ram")):
            doc = copy.deepcopy(self.contract)
            doc[field] = value
            with self.assertRaises(ValueError):
                validate_primary_contracts(doc)
        self.contract["interfaces"][0]["evidence_locators"] = []
        with self.assertRaises(ValueError):
            validate_primary_contracts(self.contract)
