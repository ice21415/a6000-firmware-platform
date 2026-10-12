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

    def test_paramlist_add_contract_keeps_replacement_and_ownership_unknown(self):
        add = next(item for item in self.contract["interfaces"]
                   if item["name"] == "ParamList::add")
        self.assertEqual(add["entry"], "0x7ee0e6")
        self.assertEqual(add["add_binding"]["symbol"], "_ZN9ParamList3addEmP9ParamBase")
        self.assertFalse(add["safe_to_call"])
        self.assertTrue(add["declared_return_type"].startswith("UNKNOWN"))
        self.assertIn("ownership", add)
        self.assertIn("UNKNOWN", add["ownership"])

    def test_paramlist_mutation_contracts_are_static_only(self):
        interfaces = {item["name"]: item for item in self.contract["interfaces"]}
        clear = interfaces["ParamList::clear"]
        destructor = interfaces["ParamList::~ParamList"]
        assignment = interfaces["ParamList::assignment_like_candidate"]
        self.assertEqual(clear["entry"], "0x7edb76")
        self.assertEqual(destructor["delete_binding"]["symbol"], "_ZdlPv")
        self.assertFalse(assignment["copy_on_write_detach_observed"])
        for item in (clear, destructor, assignment):
            self.assertFalse(item["safe_to_call"])
            self.assertTrue(item["declared_return_type"].startswith("UNKNOWN"))

    def test_static_status_cannot_enable_runtime(self):
        for field in ("runtime_verified", "callable"):
            doc = copy.deepcopy(self.contract)
            doc[field] = True
            with self.assertRaises(ValueError):
                validate_primary_contracts(doc)

    def test_query_callsite_index_remains_separate_static_evidence(self):
        index = self.contract["query_callsite_index"]
        self.assertEqual(index["contract"], "sdk/param_query_callers_3_21.json")
        self.assertEqual(index["address_space"], "ELF_VMA")
        self.assertFalse(index["runtime_verified"])
        self.assertFalse(index["callable"])

    def test_identity_address_and_evidence_fail_closed(self):
        for field, value in (("binary_sha256", "0" * 64), ("address_space", "ram")):
            doc = copy.deepcopy(self.contract)
            doc[field] = value
            with self.assertRaises(ValueError):
                validate_primary_contracts(doc)
        self.contract["interfaces"][0]["evidence_locators"] = []
        with self.assertRaises(ValueError):
            validate_primary_contracts(self.contract)
