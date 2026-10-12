"""Synthetic report validation; never primary ELF certification."""
import unittest
from fwplatform.event_manager_provider_probe import EXPECTED_SHA256, validate_event_manager_provider

def report():
    return {"schema_version":2,"elf_sha256":EXPECTED_SHA256,"address_space":"ELF_VMA","function_pointer_table_slot":"0x1031c38","indirection_level":1,"import_symbol":"getConfig","runtime_verified":False,"function_pointer_table_relocations":[{"type":21,"symbol":"getConfig"}]}

class ProviderTests(unittest.TestCase):
    def test_structure(self):
        self.assertEqual(validate_event_manager_provider(report()), [])
    def test_old_bss_model_rejected(self):
        r=report(); r.update(function_pointer_table_slot="0x1032238",indirection_level=2)
        self.assertIn("function_pointer_table_slot",validate_event_manager_provider(r))
    def test_wrong_relocation(self):
        r=report();r["function_pointer_table_relocations"]=[{"type":23,"symbol":""}]
        self.assertIn("table_relocation",validate_event_manager_provider(r))
    def test_runtime_rejected(self):
        r=report();r["runtime_verified"]=True
        self.assertIn("runtime_verified",validate_event_manager_provider(r))
    def test_hash_rejected(self):
        r=report();r["elf_sha256"]="0"*64
        self.assertIn("elf_sha256",validate_event_manager_provider(r))
