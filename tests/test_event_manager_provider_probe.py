import copy
import unittest

from fwplatform.event_manager_provider_probe import (
    FUNCTION_POINTER_CELL,
    FUNCTION_POINTER_TABLE_SLOT,
    GETTER_ENTRY,
    validate_event_manager_provider,
)
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


def _report():
    return {
        "status": "PRIMARY_ELF_PROVIDER_GETTER_EVIDENCE",
        "elf_sha256": EXPECTED_LIBOBJ_SHA,
        "address_space": "ELF_VMA",
        "getter_entry_vma": hex(GETTER_ENTRY),
        "getter_instructions": [
            {"instruction_vma": "0x7ef234", "mnemonic": "ldr", "operands": "r3, [pc, #0x14]", "verification": "PRIMARY_ELF_VERIFIED"},
            {"instruction_vma": "0x7ef23a", "mnemonic": "ldr", "operands": "r3, [r4, r3]", "verification": "PRIMARY_ELF_VERIFIED"},
            {"instruction_vma": "0x7ef23c", "mnemonic": "blx", "operands": "r3", "verification": "PRIMARY_ELF_VERIFIED"},
        ],
        "function_pointer_table_slot": hex(FUNCTION_POINTER_TABLE_SLOT),
        "function_pointer_cell": hex(FUNCTION_POINTER_CELL),
        "provider_vtable_slot": "+0x30",
        "runtime_verified": False,
        "writer_search": {"status": "NO_LOCAL_WRITER_FOUND_WITHIN_LITERAL_SCAN"},
        "function_pointer_table_relocations": [{"section": ".rel.dyn", "type": 23, "symbol_index": 0}],
    }


class EventManagerProviderProbeTests(unittest.TestCase):
    def test_structured_static_evidence_is_accepted(self):
        self.assertEqual(validate_event_manager_provider(_report()), [])

    def test_empty_instruction_fact_is_rejected(self):
        report = _report()
        report["getter_instructions"][1] = {}
        self.assertIn("instruction_0x7ef23a", validate_event_manager_provider(report))

    def test_wrong_slot_or_hash_is_rejected(self):
        report = _report()
        report["function_pointer_cell"] = "0x10df828"
        report["elf_sha256"] = "0" * 64
        errors = validate_event_manager_provider(report)
        self.assertIn("binary_identity", errors)
        self.assertIn("function_cell", errors)

    def test_static_probe_cannot_promote_runtime(self):
        report = _report()
        report["runtime_verified"] = True
        self.assertIn("runtime_promotion", validate_event_manager_provider(report))


if __name__ == "__main__":
    unittest.main()
