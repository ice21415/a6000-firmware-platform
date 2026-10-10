import unittest

from fwplatform.camera_candidate_ranking import rank_indirect_candidates


class CameraCandidateRankingTests(unittest.TestCase):
    def test_ranking_is_triage_and_does_not_verify(self):
        rows = rank_indirect_candidates([
            {"target_vma": "0x100", "binary_sha256": "abc", "address_space": "ELF_VMA", "vtable_slot": 24, "instruction_evidence": True, "status": "CANDIDATE"},
            {"target_vma": "0x200", "binary_sha256": "other", "address_space": "ELF_VMA", "vtable_slot": 8, "status": "UNKNOWN"},
        ], source_sha256="abc", required_slot=24)
        self.assertEqual(rows[0]["target_vma"], "0x100")
        self.assertEqual(rows[0]["selection"], "UNRESOLVED_UNTIL_UNIQUE_PRIMARY_EVIDENCE")
        self.assertNotEqual(rows[0]["status"], "PRIMARY_ELF_VERIFIED")
