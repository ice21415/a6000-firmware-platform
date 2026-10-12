"""Synthetic tests for address-aware ParamList query callsite indexing."""
from __future__ import annotations

import json
import struct
import unittest
from pathlib import Path

from fwplatform.param_query_callers import (
    decode_thumb_branch_target,
    scan_thumb_calls,
    validate_param_query_callers,
)
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


def _thumb_bl(source: int, target: int) -> bytes:
    """Encode a Thumb-2 BL used only in a synthetic byte fixture."""
    immediate = target - (source + 4)
    if immediate & 1 or not -(1 << 24) <= immediate < (1 << 24):
        raise ValueError("synthetic target is outside Thumb BL range")
    encoded = immediate & ((1 << 25) - 1)
    sign = (encoded >> 24) & 1
    i1 = (encoded >> 23) & 1
    i2 = (encoded >> 22) & 1
    j1 = (~(i1 ^ sign)) & 1
    j2 = (~(i2 ^ sign)) & 1
    first = 0xF000 | (sign << 10) | ((encoded >> 12) & 0x3FF)
    second = 0xD000 | (j1 << 13) | (j2 << 11) | ((encoded >> 1) & 0x7FF)
    return struct.pack("<HH", first, second)


class ParamQueryCallersTests(unittest.TestCase):
    def test_thumb_call_is_decoded_and_exact_symbol_range_is_used(self):
        base = 0x1000
        callsite = base + 0x10
        target = base + 0x100
        data = bytearray(0x120)
        data[0x10:0x14] = _thumb_bl(callsite, target)
        self.assertEqual(decode_thumb_branch_target(bytes(data), base, 0x10), target)
        rows = scan_thumb_calls(
            bytes(data), base_vma=base,
            targets={"synthetic_target": target},
            symbols=[{
                "entry_vma": callsite, "size_bytes": 8,
                "symbol": "synthetic::caller",
                "address_space": "ELF_VMA",
            }],
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["caller_status"], "PRIMARY_ELF_VERIFIED")
        self.assertEqual(rows[0]["caller_candidates"][0]["symbol"], "synthetic::caller")

    def test_unknown_caller_is_not_assigned_to_nearest_lower_symbol(self):
        base = 0x2000
        callsite = base + 0x30
        target = base + 0x180
        data = bytearray(0x200)
        data[0x30:0x34] = _thumb_bl(callsite, target)
        rows = scan_thumb_calls(
            bytes(data), base_vma=base,
            targets={"target": target},
            symbols=[{
                "entry_vma": base, "size_bytes": 4,
                "symbol": "too_early",
                "address_space": "ELF_VMA",
            }],
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["caller_status"], "UNRESOLVED")
        self.assertEqual(rows[0]["caller_candidates"], [])

    def test_target_map_must_not_merge_equal_values(self):
        # The generic scanner rejects duplicate normalized VMAs before decode.
        with self.assertRaises(ValueError):
            scan_thumb_calls(
                b"\x00" * 8, base_vma=0x1000,
                targets={"a": 0x1100, "b": 0x1101},
            )

    def test_checked_in_fixture_rejects_runtime_or_callable_promotion(self):
        fixture = Path(__file__).parents[1] / "sdk" / "param_query_callers_3_21.json"
        report = json.loads(fixture.read_text(encoding="utf-8"))
        self.assertEqual(report["binary_file_sha256"], EXPECTED_LIBOBJ_SHA)
        self.assertTrue(validate_param_query_callers(report)["valid"])
        report["callable"] = True
        result = validate_param_query_callers(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])

    def test_fixture_preserves_unresolved_callers(self):
        fixture = Path(__file__).parents[1] / "sdk" / "param_query_callers_3_21.json"
        report = json.loads(fixture.read_text(encoding="utf-8"))
        target = report["targets"]["opaque_parameter_word_lookup"]
        self.assertGreater(target["callsite_count"], 0)
        self.assertGreater(target["unresolved_caller_count"], 0)
        self.assertTrue(all(
            row["caller_status"] == "UNRESOLVED"
            for row in target["examples"]
        ))

    def test_helper_chain_identity_is_evidence_bound(self):
        fixture = Path(__file__).parents[1] / "sdk" / "param_query_callers_3_21.json"
        report = json.loads(fixture.read_text(encoding="utf-8"))
        report["known_helper_chain"][0]["target_vma"] = "0xe5b18"
        result = validate_param_query_callers(report)
        self.assertFalse(result["valid"])
        self.assertIn("helper_chain_identity", result["errors"])

    def test_helper_chain_is_not_claimed_without_matching_rows(self):
        base = 0x4000
        target = 0x4100
        rows = scan_thumb_calls(
            _thumb_bl(base + 0x10, target), base_vma=base + 0x10,
            targets={"target": target},
        )
        self.assertEqual(rows[0]["callsite_status"], "PRIMARY_ELF_VERIFIED")
        from fwplatform.param_query_callers import _verified_helper_chain
        self.assertEqual(_verified_helper_chain(rows), [])


if __name__ == "__main__":
    unittest.main()
