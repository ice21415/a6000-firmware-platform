"""Synthetic fail-closed checks for the PrmObjMsg probe metadata."""
import unittest

from fwplatform.param_objmsg_probe import TARGETS, validate_param_objmsg
from fwplatform.private_thumb_research import EXPECTED_LIBOBJ_SHA


def _report():
    symbols = {
        "param_base_constructor": "_ZN9ParamBaseC2Em",
        "payload_destructor": "_ZN3MWF6ObjMsgD1Ev",
        "delete_object": "_ZdlPv",
        "payload_getter": "_ZNK9PrmObjMsg18getParamTypeObjMsgEv",
        "new_object": "_Znwj",
        "payload_copy_constructor": "_ZN3MWF6ObjMsgC1ERKS0_",
        "prm_objmsg_constructor": "_ZN9PrmObjMsgC1EPN3MWF6ObjMsgE",
    }
    return {
        "binary_file_sha256": EXPECTED_LIBOBJ_SHA,
        "address_space": "ELF_VMA",
        "runtime_verified": False,
        "callable": False,
        "vtable": {"status": "PRIMARY_ELF_VERIFIED"},
        "bindings": {
            name: {
                "status": "VERIFIED_STATIC",
                "runtime_binding": "UNKNOWN",
                "candidates": [{"symbol": symbol}],
            }
            for name, symbol in symbols.items()
        },
        "observations": {target["name"]: {"status": "PRIMARY_ELF_VERIFIED"} for target in TARGETS},
    }


class ParamObjMsgProbeTests(unittest.TestCase):
    def test_static_report_is_valid(self):
        result = validate_param_objmsg(_report())
        self.assertTrue(result["valid"])
        self.assertEqual(result["errors"], [])

    def test_wrong_binary_is_rejected(self):
        report = _report()
        report["binary_file_sha256"] = "0" * 64
        result = validate_param_objmsg(report)
        self.assertFalse(result["valid"])
        self.assertIn("binary_identity", result["errors"])

    def test_missing_target_is_rejected(self):
        report = _report()
        del report["observations"]["objmsg_getter"]
        result = validate_param_objmsg(report)
        self.assertFalse(result["valid"])
        self.assertIn("missing:objmsg_getter", result["errors"])

    def test_callable_promotion_is_rejected(self):
        report = _report()
        report["callable"] = True
        result = validate_param_objmsg(report)
        self.assertFalse(result["valid"])
        self.assertIn("runtime_or_callable_claim", result["errors"])

    def test_missing_vtable_is_rejected(self):
        report = _report()
        del report["vtable"]
        result = validate_param_objmsg(report)
        self.assertFalse(result["valid"])
        self.assertIn("missing:vtable", result["errors"])

    def test_binding_symbol_mismatch_is_rejected(self):
        report = _report()
        report["bindings"]["payload_copy_constructor"]["candidates"][0]["symbol"] = "wrong"
        result = validate_param_objmsg(report)
        self.assertFalse(result["valid"])
        self.assertIn("binding_symbol:payload_copy_constructor", result["errors"])


if __name__ == "__main__":
    unittest.main()
