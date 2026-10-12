import unittest

from fwplatform.usb_abi_validation import REQUIRED_SYMBOLS, validate_libusb_abi


class UsbAbiValidationTests(unittest.TestCase):
    def test_offline_review_is_conservative(self):
        report = validate_libusb_abi()
        self.assertEqual(report["verification_status"], "ABI_UNVERIFIED")
        self.assertFalse(report["transfer_authorized"])
        self.assertEqual(report["checked_symbols"], list(REQUIRED_SYMBOLS))

    def test_missing_paths_are_explicit(self):
        report = validate_libusb_abi(dll_path="missing.dll", header_path="missing.h")
        kinds = {item["kind"] for item in report["issues"]}
        self.assertIn("MISSING_EVIDENCE", kinds)

