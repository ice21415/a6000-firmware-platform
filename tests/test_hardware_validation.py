import unittest

from fwplatform.hardware_validation import (
    STATUS_NOT_CONNECTED,
    STATUS_USB_NOT_ACCESSIBLE,
    enumerate_usb,
    parse_pnputil,
)


USB = """Microsoft PnP Utility\n\nInstance ID:                USB\\VID_054C&PID_0C02\\private-serial\nDevice Description:         Sony Camera\nClass Name:                 libusb-win32 devices\nManufacturer Name:          Sony Corporation\nStatus:                     Started\n\nInstance ID:                USB\\VID_214B&PID_7250\\hub\nDevice Description:         Generic USB Hub\nManufacturer Name:          Generic\nStatus:                     Started\n"""


class HardwareValidationTests(unittest.TestCase):
    def test_parser_redacts_instance_identity_and_finds_sony(self):
        devices = parse_pnputil(USB)
        self.assertEqual(len(devices), 2)
        self.assertEqual(devices[0].vendor_id, "054C")
        self.assertEqual(devices[0].class_name, "libusb-win32 devices")
        self.assertNotIn("private-serial", repr(devices[0]))

    def test_missing_camera_is_not_runtime_verification(self):
        result = enumerate_usb(runner=lambda _: (0, USB.replace("VID_054C&PID_0C02", "VID_0C45&PID_7698").replace("Sony Camera", "USB Composite Device").replace("Sony Corporation", "Generic"), ""))
        self.assertEqual(result.status, STATUS_NOT_CONNECTED)
        self.assertFalse(result.runtime_verified)
        self.assertFalse(result.ptp_queried)

    def test_enumeration_failure_is_access_blocker(self):
        result = enumerate_usb(runner=lambda _: (1, "", "Access is denied"))
        self.assertEqual(result.status, STATUS_USB_NOT_ACCESSIBLE)
        self.assertIn("denied", result.access_error)

