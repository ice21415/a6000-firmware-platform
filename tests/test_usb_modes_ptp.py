import json
import struct
import unittest
from pathlib import Path

from fwplatform.ptp_protocol import parse_container
from fwplatform.usb_modes import classify_descriptor, result_from_observation


class USBModesAndPTPTests(unittest.TestCase):
    def test_real_sanitized_observation_is_mass_storage_only(self):
        data = json.loads(Path("sdk/usb_descriptor_observation_2026-10-10.json").read_text(encoding="utf-8"))
        result = classify_descriptor(result_from_observation(data))
        self.assertEqual(result["modes"], ["USB_MASS_STORAGE"])
        self.assertNotIn("PTP_STILL_IMAGE_CANDIDATE", result["modes"])

    def test_standard_get_device_info_command_container(self):
        packet = struct.pack("<IHHI", 12, 1, 0x1001, 7)
        parsed = parse_container(packet)
        self.assertEqual(parsed.container_type_name, "COMMAND")
        self.assertEqual(parsed.code_name, "GetDeviceInfo")
        self.assertEqual(parsed.transaction_id, 7)
        self.assertEqual(parsed.payload, b"")

    def test_response_and_unknown_vendor_code_are_descriptive(self):
        ok = parse_container(struct.pack("<IHHI", 12, 3, 0x2001, 9))
        unknown = parse_container(struct.pack("<IHHI", 12, 1, 0x9001, 10))
        self.assertEqual(ok.code_name, "OK")
        self.assertIsNone(unknown.code_name)

    def test_malformed_ptp_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_container(b"\x0c\x00")
        with self.assertRaises(ValueError):
            parse_container(struct.pack("<IHHI", 8, 1, 0x1001, 1))
        with self.assertRaises(ValueError):
            parse_container(struct.pack("<IHHI", 12, 9, 0x1001, 1))
        with self.assertRaises(ValueError):
            parse_container(struct.pack("<IHHI", 20, 1, 0x1001, 1))

