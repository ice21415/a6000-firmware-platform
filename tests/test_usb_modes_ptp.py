import json
import struct
import unittest
from pathlib import Path

from fwplatform.ptp_protocol import (evidence_for_container, parse_container,
                                      parse_device_info_dataset, parse_stream)
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

    def test_event_table_is_separate_from_response_table(self):
        event = parse_container(struct.pack("<IHHI", 12, 4, 0x400E, 3))
        self.assertEqual(event.container_type_name, "EVENT")
        self.assertEqual(event.code_name, "CaptureComplete")
        self.assertIsNone(parse_container(struct.pack("<IHHI", 12, 3, 0x400E, 3)).code_name)

    def test_stream_boundaries_and_device_info_dataset(self):
        first = struct.pack("<IHHI", 12, 1, 0x1001, 1)
        second = struct.pack("<IHHI", 12, 3, 0x2001, 1)
        self.assertEqual(len(parse_stream(first + second)), 2)
        with self.assertRaises(ValueError):
            parse_stream(first + second[:-1])
        text = bytes([3]) + "AC".encode("utf-16le") + b"\x00\x00"
        dataset = struct.pack("<HIH", 100, 0x00000006, 100) + text + struct.pack("<H", 0)
        dataset += struct.pack("<I", 1) + struct.pack("<H", 0x1001)
        dataset += struct.pack("<I", 0) * 4
        parsed = parse_device_info_dataset(dataset)
        self.assertEqual(parsed["vendor_extension_description"], "AC")
        self.assertEqual(parsed["operations"], [0x1001])

    def test_protocol_evidence_cannot_be_runtime_promoted(self):
        packet = parse_container(struct.pack("<IHHI", 12, 4, 0x400E, 1))
        evidence = evidence_for_container(packet)
        self.assertEqual(evidence.evidence_level, "SYNTHETIC_TESTED")
        self.assertEqual(evidence.verification_status, "NOT_RUNTIME_VERIFIED")
        with self.assertRaises(ValueError):
            evidence_for_container(packet, source_type="RUNTIME_PROTOCOL_VERIFIED")

