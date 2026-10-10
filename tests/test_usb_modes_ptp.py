import json
import struct
import unittest
from pathlib import Path

from fwplatform.ptp_protocol import (evidence_for_container, parse_container,
                                      parse_device_info_dataset, parse_stream)
from fwplatform.ptp_readiness import (ABI_UNVERIFIED, INCOMPATIBLE_INTERFACE,
                                      NOT_READY, READY_FOR_REVIEW,
                                      assess_ptp_readiness)
from fwplatform.usb_modes import (classify_descriptor, result_from_observation,
                                   validate_endpoint_evidence)


class USBModesAndPTPTests(unittest.TestCase):
    def test_real_sanitized_observation_is_mass_storage_only(self):
        data = json.loads(Path("sdk/usb_descriptor_observation_2026-10-10.json").read_text(encoding="utf-8"))
        result = classify_descriptor(result_from_observation(data))
        self.assertEqual(result["modes"], ["USB_MASS_STORAGE"])
        self.assertNotIn("PTP_STILL_IMAGE_CANDIDATE", result["modes"])

    def test_serialized_verified_status_requires_external_provenance(self):
        data = json.loads(Path("sdk/usb_descriptor_observation_2026-10-10.json").read_text(encoding="utf-8"))
        untrusted = result_from_observation(data)
        trusted = result_from_observation(data, provenance_verified=True)
        self.assertEqual(untrusted.status, "INCONCLUSIVE")
        self.assertEqual(trusted.status, "READ_ONLY_VERIFIED")

    def test_endpoint_evidence_keeps_interface_scope(self):
        data = json.loads(Path("sdk/usb_descriptor_observation_2026-10-10.json").read_text(encoding="utf-8"))
        report = validate_endpoint_evidence(result_from_observation(data))
        self.assertEqual(len(report["interfaces"]), 1)
        self.assertTrue(report["interfaces"][0]["valid"])
        self.assertEqual(report["interfaces"][0]["scope"]["interface"], 0)

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
        dataset += bytes([0, 0, 0, 0])
        parsed = parse_device_info_dataset(dataset)
        self.assertEqual(parsed["vendor_extension_description"], "AC")
        self.assertEqual(parsed["operations"], [0x1001])
        self.assertEqual(parsed["serial_number_redacted"], True)
        self.assertNotIn("serial_number", parsed)

    def test_device_info_rejects_bad_string_and_large_array(self):
        base = struct.pack("<HIH", 100, 0, 1) + bytes([2, 0x41, 0x00])
        with self.assertRaises(ValueError):
            parse_device_info_dataset(base)
        oversized = struct.pack("<HIH", 100, 0, 1) + bytes([0]) + struct.pack("<H", 0)
        oversized += struct.pack("<I", 4097)
        with self.assertRaises(ValueError):
            parse_device_info_dataset(oversized)

    def test_protocol_evidence_cannot_be_runtime_promoted(self):
        packet = parse_container(struct.pack("<IHHI", 12, 4, 0x400E, 1))
        evidence = evidence_for_container(packet)
        self.assertEqual(evidence.evidence_level, "SYNTHETIC_TESTED")
        self.assertEqual(evidence.verification_status, "NOT_RUNTIME_VERIFIED")
        with self.assertRaises(ValueError):
            evidence_for_container(packet, source_type="RUNTIME_PROTOCOL_VERIFIED")

    def test_mass_storage_observation_is_not_ptp_ready(self):
        data = json.loads(Path("sdk/usb_descriptor_observation_2026-10-10.json").read_text(encoding="utf-8"))
        readiness = assess_ptp_readiness(result_from_observation(data, provenance_verified=True), transport_abi_verified=True)
        self.assertEqual(readiness["status"], INCOMPATIBLE_INTERFACE)
        self.assertFalse(readiness["transfer_authorized"])

    def test_ptp_candidate_still_requires_transport_abi(self):
        data = json.loads(Path("sdk/usb_descriptor_observation_2026-10-10.json").read_text(encoding="utf-8"))
        data["interfaces"][0].update({"interface_class": 6, "subclass": 1, "protocol": 1, "ptp_compatible": True})
        readiness = assess_ptp_readiness(result_from_observation(data, provenance_verified=True))
        self.assertEqual(readiness["status"], ABI_UNVERIFIED)

    def test_readiness_candidate_endpoint_states_and_no_authorization(self):
        data = json.loads(Path("sdk/usb_descriptor_observation_2026-10-10.json").read_text(encoding="utf-8"))
        data["interfaces"][0].update({"interface_class": 6, "subclass": 1, "protocol": 1, "ptp_compatible": True})
        data["endpoints"] = []
        missing = assess_ptp_readiness(result_from_observation(data, provenance_verified=True))
        self.assertEqual(missing["status"], NOT_READY)
        data["endpoints"] = [
            {"configuration": 0, "interface_number": 0, "alternate": 0, "address": 129, "direction": "IN", "transfer_type": "BULK", "max_packet_size": 512},
            {"configuration": 0, "interface_number": 0, "alternate": 0, "address": 2, "direction": "OUT", "transfer_type": "BULK", "max_packet_size": 512},
        ]
        abi = {"status": "ABI_VERIFIED", "evidence_source": "synthetic trusted header fixture"}
        ready = assess_ptp_readiness(result_from_observation(data, provenance_verified=True), transport_abi=abi)
        self.assertEqual(ready["status"], READY_FOR_REVIEW)
        self.assertFalse(ready["transfer_authorized"])

    def test_multiple_candidates_are_evaluated_independently(self):
        data = json.loads(Path("sdk/usb_descriptor_observation_2026-10-10.json").read_text(encoding="utf-8"))
        base = data["interfaces"][0]
        base.update({"interface_class": 6, "subclass": 1, "protocol": 1, "ptp_compatible": True})
        data["interfaces"].append({**base, "number": 1})
        data["endpoints"] = [
            {"configuration": 0, "interface_number": 0, "alternate": 0, "address": 129, "direction": "IN", "transfer_type": "BULK", "max_packet_size": 512},
            {"configuration": 0, "interface_number": 0, "alternate": 0, "address": 2, "direction": "OUT", "transfer_type": "BULK", "max_packet_size": 512},
        ]
        result = assess_ptp_readiness(result_from_observation(data, provenance_verified=True), transport_abi={"status": "ABI_VERIFIED", "evidence_source": "fixture"})
        self.assertEqual(result["status"], READY_FOR_REVIEW)
        self.assertEqual(len(result["ptp_interface_candidates"]), 2)

