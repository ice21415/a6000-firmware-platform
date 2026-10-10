import struct
import unittest

from fwplatform.usb_descriptor_probe import (
    MAX_DESCRIPTOR_BYTES,
    USB_DT_CONFIG,
    USB_DT_DEVICE,
    parse_configuration_descriptor,
    parse_device_descriptor,
    probe_descriptors,
)


def device(vendor=0x054C, product=0x07C4, configs=1):
    return struct.pack("<BBHBBBBHHHBBBB", 18, 1, 0x0200, 0, 0, 0, 64, vendor, product, 0x0100, 1, 2, 0, configs)


def config(ptp=True):
    interface = bytes([9, 4, 0, 0, 2, 6 if ptp else 8, 1 if ptp else 6, 1 if ptp else 80, 0])
    ep_in = bytes([7, 5, 0x81, 2, 0x40, 0, 0])
    ep_out = bytes([7, 5, 0x02, 2, 0x40, 0, 0])
    body = interface + ep_in + ep_out
    return bytes([9, 2, 9 + len(body), 0, 1, 1, 0, 0x80, 50]) + body


class MockTransport:
    def __init__(self, descriptors, error=None):
        self.descriptors = descriptors
        self.error = error
        self.calls = []
        self.closed = False

    def get_descriptor(self, descriptor_type, index, length, timeout_ms):
        self.calls.append((descriptor_type, index, length, timeout_ms))
        if self.error:
            raise self.error
        value = self.descriptors[(descriptor_type, index)]
        return value[:length]

    def close(self):
        self.closed = True


class USBDescriptorProbeTests(unittest.TestCase):
    def test_valid_ptp_descriptor_and_fixed_requests(self):
        tr = MockTransport({(USB_DT_DEVICE, 0): device(), (USB_DT_CONFIG, 0): config()})
        result = probe_descriptors(tr)
        self.assertEqual(result.status, "READ_ONLY_VERIFIED")
        self.assertEqual(result.vendor_id, 0x054C)
        self.assertTrue(result.interfaces[0].ptp_compatible)
        self.assertEqual([call[:3] for call in tr.calls], [(1, 0, 18), (2, 0, 9), (2, 0, len(config()))])
        self.assertTrue(tr.closed)

    def test_wrong_vid_pid_is_not_promoted(self):
        tr = MockTransport({(1, 0): device(0x1234, 0x5678), (2, 0): config()})
        result = probe_descriptors(tr)
        self.assertEqual(result.status, "INCONCLUSIVE")
        self.assertIn("mismatch", result.error)

    def test_truncated_and_invalid_lengths_fail_closed(self):
        with self.assertRaises(ValueError):
            parse_device_descriptor(b"\x12\x01")
        with self.assertRaises(ValueError):
            parse_configuration_descriptor(bytes([1, 2, 9, 0]))
        malformed = bytes([9, 2, 10, 0, 1, 0, 0, 0, 0, 1])
        with self.assertRaises(ValueError):
            parse_configuration_descriptor(malformed)

    def test_oversized_configuration_is_rejected(self):
        header = bytes([9, 2]) + struct.pack("<H", MAX_DESCRIPTOR_BYTES + 1) + bytes(5)
        tr = MockTransport({(1, 0): device(), (2, 0): header})
        result = probe_descriptors(tr)
        self.assertEqual(result.status, "INCONCLUSIVE")

    def test_access_and_timeout_are_explicit(self):
        access = probe_descriptors(MockTransport({}, PermissionError("denied")))
        timeout = probe_descriptors(MockTransport({}, TimeoutError("timeout")))
        self.assertEqual(access.status, "USB_NOT_ACCESSIBLE")
        self.assertEqual(timeout.status, "INCONCLUSIVE")

    def test_non_ptp_interface_remains_static_evidence_only(self):
        tr = MockTransport({(1, 0): device(), (2, 0): config(False)})
        result = probe_descriptors(tr)
        self.assertEqual(result.status, "READ_ONLY_VERIFIED")
        self.assertFalse(result.interfaces[0].ptp_compatible)
        self.assertIn("does not prove PTP", result.limitations[1])

    def test_transport_has_no_allowed_method_for_writes(self):
        tr = MockTransport({(1, 0): device(), (2, 0): config()})
        probe_descriptors(tr)
        for descriptor_type, index, _, _ in tr.calls:
            self.assertIn(descriptor_type, (USB_DT_DEVICE, USB_DT_CONFIG))
            self.assertEqual(index, 0)

    def test_multiple_configurations_and_alternate_settings_keep_scope(self):
        tr = MockTransport({(1, 0): device(configs=2), (2, 0): config(False), (2, 1): config()})
        result = probe_descriptors(tr)
        self.assertEqual(result.configurations, 2)
        self.assertEqual({item.configuration for item in result.interfaces}, {0, 1})
        self.assertTrue(all(endpoint.configuration in {0, 1} for endpoint in result.endpoints))

        alt0 = bytes([9, 4, 0, 0, 1, 6, 1, 1, 0]) + bytes([7, 5, 0x81, 2, 0x40, 0, 0])
        alt1 = bytes([9, 4, 0, 1, 1, 6, 1, 1, 0]) + bytes([7, 5, 0x82, 2, 0x40, 0, 0])
        body = alt0 + alt1
        raw = bytes([9, 2, 9 + len(body), 0, 1, 1, 0, 0x80, 50]) + body
        interfaces, endpoints = parse_configuration_descriptor(raw)
        self.assertEqual({item.alternate for item in interfaces}, {0, 1})
        self.assertEqual({item.alternate for item in endpoints}, {0, 1})

