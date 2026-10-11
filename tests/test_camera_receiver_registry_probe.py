import unittest

from fwplatform.camera_receiver_registry_probe import (
    classify_receiver_field,
    classify_registry_record,
    classify_record_state,
)


class ReceiverRegistryProbeTests(unittest.TestCase):
    def test_receiver_getter_is_only_zero_nonzero(self):
        self.assertEqual(classify_receiver_field(0), "DISABLED")
        self.assertEqual(classify_receiver_field(0x40000), "NONZERO")
        self.assertEqual(classify_receiver_field(0xFFFFFFFF), "NONZERO")

    def test_receiver_rejects_boolean_and_out_of_range(self):
        with self.assertRaises(ValueError):
            classify_receiver_field(True)
        with self.assertRaises(ValueError):
            classify_receiver_field(-1)

    def test_registry_gate_is_not_called_model_id(self):
        self.assertEqual(classify_registry_record(None, record_present=False), "NULL_RECORD")
        self.assertEqual(classify_registry_record(0x10000), "REJECT")
        self.assertEqual(classify_registry_record(0x10001), "FORWARD")
        self.assertEqual(classify_registry_record(0x6FFFF), "FORWARD")
        self.assertEqual(classify_registry_record(0x70000), "REJECT")

    def test_unknown_record_field_remains_unknown(self):
        self.assertEqual(classify_registry_record(None), "UNKNOWN_RECORD_FIELD")
        self.assertEqual(classify_registry_record(True), "UNKNOWN_RECORD_FIELD")

    def test_record_state_domain_is_not_model_id(self):
        self.assertEqual(classify_record_state(0x10000), "INITIAL_SENTINEL")
        self.assertEqual(classify_record_state(0x40000), "STATE_DOMAIN")
        self.assertEqual(classify_record_state(0x70000), "STATE_DOMAIN")
        self.assertEqual(classify_record_state(11), "OUTSIDE_OBSERVED_DOMAIN")
        self.assertEqual(classify_record_state(None), "UNKNOWN")

