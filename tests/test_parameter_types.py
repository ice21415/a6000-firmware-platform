"""Self-authored records; do not include original firmware instruction bytes."""
import unittest
from fwplatform.paramlist_snapshot import ParameterWords, PayloadType, decode_payload, lookup_snapshot


class ParameterTypeTests(unittest.TestCase):
    def test_public_type_contract_matches_parser_and_never_claims_runtime(self):
        import json
        from pathlib import Path
        from fwplatform.paramlist_snapshot import KNOWN_PAYLOAD_TYPES
        doc = json.loads((Path(__file__).resolve().parents[1] / 'sdk/parameter_types_lifetime_3_21.json').read_text())
        self.assertFalse(doc['callable'])
        self.assertFalse(doc['runtime_verified'])
        for profile in KNOWN_PAYLOAD_TYPES:
            item = next(t for t in doc['types'] if t['name'] == profile.name)
            self.assertEqual(int(item['vptr_address_point'], 16), profile.vtable_address_point)
            self.assertEqual(item['discriminator'], profile.discriminator)
            self.assertEqual(item['payload_width'], profile.width)

    def test_signed_number_requires_both_type_witnesses(self):
        p = ParameterWords(0x1000, 0xfe8928, 1, 55, 0xffffffff)
        self.assertEqual(decode_payload(p)['value'], -1)
        wrong = ParameterWords(0x1000, 0xfe8928, 5, 55, 1)
        self.assertEqual(decode_payload(wrong)['type'], 'UNKNOWN')

    def test_bool_ignores_padding_but_rejects_noncanonical_value(self):
        p = ParameterWords(0x1000, 0xfe6e08, 5, 55, 0xaabbcc01)
        self.assertIs(decode_payload(p)['value'], True)
        p = ParameterWords(0x1000, 0xfe6e08, 5, 55, 2)
        self.assertIsNone(decode_payload(p)['value'])

    def test_runtime_addresses_require_explicit_bias(self):
        p = ParameterWords(0x1000, 0x10e8928, 1, 55, 10)
        self.assertEqual(decode_payload(p)['type'], 'UNKNOWN')
        self.assertEqual(decode_payload(p, load_bias=0x100000)['value'], 10)

    def test_ambiguous_profiles_and_null_element_fail_closed(self):
        profile = PayloadType('Synthetic', 77, 0x2000, 4)
        p = ParameterWords(0x1000, 0x2000, 77, 55, 10)
        self.assertEqual(decode_payload(p, types=(profile, profile))['type'], 'UNKNOWN')
        # Mapping address zero in a snapshot must not make a null element valid.
        import struct
        data = bytearray(96)
        for offset, values in ((16,(32,)), (32,(48,52)), (48,(0,))):
            struct.pack_into('<'+'I'*len(values), data, offset, *values)
        with self.assertRaises(ValueError):
            lookup_snapshot(data, base=0, list_address=16, key=55)

    def test_additional_parambase_families_are_static_and_layout_scoped(self):
        import json
        from pathlib import Path
        doc = json.loads((Path(__file__).resolve().parents[1] /
                          'sdk/parameter_types_lifetime_3_21.json').read_text())
        by_name = {item['name']: item for item in doc['types']}
        self.assertEqual(by_name['PrmNumberList']['discriminator'], 10)
        self.assertEqual(by_name['PrmNumberList']['object_size_witness'], 24)
        self.assertEqual(by_name['PrmCntInfoList']['discriminator'], 9)
        self.assertEqual(by_name['PrmCntInfoList']['object_size_witness'], 92)
        self.assertEqual(by_name['PrmObjMsg']['discriminator'], 8)
        self.assertEqual(by_name['PrmObjMsg']['payload_offset'], 12)
        self.assertEqual(by_name['PrmString']['discriminator'], 2)
        self.assertEqual(by_name['PrmString']['object_size_witness'], 16)
        self.assertEqual(by_name['PrmPoint']['discriminator'], 3)
        self.assertEqual(by_name['PrmDimension']['discriminator'], 4)
        self.assertEqual(by_name['PrmStruct']['discriminator'], 6)
        self.assertEqual(by_name['PrmSet']['discriminator'], 7)
        self.assertEqual(by_name['PrmSet']['object_size_witness'], 36)
        for name in ('PrmNumberList', 'PrmCntInfoList', 'PrmObjMsg',
                     'PrmString', 'PrmPoint', 'PrmDimension', 'PrmStruct', 'PrmSet'):
            self.assertEqual(by_name[name]['verification'], 'PRIMARY_ELF_VERIFIED')
            self.assertFalse(doc['runtime_verified'])
            self.assertFalse(doc['callable'])
