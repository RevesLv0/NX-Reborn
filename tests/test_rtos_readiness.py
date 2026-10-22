import importlib.util
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / 'tools/firmware'))
SPEC = importlib.util.spec_from_file_location('rtos_readiness', ROOT / 'tools/firmware/rtos_readiness.py')
rtos = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rtos)


class RtosReadinessTests(unittest.TestCase):
    def test_mov_halves_and_condition_do_not_imply_pointer(self):
        self.assertEqual(rtos.mov_half(0xe3011c4d)['immediate'], 0x1c4d)
        self.assertEqual(rtos.mov_half(0xe3480540),
                         dict(kind='movt', register=0, immediate=0x8540, condition=14))
        self.assertIsNone(rtos.mov_half(0xf3480540))
        # A valid conditional opcode in arbitrary data is retained as a candidate.
        self.assertEqual(rtos.mov_half(0x23410c4d)['immediate'], 0x1c4d)
        self.assertIsNone(rtos.mov_half(0xe3a000ff))

    def test_arm_branch_sign_and_blx_exclusion(self):
        self.assertEqual(rtos.branch_target(0xeafffffc, 0x100), 0xf8)
        self.assertEqual(rtos.branch_target(0xeb000000, 0x100), 0x108)
        self.assertIsNone(rtos.branch_target(0xfa000000, 0x100))
        self.assertIsNone(rtos.branch_target(0xe3011c4d, 0x100))

    def test_scan_keeps_literal_data_and_unaligned_bin_origin_distinct(self):
        # ldr r0,[pc]; bx lr; readiness base literal. Exact constants may be data.
        data = bytes.fromhex('00009fe51eff2fe1') + struct.pack('<I', 0x85400000)
        survey = rtos.scan(data, 0xef4301)
        self.assertEqual(survey['exact_little_endian_byte_patterns']['0x85400000'],
                         [dict(section_offset=8, bin_offset=0xef4309, aligned_to_section_word=True)])
        row = survey['arm_pc_literal_candidates'][0]
        self.assertEqual(row['section_offset'], 0)
        self.assertEqual(row['literal_section_offset'], 8)
        self.assertEqual(row['literal_bin_offset'], 0xef4309)
        self.assertEqual(row['literal_value'], '0x85400000')
        self.assertEqual(survey['arm_branch_candidates'], [])


if __name__ == '__main__':
    unittest.main()
