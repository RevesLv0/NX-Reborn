import importlib.util
from pathlib import Path
import struct
import unittest

SPEC = importlib.util.spec_from_file_location('boot_sections', Path(__file__).parents[1] / 'tools/firmware/boot_sections.py')
boot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boot)


class BootSectionTests(unittest.TestCase):
    def test_hash_and_boundaries_are_required(self):
        blob = b'header\0section!'
        section = dict(index=1, offset_decimal=7, length_bytes=8, sha256=boot.sha256(blob[7:]))
        manifest = dict(bin_size=len(blob), bin_sha256=boot.sha256(blob), sections=[section])
        self.assertEqual(boot.verified_sections(blob, manifest)[1][1], b'section!')
        with self.assertRaisesRegex(ValueError, 'Firmware'):
            boot.verified_sections(blob + b'!', manifest)
        section['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'Section SHA'):
            boot.verified_sections(blob, manifest)
        section['length_bytes'] = len(blob)
        with self.assertRaisesRegex(ValueError, 'outside'):
            boot.verified_sections(blob, manifest)

    def test_exact_printable_offsets_and_unaligned_section_origin(self):
        data = b'\0 root=/dev/mmcblk0p10 rw \0other\x00'
        rows = boot.selected_strings(data, rb'root=', 0x5ede01)
        self.assertEqual(rows, [dict(offset_in_input=1, absolute_file_offset=0x5ede02,
                                    text=' root=/dev/mmcblk0p10 rw ')])
        self.assertEqual(boot.selected_strings(data, rb'rootfs='), [])

    @unittest.skipUnless(importlib.util.find_spec('capstone'), 'Capstone unavailable')
    def test_arm_literal_offsets_remain_file_offsets(self):
        # ldr r0,[pc]; bx lr; literal. Code VA and unaligned BIN origin differ.
        data = bytes.fromhex('00009fe51eff2fe1') + struct.pack('<I', 0x54410009)
        row = boot.bounded_disassembly(data, 0, 8, 'ARM', 0x2000200, 0x5ede01)
        self.assertEqual(row['bytes_covered'], 8)
        self.assertEqual(row['instructions'][0]['address'], '0x2000200')
        self.assertEqual(row['instructions'][0]['file_offset'], 0x5ede01)
        self.assertEqual(row['instructions'][0]['pc_literal'],
                         dict(file_offset=0x5ede09, value='0x54410009'))
        with self.assertRaisesRegex(ValueError, 'outside'):
            boot.bounded_disassembly(data, 0, 13, 'ARM')

    @unittest.skipUnless(importlib.util.find_spec('capstone'), 'Capstone unavailable')
    def test_thumb_pc_relative_string_uses_link_va(self):
        data = bytes.fromhex('00487844040000000000') + b'foo\0'
        row = boot.bounded_disassembly(data, 0, 4, 'THUMB', 0x1000)
        self.assertEqual(row['instructions'][1]['pc_relative_string'],
                         dict(address='0x100a', file_offset=10, text='foo'))

    @unittest.skipUnless(importlib.util.find_spec('capstone'), 'Capstone unavailable')
    def test_thumb_pc_literal_alignment(self):
        # At VA 0x1002, ldr r0,[pc,#0] reads aligned PC 0x1004.
        data = bytes.fromhex('004800bf') + struct.pack('<I', 0x12345678)
        row = boot.bounded_disassembly(data, 0, 2, 'THUMB', 0x1002)
        self.assertEqual(row['instructions'][0]['pc_literal']['file_offset'], 2)
        self.assertEqual(row['instructions'][0]['pc_literal']['value'], '0x5678bf00')


if __name__ == '__main__':
    unittest.main()
