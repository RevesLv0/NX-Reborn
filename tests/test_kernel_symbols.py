import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location('kernel_symbols', Path(__file__).parents[1] / 'tools/firmware/kernel_symbols.py')
KS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(KS)


def fixture(count=300):
    data = bytearray(256)
    positions = {'addresses_offset': len(data)}
    data.extend(struct.pack('<%dI' % count, *(0xc0008000 + i * 4 for i in range(count))))

    def align():
        data.extend(bytes((-len(data)) % 16))

    align()
    positions['count_offset'] = len(data)
    data.extend(struct.pack('<I', count))
    align()
    positions['names_offset'] = len(data)
    alphabet = 'Tname0123456789'
    tokens = list(alphabet) + ['x'] * (256 - len(alphabet))
    markers = []
    for i in range(count):
        if i % 256 == 0:
            markers.append(len(data) - positions['names_offset'])
        encoded = bytes(alphabet.index(c) for c in 'Tname%d' % i)
        data.extend(bytes([len(encoded)]) + encoded)
    align()
    positions['markers_offset'] = len(data)
    data.extend(struct.pack('<%dI' % len(markers), *markers))
    align()
    positions['token_table_offset'] = len(data)
    index = []
    for token in tokens:
        index.append(len(data) - positions['token_table_offset'])
        data.extend(token.encode() + b'\0')
    align()
    positions['token_index_offset'] = len(data)
    data.extend(struct.pack('<256H', *index))
    data.extend(bytes(16))
    return bytes(data), positions


class KernelSymbolsTests(unittest.TestCase):
    def test_complete_synthetic_table_and_second_marker(self):
        data, positions = fixture()
        tables, candidates = KS.recover(data, minimum=16)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(len(tables), 1)
        table = tables[0]
        for key, offset in positions.items():
            self.assertEqual(table[key], offset)
        self.assertEqual(table['markers_count'], 2)
        self.assertEqual(table['symbols'][299], dict(index=299, address=0xc00084ac, type='T', name='name299'))

    def test_address_like_run_is_insufficient(self):
        data = struct.pack('<300I', *(0xc0008000 + 4 * i for i in range(300))) + bytes(4096)
        tables, candidates = KS.recover(data, minimum=16)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(tables, [])

    def test_reject_corrupt_structural_components(self):
        original, positions = fixture()
        mutations = [positions['count_offset'], positions['markers_offset'] + 4,
                     positions['token_index_offset'] + 2, positions['names_offset'],
                     positions['token_table_offset']]
        for offset in mutations:
            with self.subTest(offset=offset):
                data = bytearray(original)
                data[offset] ^= 0x80
                self.assertEqual(KS.recover(bytes(data), minimum=16)[0], [])

    def test_reject_truncated_index_and_unsorted_addresses(self):
        data, positions = fixture()
        self.assertEqual(KS.recover(data[:positions['token_index_offset'] + 510], minimum=16)[0], [])
        data = bytearray(data)
        struct.pack_into('<I', data, positions['addresses_offset'] + 8, 0xc0007000)
        with self.assertRaisesRegex(ValueError, 'not sorted'):
            KS.validate_structure(data, positions['addresses_offset'], 300, positions['count_offset'], positions['names_offset'])

    def test_mapping_needs_all_export_string_checks(self):
        data = bytearray(2048)
        symbols = [dict(name='_text', address=0xc0008000)]
        for i in range(10):
            offset = 128 + i * 32
            data[offset:offset + len('export%d' % i) + 1] = ('export%d\0' % i).encode()
            symbols.append(dict(name='__kstrtab_export%d' % i, address=0xc0008000 + offset))
        self.assertEqual(KS.infer_mapping(data, symbols)['matched_export_strings'], 10)
        data[128] = ord('z')
        self.assertIsNone(KS.infer_mapping(data, symbols))
        self.assertIsNone(KS.infer_mapping(data, symbols[:2]))

    def test_input_sha_and_size_gate(self):
        metadata = dict(kernels=[dict(section_index=2, kernel_streams=[dict(decompressed_bytes=4, sha256='0' * 64)])])
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'kernel.raw'
            path.write_bytes(b'test')
            with self.assertRaisesRegex(ValueError, 'SHA-256 mismatch'):
                KS.verify_input(path, metadata, 2)


if __name__ == '__main__':
    unittest.main()
