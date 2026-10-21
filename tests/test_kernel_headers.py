import importlib.util
from pathlib import Path
import struct
import unittest
import zlib

spec = importlib.util.spec_from_file_location('kernel_headers', Path(__file__).resolve().parents[1] / 'tools/firmware/kernel_headers.py')
kernel_headers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kernel_headers)


def image(payload):
    header = bytearray(struct.pack('>7I4B32s', 0x27051956, 0, 0, len(payload), 0x8000, 0x8000,
                                   zlib.crc32(payload), 5, 2, 2, 0, b'test'))
    struct.pack_into('>I', header, 4, zlib.crc32(header))
    return bytes(header) + payload


class KernelHeaderTests(unittest.TestCase):
    def test_crc_and_length_corruption_rejected(self):
        data = image(b'payload')
        self.assertTrue(kernel_headers.inspect_uimage(data)['crc_verified'])
        for corrupt in (data[:-1], data[:-1] + b'X', data[:8] + b'X' + data[9:]):
            with self.assertRaises(ValueError):
                kernel_headers.inspect_uimage(corrupt)

    def test_gzip_candidate_requires_complete_linux_stream(self):
        compressor = zlib.compressobj(wbits=31)
        content = b'Linux version test\0IKCFG_STdataIKCFG_ED'
        compressed = compressor.compress(content) + compressor.flush()
        result = kernel_headers.inspect_kernel(image(b'prefix' + compressed + b'tail'))
        stream = result['kernel_streams'][0]
        self.assertEqual(stream['offset_in_section'], 70)
        self.assertEqual(stream['compressed_bytes'], len(compressed))
        self.assertEqual(stream['decompressed_bytes'], len(content))
        self.assertEqual(kernel_headers.inspect_kernel(image(compressed[:-1]))['kernel_streams'], [])
