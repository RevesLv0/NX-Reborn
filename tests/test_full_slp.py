import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile
import zlib

SCRIPT = Path(__file__).resolve().parents[1] / 'tools/firmware/full_slp.py'
SPEC = importlib.util.spec_from_file_location('full_slp', SCRIPT)
slp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(slp)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def stored_lzop(data):
    header = struct.pack('>HHHBBIIIII', 0x1030, 0x20a0, 0x0940, 1, 3, 1, 0, 0, 0, 0)
    # Last byte is filename length; preceding bytes are three u32 fields after flags.
    header = header[:-4] + b'\0'
    return (slp.MAGIC + header + struct.pack('>I', zlib.adler32(header))
            + struct.pack('>III', len(data), len(data), zlib.adler32(data)) + data + b'\0' * 4)


class FullSLPTests(unittest.TestCase):
    def fixture(self, root):
        header = b'SLP\0' + b'h' * 300
        parts = [b'kernel', b'root-first', b'root-last', b'opt']
        section_data = [parts[0], parts[1] + parts[2], parts[3]]
        archive = root / 'sections.zip'
        with zipfile.ZipFile(archive, 'w') as bundle:
            bundle.writestr('header.bin', header)
            bundle.writestr('s0', parts[0])
            bundle.writestr('s2', parts[3])
        sections = []
        position = len(header)
        for i, data in enumerate(section_data):
            item = dict(index=i, offset_decimal=position, length_bytes=len(data),
                        sha256=sha(data), inverted_crc32=hex((~zlib.crc32(data)) & 0xffffffff))
            if i != 1:
                item.update(archive_filename='sections.zip', archive_member='s' + str(i))
            sections.append(item)
            position += len(data)
        deliverables = [dict(file='sections.zip', size_bytes=archive.stat().st_size, sha256=slp.digest(archive))]
        offset = sections[1]['offset_decimal']
        for index, data in enumerate(parts[1:3]):
            name = f'part{index}'
            (root / name).write_bytes(data)
            deliverables.append(dict(file=name, size_bytes=len(data), sha256=sha(data),
                                     offset_within_section=offset-sections[1]['offset_decimal'], offset_within_bin=offset))
            offset += len(data)
        binary = header + b''.join(section_data)
        return dict(section_count=3, slp_header_bytes=304, bin_size=len(binary),
                    bin_sha256=sha(binary), sections=sections, deliverables=deliverables), binary

    def test_exact_reconstruction_and_section_receipts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest, binary = self.fixture(root)
            receipt = slp.reconstruct(manifest, root, root/'result.bin')
            self.assertEqual((root/'result.bin').read_bytes(), binary)
            self.assertEqual(len(receipt['sections']), 3)
            self.assertFalse(receipt['original_zip_verified'])

    def test_tamper_and_range_overlap_do_not_publish_bin(self):
        for tamper in ('bytes', 'range', 'crc'):
            with self.subTest(tamper=tamper), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                manifest, _ = self.fixture(root)
                if tamper == 'bytes':
                    (root/'part0').write_bytes(b'X'*10)
                elif tamper == 'range':
                    manifest['deliverables'][2]['offset_within_bin'] -= 1
                else:
                    manifest['sections'][0]['inverted_crc32'] = '0x00000000'
                with self.assertRaises(ValueError):
                    slp.reconstruct(manifest, root, root/'result.bin')
                self.assertFalse((root/'result.bin').exists())
                self.assertFalse((root/'result.bin.partial').exists())

    def test_preexisting_partial_is_not_deleted_on_exclusive_create_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest, _ = self.fixture(root)
            partial = root/'result.bin.partial'
            partial.write_bytes(b'preexisting incomplete work')
            with self.assertRaises(FileExistsError):
                slp.reconstruct(manifest, root, root/'result.bin')
            self.assertEqual(partial.read_bytes(), b'preexisting incomplete work')

    def test_stored_lzop_with_checksums_and_exact_consumption(self):
        data = b'filesystem fixture\0' * 13
        encoded = stored_lzop(data)
        target = io.BytesIO()
        receipt = slp.decode_lzop(io.BytesIO(encoded), target, len(encoded), len(data), sha(data))
        self.assertEqual(target.getvalue(), data)
        self.assertTrue(receipt['fully_consumed'])

    def test_lzop_corruption_truncation_and_trailer_are_rejected(self):
        data = b'filesystem fixture'
        encoded = stored_lzop(data)
        bad_checksum = bytearray(encoded)
        bad_checksum[-5] ^= 1
        for bad in (bytes(bad_checksum), encoded[:-1], encoded+b'garbage', encoded[:20]):
            with self.subTest(size=len(bad)), self.assertRaises((ValueError, EOFError)):
                slp.decode_lzop(io.BytesIO(bad), io.BytesIO(), len(bad), len(data), sha(data))


if __name__ == '__main__':
    unittest.main()
