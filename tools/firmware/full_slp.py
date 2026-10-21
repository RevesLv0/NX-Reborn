#!/usr/bin/env python3
"""Reconstruct verified archival SLP slices and decode bounded LZOP streams offline.

Only input reads and new output files are used. No firmware executable is run.
The complete BIN hash is checked; this does not verify the unavailable original ZIP.
"""
import argparse
import ctypes
import ctypes.util
import hashlib
import json
from pathlib import Path
import struct
import zipfile
import zlib

MAGIC = b'\x89LZO\x00\r\n\x1a\n'


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(data)
    return value.hexdigest()


def copy_checked(source, target, expected_size, expected_hash):
    value = hashlib.sha256()
    count = 0
    for data in iter(lambda: source.read(1024 * 1024), b''):
        count += len(data)
        if count > expected_size:
            raise ValueError('Source exceeds declared size')
        value.update(data)
        target.write(data)
    if count != expected_size or value.hexdigest() != expected_hash:
        raise ValueError('Source size/SHA-256 mismatch')


def reconstruct(manifest, input_dir, output):
    sections = manifest['sections']
    if len(sections) != manifest['section_count']:
        raise ValueError('Wrong section count')
    position = manifest['slp_header_bytes']
    for index, section in enumerate(sections):
        if section['index'] != index or section['offset_decimal'] != position or section['length_bytes'] <= 0:
            raise ValueError('Sections are not ordered contiguous ranges')
        position += section['length_bytes']
    if position != manifest['bin_size']:
        raise ValueError('Section ranges do not cover BIN')
    deliverables = manifest['deliverables']
    for item in deliverables:
        name = item['file']
        if Path(name).name != name:
            raise ValueError('Unsafe deliverable name')
        path = input_dir / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Input is not a regular archive/part')
        if path.stat().st_size != item['size_bytes'] or digest(path) != item['sha256']:
            raise ValueError('Deliverable size/SHA-256 mismatch: ' + name)
    archives = {section.get('archive_filename') for section in sections if section.get('archive_filename')}
    if len(archives) != 1:
        raise ValueError('Expected one header/section ZIP')
    archive = input_dir / archives.pop()
    output.parent.mkdir(parents=True, exist_ok=True)
    partial = output.with_name(output.name + '.partial')
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    receipts = []
    created_partial = False
    try:
        with zipfile.ZipFile(archive) as bundle, partial.open('xb') as target:
            created_partial = True
            names = bundle.namelist()
            if len(names) != len(set(names)):
                raise ValueError('Duplicate ZIP members')
            headers = [item for item in bundle.infolist() if item.file_size == manifest['slp_header_bytes']]
            if len(headers) != 1:
                raise ValueError('Expected one SLP header member')
            header = bundle.read(headers[0])
            if not header.startswith(b'SLP\0'):
                raise ValueError('Invalid SLP header')
            target.write(header)
            for section in sections:
                start = target.tell()
                if 'archive_member' in section:
                    member = bundle.getinfo(section['archive_member'])
                    if member.file_size != section['length_bytes']:
                        raise ValueError('Section ZIP member size mismatch')
                    with bundle.open(member) as source:
                        copy_checked(source, target, section['length_bytes'], section['sha256'])
                else:
                    parts = sorted((x for x in deliverables if x.get('offset_within_bin', -1) >= start
                                    and x.get('offset_within_bin', -1) < start + section['length_bytes']),
                                   key=lambda x: x['offset_within_bin'])
                    for part in parts:
                        if part['offset_within_bin'] != target.tell() or part['offset_within_section'] != target.tell() - start:
                            raise ValueError('Split part range gap/overlap')
                        with (input_dir / part['file']).open('rb') as source:
                            copy_checked(source, target, part['size_bytes'], part['sha256'])
                if target.tell() - start != section['length_bytes']:
                    raise ValueError('Wrong reconstructed section length')
            if target.tell() != manifest['bin_size']:
                raise ValueError('Wrong reconstructed BIN length')
        if digest(partial) != manifest['bin_sha256']:
            raise ValueError('Reconstructed BIN SHA-256 mismatch')
        with partial.open('rb') as stream:
            for section in sections:
                stream.seek(section['offset_decimal'])
                remaining = section['length_bytes']
                sha = hashlib.sha256()
                crc = 0
                while remaining:
                    data = stream.read(min(1024 * 1024, remaining))
                    if not data:
                        raise EOFError('Truncated section')
                    remaining -= len(data)
                    sha.update(data)
                    crc = zlib.crc32(data, crc)
                inverted = (~crc) & 0xffffffff
                if sha.hexdigest() != section['sha256'] or inverted != int(section['inverted_crc32'], 16):
                    raise ValueError('Section hash/CRC mismatch')
                receipts.append(dict(index=section['index'], offset=section['offset_decimal'],
                                     bytes=section['length_bytes'], sha256=sha.hexdigest(),
                                     inverted_crc32=f'{inverted:08x}', verified=True))
        partial.replace(output)
    except BaseException:
        if created_partial:
            partial.unlink(missing_ok=True)
        raise
    return dict(schema_version=1, bin_bytes=output.stat().st_size, bin_sha256=digest(output),
                sections=receipts, original_zip_verified=False,
                verification='reconstructed_BIN_and_each_section_against_inherited_hashes',
                semantic_analysis_complete=False)


class BoundedReader:
    def __init__(self, source, length):
        self.source = source
        self.remaining = length

    def read(self, count):
        if count < 0 or count > self.remaining:
            raise EOFError('LZOP read crosses section boundary')
        data = self.source.read(count)
        if len(data) != count:
            raise EOFError('Truncated LZOP stream')
        self.remaining -= count
        return data

    def u32(self):
        return struct.unpack('>I', self.read(4))[0]


def lzo_function(library=None):
    lib = ctypes.CDLL(str(library) if library else ctypes.util.find_library('lzo2') or 'liblzo2.so.2')
    function = lib.lzo1x_decompress_safe
    function.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                         ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p]
    function.restype = ctypes.c_int
    return function


def decode_lzop(source, target, length, expected_bytes, expected_sha256, library=None):
    reader = BoundedReader(source, length)
    if reader.read(9) != MAGIC:
        raise ValueError('Invalid LZOP magic')
    header = reader.read(25)
    version, _, needed = struct.unpack_from('>HHH', header)
    method, level = header[6:8]
    flags = struct.unpack_from('>I', header, 8)[0]
    # Pin the supported modern, non-filtered single-stream format; do not silently
    # parse optional fields using the fixed NX500 profile.
    if version < 0x0940 or needed > 0x1030 or method not in (1, 2, 3):
        raise ValueError('Unsupported LZOP version/method')
    if flags & ~0xff0033bf or flags & (0x40 | 0x400 | 0x800 | 0x2000):
        raise ValueError('Unsupported LZOP header flags')
    header += reader.read(header[-1])
    expected_header_checksum = reader.u32()
    checksum = zlib.crc32 if flags & 0x1000 else zlib.adler32
    if checksum(header) & 0xffffffff != expected_header_checksum:
        raise ValueError('LZOP header checksum mismatch')
    blocks, total, value = 0, 0, hashlib.sha256()
    decompress = None
    while True:
        raw_size = reader.u32()
        if raw_size == 0:
            break
        compressed_size = reader.u32()
        if not 0 < compressed_size <= raw_size <= 4 * 1024 * 1024:
            raise ValueError('Invalid LZOP block size')
        if total + raw_size > expected_bytes:
            raise ValueError('Decoded data exceeds expected size')
        adler_raw = reader.u32() if flags & 1 else None
        crc_raw = reader.u32() if flags & 0x100 else None
        adler_compressed = reader.u32() if compressed_size < raw_size and flags & 2 else None
        crc_compressed = reader.u32() if compressed_size < raw_size and flags & 0x200 else None
        data = reader.read(compressed_size)
        if adler_compressed is not None and zlib.adler32(data) & 0xffffffff != adler_compressed:
            raise ValueError('Compressed block Adler mismatch')
        if crc_compressed is not None and zlib.crc32(data) & 0xffffffff != crc_compressed:
            raise ValueError('Compressed block CRC mismatch')
        if compressed_size < raw_size:
            decompress = decompress or lzo_function(library)
            buffer = ctypes.create_string_buffer(raw_size)
            result_size = ctypes.c_size_t(raw_size)
            result = decompress(ctypes.create_string_buffer(data), len(data), buffer,
                                ctypes.byref(result_size), None)
            if result or result_size.value != raw_size:
                raise ValueError('LZO decompression failed')
            data = buffer.raw
        if adler_raw is not None and zlib.adler32(data) & 0xffffffff != adler_raw:
            raise ValueError('Decoded block Adler mismatch')
        if crc_raw is not None and zlib.crc32(data) & 0xffffffff != crc_raw:
            raise ValueError('Decoded block CRC mismatch')
        target.write(data)
        value.update(data)
        total += len(data)
        blocks += 1
    if reader.remaining:
        raise ValueError('Trailing bytes after LZOP terminator')
    if total != expected_bytes or value.hexdigest() != expected_sha256:
        raise ValueError('Decoded image size/SHA-256 mismatch')
    return dict(bytes=total, sha256=value.hexdigest(), blocks=blocks, header_flags=hex(flags),
                method=method, level=level, compressed_bytes=length, fully_consumed=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    command = sub.add_parser('reconstruct')
    command.add_argument('--manifest', type=Path, required=True)
    command.add_argument('--input', type=Path, required=True)
    command.add_argument('--output', type=Path, required=True)
    command.add_argument('--receipt', type=Path, required=True)
    command = sub.add_parser('decode')
    command.add_argument('--input', type=Path, required=True)
    command.add_argument('--offset', type=int, required=True)
    command.add_argument('--length', type=int, required=True)
    command.add_argument('--expected-bytes', type=int, required=True)
    command.add_argument('--expected-sha256', required=True)
    command.add_argument('--lzo-library', type=Path)
    command.add_argument('--output', type=Path, required=True)
    command.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    if args.action == 'reconstruct':
        receipt = reconstruct(json.loads(args.manifest.read_text()), args.input, args.output)
    else:
        if min(args.offset, args.length, args.expected_bytes) < 0 or args.offset + args.length > args.input.stat().st_size:
            raise ValueError('Invalid input range')
        args.output.parent.mkdir(parents=True, exist_ok=True)
        if args.output.exists() or args.output.is_symlink():
            raise FileExistsError(args.output)
        partial = args.output.with_name(args.output.name + '.partial')
        created_partial = False
        try:
            with args.input.open('rb') as source, partial.open('xb') as target:
                created_partial = True
                source.seek(args.offset)
                receipt = decode_lzop(source, target, args.length, args.expected_bytes,
                                      args.expected_sha256, args.lzo_library)
            partial.replace(args.output)
        except BaseException:
            if created_partial:
                partial.unlink(missing_ok=True)
            raise
        receipt.update(input_sha256=digest(args.input), input_offset=args.offset)
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    args.receipt.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
