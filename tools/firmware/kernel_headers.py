#!/usr/bin/env python3
"""Verify legacy uImage headers and inspect embedded ARM zImage gzip streams offline."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import zlib


def inspect_uimage(data):
    if len(data) < 64:
        raise ValueError('Truncated uImage')
    magic, hcrc, stamp, length, load, entry, dcrc, os_id, arch, kind, compression, name = struct.unpack('>7I4B32s', data[:64])
    if magic != 0x27051956 or length != len(data) - 64:
        raise ValueError('Invalid uImage magic or payload length')
    header = bytearray(data[:64])
    header[4:8] = bytes(4)
    if zlib.crc32(header) != hcrc or zlib.crc32(data[64:]) != dcrc:
        raise ValueError('uImage header or payload CRC mismatch')
    return dict(name=name.rstrip(b'\0').decode('ascii'), payload_bytes=length,
                timestamp_unix=stamp, load_address=hex(load), entry_address=hex(entry),
                os_id=os_id, arch_id=arch, type_id=kind, compression_id=compression,
                header_crc32=f'{hcrc:08x}', payload_crc32=f'{dcrc:08x}', crc_verified=True)


def inspect_kernel(data):
    result = inspect_uimage(data)
    payload = data[64:]
    result['arm_zimage_magic'] = len(payload) >= 40 and payload[36:40] == bytes.fromhex('18286f01')
    streams = []
    for match in re.finditer(b'\x1f\x8b\x08', payload):
        offset = match.start()
        decoder = zlib.decompressobj(31)
        try:
            kernel = decoder.decompress(payload[offset:], 128 * 1024 * 1024)
        except zlib.error:
            continue
        if not decoder.eof:
            continue
        banners = [x.decode('ascii', errors='replace') for x in re.findall(rb'Linux version [^\x00\n]+', kernel)]
        if not banners:
            continue
        consumed = len(payload) - offset - len(decoder.unused_data)
        streams.append(dict(offset_in_section=64 + offset, compressed_bytes=consumed,
                            decompressed_bytes=len(kernel), sha256=hashlib.sha256(kernel).hexdigest(),
                            gzip_complete=True, linux_version_strings=banners,
                            ikconfig_start_marker_present=b'IKCFG_ST' in kernel,
                            ikconfig_end_marker_present=b'IKCFG_ED' in kernel))
    result['kernel_streams'] = streams
    result['limitations'] = 'Embedded metadata and CRC checks only; boot slot selection and hardware execution unverified. uImage compression_id=0 describes the outer payload; ARM zImage can contain compressed code.'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', required=True, type=Path)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    blob = args.bin.read_bytes()
    manifest = json.loads(args.manifest.read_text())
    digest = hashlib.sha256(blob).hexdigest()
    if len(blob) != manifest['bin_size'] or digest != manifest['bin_sha256']:
        raise ValueError('Unexpected firmware input')
    rows = []
    for section in manifest['sections']:
        offset, size = section['offset_decimal'], section['length_bytes']
        data = blob[offset:offset + size]
        if hashlib.sha256(data).hexdigest() != section['sha256']:
            raise ValueError('Section hash mismatch')
        if data[:4] != bytes.fromhex('27051956'):
            continue
        row = dict(section_index=section['index'], bin_offset=offset, section_bytes=size,
                   section_sha256=section['sha256'], **inspect_kernel(data))
        for stream in row['kernel_streams']:
            stream['offset_in_bin'] = offset + stream['offset_in_section']
        rows.append(row)
    result = dict(bin_sha256=digest, method='uImage big-endian header/data CRC32 + bounded gzip stream decoding; string inspection', kernels=rows)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(f'Verified {len(rows)} uImages; {sum(len(r["kernel_streams"]) for r in rows)} embedded Linux gzip streams')


if __name__ == '__main__':
    main()
