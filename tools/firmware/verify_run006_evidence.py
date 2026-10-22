#!/usr/bin/env python3
"""Recheck RUN006 evidence against original files without executing target code.

This is byte/artifact validation by the primary agent, not independent semantic
review or runtime validation. Run from the repository root with pyelftools and
Capstone on PYTHONPATH.
"""
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from elftools.elf.elffile import ELFFile


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(path):
    return json.loads(Path(path).read_text())


def main():
    decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    checked = []
    source_checks = {}

    def elf_bytes(original_path, expected_sha, va, size, expected_offset=None):
        source = Path('.work/full/extracted/rootfs') / original_path.lstrip('/')
        if str(source) not in source_checks:
            assert sha(source) == expected_sha, source
            source_checks[str(source)] = expected_sha
        assert source_checks[str(source)] == expected_sha
        with source.open('rb') as stream:
            elf = ELFFile(stream)
            segment = next(s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD'
                           and s['p_vaddr'] <= va and va + size <= s['p_vaddr'] + s['p_filesz'])
            offset = segment['p_offset'] + va - segment['p_vaddr']
            if expected_offset is not None:
                assert offset == expected_offset
            stream.seek(offset)
            return stream.read(size)

    def decode(raw, va, expected):
        actual = list(decoder.disasm(raw, va))
        assert sum(i.size for i in actual) == len(raw), hex(va)
        assert len(actual) == len(expected), hex(va)
        for ins, row in zip(actual, expected):
            if isinstance(row, str):
                assert row == f'{ins.address:#x} {ins.mnemonic} {ins.op_str}'
            else:
                address = row.get('original_elf_va', row.get('va', row.get('address')))
                assert int(address, 16) == ins.address
                assert row['bytes'] == ins.bytes.hex()
                assert (row['mnemonic'], row['operands']) == (ins.mnemonic, ins.op_str)

    path = 'analysis/evidence/storage-errors-run006.json'
    storage = load(path)
    windows = 0
    for source in storage['sources']:
        for w in source['byte_windows']:
            raw = bytes.fromhex(w['bytes'])
            va = int(w['original_elf_va'], 16)
            assert raw == elf_bytes(source['path'], source['sha256'], va, len(raw), int(w['file_offset'], 16))
            decode(raw, va, w['instructions'])
            windows += 1
        for row in source['decompilations']:
            assert sha(row['artifact']) == row['artifact_sha256']
    checked.append(dict(path=path, sha256=sha(path), original_byte_windows=windows))

    path = 'analysis/evidence/app-error-consumers-run006.json'
    app = load(path)
    for w in app['windows']:
        raw = bytes.fromhex(w['raw_hex'])
        va = int(w['original_elf_va'], 16)
        assert raw == elf_bytes(w['source_path'], w['source_sha256'], va, len(raw), int(w['file_offset'], 16))
        decode(raw, va, w['instructions'])
    for table in app['tables']:
        raw = bytes.fromhex(table['raw_hex'])
        va = int(table['original_elf_va'], 16)
        assert raw == elf_bytes(table['source_path'], table['source_sha256'], va, len(raw), int(table['file_offset'], 16))
        selected = int(table['selected_input'], 16)
        assert struct.unpack_from('<I', raw, (selected - 1) * 4)[0] == int(table['selected_target_va'], 16)
        target = bytes.fromhex(table['selected_target_raw_hex'])
        assert target == elf_bytes(table['source_path'], table['source_sha256'], int(table['selected_target_va'], 16), len(target), int(table['selected_target_file_offset'], 16))
    for row in app.get('elf_data', []):
        raw = bytes.fromhex(row['raw_hex'])
        assert raw == elf_bytes(row['source_path'], row['source_sha256'], int(row['original_elf_va'], 16), len(raw), int(row['file_offset'], 16))
    for source in app['source_checks']:
        relevant = [r for r in app['relocations'] if r['source_sha256'] == source['sha256']]
        with Path(source['staged_path']).open('rb') as stream:
            elf = ELFFile(stream)
            actual = set()
            for sec in elf.iter_sections():
                if sec['sh_type'] not in ('SHT_REL', 'SHT_RELA'):
                    continue
                for rel in sec.iter_relocations():
                    sym = elf.get_section(sec['sh_link']).get_symbol(rel['r_info_sym'])
                    actual.add((hex(rel['r_offset']),rel['r_info_type'],sym.name,hex(sym['st_value'])))
            for row in relevant:
                assert (row['original_elf_va'],row['type'],row['symbol'],row['symbol_value']) in actual
    for g in app['ghidra']:
        assert sha(g['path']) == g['sha256']
        assert sha(g['summary_path']) == g['summary_sha256']
    checked.append(dict(path=path, sha256=sha(path), original_byte_windows=len(app['windows']), data_tables=len(app['tables'])))

    path = 'analysis/evidence/transfer-boundaries-run006.json'
    transfer = load(path)
    for row in transfer['ghidra']:
        assert sha(row['path']) == row['sha256']
    for w in transfer['windows']:
        raw = bytes.fromhex(w['raw_hex'])
        va = int(w['original_elf_va'], 16)
        assert raw == elf_bytes(w['source_path'], w['source_sha256'], va, len(raw), int(w['file_offset'], 16))
        decode(raw, va, w['instructions'])
    checked.append(dict(path=path, sha256=sha(path), original_byte_windows=len(transfer['windows'])))

    path = 'analysis/evidence/rtos-transport-run006.json'
    rtos = load(path)
    original = Path(rtos['source']['bin_path']).read_bytes()
    assert hashlib.sha256(original).hexdigest() == rtos['source']['bin_sha256']
    origin = rtos['source']['section_bin_start']
    section = original[origin:origin + rtos['source']['section_bytes']]
    assert hashlib.sha256(section).hexdigest() == rtos['source']['section_sha256']
    for region in rtos['code_regions'] + rtos['data_blocks']:
        raw = bytes.fromhex(region['bytes'])
        assert raw == original[region['bin_offset']:region['bin_offset'] + len(raw)]
        assert hashlib.sha256(raw).hexdigest() == region['sha256']
        if 'instructions' in region:
            decode(raw, int(region['inferred_link_va'], 16), region['instructions'])
    checked.append(dict(path=path, sha256=sha(path), original_byte_windows=len(rtos['code_regions']), data_blocks=len(rtos['data_blocks'])))

    path = 'analysis/evidence/kernel-prefix-run006.json'
    kernel = load(path)
    original = Path(kernel['source']).read_bytes()
    assert hashlib.sha256(original).hexdigest() == kernel['sha256']
    for region in kernel['regions']:
        raw = bytes.fromhex(region['bytes'])
        va = int(region['va'], 16)
        offset = region['decoded_offset']
        assert va == int(kernel['base'], 16) + offset
        assert raw == original[offset:offset + len(raw)]
        assert hashlib.sha256(raw).hexdigest() == region['sha256']
        decode(raw, va, region['instructions'])
    checked.append(dict(path=path, sha256=sha(path), original_byte_windows=len(kernel['regions'])))

    # Arithmetic checks of the manually traced normal frame. These do not emulate
    # the code or establish that this kernel was active on a camera.
    frame = bytes.fromhex(rtos['reconstructed_ready_frame']['combined_bytes'])
    assert frame.hex() == kernel['frame']
    delivered = frame[4:]
    assert delivered.hex() == kernel['delivered_after_prefix']
    length = struct.unpack_from('<H', frame, 2)[0]
    assert length == len(delivered) == 10
    assert struct.unpack_from('<H', delivered, 2)[0] == 0x82
    assert struct.unpack_from('<H', delivered, 4)[0] == 0x020a
    assert struct.unpack_from('<H', delivered, 6)[0] == 0
    assert (length - 8) + 12 - 4 == length
    assert length - 10 == 0
    result = dict(schema_version=1, static_only=True, verifier=__file__,
                  verifier_sha256=sha(__file__), checked_evidence=checked,
                  source_checks=source_checks, frame_arithmetic_checked=True,
                  independent_semantic_review_completed=False,
                  limitations=['Primary-agent byte/artifact validation and bounded manual interpretation only.',
                               'Independent RUN006 review agent ended with an actual usage-limit error.',
                               'No active-boot, runtime delivery, queue ordering, peer acknowledgement or medium durability validation.'])
    output = Path('manifests/evidence-verification-run006.json')
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(original_byte_windows=sum(r['original_byte_windows'] for r in checked),
                          evidence_files=len(checked), frame_arithmetic_checked=True)))


if __name__ == '__main__':
    main()
