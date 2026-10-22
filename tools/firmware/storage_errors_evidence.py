#!/usr/bin/env python3
"""Reproduce bounded RUN006 storage-error evidence; never execute target code."""
import argparse
import bisect
import hashlib
import json
import re
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from elftools.elf.elffile import ELFFile

HASHES = {
    'libsif.so': '9790fc02fe5b9793fc09da7eb5fd9453c730a55880654c84caf02dd3d1001109',
    'libmm-photo.so': 'ea4ae65608a6f9ea0761e35c18764401cf7b876652f7949c322e880fa9f68ca9',
}
GENERATIONS = ['initial', 'followup', 'ownership', 'closure', 'cancel']
QUEUES = ['StorageStateQueue', 'FilePathQueue', 'FilePathQueue2',
          'FilePathQueueForModeChange', '_ZN14ImageGenerator19m_SIFMsgRemainCountE']
KEY_FUNCTIONS = {
    'DscFileHandler::taskMain', 'DscFileHandler::writeChunks',
    'DscFileHandler::storageException', 'DscFileHandler::stop',
    'DscFileHandler::operate', 'DscFileHandler::pauseOrResume',
    'DscOsalFile::create', 'DscOsalFile::write', 'DscOsalFile::close',
    'DscOsalFile::~DscOsalFile', 'DscImage::StorageException',
    'DscJPEG::stopFileSave', 'ImageGenerator::SIFListener',
    'ImageGenerator::setCaptureException', 'ImageGenerator::init',
    'ImageGenerator::captureSaveDone', 'ImageGenerator::afterStorageException',
    'ImageGenerator::runFromCapture', 'ImageGenerator::runFromPlayback',
    'ImageGenerator::registerGetFileName', 'ImageGenerator::registerIsStorageSpaceCheck',
    'ImageGenerator::isCaptureNotProcessing', 'card_callback',
    'FUN_00091464', 'FUN_00091884', 'FUN_00041458', 'captureNotifyCB',
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifact(path):
    return {'path': str(path), 'sha256': sha(path), 'bytes': path.stat().st_size}


def rows(path):
    with path.open() as stream:
        for line in stream:
            yield json.loads(line)


def collect(root, work, name):
    source = root / 'usr/lib' / name
    assert sha(source) == HASHES[name], source
    data = source.read_bytes()
    identity = name + '-' + HASHES[name][:12]
    first = work / 'initial/outputs/ghidra' / identity
    functions = list(rows(first / 'functions.jsonl'))
    names = {int(r['va'], 16): r['name'] for r in functions}
    funcs = sorted((r for r in functions if not r['external']),
                   key=lambda r: int(r['elf_va'], 16))
    starts = [int(r['elf_va'], 16) for r in funcs]
    out = {'path': '/usr/lib/' + name, 'sha256': HASHES[name],
           'decompilations': [], 'byte_windows': [], 'relocations': [],
           'got_literal_candidates': [], 'direct_call_candidates': []}
    selected = {}
    for generation in GENERATIONS:
        p = work / generation / 'outputs/ghidra' / identity / 'decompiled.jsonl'
        for r in rows(p):
            out['decompilations'].append({
                'generation': generation, 'artifact': str(p), 'artifact_sha256': sha(p),
                **{k: v for k, v in r.items() if k != 'instructions'}})
            selected[r['elf_va']] = r
    with source.open('rb') as stream:
        elf = ELFFile(stream)
        segments = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']

        def offset(va, size=4):
            seg = next(s for s in segments if s['p_vaddr'] <= va and
                       va + size <= s['p_vaddr'] + s['p_filesz'])
            return seg['p_offset'] + va - seg['p_vaddr']

        # Use recovered instruction addresses only; do not linearly decode literal pools.
        # Each run of adjacent selected addresses is independently decoded from ELF bytes.
        decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        for r in selected.values():
            if r['name'] not in KEY_FUNCTIONS:
                continue
            instructions = r['instructions']
            picked = set(range(min(14, len(instructions))))
            for i, line in enumerate(instructions):
                call = re.search(r'bl (0x[0-9a-f]+)', line)
                callee = names.get(int(call[1], 16), '') if call else ''
                relevant = any(k in callee for k in [
                    'sync', 'StorageException', 'DscOsalFile', 'writeChunks',
                    'memoryRelease', 'queue<', 'ScopedLock', 'g_idle_add',
                    'releaseCaptureResource', 'GetInstance', 'vconf_', 'device_get_property'])
                relevant |= bool(re.search(r'blx |mov r[45],#0x[01]$|\[#?r\d+,#0x64\]', line))
                if relevant:
                    picked.update(range(max(0, i-8), min(len(instructions), i+10)))
            # Small wrappers are preserved in full, including their ABI argument registers.
            if len(instructions) <= 100:
                picked.update(range(len(instructions)))
            addresses = sorted(int(instructions[i].split()[0], 16) - 0x10000 for i in picked)
            runs = []
            for va in addresses:
                if runs and runs[-1][-1] + 4 == va:
                    runs[-1].append(va)
                else:
                    runs.append([va])
            for run in runs:
                va = run[0]
                raw = data[offset(va):offset(va) + len(run)*4]
                decoded = list(decoder.disasm(raw, va))
                assert sum(i.size for i in decoded) == len(raw), (name, hex(va))
                out['byte_windows'].append({
                    'function': r['name'], 'function_original_elf_va': r['elf_va'],
                    'original_elf_va': hex(va), 'file_offset': hex(offset(va)),
                    'bytes': raw.hex(), 'decoded_bytes': len(raw),
                    'instructions': [f'{i.address:#x} {i.mnemonic} {i.op_str}' for i in decoded],
                    'method': 'Capstone 5.0.6 ARM; PT_LOAD mapping; only contiguous Ghidra recovered instruction addresses selected',
                    'limitation': 'Selection corroborates local branches, not exhaustive function recovery or runtime behavior.'})
        symtab = elf.get_section_by_name('.dynsym')
        out['queue_symbols'] = [
            {'name': s.name, 'original_elf_va': hex(s['st_value']), 'bytes': s['st_size'],
             'section': s['st_shndx']} for s in symtab.iter_symbols() if s.name in QUEUES]
        for section in elf.iter_sections():
            if section['sh_type'] != 'SHT_REL':
                continue
            tab = elf.get_section(section['sh_link'])
            for rel in section.iter_relocations():
                symbol = tab.get_symbol(rel['r_info_sym'])
                if symbol.name in QUEUES or any(x in symbol.name for x in [
                        'StorageException', 'sync', 'fwrite', 'fclose', 'fopen64',
                        'SIFListener', 'pbSaveComplete', 'captureSaveDone']):
                    row = {'original_elf_va': hex(rel['r_offset']),
                           'file_offset': hex(offset(rel['r_offset'])),
                           'type': rel['r_info_type'], 'symbol': symbol.name,
                           'symbol_value': hex(symbol['st_value'])}
                    out['relocations'].append(row)
                    if symbol.name in QUEUES:
                        got = elf.get_section_by_name('.got')['sh_addr']
                        word = rel['r_offset'] - got
                        for seg in segments:
                            if not seg['p_flags'] & 1:
                                continue
                            for off in range(seg['p_offset'], seg['p_offset'] + seg['p_filesz'] - 3, 4):
                                if struct.unpack_from('<I', data, off)[0] != word:
                                    continue
                                va = off + seg['p_vaddr'] - seg['p_offset']
                                owner = funcs[bisect.bisect_right(starts, va)-1]
                                out['got_literal_candidates'].append({
                                    'symbol': symbol.name, 'slot': hex(rel['r_offset']),
                                    'got_base': hex(got), 'literal_word': hex(word),
                                    'literal_original_elf_va': hex(va), 'file_offset': hex(off),
                                    'nearest_preceding_function': owner['name'],
                                    'function_original_elf_va': owner['elf_va'],
                                    'limitation': 'Aligned constant search over executable PT_LOAD, with nearest function attribution; not an exhaustive alias or xref proof.'})
    calls = work / 'closure/outputs/ghidra' / identity / 'calls.jsonl'
    out['direct_call_artifact'] = artifact(calls)
    for r in rows(calls):
        if any(k in r['callee'] for k in ['queue<StorageState', 'queue<std::string',
            'StorageException', 'setCaptureException', 'registerGetFileName',
            'registerIsStorageSpaceCheck', 'DscFileHandler::stop', 'DscJPEG::stopFileSave']):
            out['direct_call_candidates'].append(r)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root', type=Path, default=Path('.work/full/extracted/rootfs'))
    ap.add_argument('--work', type=Path, default=Path('.work/run006/storage'))
    ap.add_argument('--output', type=Path, default=Path('analysis/evidence/storage-errors-run006.json'))
    args = ap.parse_args()
    catalog = Path('.work/run003/symbols/named_symbols.jsonl')
    result = {'schema_version': 1, 'scope': 'Bounded offline storage failure, queue ownership and synchronization evidence',
              'static_only': True, 'sources': [collect(args.root, args.work, n) for n in HASHES],
              'symbol_catalog': artifact(catalog), 'catalog_matches': []}
    for row in rows(catalog):
        if row['name'] in QUEUES:
            result['catalog_matches'].append(row)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'output': str(args.output), 'sha256': sha(args.output),
                      'sources': len(result['sources']),
                      'byte_windows': sum(len(s['byte_windows']) for s in result['sources'])}))


if __name__ == '__main__':
    main()
