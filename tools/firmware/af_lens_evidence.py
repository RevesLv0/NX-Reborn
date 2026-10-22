#!/usr/bin/env python3
"""Enrich RUN010 selected evidence with original ELF API and pointer-table facts.

Run selected_elf_evidence.py first. This script only reads target bytes; it never
loads or executes a target ELF. Cross-file symbol equality is a binding candidate.
"""
import argparse
import hashlib
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile
from symbol_catalog import inspect


def enrich(evidence, manifest):
    api = []
    symbols = {}
    for item in manifest:
        path = Path(item['staged_path'])
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item['sha256']
        rows, counts = inspect(path)
        symbols[item['sha256']] = rows
        with path.open('rb') as stream:
            elf = ELFFile(stream)
            dynamic = elf.get_section_by_name('.dynamic')
            needed = [t.needed for t in dynamic.iter_tags() if t.entry.d_tag == 'DT_NEEDED']
        selected = [r for r in rows if any(t in r['name'] for t in
                    ('Lens', 'AFScan', 'Control3A', 'mm_camera_ioctl',
                     'mcb_', 'CMulticoreBridge4Send', 'pref_rtos_get_bytes'))]
        api.append(dict(source_sha256=item['sha256'], source_path=item['path'],
                        counts=counts, needed=needed, selected_declared_symbols=selected))
    candidates = []
    for consumer in manifest:
        imports = [r for r in symbols[consumer['sha256']]
                   if r['table'] == '.dynsym' and not r['defined']]
        for provider in manifest:
            if consumer == provider:
                continue
            exports = {r['name']: r for r in symbols[provider['sha256']]
                       if r['dynamic_export_candidate']}
            for imported in imports:
                if imported['name'] in exports:
                    target = exports[imported['name']]
                    candidates.append(dict(consumer_sha256=consumer['sha256'],
                        provider_sha256=provider['sha256'], symbol=imported['name'],
                        provider_original_elf_va=target['code_address'],
                        method='Equal dynamic import/export names among selected source-verified ELFs; inspect relocations and callers separately',
                        limitation='Does not establish runtime loader resolution or successful execution'))
    tables = []
    for item in manifest:
        if Path(item['path']).name != 'libcapture-fw-prod.so':
            continue
        with Path(item['staged_path']).open('rb') as stream:
            elf = ELFFile(stream)
            dyn = elf.get_section_by_name('.dynsym')
            for symbol in dyn.iter_symbols():
                if not (symbol.name.startswith('_ZN14CNotifyHandler') or
                        symbol.name == '_ZTV14CNotifyHandler'):
                    continue
                if not any(t in symbol.name for t in
                           ('arpLensNtfyFnc', 'arpCategoryTbl', 'arpLiveviewNtfyFnc',
                            '_ZTV14CNotifyHandler')):
                    continue
                va, size = symbol['st_value'], symbol['st_size']
                assert size and size % 4 == 0
                segment = next(s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD'
                    and s['p_vaddr'] <= va and va + size <= s['p_vaddr'] + s['p_filesz'])
                offset = segment['p_offset'] + va - segment['p_vaddr']
                stream.seek(offset)
                raw = stream.read(size)
                tables.append(dict(source_sha256=item['sha256'], source_path=item['path'],
                    symbol=symbol.name, original_elf_va=hex(va), file_offset=hex(offset),
                    bytes=size, raw_hex=raw.hex(),
                    little_endian_words=[hex(int.from_bytes(raw[i:i+4], 'little'))
                                         for i in range(0, size, 4)],
                    limitation='Original stored words; dynamic relocations are separate evidence and must be applied before interpreting pointers'))
    evidence.update(declared_apis=api, symbol_binding_candidates=candidates,
                    original_pointer_tables=tables)
    evidence['data_blocks'] = tables
    app = next(item for item in manifest if Path(item['path']).name == 'di-camera-app')
    callsite = 0x12dbd4
    contexts = [target['thumb_mode_context'] for query in evidence.get('mode_queries', [])
                if query['query']['source_sha256'] == app['sha256']
                for target in query['query']['targets']
                if int(target['target_va'], 16) == callsite]
    if contexts:
        assert contexts == [0]
        with Path(app['staged_path']).open('rb') as stream:
            elf = ELFFile(stream)
            segment = next(s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD'
                and s['p_vaddr'] <= callsite and callsite + 12 <= s['p_vaddr'] + s['p_filesz'])
            offset = segment['p_offset'] + callsite - segment['p_vaddr']
            stream.seek(offset)
            raw = stream.read(12)
        instructions = list(Cs(CS_ARCH_ARM, CS_MODE_ARM).disasm(raw, callsite))
        assert len(instructions) == 3
        evidence['windows'].append(dict(source_sha256=app['sha256'], source_path=app['path'],
            function='UI_Manage_Power_On_Before_SnapShot bounded lens registration callsite',
            original_elf_va=hex(callsite), file_offset=hex(offset), mode='ARM', raw_hex=raw.hex(),
            instructions=[dict(va=hex(i.address), bytes=i.bytes.hex(), mnemonic=i.mnemonic,
                               operands=i.op_str) for i in instructions],
            limitation='Three original instructions only; not a selected function completion or full caller review'))
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    args = parser.parse_args()
    data = enrich(json.loads(args.evidence.read_text()), json.loads(args.manifest.read_text()))
    args.evidence.write_text(json.dumps(data, indent=2) + '\n')
    print(json.dumps(dict(sources=len(data['declared_apis']),
        binding_candidates=len(data['symbol_binding_candidates']),
        pointer_tables=len(data['original_pointer_tables']))))


if __name__ == '__main__':
    main()
