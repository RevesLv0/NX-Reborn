#!/usr/bin/env python3
"""Reproduce selected RUN006 network state/API boundaries; offline ARM only."""
import hashlib
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from elftools.elf.elffile import ELFFile


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    inputs = json.loads(Path('.work/run006/transfer/input-manifest.json').read_text())
    sources = {r['sha256']: r for r in inputs}
    for row in inputs:
        original = Path('.work/full/extracted') / row['partition'] / row['path'].lstrip('/')
        assert sha(original) == sha(row['staged_path']) == row['sha256']
    selected = {'CSAFStateMachine::dispatch', 'CAPPUIApplication::dispatch',
                'CAPPNetworkSmartphoneLinkState::handle',
                'CAPPNetworkSmartphoneLinkState::getNPushEachFileCompleteCheck',
                'CAPPNetworkSmartphoneLinkState::getNPushAllFileSendWait',
                'CAPPNetworkSmartphoneLinkState::nPushCheckSendComplete', 'DlnaRVFEvent'}
    output = dict(schema_version=1, static_only=True, source_checks=inputs,
                  ghidra=[], windows=[], limitations=[
                      'Bounded state/API paths; no global absence-of-writer claim.',
                      'No remote receipt, active-state reachability or successful transfer observation.',
                      'Smart-wifi original ELF addresses equal Ghidra addresses; DSO Ghidra addresses add0x10000.'])
    decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    seen = set()
    for path in sorted(Path('.work/run006/transfer').glob('*/outputs/ghidra/*/decompiled.jsonl')):
        summary = json.loads((path.parent / 'summary.json').read_text())
        source = sources[summary['sha256']]
        for line in path.open():
            row = json.loads(line)
            key = (source['sha256'], row['elf_va'])
            if row['name'] not in selected or key in seen:
                continue
            assert row['completed'] is True
            seen.add(key)
            output['ghidra'].append(dict(source_sha256=source['sha256'], source_path=source['path'],
                path=str(path), sha256=sha(path), **row))
            delta = 0x10000 if source['path'].endswith('.so') else 0
            addresses = sorted(int(i.split()[0], 16) - delta for i in row['instructions'])
            runs = []
            for va in addresses:
                if runs and runs[-1][-1] + 4 == va:
                    runs[-1].append(va)
                else:
                    runs.append([va])
            with Path(source['staged_path']).open('rb') as stream:
                elf = ELFFile(stream)
                for run in runs:
                    va, size = run[0], len(run) * 4
                    segment = next(s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD'
                                   and s['p_vaddr'] <= va and va + size <= s['p_vaddr'] + s['p_filesz'])
                    offset = segment['p_offset'] + va - segment['p_vaddr']
                    stream.seek(offset)
                    raw = stream.read(size)
                    decoded = list(decoder.disasm(raw, va))
                    assert sum(i.size for i in decoded) == size
                    output['windows'].append(dict(source_sha256=source['sha256'], source_path=source['path'],
                        function=row['name'], original_elf_va=hex(va), file_offset=hex(offset), raw_hex=raw.hex(),
                        instructions=[dict(original_elf_va=hex(i.address),bytes=i.bytes.hex(),
                            mnemonic=i.mnemonic,operands=i.op_str) for i in decoded],
                        method='PT_LOAD-mapped original ARM bytes; contiguous recovered code addresses only'))
    path = Path('analysis/evidence/transfer-boundaries-run006.json')
    path.write_text(json.dumps(output, indent=2) + '\n')
    print(json.dumps(dict(functions=len(seen), windows=len(output['windows']), sha256=sha(path))))


if __name__ == '__main__':
    main()
