#!/usr/bin/env python3
"""Reproduce RUN010 transfer outcome evidence from saved offline exports."""
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from elftools.elf.elffile import ELFFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ghidra'))
from validate_exports import validate_export

ROOT = Path('.work/run010/transfer')
OUT = Path('analysis/evidence/transfer-state-run010.json')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def artifact(path):
    return dict(path=str(path), sha256=sha(path), bytes=Path(path).stat().st_size)


def main():
    subprocess.run([sys.executable, 'tools/firmware/selected_elf_evidence.py',
                    '--root', str(ROOT), '--output', str(OUT),
                    '--relocation-term', 'SPClientManager',
                    '--relocation-term', 'SNPushClientNotificationCallback',
                    '--relocation-term', 'gSelectivePushCallback'], check=True)
    data = json.loads(OUT.read_text())
    sources = {Path(s['path']).name: s for s in data['sources']}
    data['data_blocks'] = []
    data['selected_strings'] = []
    data['literal_checks'] = []
    app_modes = json.loads((ROOT / 'modes/app/references.json').read_text())
    assert all(t['thumb_mode_context'] == 0 for t in app_modes['targets'])

    def raw(name, va, size):
        source = sources[name]
        with Path(source['staged_path']).open('rb') as stream:
            elf = ELFFile(stream)
            seg = next(s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD'
                       and s['p_vaddr'] <= va and va + size <= s['p_vaddr'] + s['p_filesz'])
            offset = seg['p_offset'] + va - seg['p_vaddr']
            stream.seek(offset)
            blob = stream.read(size)
        return dict(source_sha256=source['sha256'], source_path=source['path'],
                    original_elf_va=hex(va), file_offset=hex(offset), raw_hex=blob.hex())

    api = 'libdi-network-dlna-api.so'
    app = 'smart-wifi-app'
    for name, va, size, purpose in [
        (api, 0x81340, 20, 'SPClientManager vtable; zero original words require ELF relocations'),
        (app, 0x105168, 36, 'CAPPUIApplication vtable'),
        (app, 0xf5a40, 56, 'CSAFEvent vtable'),
        (app, 0x810d8, 76, 'Smartphone handle type jump table; type 0x13 entry is 0x81220')]:
        row = raw(name, va, size)
        row.update(purpose=purpose, decoded_u32=[hex(x[0]) for x in struct.iter_unpack('<I', bytes.fromhex(row['raw_hex']))])
        data['data_blocks'].append(row)
    assert data['data_blocks'][1]['decoded_u32'][5] == '0x4cd30'
    assert data['data_blocks'][3]['decoded_u32'][18] == '0x81220'
    for name, va, size, purpose in [
        (app, 0x4caa8, 4, 'Application constructor installs vtable address point 0x105170'),
        (app, 0x4cb0c, 20, 'Singleton guard/object/destructor literals'),
        (api, 0x41378, 8, 'Manager constructor GOT calculation: 0x4133c + word0 + word1 = 0x820e4'),
        (api, 0x820e4, 4, 'Manager vtable GOT slot; requires _ZTV15SPClientManager relocation')]:
        row = raw(name, va, size)
        row.update(purpose=purpose, decoded_u32=[hex(x[0]) for x in struct.iter_unpack('<I', bytes.fromhex(row['raw_hex']))])
        data['data_blocks'].append(row)
    assert data['data_blocks'][4]['decoded_u32'] == ['0x105170']
    assert any(r['original_elf_va'] == '0x820e4' and r['symbol'] == '_ZTV15SPClientManager' for r in data['relocations'])
    assert any(r['original_elf_va'] == '0x81348' and r['symbol_value'] == '0x40c14' for r in data['relocations'])

    for va, size, purpose in [(0x5a368, 64, 'API callback label: convert event/status then tail branch'),
                              (0x40c34, 64, 'CSAFEvent getter/setter implementations')]:
        row = raw(app, va, size)
        blob = bytes.fromhex(row['raw_hex'])
        instructions = list(Cs(CS_ARCH_ARM, CS_MODE_ARM).disasm(blob, va))
        assert sum(i.size for i in instructions) == size
        row.update(mode='ARM', function=purpose, instructions=[dict(va=hex(i.address), bytes=i.bytes.hex(),
                   mnemonic=i.mnemonic, operands=i.op_str) for i in instructions])
        data['windows'].append(row)

    def string(name, va):
        blob = bytes.fromhex(raw(name, va, 512)['raw_hex']).split(b'\0', 1)[0]
        row = raw(name, va, len(blob) + 1)
        row['value'] = blob.decode('ascii')
        if not any(r['source_sha256'] == row['source_sha256'] and r['original_elf_va'] == row['original_elf_va'] for r in data['selected_strings']):
            data['selected_strings'].append(row)
        return row['value']

    for literal, base, expected in [(0x4c9a8, 0x4ce00, '100'), (0x4c9ac, 0x4ce18, '500'),
                                    (0x4e88c, 0x4e314, '200')]:
        row = raw(api, literal, 4)
        target = (struct.unpack('<I', bytes.fromhex(row['raw_hex']))[0] + base) & 0xffffffff
        assert string(api, target) == expected
        row.update(pc_relative_base=hex(base), resolved_original_elf_va=hex(target), value=expected)
        data['literal_checks'].append(row)
        data['data_blocks'].append(dict(row, purpose='PC-relative comparison literal'))
    for va in [0x75f7c, 0x761e4, 0x76200, 0x76398, 0x76110, 0x76144, 0x76304]:
        string(api, va)

    # Preserve the completed budget-limited attempt, even though the complete
    # repeat above supplies all seven requested functions and original windows.
    old = Path('.work/run010/transfer-budget-attempts/api-binding')
    receipt_path = next((old / 'logs').glob('NX500*.json'))
    receipt = json.loads(receipt_path.read_text())
    folder = next((old / 'outputs/ghidra').iterdir())
    summary = json.loads((folder / 'summary.json').read_text())
    validate_export(folder, sources[api]['sha256'], receipt['run_id'])
    assert receipt['completed'] and summary['decompile_omitted_by_budget'] == 1
    data['generations'].append(dict(work=str(old), receipt=receipt, receipt_artifact=artifact(receipt_path),
        input_manifest=artifact(old / 'input-manifest.json'), summaries=[summary],
        relocated_from='.work/run010/transfer/network/api-binding',
        limitation='One requested match omitted by budget; subsequent full repeat recovered all seven.'))
    for line in (folder / 'decompiled.jsonl').read_text().splitlines():
        row = json.loads(line)
        assert row['completed']
        data['ghidra'].append(dict(source_sha256=sources[api]['sha256'], source_path=sources[api]['path'],
            artifact=artifact(folder / 'decompiled.jsonl'), generation=str(old), **row))
    data['selected_attempts'] += summary['decompile_attempted']
    data['selected_completed'] += summary['decompile_completed']
    data['budget_omissions'] = 1
    data['budget_omissions_recovered_by_repeat'] = 1
    data['producer_note'] = 'Worker-local outcomes 1/2/3/4 are distinct from APP client record state +0xac.'
    OUT.write_text(json.dumps(data, indent=2) + '\n')

    manifest = dict(schema_version=1, static_only=True, input_inventory=artifact('.work/full/inventory/full_filesystem_inventory.json'),
        collector=artifact(__file__), evidence=artifact(OUT), sources=data['sources'], generations=data['generations'],
        mode_queries=data['mode_queries'], export_generations=sum(len(g['summaries']) for g in data['generations']),
        selected_attempts=data['selected_attempts'], selected_completed=data['selected_completed'],
        unique_selected_functions=data['unique_selected_functions'], imported_programs=0, auto_analysis_programs=0,
        budget_omissions=1, budget_omissions_recovered_by_repeat=1,
        independent_semantic_review_completed=False,
        limitations=data['limitations'] + ['Five generations include one budget-limited attempt and its complete repeat; no decompiler failure or target execution.'])
    Path('manifests/ghidra-transfer-run010.json').write_text(json.dumps(manifest, indent=2) + '\n')
    findings = []
    for ident, name, va, offset, claim, unresolved in [
        ('TRANSFER010-SUBCODE', api, 0x4a9ec, 0x4a9ec,
         'Response parser writes Sub-ErrorCode via sscanf into response +0x10, the worker handler +0x28; initial non-100 status containing 500 selects decimal subcodes 2502 and 2503.',
         'Malformed headers, unchecked sscanf conversion, socket-read semantics and actual receiver responses remain unobserved.'),
        ('TRANSFER010-OUTCOME', api, 0x4b848, 0x4b848,
         'Worker outcomes two/three/four/default dispatch notifier events three/four/six/five, mapping to API UI events 0x49/0x4d/0x4c/0x4b; diagnostics associate subcodes2502/2503 with storage-space/unsupported-file errors.',
         'Worker-local outcomes are distinct from APP client states; remote persistence, successful join and camera quiescence are not established.'),
        ('TRANSFER010-APP-SINGLETON', app, 0x4ca8c, 0x44a8c,
         'APP singleton constructor installs address point0x105170; its original vtable slot+0xc is dispatch0x4cd30, concretely binding the UI idle callback application dispatch.',
         'Active state at delivery, alternate observers and concrete APP +0xac terminal-state writers remain unresolved.')]:
        source = sources[name]
        findings.append(dict(id=ident, source_sha256=source['sha256'], original_path=source['path'],
            original_elf_va=hex(va), file_offset=offset, evidence=str(OUT), evidence_sha256=sha(OUT),
            method='Sub-agent selected C; original PT_LOAD-mapped ARM windows and mode queries; original literals, vtables and ELF relocation checks.',
            claim=claim, limitations=[unresolved, 'Bounded static interpretation; no target execution or independent semantic review.'],
            unresolved_questions=[unresolved], independent_review_completed=False))
    Path('manifests/review-transfer-run010.json').write_text(json.dumps(dict(schema_version=1,
        run='RUN010', reviewed_findings=findings), indent=2) + '\n')
    print(json.dumps({k: manifest[k] for k in ['export_generations', 'selected_attempts', 'selected_completed', 'unique_selected_functions', 'budget_omissions']}))


if __name__ == '__main__':
    main()
