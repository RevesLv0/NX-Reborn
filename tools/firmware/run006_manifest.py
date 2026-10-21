#!/usr/bin/env python3
"""Validate all saved RUN006 Ghidra generations and preserve their receipts."""
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ghidra'))
from validate_exports import validate_export


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def artifact(path):
    return dict(path=str(path), sha256=sha(path), bytes=Path(path).stat().st_size)


def main():
    generations = []
    sources = {}
    selected = set()
    groups = {'storage': dict(attempted=0, completed=0, exports=0),
              'app': dict(attempted=0, completed=0, exports=0),
              'transfer': dict(attempted=0, completed=0, exports=0)}
    masters = {'NX500_FW112': '.work/run006/storage/input-manifest.json',
               'NX500_FW112_SURVEY': '.work/run006/app/input-manifest.json',
               'NX500_RUN003_CAPTURE': '.work/run006/app-bridge/input-manifest.json',
               'NX500_FULL_RUN002': '.work/run006/transfer/input-manifest.json'}
    directories = sorted({p.parent.parent for pattern in ['*/outputs/ghidra','*/*/outputs/ghidra']
                          for p in Path('.work/run006').glob(pattern)})
    for work in directories:
        receipts = sorted((work / 'logs').glob('NX500*.json'))
        assert len(receipts) == 1, work
        receipt = json.loads(receipts[0].read_text())
        assert receipt['completed'] is True and receipt['returncode'] == 0, work
        assert '-noanalysis' in receipt['command'] and '-import' not in receipt['command']
        project = receipt['command'][2]
        inputs = json.loads(Path(masters[project]).read_text())
        paired = work / 'input-manifest.json'
        if paired.exists():
            assert json.loads(paired.read_text()) == inputs, paired
        else:
            paired.write_text(json.dumps(inputs, indent=2) + '\n')
        for row in inputs:
            assert sha(row['staged_path']) == row['sha256']
            original = Path('.work/full/extracted') / row['partition'] / row['path'].lstrip('/')
            assert sha(original) == row['sha256']
            sources[row['sha256']] = row
        summaries = []
        for folder in sorted((work / 'outputs/ghidra').iterdir()):
            if not folder.is_dir():
                continue
            summary = json.loads((folder / 'summary.json').read_text())
            validate_export(folder, summary['sha256'], receipt['run_id'])
            summaries.append(summary)
            assert summary['decompile_omitted_by_budget'] == 0, folder
            for line in (folder / 'decompiled.jsonl').open():
                row = json.loads(line)
                assert row['completed'] is True, (folder,row['name'])
                selected.add((summary['sha256'], row['elf_va']))
        assert {s['sha256'] for s in summaries} == {r['sha256'] for r in inputs}
        group = 'storage' if project == 'NX500_FW112' else 'transfer' if project == 'NX500_FULL_RUN002' else 'app'
        for key, field in [('attempted','decompile_attempted'),('completed','decompile_completed')]:
            groups[group][key] += sum(s[field] for s in summaries)
        groups[group]['exports'] += len(summaries)
        generations.append(dict(work=str(work), group=group, project=project,
            input_manifest=artifact(paired), receipt_artifact=artifact(receipts[0]),
            receipt=receipt, summaries=summaries))
    result = dict(schema_version=1, run='RUN006', static_only=True,
        inputs=list(sources.values()), new_imports=0, new_auto_analysis_generations=0,
        generations=generations, groups=groups, validated_exports=sum(g['exports'] for g in groups.values()),
        selected_attempts=sum(g['attempted'] for g in groups.values()),
        selected_completed=sum(g['completed'] for g in groups.values()),
        distinct_selected_functions=len(selected), failures=[], omissions=[],
        source_inventory=artifact('.work/full/inventory/full_filesystem_inventory.json'),
        review_ledger='manifests/review-run006.json',
        independent_semantic_review_completed=False,
        review_status='Primary agent checked original bytes and bounded claims; independent agent stopped with actual usage-limit error.',
        project_lock_files=[str(p) for p in Path('ghidra-projects').glob('*.lock*')],
        limitations=['Reprocessing existing programs does not increase unique ELF inventory coverage.',
                     'Selected decompilation counts and reviewed static findings are separate; neither measures whole-firmware completion.',
                     'No target execution, camera I/O or installation.'])
    result['project_unlocked'] = not result['project_lock_files']
    Path('manifests/ghidra-run006.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ['groups','validated_exports','selected_attempts','selected_completed','distinct_selected_functions','project_unlocked']}))


if __name__ == '__main__':
    main()
