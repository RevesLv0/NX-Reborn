#!/usr/bin/env python3
"""Validate completed Ghidra evidence generations before archiving or reporting them."""
import hashlib
import json
from pathlib import Path

ARTIFACTS=('functions.jsonl','calls.jsonl','decompiled.jsonl','strings.jsonl')

def validate_export(directory,expected_sha=None,expected_run=None):
    directory=Path(directory)
    summary=json.loads((directory/'summary.json').read_text())
    if summary.get('export_schema_version')!=2 or summary.get('export_completed') is not True:
        raise ValueError('Missing completed schema-v2 export')
    if expected_sha and summary['sha256']!=expected_sha:
        raise ValueError('Program SHA256 mismatch')
    if expected_run and summary.get('run_id')!=expected_run:
        raise ValueError('Wrong/stale export run')
    counts={}; successful=0
    for name in ARTIFACTS:
        data=(directory/name).read_bytes()
        receipt=summary['artifacts'][name]
        if len(data)!=receipt['bytes'] or hashlib.sha256(data).hexdigest()!=receipt['sha256']:
            raise ValueError(f'Artifact integrity mismatch: {name}')
        rows=[json.loads(line) for line in data.splitlines()]
        if not all(isinstance(row,dict) for row in rows):
            raise ValueError(f'Invalid row type: {name}')
        counts[name]=len(rows)
        if name=='decompiled.jsonl': successful=sum(row.get('completed') is True for row in rows)
        if name=='strings.jsonl':
            for row in rows:
                if row.get('loaded_memory') is False and row.get('elf_va') is not None:
                    raise ValueError('Unloaded string has fabricated ELF VA')
    expected={'functions.jsonl':summary['functions'],'strings.jsonl':summary['strings'],
              'decompiled.jsonl':summary['decompile_attempted']}
    if any(counts[name]!=count for name,count in expected.items()) or successful!=summary['decompile_completed']:
        raise ValueError('Export row counts do not match summary')
    if summary['matched_functions']-summary['decompile_attempted']!=summary['decompile_omitted_by_budget']:
        raise ValueError('Decompilation selection accounting mismatch')
    return summary

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('directory',type=Path)
    args=p.parse_args()
    print(json.dumps(validate_export(args.directory),indent=2))
