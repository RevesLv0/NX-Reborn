#!/usr/bin/env python3
"""Collect SHA-bound selected C and original ARM/Thumb code for a run root.

Requires completed per-source address/TMode queries under ROOT/modes and paired
input manifests at each subsystem root. It does not run or modify target code.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ghidra'))
from validate_exports import validate_export


def load(path):
    return json.loads(Path(path).read_text())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def artifact(path):
    return dict(path=str(path),sha256=sha(path),bytes=Path(path).stat().st_size)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--relocation-term',action='append',default=[])
    ap.add_argument('--string-term',action='append',default=[])
    a=ap.parse_args()
    output=dict(schema_version=1,static_only=True,generations=[],failed_generations=[],sources=[],mode_queries=[],
                ghidra=[],windows=[],relocations=[],strings_collection='Full strings remain in validated exports; no selective string extraction is performed.',limitations=[
                    'Selected decompilation and primary-agent byte verification only; no independent semantic review or runtime observation.',
                    'Original ELF VAs use per-source Ghidra delta; original file offsets use PT_LOAD independently.',
                    'Recovered instruction addresses are decoded in saved TMode context and split at gaps; C signatures remain inferred.'])
    modes={}
    sources={}
    string_artifacts={}
    for root in sorted((a.root/'modes').iterdir()):
        receipt=load(root/'receipt.json');query=load(root/'references.json')
        assert receipt['completed'] is True and receipt['returncode']==0
        assert receipt['output_sha256']==sha(root/'references.json')
        assert query['source_sha256']==receipt['source_sha256']
        mapping=modes.setdefault(query['source_sha256'],{})
        for target in query['targets']:
            va=int(target['target_va'],16)
            if va in mapping:
                assert mapping[va]==target['thumb_mode_context']
            mapping[va]=target['thumb_mode_context']
        output['mode_queries'].append(dict(receipt=receipt,query=query,artifact=artifact(root/'references.json')))
    for folder in sorted(a.root.glob('*/*/outputs/ghidra')):
        work=folder.parent.parent
        receipts=list((work/'logs').glob('NX500*.json'));assert len(receipts)==1
        receipt=load(receipts[0])
        if not receipt['completed']:
            assert receipt.get('returncode', 0) != 0, 'Unfinished generation: wait for the process before collecting'
            assert not list(folder.glob('*/summary.json')), 'Partially exported failure requires explicit review'
            output['failed_generations'].append(dict(work=str(work),receipt=receipt,receipt_artifact=artifact(receipts[0])))
            continue
        assert receipt['returncode']==0
        master=work.parent/'input-manifest.json'
        inputs=load(master)
        paired=work/'input-manifest.json'
        if paired.exists():
            selected=load(paired)
            assert all(row in inputs for row in selected), 'Generation inputs must be a subset of the subsystem manifest'
            inputs=selected
        else:
            paired.write_text(json.dumps(inputs,indent=2)+'\n')
        for row in inputs:
            original_path=row.get('path') or row['original_path']
            partition=row.get('partition','rootfs')
            original=Path('.work/full/extracted')/partition/original_path.lstrip('/')
            assert sha(original)==sha(row['staged_path'])==row['sha256']
            sources[row['sha256']]=dict(path=original_path,partition=partition,sha256=row['sha256'],staged_path=row['staged_path'])
        summaries=[]
        for p in sorted(folder.glob('*/summary.json')):
            summary=load(p);validate_export(p.parent,summary['sha256'],receipt['run_id']);summaries.append(summary)
            assert summary['decompile_omitted_by_budget']==0
            source=sources[summary['sha256']]
            string_artifacts.setdefault(source['sha256'],p.parent/'strings.jsonl')
            for line in (p.parent/'decompiled.jsonl').open():
                row=json.loads(line);assert row['completed'] is True
                output['ghidra'].append(dict(source_sha256=source['sha256'],source_path=source['path'],
                    artifact=artifact(p.parent/'decompiled.jsonl'),generation=str(work),**row))
        assert {s['sha256'] for s in summaries}=={r['sha256'] for r in inputs}
        output['generations'].append(dict(work=str(work),receipt=receipt,receipt_artifact=artifact(receipts[0]),
            input_manifest=artifact(paired),summaries=summaries))
    seen=set()
    for row in output['ghidra']:
        key=(row['source_sha256'],row['elf_va'])
        if key in seen:
            continue
        seen.add(key)
        source=sources[row['source_sha256']]
        thumb=modes[source['sha256']][int(row['va'],16)];assert thumb in (0,1)
        decoder=Cs(CS_ARCH_ARM,CS_MODE_THUMB if thumb else CS_MODE_ARM)
        delta=int(row['va'],16)-int(row['elf_va'],16)
        with Path(source['staged_path']).open('rb') as stream:
            elf=ELFFile(stream)
            def read(va,size):
                seg=next(s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=va and va+size<=s['p_vaddr']+s['p_filesz'])
                offset=seg['p_offset']+va-seg['p_vaddr'];stream.seek(offset)
                return offset,stream.read(size)
            runs=[]
            for va in sorted(int(i.split()[0],16)-delta for i in row['instructions']):
                _,raw=read(va,4);ins=next(decoder.disasm(raw,va,count=1))
                if runs and runs[-1][0]+len(runs[-1][1])==va:
                    runs[-1][1].extend(ins.bytes)
                else:
                    runs.append((va,bytearray(ins.bytes)))
            for va,raw in runs:
                offset,original=read(va,len(raw));assert raw==original
                instructions=list(decoder.disasm(raw,va));assert sum(i.size for i in instructions)==len(raw)
                output['windows'].append(dict(source_sha256=source['sha256'],source_path=source['path'],function=row['name'],
                    original_elf_va=hex(va),file_offset=hex(offset),mode='Thumb' if thumb else 'ARM',raw_hex=raw.hex(),
                    instructions=[dict(va=hex(i.address),bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str) for i in instructions]))
    used={r['source_sha256'] for r in output['ghidra']}
    output['sources']=[sources[s] for s in sorted(used)]
    if a.string_term:
        output['strings_collection']='Selected original strings by explicit substring terms; not an exhaustive string inventory.'
        output['selected_strings']=[]
        for source in output['sources']:
            with Path(source['staged_path']).open('rb') as stream:
                elf=ELFFile(stream)
                for line in string_artifacts[source['sha256']].open():
                    row=json.loads(line)
                    if not any(term in row['value'] for term in a.string_term) or row.get('elf_va') is None:
                        continue
                    va=int(row['elf_va'],16)
                    expected=row['value'].encode('utf-8')+b'\0'
                    seg=next(s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=va and va+len(expected)<=s['p_vaddr']+s['p_filesz'])
                    offset=seg['p_offset']+va-seg['p_vaddr'];stream.seek(offset);raw=stream.read(len(expected));assert raw==expected
                    output['selected_strings'].append(dict(source_sha256=source['sha256'],source_path=source['path'],
                        original_elf_va=hex(va),file_offset=hex(offset),raw_hex=raw.hex(),value=row['value']))
    for source in output['sources']:
        with Path(source['staged_path']).open('rb') as stream:
            elf=ELFFile(stream)
            for sec in elf.iter_sections():
                if sec['sh_type'] not in ('SHT_REL','SHT_RELA'):
                    continue
                for rel in sec.iter_relocations():
                    sym=elf.get_section(sec['sh_link']).get_symbol(rel['r_info_sym'])
                    if any(term in sym.name for term in a.relocation_term):
                        output['relocations'].append(dict(source_sha256=source['sha256'],source_path=source['path'],
                            section=sec.name,original_elf_va=hex(rel['r_offset']),type=rel['r_info_type'],symbol=sym.name,
                            symbol_value=hex(sym['st_value'])))
    output['unique_selected_functions']=len(seen)
    output['selected_attempts']=sum(s['decompile_attempted'] for g in output['generations'] for s in g['summaries'])
    output['selected_completed']=sum(s['decompile_completed'] for g in output['generations'] for s in g['summaries'])
    # Source strings stay in full saved exports; the selected C and original
    # instructions above are the public claim anchors.
    a.output.write_text(json.dumps(output,indent=2)+'\n')
    print(json.dumps(dict(exports=sum(len(g['summaries']) for g in output['generations']),
        selected_attempts=output['selected_attempts'],selected_completed=output['selected_completed'],
        unique_selected_functions=len(seen),windows=len(output['windows']),sha256=sha(a.output))))


if __name__=='__main__':
    main()
