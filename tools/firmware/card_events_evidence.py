#!/usr/bin/env python3
"""Reproduce RUN007 card-event and dynamically selected OEM getter evidence."""
import hashlib
import json
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ghidra'))
from validate_exports import validate_export


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def artifact(path):
    return dict(path=str(path),bytes=Path(path).stat().st_size,sha256=sha(path))


def load(path):
    return json.loads(Path(path).read_text())


def main():
    result = dict(schema_version=1,static_only=True,sources=[],generations=[],ghidra=[],
                  windows=[],data_blocks=[],relocations=[],reference_queries=[],limitations=[
                      'Primary-agent static validation; independent semantic review remains incomplete.',
                      'No target execution, card I/O, formatting, filesystem mounting or firmware installation.',
                      'Device event and admission state do not correlate a particular file-worker failure.',
                      'Dynamic plugin selection and sysfs nodes are code paths, not observations of the active camera.'])
    identities = {}
    modes = {}
    for mode_root in sorted(Path('.work/run007/modes').iterdir()):
        receipt = load(mode_root/'receipt.json')
        assert receipt['completed'] is True and receipt['returncode'] == 0
        assert sha(mode_root/'references.json') == receipt['output_sha256']
        query = load(mode_root/'references.json')
        assert query['source_sha256'] == receipt['source_sha256']
        mapping=modes.setdefault(query['source_sha256'],{})
        for row in query['targets']:
            va=int(row['target_va'],16)
            if va in mapping:
                assert mapping[va]==row['thumb_mode_context']
            mapping[va]=row['thumb_mode_context']
        result['reference_queries'].append(dict(receipt=receipt,artifact=artifact(mode_root/'references.json'),query=query))
    for group in ['card','device','plugin']:
        root = Path('.work/run007')/group
        inputs = load(root/'input-manifest.json')
        for row in inputs:
            path = row.get('path') or row['original_path']
            original = Path('.work/full/extracted/rootfs')/path.lstrip('/')
            assert sha(original) == row['sha256'] == sha(row['staged_path'])
            identities[row['sha256']] = dict(path=path,staged_path=row['staged_path'],sha256=row['sha256'])
        for work in sorted(root.glob('*/outputs/ghidra')):
            directory = work.parent.parent
            receipts = list((directory/'logs').glob('NX500*.json'))
            assert len(receipts)==1
            receipt = load(receipts[0])
            assert receipt['completed'] is True and receipt['returncode']==0
            paired = directory/'input-manifest.json'
            if paired.exists():
                assert load(paired)==inputs
            else:
                paired.write_text(json.dumps(inputs,indent=2)+'\n')
            summaries=[]
            for summary_path in sorted(work.glob('*/summary.json')):
                summary=load(summary_path)
                validate_export(summary_path.parent,summary['sha256'],receipt['run_id'])
                assert summary['sha256'] in {r['sha256'] for r in inputs}
                assert summary['decompile_omitted_by_budget']==0
                summaries.append(summary)
                source=identities[summary['sha256']]
                for line in (summary_path.parent/'decompiled.jsonl').open():
                    row=json.loads(line)
                    assert row['completed'] is True
                    # Unrelated constructors sharing a pattern in the other
                    # programs remain counted attempts, not selected evidence.
                    if source['path'].split('/')[-1] not in ['deviced','libdevice-node.so.0.1','libdeviced.so.0.1.0','libslp_devman_plugin.so']:
                        continue
                    result['ghidra'].append(dict(source_sha256=source['sha256'],source_path=source['path'],
                        generation=str(directory),artifact=artifact(summary_path.parent/'decompiled.jsonl'),**row))
            assert {s['sha256'] for s in summaries}=={r['sha256'] for r in inputs}
            result['generations'].append(dict(work=str(directory),input_manifest=artifact(paired),
                receipt_artifact=artifact(receipts[0]),receipt=receipt,summaries=summaries))

    def read(source,va,size):
        with Path(source['staged_path']).open('rb') as stream:
            elf=ELFFile(stream)
            seg=next(s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=va and va+size<=s['p_vaddr']+s['p_filesz'])
            offset=seg['p_offset']+va-seg['p_vaddr']
            stream.seek(offset)
            return offset,stream.read(size)

    def window(source,va,raw,thumb,purpose):
        offset,original=read(source,va,len(raw))
        assert raw==original
        decoded=list(Cs(CS_ARCH_ARM,CS_MODE_THUMB if thumb else CS_MODE_ARM).disasm(raw,va))
        assert sum(i.size for i in decoded)==len(raw),(source['path'],hex(va))
        result['windows'].append(dict(source_path=source['path'],source_sha256=source['sha256'],
            original_elf_va=hex(va),file_offset=hex(offset),mode='Thumb' if thumb else 'ARM',raw_hex=raw.hex(),purpose=purpose,
            instructions=[dict(va=hex(i.address),bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str) for i in decoded]))

    seen=set()
    for row in result['ghidra']:
        key=(row['source_sha256'],row['elf_va'])
        if key in seen:
            continue
        seen.add(key)
        source=identities[row['source_sha256']]
        thumb=modes[row['source_sha256']][int(row['va'],16)]
        assert thumb in (0,1)
        delta=int(row['va'],16)-int(row['elf_va'],16)
        decoder=Cs(CS_ARCH_ARM,CS_MODE_THUMB if thumb else CS_MODE_ARM)
        runs=[]
        for va in sorted(int(i.split()[0],16)-delta for i in row['instructions']):
            _,raw=read(source,va,4)
            ins=next(decoder.disasm(raw,va,count=1))
            if runs and runs[-1][0]+len(runs[-1][1])==va:
                runs[-1][1].extend(ins.bytes)
            else:
                runs.append((va,bytearray(ins.bytes)))
        for va,raw in runs:
            window(source,va,bytes(raw),thumb,'Contiguous Ghidra recovered instructions for '+row['name']+'; mode from saved TMode context')

    source=next(r for r in identities.values() if r['path'].endswith('/libdevice-node.so.0.1'))
    # These concrete targets were NOT recovered as functions by the saved Ghidra
    # auto-analysis. Descriptor Thumb bits and original control flow supply the
    # mode. Keep inline TBB table and literal pools as data.
    for lo,hi in [(0x3378,0x3386),(0x338a,0x33f8),(0x3404,0x3468)]:
        _,raw=read(source,lo,hi-lo)
        window(source,lo,raw,True,'Manual descriptor-target Thumb window, separate from Ghidra decompilation; inline tables/pools excluded')
    for lo,hi,label in [(0xc5cc,0xc5dc,'Type11 descriptor: ID,name,setter pointer,getter pointer'),
                         (0x3386,0x338a,'Four-byte TBB table indexed by getter property0..3'),
                         (0x33f8,0x3404,'Getter GOT literals'),(0x3468,0x3474,'Setter GOT literals')]:
        offset,raw=read(source,lo,hi-lo)
        result['data_blocks'].append(dict(source_path=source['path'],source_sha256=source['sha256'],
            original_elf_va=hex(lo),file_offset=hex(offset),raw_hex=raw.hex(),purpose=label))
    _,descriptor=read(source,0xc5cc,16)
    assert struct.unpack('<IIII',descriptor)==(11,0x4244,0x3405,0x3379)
    _,table=read(source,0x3386,4)
    assert [0x3386+2*b for b in table]==[0x33b6,0x33d4,0x339e,0x338a]
    result['sources']=[identities[s] for s in sorted({r['source_sha256'] for r in result['ghidra']})]
    for source in result['sources']:
        with Path(source['staged_path']).open('rb') as stream:
            elf=ELFFile(stream)
            for sec in elf.iter_sections():
                if sec['sh_type'] not in ('SHT_REL','SHT_RELA'):
                    continue
                for rel in sec.iter_relocations():
                    sym=elf.get_section(sec['sh_link']).get_symbol(rel['r_info_sym'])
                    if any(t in sym.name for t in ['OEM_sys_get_mmc','OEM_sys_get_devman','device_get_property','vconf_set_int','sys_get_int']) or 0xc5cc<=rel['r_offset']<0xc5dc:
                        result['relocations'].append(dict(source_sha256=source['sha256'],section=sec.name,va=hex(rel['r_offset']),type=rel['r_info_type'],symbol=sym.name,symbol_value=hex(sym['st_value'])))
    result['selected_attempts']=sum(s['decompile_attempted'] for g in result['generations'] for s in g['summaries'])
    result['selected_completed']=sum(s['decompile_completed'] for g in result['generations'] for s in g['summaries'])
    result['unique_evidence_selected_functions']=len(seen)
    result['manual_additional_getter_targets']=['0x3378','0x3404']
    path=Path('analysis/evidence/card-events-run007.json')
    path.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(exports=sum(len(g['summaries']) for g in result['generations']),
        selected_attempts=result['selected_attempts'],selected_completed=result['selected_completed'],
        evidence_functions=len(seen),windows=len(result['windows']),data_blocks=len(result['data_blocks']),sha256=sha(path))))


if __name__=='__main__':
    main()
