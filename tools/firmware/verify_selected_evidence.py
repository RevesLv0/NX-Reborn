#!/usr/bin/env python3
"""Audit selected ELF/kernel evidence against source bytes and saved C artifacts."""
import argparse
import hashlib
import json
from pathlib import Path

from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
from elftools.elf.elffile import ELFFile


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def decode(row,va,raw):
    decoder=Cs(CS_ARCH_ARM,CS_MODE_THUMB if row.get('mode')=='Thumb' else CS_MODE_ARM)
    actual=list(decoder.disasm(raw,va));assert sum(i.size for i in actual)==len(raw)
    assert [(hex(i.address),i.bytes.hex(),i.mnemonic,i.op_str) for i in actual]==[
        (r.get('va',r.get('original_elf_va')),r.get('bytes',r.get('raw_hex')),r['mnemonic'],r['operands']) for r in row['instructions']]


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--evidence',type=Path,action='append',required=True)
    ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args();checks=[]
    for path in a.evidence:
        d=json.loads(path.read_text());counts=dict(code_windows=0,data_blocks=0,strings=0)
        if isinstance(d.get('sources'),list):
            sources={s['sha256']:s for s in d['sources']}
            for source in sources.values():
                original=Path('.work/full/extracted')/source.get('partition','rootfs')/source['path'].lstrip('/')
                assert sha(original)==source['sha256']==sha(source['staged_path'])
            for field,count_name in [('windows','code_windows'),('data_blocks','data_blocks'),('selected_strings','strings')]:
                for row in d.get(field,[]):
                    source=sources[row['source_sha256']];va=int(row['original_elf_va'],16);raw=bytes.fromhex(row['raw_hex'])
                    with Path(source['staged_path']).open('rb') as stream:
                        elf=ELFFile(stream)
                        seg=next(s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=va and va+len(raw)<=s['p_vaddr']+s['p_filesz'])
                        offset=seg['p_offset']+va-seg['p_vaddr'];assert offset==int(row['file_offset'],16)
                        stream.seek(offset);assert stream.read(len(raw))==raw
                    if 'instructions' in row:decode(row,va,raw)
                    if field=='selected_strings':assert raw==row['value'].encode('utf-8')+b'\0'
                    counts[count_name]+=1
            cache={}
            for row in d['ghidra']:
                artifact=row['artifact'];p=Path(artifact['path'])
                if str(p) not in cache:
                    assert sha(p)==artifact['sha256'] and p.stat().st_size==artifact['bytes']
                    cache[str(p)]={(r['va'],r['elf_va'],r['name']):r for r in map(json.loads,p.read_text().splitlines())}
                original=cache[str(p)][(row['va'],row['elf_va'],row['name'])]
                for key in ['c','instructions','completed']:assert row[key]==original[key]
            for source in sources.values():
                recorded=[r for r in d.get('relocations',[]) if r['source_sha256']==source['sha256']]
                with Path(source['staged_path']).open('rb') as stream:
                    elf=ELFFile(stream);actual=set()
                    for sec in elf.iter_sections():
                        if sec['sh_type'] not in ('SHT_REL','SHT_RELA'):
                            continue
                        for rel in sec.iter_relocations():
                            sym=elf.get_section(sec['sh_link']).get_symbol(rel['r_info_sym'])
                            actual.add((hex(rel['r_offset']),rel['r_info_type'],sym.name,hex(sym['st_value'])))
                    for row in recorded:
                        assert (row['original_elf_va'],row['type'],row['symbol'],row['symbol_value']) in actual
        elif isinstance(d.get('sources'),dict) and 'kernel_link_base' in d and 'code_regions' in d:
            sources=d['sources'];blobs={}
            for name,source in sources.items():
                assert sha(source['path'])==source['sha256']
                blobs[name]=Path(source['path']).read_bytes()
                assert len(blobs[name])==source['size']
            for field,count_name in [('code_regions','code_windows'),('data_blocks','data_blocks'),('strings','strings'),('plt_bindings','plt_bindings')]:
                for row in d.get(field,[]):
                    blob=blobs[row['source']];va=int(row['va'],16);raw=bytes.fromhex(row['raw_hex'])
                    if blob[:4]==b'\x7fELF':
                        with Path(sources[row['source']]['path']).open('rb') as stream:
                            elf=ELFFile(stream)
                            seg=next(s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=va and va+len(raw)<=s['p_vaddr']+s['p_filesz'])
                            offset=seg['p_offset']+va-seg['p_vaddr']
                    else:
                        offset=va-int(d['kernel_link_base'],16)
                    assert offset==row['file_offset'] and offset>=0
                    assert blob[offset:offset+len(raw)]==raw and hashlib.sha256(raw).hexdigest()==row['sha256']
                    if 'instructions' in row:decode(row,va,raw)
                    if field=='strings':assert raw==row['value'].encode('ascii')+b'\0'
                    if field=='plt_bindings':
                        rel_offset=row['relocation_file_offset'];rel_raw=bytes.fromhex(row['relocation_raw_hex'])
                        assert blob[rel_offset:rel_offset+len(rel_raw)]==rel_raw
                        with Path(sources[row['source']]['path']).open('rb') as stream:
                            elf=ELFFile(stream);section=elf.get_section_by_name('.rel.plt')
                            index=(rel_offset-section['sh_offset'])//section['sh_entsize']
                            assert section['sh_offset']+index*section['sh_entsize']==rel_offset
                            relocation=section.get_relocation(index)
                            symbol=elf.get_section(section['sh_link']).get_symbol(relocation['r_info_sym'])
                            assert relocation['r_info_type']==row['relocation_type'] and hex(relocation['r_offset'])==row['got_va']
                            assert symbol.name==row['symbol'] and hex(symbol['st_value'])==row['symbol_defined_va']
                    counts[count_name]=counts.get(count_name,0)+1
        elif 'code_regions' in d and 'decoded_base' in d:
            source=Path(d['source']);assert sha(source)==d['source_sha256'];blob=source.read_bytes();base=int(d['decoded_base'],16)
            for field,count_name in [('code_regions','code_windows'),('data_blocks','data_blocks'),('strings','strings')]:
                for row in d.get(field,[]):
                    va=int(row['kernel_link_va'],16);offset=row['decoded_offset'];assert va==base+offset
                    raw=bytes.fromhex(row['raw_hex']);assert raw==blob[offset:offset+len(raw)]
                    assert hashlib.sha256(raw).hexdigest()==row['sha256']
                    if 'instructions' in row:decode(row,va,raw)
                    if field=='strings':assert raw==row['value'].encode('ascii')+b'\0'
                    counts[count_name]+=1
        else:
            raise ValueError('Unsupported evidence schema: '+str(path))
        checks.append(dict(path=str(path),sha256=sha(path),**counts))
    result=dict(schema_version=1,static_only=True,verifier_sha256=sha(__file__),checked_evidence=checks,
        independent_semantic_review_completed=False,limitations=[
            'Primary-agent original-byte and artifact consistency checks, not independent semantic review.',
            'No camera observations, active-boot proof, sensor calibration or runtime policy validation.'])
    a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(evidence_files=len(checks),code_windows=sum(r['code_windows'] for r in checks),
        data_blocks=sum(r['data_blocks'] for r in checks),strings=sum(r['strings'] for r in checks))))


if __name__=='__main__':
    main()
