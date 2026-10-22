#!/usr/bin/env python3
"""Verify packaged preference slices and manually bounded prefman Thumb dispatch.

Enrich a selected_elf_evidence.py result. No shell script, utility or target code
is executed, and no preference/database/device is written.
"""
import argparse
import hashlib
import json
import re
import struct
import zlib
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--selected',type=Path,default=Path('.work/run011/prefinit-selected.json'))
    ap.add_argument('--output',type=Path,default=Path('analysis/evidence/packaged-preferences-run011.json'))
    args=ap.parse_args();result=json.loads(args.selected.read_text())
    inventory=json.loads(Path('.work/full/inventory/full_filesystem_inventory.json').read_text())
    files=[]
    def source(partition,path):
        row=next(r for r in inventory if r['partition']==partition and r['original_path']==path)
        p=Path('.work/full/extracted')/partition/path.lstrip('/');raw=p.read_bytes()
        assert digest(raw)==row['sha256']==row['source_sha256'] and row['source_bytes_match_extracted']
        files.append(dict(partition=partition,original_path=path,local_path=str(p),bytes=len(raw),sha256=digest(raw)))
        return raw
    script=source('rootfs','/usr/bin/prefman.sh');text=script.decode('utf-8')
    bundle=source('opt','/pref/default/pref.bin')
    variables=dict(re.findall(r'^(PREF_DEFAULT\w*)="([^\"]+)"',text,re.M))
    segments=[]
    for variable,sector in re.findall(r'dd if="\$IMG_PATH\$(PREF_DEFAULT_\w+)" of="\$IMG_PATH\$PREF_DEFAULT" obs=512 seek=(\d+)',text):
        path='/pref/default/'+variables[variable].lstrip('/');raw=source('opt',path)
        offset=int(sector)*512;assert bundle[offset:offset+len(raw)]==raw
        magic,crc,size=struct.unpack_from('<3I',raw)
        assert magic==0x330033 and size==len(raw) and crc==zlib.crc32(raw[0x200:])
        segments.append(dict(script_variable=variable,original_path=path,sector=int(sector),
            bundle_file_offset=hex(offset),bytes=len(raw),sha256=digest(raw),
            slice_sha256=digest(bundle[offset:offset+len(raw)]),header_magic=hex(magic),
            header_size=size,header_crc32=hex(crc),zlib_body_crc32_matched=True))
    assert len(segments)==11
    system=next(r for r in files if r['original_path']=='/pref/default/pref_adj_sys.bin')
    raw=Path(system['local_path']).read_bytes()
    result['packaged_system_temperature_words']=[dict(lower_id=hex(low),file_offset=hex(0x200+low),
        raw_hex=raw[0x200+low:0x204+low].hex(),signed_value=struct.unpack_from('<i',raw,0x200+low)[0])
        for low in [0x91,0x95,0x99,0x9d,0xa1,0xa5,0xa9]]
    assert [r['signed_value'] for r in result['packaged_system_temperature_words']]==[4,106,110,102,105,106,110]
    result['packaged_files']=files;result['packaged_segments']=segments
    result['preference_script']=dict(source_sha256=digest(script),original_path='/usr/bin/prefman.sh',text=text,
        limitation='Script input path /opt/pref differs from packaged default directory; no invocation or file-copy success is inferred.')
    src=next(s for s in result['sources'] if s['path']=='/usr/bin/prefman')
    with Path(src['staged_path']).open('rb') as stream:
        elf=ELFFile(stream)
        def read(va,size):
            seg=next(s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=va and va+size<=s['p_vaddr']+s['p_filesz'])
            offset=seg['p_offset']+va-seg['p_vaddr'];stream.seek(offset);return offset,stream.read(size)
        def data(va,size,label):
            offset,raw=read(va,size);result.setdefault('data_blocks',[]).append(dict(source_sha256=src['sha256'],source_path=src['path'],
                original_elf_va=hex(va),file_offset=hex(offset),raw_hex=raw.hex(),label=label));return raw
        entry_target=struct.unpack('<I',data(0x8fd0,4,'libc_start_main argument literal'))[0]
        assert entry_target==0x8ef9
        symbols=elf.get_section_by_name('.dynsym');symbol=next(s for s in symbols.iter_symbols() if s.name=='cmd_list')
        table=data(symbol['st_value'],symbol['st_size'],'18 command name/function-pointer pairs')
        commands=[]
        for index,(name,pointer) in enumerate(struct.iter_unpack('<II',table)):
            _,raw=read(name,64);name_raw=raw.split(b'\0')[0]+b'\0';data(name,len(name_raw),'Command name')
            commands.append(dict(index=index,name=name_raw[:-1].decode('ascii'),pointer=hex(pointer),
                code_va=hex(pointer&~1),thumb_pointer=bool(pointer&1)))
        assert next(r for r in commands if r['name']=='load')['pointer']=='0x9b8d'
        result['utility_commands']=commands
        for start,end,label in [(0x8ef8,0x8f8c,'Manually bounded main, Thumb from entry argument bit0'),
                                (0x9b8c,0x9ca8,'Manually bounded load command, Thumb from cmd_list bit0')]:
            offset,raw=read(start,end-start);instructions=list(Cs(CS_ARCH_ARM,CS_MODE_THUMB).disasm(raw,start))
            assert sum(i.size for i in instructions)==len(raw)
            result['windows'].append(dict(source_sha256=src['sha256'],source_path=src['path'],function=label,
                original_elf_va=hex(start),file_offset=hex(offset),mode='Thumb',raw_hex=raw.hex(),
                instructions=[dict(va=hex(i.address),bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str) for i in instructions],
                limitation='Manual original-code region; not a Ghidra selected-C completion.'))
        data(0x8f8c,0x10,'Main trailing literals, excluded from code')
        data(0x9ca8,0x50,'Load-command trailing literals, excluded from code')
    result['limitations']+=['Package default slices match factory temperature constants but do not establish live NVD selection.',
        'Original prefman main/load were not recovered as Ghidra functions; manual Thumb regions are separate from selected-C counts.',
        'Script --start describes load-all, but its no-ID load command follows the inspected CLI usage branch; boot preload is separate.']
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(packaged_segments=len(segments),temperature_words=[r['signed_value'] for r in result['packaged_system_temperature_words']],manual_code_regions=2)))


if __name__=='__main__':main()
