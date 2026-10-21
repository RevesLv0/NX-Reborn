#!/usr/bin/env python3
"""Reproduce bounded RUN005 app evidence from original ARM ELF and saved exports."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from elftools.elf.elffile import ELFFile


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--source', type=Path, default=Path('.work/full/extracted/rootfs/usr/apps/com.samsung.di-camera-app/bin/di-camera-app'))
    ap.add_argument('--output', type=Path, default=Path('analysis/evidence/app-storage-run005.json'))
    args = ap.parse_args()
    expected = '55dcc78143724435a2e38b9e0d809960bd728668634bbcf7532ce137f882eb04'
    assert digest(args.source) == expected
    result = dict(source_path='/usr/apps/com.samsung.di-camera-app/bin/di-camera-app', source_sha256=expected,
                  method='Original ELF PT_LOAD mapping, ARM Capstone 5.0.6, relocation and jump-table decoding; fresh Ghidra 12.1.4 selected noanalysis exports',
                  address_convention='Original ELF link-time VA equals Ghidra app VA; no runtime addresses',
                  limitations=['Static only; no target execution, camera I/O or firmware installation.',
                               'Inferred Ghidra signatures are not independent ABI proof; instructions corroborate selected arguments.',
                               'Selected windows and functions do not establish runtime ordering, complete counter balance or durable writes.'],
                  ghidra=[], windows=[], relocations=[])
    for generation in ['app-initial', 'app-followup', 'app-counter']:
        folder = Path('.work/run005') / generation / 'outputs/ghidra/di-camera-app-55dcc7814372'
        p = folder / 'decompiled.jsonl'
        rows = [json.loads(l) for l in p.open()]
        result['ghidra'].append(dict(generation=generation, path=str(p), sha256=digest(p), summary_sha256=digest(folder/'summary.json'), functions=rows))
    with args.source.open('rb') as f:
        elf = ELFFile(f)
        def read(va, size):
            seg = next(s for s in elf.iter_segments() if s['p_type']=='PT_LOAD' and s['p_vaddr']<=va and va+size<=s['p_vaddr']+s['p_filesz'])
            off = seg['p_offset']+va-seg['p_vaddr']; f.seek(off)
            return off, f.read(size)
        def window(va, size, purpose):
            off, data = read(va, size)
            instructions=[dict(elf_va=hex(i.address),bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str) for i in Cs(CS_ARCH_ARM, CS_MODE_ARM).disasm(data, va)]
            covered=sum(len(bytes.fromhex(i['bytes'])) for i in instructions)
            result['windows'].append(dict(original_elf_va=hex(va),file_offset=hex(off),bytes=size,purpose=purpose,
                disassembled_bytes=covered,undecoded_bytes=size-covered,
                limitations=['Linear bounded ARM decode; literal pools and jump-table words are not control-flow analysis.'],instructions=instructions))
        for va,size,purpose in [(0x12dc10,32,'Registration caller: exact callback pointer and ids'),
                (0x1dc2d4,32,'Registration wrapper ARM r0-r3 argument forwarding'),(0xac604,12,'Imported mm_photo callback PLT thunk'),
                (0x1dc3fc,16,'Conversion unsigned jump-table bound'),(0x1dc43c,104,'Conversion return blocks'),
                (0x21b978,48,'Callback entry saves supplied args'),(0x21bb60,88,'Status routing and downstream BT call'),
                (0x2103cc,40,'Error accounting decrement and saved converted status'),(0x210500,704,'Bounded error-helper effects'),
                (0x217cac,44,'Normal accounting decrement'),(0x218b44,16,'Second entry dispatcher unsigned bounds'),(0x212448,88,'Counter helper inputs and prior count; ends before jump-table data'),
                (0x2124f4,480,'Counter additions selected routes')]:
            window(va,size,purpose)
        off,data=read(0x1dc40c,48)
        entries=[]
        for n,dest in enumerate(struct.unpack('<12I',data),1):
            block_off, block=read(dest,8)
            entries.append(dict(input=n,table_va=hex(0x1dc40c+(n-1)*4),target_va=hex(dest),target_file_offset=hex(block_off),target_bytes=block.hex(),
                                instructions=[dict(elf_va=hex(i.address),mnemonic=i.mnemonic,operands=i.op_str) for i in Cs(CS_ARCH_ARM, CS_MODE_ARM).disasm(block,dest)]))
        result['conversion_table']=dict(original_elf_va='0x1dc40c',file_offset=hex(off),raw_hex=data.hex(),entries=entries,default=0)
        off,data=read(0x218b54+(0x39-1)*4,4)
        result['second_entry_table']=dict(input='0x39',table_base='0x218b54',entry_va=hex(0x218b54+(0x39-1)*4),file_offset=hex(off),bytes=data.hex(),target=hex(struct.unpack('<I',data)[0]))
        # Preserve the second entry branch and its table destination without assigning a producer.
        _,data=read(0x218920,11616)
        md=Cs(CS_ARCH_ARM,CS_MODE_ARM); md.skipdata=True
        hits=[i.address for i in md.disasm(data,0x218920) if i.mnemonic=='bl' and i.op_str=='#0x217cac']
        result['second_entry_calls']=[hex(x) for x in hits]
        for va in hits: window(va-16,40,'Dispatcher second File_Write_Done entry; case0x39 in selected C')
        for sec in elf.iter_sections():
            if sec['sh_type'] not in ('SHT_REL','SHT_RELA'): continue
            table=elf.get_section(sec['sh_link'])
            for rel in sec.iter_relocations():
                sym=table.get_symbol(rel['r_info_sym'])
                if 'mm_photo_capture_callback' in sym.name:
                    result['relocations'].append(dict(section=sec.name,original_elf_va=hex(rel['r_offset']),type=rel['r_info_type'],symbol=sym.name,symbol_value=hex(sym['st_value'])))
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(output=str(args.output),sha256=digest(args.output),selected_functions=sum(len(x['functions']) for x in result['ghidra']),windows=len(result['windows']))))


if __name__ == '__main__':
    main()
