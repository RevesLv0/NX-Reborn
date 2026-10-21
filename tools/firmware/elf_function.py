#!/usr/bin/env python3
"""Independently disassemble a named ARM ELF function using symbol link-time VAs."""
import argparse
import hashlib
import json
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--elf',type=Path,required=True)
    p.add_argument('--symbol',required=True,help='Exact ELF mangled symbol')
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    with a.elf.open('rb') as stream:
        elf=ELFFile(stream)
        if elf['e_machine']!='EM_ARM' or not elf.little_endian:
            raise ValueError('This tool supports little-endian ARM ELF only')
        matches=[]
        for name in ('.dynsym','.symtab'):
            table=elf.get_section_by_name(name)
            if table:
                matches.extend(s for s in table.iter_symbols() if s.name==a.symbol and s['st_shndx']!='SHN_UNDEF' and s['st_info']['type']=='STT_FUNC')
        if not matches: raise ValueError('Defined symbol not found')
        if len({(s['st_value'],s['st_size'],s['st_shndx']) for s in matches})!=1:
            raise ValueError('Ambiguous function definition')
        symbol=matches[0]
        value=symbol['st_value']; address=value&~1
        size=symbol['st_size']
        if not size: raise ValueError('Zero-sized function; explicit bounds required')
        for seg in elf.iter_segments():
            if seg['p_type']=='PT_LOAD' and seg['p_flags']&1 and seg['p_vaddr']<=address and address+size<=seg['p_vaddr']+seg['p_filesz']:
                offset=seg['p_offset']+address-seg['p_vaddr']; break
        else: raise ValueError('Function is not entirely file-backed')
        stream.seek(offset); data=stream.read(size)
        mode=CS_MODE_THUMB if value&1 else CS_MODE_ARM
        md=Cs(CS_ARCH_ARM,mode|CS_MODE_LITTLE_ENDIAN)
        instructions=[dict(elf_va=hex(i.address),bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str) for i in md.disasm(data,address)]
        if sum(len(bytes.fromhex(i['bytes'])) for i in instructions)!=size:
            raise ValueError('Disassembly did not cover the complete symbol')
        relocations=[]
        for sec in elf.iter_sections():
            if sec['sh_type'] not in ('SHT_REL','SHT_RELA'): continue
            table=elf.get_section(sec['sh_link'])
            for rel in sec.iter_relocations():
                sym=table.get_symbol(rel['r_info_sym'])
                if sym.name=='fclose': relocations.append(dict(section=sec.name,got_elf_va=hex(rel['r_offset']),symbol=sym.name,type=rel['r_info_type']))
    result=dict(path=str(a.elf),sha256=hashlib.sha256(a.elf.read_bytes()).hexdigest(),
        symbol=a.symbol,elf_va=hex(address),file_offset=hex(offset),size=size,
        mode='THUMB' if value&1 else 'ARM',instructions=instructions,fclose_relocations=relocations,
        limitation='Linear symbol disassembly; does not independently resolve indirect calls or prove runtime behavior')
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))

if __name__=='__main__': main()
