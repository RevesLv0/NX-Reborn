#!/usr/bin/env python3
"""Index selected OEM interface assignments as navigation hints, not semantics."""
import hashlib
import json
import re
from pathlib import Path

from elftools.elf.elffile import ELFFile


def main():
    source=Path('.work/full/extracted/rootfs/usr/lib/libslp_devman_plugin.so')
    expected='a88cb8130ba246b45c077cf25f0c5944077e41b780eee20f5a5a675b35a15588'
    assert hashlib.sha256(source.read_bytes()).hexdigest()==expected
    evidence=Path('analysis/evidence/card-events-run007.json')
    rows=json.loads(evidence.read_text())['ghidra']
    function=next(r for r in rows if r['source_sha256']==expected and r['name']=='OEM_sys_get_devman_plugin_interface')
    with source.open('rb') as stream:
        elf=ELFFile(stream)
        symbols={s.name:s for s in elf.get_section_by_name('.dynsym').iter_symbols() if s['st_shndx']!='SHN_UNDEF'}
        assignments=[]
        for address,target in re.findall(r'DAT_([0-9a-f]+) = ([^;\n]+);',function['c']):
            slot=int(address,16)-0x10000
            row=dict(original_table_slot_va=hex(slot),offset_from_table_base=hex(slot-0x15830),
                     c_target_expression=target)
            if target in symbols:
                symbol=symbols[target]
                value=symbol['st_value']
                row.update(symbol=target,original_symbol_pointer=hex(value),
                    original_code_va=hex(value & ~1),thumb_pointer_bit=bool(value&1),symbol_bytes=symbol['st_size'])
            else:
                row['unresolved_expression']=True
            assignments.append(row)
    assert next(r for r in assignments if r['offset_from_table_base']=='0x2b8')['symbol']=='OEM_sys_get_mmc_sdcard_online'
    assert next(r for r in assignments if r['offset_from_table_base']=='0x2bc')['symbol']=='OEM_sys_get_mmc_sdcard_protect'
    result=dict(schema_version=1,source_path='/usr/lib/libslp_devman_plugin.so',source_sha256=expected,
        source_evidence=str(evidence),source_evidence_sha256=hashlib.sha256(evidence.read_bytes()).hexdigest(),
        interface_builder_original_va='0x8e98',table_base_original_va='0x15830',assignments=assignments,
        method='Parse assignments from selected C and resolve exact exported names against original .dynsym; original interface-builder bytes retained in source evidence.',
        limitations=['Navigation index only; each handler requires its own semantic/ABI review.',
                     'Table slots are runtime-initialized storage, not initialized file offsets.',
                     'Non-symbol target expressions are retained unresolved; C types and names do not establish active hardware support.',
                     'No target execution or sysfs access.'])
    path=Path('analysis/evidence/oem-interface-index-run007.json')
    path.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(assignments=len(assignments),resolved_named_targets=sum('symbol' in r for r in assignments),unresolved=sum(r.get('unresolved_expression',False) for r in assignments))))


if __name__=='__main__':
    main()
