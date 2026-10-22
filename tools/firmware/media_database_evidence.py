#!/usr/bin/env python3
"""Reproduce bounded offline RUN011 media/DCF evidence from original firmware."""
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/ghidra'))
from validate_exports import validate_export


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rows(path):
    return [json.loads(line) for line in path.open()]


def main():
    work = ROOT / '.work/run011/media'
    inventory_path = ROOT / '.work/full/inventory/full_filesystem_inventory.json'
    inventory = json.loads(inventory_path.read_text())
    indexed = {(x['partition'], x['original_path']): x for x in inventory}
    inputs = []
    for filename in ['input-manifest.json', 'app-input-manifest.json']:
        inputs.extend(json.loads((work / filename).read_text()))
    result = dict(schema_version=1, static_only=True,
        method='Inventory/source SHA checks, validated Ghidra exports, original ELF PT_LOAD byte mapping, recovered instruction addresses, ELF relocations and bounded raw strings',
        address_convention='All normalized instruction addresses and file offsets refer to original ELF. Selected C retains Ghidra addresses; DSO exports add 0x10000 and app uses original VAs. Thumb symbol bit is retained in symbol_value and cleared for code addresses.',
        inventory=dict(path=str(inventory_path.relative_to(ROOT)), sha256=digest(inventory_path),
                       paths=len(inventory), elf_paths=sum('elf' in x for x in inventory),
                       unique_elf_contents=len({x['sha256'] for x in inventory if 'elf' in x})),
        sources=[], generations=[], selected_functions=[], configurations=[],
        limitations=['Static only: no target execution, camera access, filesystem writes to extracted sources, DB SQL execution or firmware modification.',
                      'Source C signatures are inferred; original instruction/register and relocation evidence governs bounded ABI claims.',
                      'Direct call exports omit unresolved indirect/virtual calls. Vtable rows prove intended ELF binding, not runtime object identity or interposition.',
                      'A reserved DCF item, DB row, queued callback or service notification does not prove complete capture, successful close, persistence or remote delivery.',
                      'Only selected bodies were semantically inspected. No complete cancellation rollback, service startup, IPC protocol or media DB runtime snapshot is established.'])
    source_map = {}
    opened = []
    for x in inputs:
        original = ROOT / '.work/full/extracted' / x['partition'] / x['original_path'].lstrip('/')
        current = indexed[x['partition'], x['original_path']]
        sha = digest(original)
        assert sha == x['sha256'] == x['source_sha256'] == current['source_sha256']
        stream = original.open('rb'); opened.append(stream)
        elf = ELFFile(stream)
        segments = [dict(va=int(s['p_vaddr']), offset=int(s['p_offset']), filesz=int(s['p_filesz']), flags=int(s['p_flags'])) for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
        source = dict(partition=x['partition'], original_path=x['original_path'], sha256=sha,
                      source_inode=x['source_inode'], source_byte_verification=x['source_byte_verification'],
                      elf_type=elf['e_type'], needed=x['elf']['needed'], pt_load=segments,
                      symbols=[], relocations=[], strings=[])
        def read(va, size):
            segment = next(s for s in segments if s['va'] <= va and va + size <= s['va'] + s['filesz'])
            offset = segment['offset'] + va - segment['va']
            stream.seek(offset)
            return offset, stream.read(size)
        syms = list(elf.get_section_by_name('.dynsym').iter_symbols())
        for s in syms:
            if re.search(r'(CSFileList|CSDCFList|CBIFileList|media_svc|media_content|media_info|media_db|mm_photo_register)', s.name):
                source['symbols'].append(dict(name=s.name, symbol_value=hex(s['st_value']), original_elf_va=hex(s['st_value'] & ~1), size=s['st_size'], section=str(s['st_shndx'])))
        for section in elf.iter_sections():
            if section['sh_type'] not in ('SHT_REL', 'SHT_RELA'):
                continue
            table = elf.get_section(section['sh_link'])
            for relocation in section.iter_relocations():
                symbol = table.get_symbol(relocation['r_info_sym'])
                va = relocation['r_offset']
                vtable = original.name == 'libfilelist-manager.so' and 0x1d670 <= va < 0x1d73c
                if not vtable and not re.search(r'(CBIFileList|_ZTV10CSFileList|mm_photo_register|media_svc|media_db|media_directory)', symbol.name):
                    continue
                off, data = read(va, 4)
                row = dict(section=section.name, original_elf_va=hex(va), file_offset=hex(off), raw_word_hex=data.hex(), relocation_type=relocation['r_info_type'], symbol=symbol.name, symbol_value=hex(symbol['st_value']))
                if vtable:
                    row['CSFileList_address_point'] = '0x1d678'
                    row['vtable_slot_offset'] = hex(va - 0x1d678)
                source['relocations'].append(row)
        raw = original.read_bytes()
        for m in re.finditer(rb'[\x20-\x7e\t]{6,}', raw):
            value = m.group().decode('ascii')
            if not re.search(r'(CREATE TABLE|INSERT INTO|DELETE FROM|UPDATE .*SET|SELECT path FROM media|/.*(?:\.db|DCIM)|media-server|media-scanner)', value):
                continue
            offset = m.start()
            segment = next((s for s in segments if s['offset'] <= offset < s['offset'] + s['filesz']), None)
            if segment:
                source['strings'].append(dict(original_elf_va=hex(segment['va'] + offset-segment['offset']), file_offset=hex(offset), value=value))
        result['sources'].append(source)
        source_map[sha] = (source, original, elf, segments)
    manifest = dict(project='NX500_RUN011_MEDIA', resource_limits=dict(max_cpu=1, max_memory='1024M', max_concurrent_headless=1), source_contents=len(source_map), generations=[], input_manifests=[])
    for name in ['input-manifest.json', 'app-input-manifest.json']:
        path=work/name
        manifest['input_manifests'].append(dict(path=str(path.relative_to(ROOT)), sha256=digest(path), records=json.loads(path.read_text())))
    for generation in sorted(work.glob('g[1-9]')):
        generation_inputs = generation/'input-manifest.json'
        assert generation_inputs.exists()
        manifest['input_manifests'].append(dict(path=str(generation_inputs.relative_to(ROOT)),sha256=digest(generation_inputs),records=json.loads(generation_inputs.read_text())))
        receipts = sorted((generation/'logs').glob('NX500_RUN011_MEDIA-*.json'))
        for path in receipts:
            receipt=json.loads(path.read_text())
            manifest['generations'].append(dict(generation=generation.name, receipt_path=str(path.relative_to(ROOT)), receipt_sha256=digest(path), receipt=receipt))
        for folder in sorted((generation/'outputs/ghidra').glob('*')):
            if not (folder/'summary.json').exists():
                continue
            summary=json.loads((folder/'summary.json').read_text())
            source, original, elf, segments=source_map[summary['sha256']]
            validate_export(folder, summary['sha256'], summary['run_id'])
            entry=dict(generation=generation.name, path=str(folder.relative_to(ROOT)), summary_sha256=digest(folder/'summary.json'), summary=summary)
            result['generations'].append(entry)
            selected=rows(folder/'decompiled.jsonl')
            selected_addresses={x['elf_va'] for x in selected}
            entry['selected_direct_calls']=[x for x in rows(folder/'calls.jsonl') if x['caller_elf_va'] in selected_addresses]
            shift=int(summary['image_base'],16)-int(summary['elf_original_image_base'],16)
            symbols=list(elf.get_section_by_name('.dynsym').iter_symbols())
            for function in selected:
                va=int(function['elf_va'],16)
                matches=[s for s in symbols if (s['st_value']&~1)==va and s['st_info']['type']=='STT_FUNC' and s['st_shndx']!='SHN_UNDEF']
                thumb=bool(matches[0]['st_value']&1) if matches else False
                md=Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)
                normalized=[]
                for instruction in function.get('instructions',[]):
                    address=int(instruction.split()[0],16)-shift
                    segment=next(s for s in segments if s['va']<=address< s['va']+s['filesz'])
                    off=segment['offset']+address-segment['va']
                    with original.open('rb') as handle:
                        handle.seek(off); data=handle.read(min(4,segment['offset']+segment['filesz']-off))
                    decoded=list(md.disasm(data,address,count=1))
                    if not decoded:
                        normalized.append(dict(original_elf_va=hex(address), file_offset=hex(off), decode_failure=True, raw_hex=data.hex()))
                    else:
                        i=decoded[0]
                        normalized.append(dict(original_elf_va=hex(address), file_offset=hex(off), bytes=i.bytes.hex(), mnemonic=i.mnemonic, operands=i.op_str))
                result['selected_functions'].append(dict(source_sha256=source['sha256'],source_path=source['original_path'], generation=generation.name,
                    original_elf_va=function['elf_va'], instruction_mode='Thumb' if thumb else 'ARM', name=function['name'], completed=function['completed'],error=function.get('error'),
                    c=function.get('c'), c_address_convention='Ghidra VA', original_instructions=normalized))
    for name in ['/usr/etc/media-server-plugin','/usr/lib/systemd/system/media-server.service','/usr/lib/systemd/system/media-scanner.service']:
        x=indexed['rootfs',name];path=ROOT/'.work/full/extracted/rootfs'/name.lstrip('/')
        assert digest(path)==x['source_sha256']
        result['configurations'].append(dict(original_path=name, sha256=digest(path),file_offset=0,text=path.read_text()))
    result['counts']=dict(source_contents=len(source_map), validated_exports=len(result['generations']),
        selected_attempts=len(result['selected_functions']), selected_completed=sum(x['completed'] for x in result['selected_functions']),
        selected_unique_bodies=len({(x['source_sha256'],x['original_elf_va']) for x in result['selected_functions']}),
        original_instruction_records=sum(len(x['original_instructions']) for x in result['selected_functions']),
        instruction_decode_failures=sum(i.get('decode_failure',False) for x in result['selected_functions'] for i in x['original_instructions']))
    result['inventory_media_db_path_matches']=[dict(partition=x['partition'],original_path=x['original_path'],type=x['type'],sha256=x.get('sha256')) for x in inventory if '.media.db' in x['original_path']]
    out=ROOT/'analysis/evidence/media-database-run011.json'
    out.write_text(json.dumps(result,indent=2)+'\n')
    manifest['counts']=result['counts'];manifest['evidence']=dict(path=str(out.relative_to(ROOT)),sha256=digest(out))
    (ROOT/'manifests/ghidra-media-run011.json').write_text(json.dumps(manifest,indent=2)+'\n')
    for stream in opened:
        stream.close()
    print(json.dumps(result['counts']))


if __name__=='__main__':
    main()
