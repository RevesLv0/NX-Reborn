#!/usr/bin/env python3
"""Reproduce RUN006 app consumer/bridge evidence from verified original ELFs."""
import hashlib
import json
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools/ghidra'))
from validate_exports import validate_export


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    inputs = []
    for manifest in ['.work/run006/app/input-manifest.json', '.work/run006/app-bridge/input-manifest.json']:
        rows = json.loads(Path(manifest).read_text())
        assert len(rows) == (11 if '/app/' in manifest else 8)
        for row in rows:
            original = Path('.work/full/extracted') / row['partition'] / row['path'].lstrip('/')
            assert sha(original) == row['sha256'] == sha(row['staged_path'])
        inputs.extend(rows)
    sources = {Path(x['path']).name: x for x in inputs}
    result = dict(schema_version=1, static_only=True,
                  address_convention='Original ELF link-time VA and PT_LOAD file offset are separate. Ghidra app VA equals original ELF VA; DSO Ghidra VA adds 0x10000.',
                  source_checks=inputs, ghidra=[], windows=[], tables=[], relocations=[])
    generations = []
    failures = []
    omissions = []
    for work in sorted(Path('.work/run006').glob('app-*')):
        if not (work / 'outputs/ghidra').exists():
            continue
        receipts = sorted((work / 'logs').glob('NX500*.json'))
        assert len(receipts) == 1, (work, receipts)
        receipt = json.loads(receipts[0].read_text())
        assert receipt.get('completed') is True and receipt.get('returncode') == 0, receipts[0]
        project = receipt['command'][2]
        assert project in ('NX500_RUN003_CAPTURE', 'NX500_FW112_SURVEY'), project
        paired = '.work/run006/app-bridge/input-manifest.json' if project == 'NX500_RUN003_CAPTURE' else '.work/run006/app/input-manifest.json'
        paired_rows = json.loads(Path(paired).read_text())
        paired_path = work / 'input-manifest.json'
        if paired_path.exists():
            assert json.loads(paired_path.read_text()) == paired_rows, paired_path
        else:
            paired_path.write_text(json.dumps(paired_rows, indent=2) + '\n')
        summaries = []
        for folder in sorted((work / 'outputs/ghidra').iterdir()):
            if not folder.is_dir():
                continue
            summary = json.loads((folder / 'summary.json').read_text())
            assert summary['sha256'] in {r['sha256'] for r in paired_rows}, folder
            validate_export(folder, summary['sha256'], receipt['run_id'])
            summaries.append(summary)
            rows = [json.loads(line) for line in (folder / 'decompiled.jsonl').read_text().splitlines()]
            if rows:
                result['ghidra'].append(dict(generation=work.name, program=summary['program'],
                    source_sha256=summary['sha256'], path=str(folder / 'decompiled.jsonl'),
                    sha256=sha(folder / 'decompiled.jsonl'), summary_path=str(folder / 'summary.json'),
                    summary_sha256=sha(folder / 'summary.json'), functions=rows))
            failures.extend(dict(generation=work.name, program=summary['program'], function=x['name'], error=x.get('error')) for x in rows if not x['completed'])
            if summary['decompile_omitted_by_budget']:
                omissions.append(dict(generation=work.name, program=summary['program'], count=summary['decompile_omitted_by_budget']))
        assert {s['sha256'] for s in summaries} == {r['sha256'] for r in paired_rows}
        generations.append(dict(name=work.name, project=project, paired_input_manifest=str(work / 'input-manifest.json'),
            paired_input_manifest_sha256=sha(work / 'input-manifest.json'), receipt_path=str(receipts[0]),
            receipt_sha256=sha(receipts[0]), receipt=receipt, summaries=summaries,
            console_path=str(work) + '-console.log', console_sha256=sha(str(work) + '-console.log')))
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    windows = {
        'di-camera-app': [(0x21bb60,88,'Raw photo status passed to Wi-Fi before accounting; both outcomes call BT with path only'),
            (0x184c3c,68,'Wi-Fi gates and discarded status conversion result'),(0x184d40,172,'Wi-Fi null and JPG substring tests'),
            (0x184e8c,80,'Wi-Fi event24 r0/r1 path call'),(0x15cf60,84,'BT queue record allocation'),
            (0x1dc294,12,'Filename callback passthrough'),(0x1dc2b4,20,'Concrete free-space callback r0 pointer'),
            (0x1dc244,56,'Free-space callback quotient return ABI; no spurious fifth argument'),
            (0x12dbc4,20,'Concrete camera callback pointer passed at initialization'),(0x1e48ec,36,'Camera registration handle, callback r1, userdata0'),
            (0x21b868,32,'Idle trampoline unpacks UI id and data'),(0x21b000,16,'Skip-write dispatch target calls file accounting'),
            (0x1e45a8,16,'Raw-to-UI callback conversion unsigned table bound'),(0x209300,24,'Callback name unsigned table bound')],
        'libmulticore-bridge.so': [(0x5158,60,'Driver receive passes destination buffer into ipcc_read_pkt'),
            (0x5c68,100,'Aligned buffer origin and stored length'),(0x5ea4,8,'Category is buffer halfword+2'),
            (0x5eac,76,'Frame handoff pointer and callback length'),(0x6128,208,'Broadcast indirect callback preserves category/pointer/length; stops before literal pool'),
            (0x6940,72,'Receiver normal path reads and handles the same frame; cleanup landing pad excluded'),(0x6994,64,'Packet size minus8 passed to frame constructor'),
            (0x5e50,60,'Integer frame constructor requests payload size plus12')],
        'libudd5.so': [(0x46168,76,'ipcc_read_pkt packs ioctl0xc0107406 with destination in struct+12')],
        'libcapture-fw-prod.so': [(0x8390c,68,'Receive event pointer into adapter'),(0x8e23c,188,'Holder indirect handler call keeps packet pointer'),
            (0x8dfa4,220,'Holder creates handler objects and stores notify handler at slot2'),
            (0x8e2f8,224,'Category82 selects holder slot2'),
            (0x85688,348,'Concrete category82 subscription to OnReceiveEvent'),(0x8a628,160,'Notify handler stores unmodified packet pointer and supplied length')],
        'libdi-network-bt-app.so': [(0x6644,20,'bt_send_msgs returns1 after synchronous dispatch only'),(0x87a8,32,'Installed app callback global store')],
        'libdi-network-dlna-rvf.so': [(0x3255c,80,'RVF advertises URL information then returns1 without checking state-update return; stops before literal pool')],
    }
    for name, specs in windows.items():
        source = sources[name]
        with Path(source['staged_path']).open('rb') as stream:
            elf = ELFFile(stream)
            def read(va, size):
                segment = next(s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD' and s['p_vaddr'] <= va and va + size <= s['p_vaddr'] + s['p_filesz'])
                offset = segment['p_offset'] + va - segment['p_vaddr']
                stream.seek(offset)
                return offset, stream.read(size)
            for va, size, purpose in specs:
                offset, data = read(va, size)
                instructions = [dict(original_elf_va=hex(i.address), bytes=i.bytes.hex(), mnemonic=i.mnemonic, operands=i.op_str) for i in md.disasm(data,va)]
                result['windows'].append(dict(source_path=source['path'], source_sha256=source['sha256'],
                    original_elf_va=hex(va), file_offset=hex(offset), bytes=size, raw_hex=data.hex(), purpose=purpose,
                    decoded_bytes=sum(len(bytes.fromhex(x['bytes'])) for x in instructions), instructions=instructions,
                    limitations=['Bounded ARM decode; the explicitly separated tables below are data, not instructions.']))
            # Preserve recovered code ranges for the newly selected constructor
            # and URL builder; split at gaps rather than decoding literal pools.
            wanted = {'CNotifyHandler::CNotifyHandler', 'UPnPCDSRVFShotwithGPS::getURLInfo'}
            addresses = set()
            for generation in result['ghidra']:
                if generation['source_sha256'] == source['sha256']:
                    for function in generation['functions']:
                        if function['name'] in wanted:
                            addresses.update(int(i.split()[0], 16) - 0x10000 for i in function['instructions'])
            runs = []
            for va in sorted(addresses):
                if runs and runs[-1][-1] + 4 == va:
                    runs[-1].append(va)
                else:
                    runs.append([va])
            for run in runs:
                va, size = run[0], len(run) * 4
                offset, data = read(va, size)
                decoded = list(md.disasm(data, va))
                assert sum(i.size for i in decoded) == size
                result['windows'].append(dict(source_path=source['path'], source_sha256=source['sha256'],
                    original_elf_va=hex(va), file_offset=hex(offset), bytes=size, raw_hex=data.hex(),
                    purpose='New constructor or URL builder; only contiguous recovered instruction addresses',
                    decoded_bytes=size, instructions=[dict(original_elf_va=hex(i.address),bytes=i.bytes.hex(),mnemonic=i.mnemonic,operands=i.op_str) for i in decoded],
                    limitations=['Recovered code only; inferred signatures and string wrapper ABI remain unverified.']))
            if name == 'libcapture-fw-prod.so':
                for va, size, purpose in [(0x8a584,8,'Notify constructor GOT literals'),
                                          (0xb02b8,20,'Notify vtable data; symbol bindings require recorded R_ARM_ABS32 relocations')]:
                    offset, data = read(va,size)
                    result.setdefault('elf_data',[]).append(dict(source_path=source['path'],source_sha256=source['sha256'],
                        original_elf_va=hex(va),file_offset=hex(offset),raw_hex=data.hex(),purpose=purpose))
            if name == 'di-camera-app':
                for base, count, selected, purpose in [(0x1e45b8,69,0x3a,'Raw mm-camera id3a maps to UI39'),
                        (0x209318,67,0x39,'UI39 callback-name jump table'),(0x218b54,67,0x39,'UI39 dispatcher destination')]:
                    offset, data=read(base,count*4)
                    target=struct.unpack_from('<I',data,(selected-1)*4)[0]
                    target_offset, block=read(target,24)
                    result['tables'].append(dict(source_path=source['path'], source_sha256=source['sha256'],
                        original_elf_va=hex(base),file_offset=hex(offset),entry_count=count,raw_hex=data.hex(),
                        selected_input=hex(selected),selected_entry_va=hex(base+(selected-1)*4),selected_target_va=hex(target),
                        selected_target_file_offset=hex(target_offset), selected_target_raw_hex=block.hex(),purpose=purpose,
                        target_instructions=[dict(original_elf_va=hex(i.address),mnemonic=i.mnemonic,operands=i.op_str) for i in md.disasm(block,target)]))
                for va in [0x3858fc]:
                    offset,data=read(va,32)
                    result.setdefault('literals',[]).append(dict(source_path=source['path'], source_sha256=source['sha256'],original_elf_va=hex(va),file_offset=hex(offset),raw_hex=data.hex(),nul_terminated_value=data.split(b'\0')[0].decode()))
            for sec in elf.iter_sections():
                if sec['sh_type'] not in ('SHT_REL','SHT_RELA'):
                    continue
                symtab=elf.get_section(sec['sh_link'])
                for rel in sec.iter_relocations():
                    sym=symtab.get_symbol(rel['r_info_sym'])
                    if any(term in sym.name for term in ['mm_camera_set_notification','mm_photo_register_get_file_name','mm_photo_register_is_storage_space_available','DlnaRVFEvent','bt_send_msgs','mcb_register_handler','ipcc_read_pkt','_ZTV14CNotifyHandler','_ZN14CNotifyHandler3Run']):
                        result['relocations'].append(dict(source_path=source['path'], source_sha256=source['sha256'],section=sec.name,
                            original_elf_va=hex(rel['r_offset']), type=rel['r_info_type'], symbol=sym.name, symbol_value=hex(sym['st_value'])))
    out=Path('analysis/evidence/app-error-consumers-run006.json')
    out.write_text(json.dumps(result,indent=2)+'\n')
    manifest=dict(schema_version=1,scope='RUN006 app storage outcome consumers, skip-write accounting, and Linux receive pointer boundary; offline static only',
        inputs=inputs,new_imports=0,new_inventory_coverage=0,distinct_reprocessed_programs=len(set(x['sha256'] for x in inputs)),
        function_discovery_counts_additive=False,generations=generations,
        selected_attempts=sum(s['decompile_attempted'] for g in generations for s in g['summaries']),
        selected_completed=sum(s['decompile_completed'] for g in generations for s in g['summaries']),
        distinct_selected_functions=len(set((g['source_sha256'],x['elf_va']) for g in result['ghidra'] for x in g['functions'] if x['completed'])),
        failures=failures,omissions=omissions,
        auxiliary_query_failures=[
            'Exploratory pyelftools symbol scan included a non-symbol iter_symbols section and raised KeyError st_value; corrected by requiring SHT_DYNSYM/SHT_SYMTAB.',
            'Exploratory DT_NEEDED list comprehension shadowed the tag variable and raised AttributeError str.needed; corrected with tag/term variable names.',
            'Exploratory Ghidra instruction filter treated instruction strings as dictionaries and raised AttributeError str.get; corrected after inspecting schema.'
        ],reviewed_findings=[],limitations=['Static only. No runtime ordering, active boot selection, transfer completion, exclusive callback ownership or durability observation.',
            'Ghidra C types/signatures inferred; selected ARM instruction windows corroborate scalar arguments and pointer forwarding.',
            'Direct exported call edges do not enumerate indirect callbacks or prove absence of additional writers.'],
        project_lock_files=[str(p) for p in Path('ghidra-projects').glob('*.lock*') if any(t in p.name for t in ['NX500_FW112_SURVEY','NX500_RUN003_CAPTURE'])],
        artifacts=[dict(path=str(out),sha256=sha(out)),dict(path='tools/firmware/app_error_consumers_evidence.py',sha256=sha(__file__))])
    manifest['project_unlocked']=not manifest['project_lock_files']
    m=Path('manifests/ghidra-app-errors-run006.json')
    # Findings are maintained separately during the ongoing dependent review.
    if m.exists():
        manifest['reviewed_findings']=json.loads(m.read_text()).get('reviewed_findings',[])
        for finding in manifest['reviewed_findings']:
            finding['evidence_sha256']=sha(finding['evidence'])
    m.write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({k:manifest[k] for k in ['selected_attempts','selected_completed','distinct_selected_functions','failures','omissions','project_unlocked']}))


if __name__ == '__main__':
    main()
