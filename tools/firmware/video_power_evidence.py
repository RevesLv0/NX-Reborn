#!/usr/bin/env python3
"""Read bounded NX500 video/power ELF and configuration evidence; never execute it."""
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

import capstone
from elftools.elf.elffile import ELFFile

FUNCTIONS = {
    'libmmfcore.so': ['_ZN12cMmfRecorder16SetVideoPipelineEv', '_ZN16cMmfVideoEncoder7OnStartEv'],
    'libmmfmodules.so': ['_ZN13iVideoEncoder6CreateE15eMmfVideoFormat',
                         '_ZN20cHalHevcVideoEncoder10InitializeE8eMmfMode',
                         '_ZN20cHalHevcVideoEncoder9ConfigureEP17tVideoCodecConfigP15tVideoExtraData'],
    'libsysman.so.0.2.0': ['sysman_request_poweroff', 'sysman_call_predef_action'],
    'libmicom-node.so.0.1': ['get_micom_status', 'get_body_bat_soc'],
    'libhibernation.so': ['hib_post', 'hib_has_hibdata'],
    'libfirmware-upgrade.so': ['fw_validate', 'fw_upgrade_crc32', 'fw_start_upgrade'],
}
STRINGS = re.compile(rb'/dev/(?:d5_[a-z_]+|micom)|/usr/share/hevc/[^\x00\n]+|'
                     rb'(?i:thermal|temperature|overheat)|memory/sysman/battery_[a-z_]+|'
                     rb'/tmp/sn|pwroff-popup')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def elf_record(path, original):
    raw = path.read_bytes()
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        assert elf['e_machine'] == 'EM_ARM' and elf.little_endian
        loads = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
        symbols = {s.name: s for sec in elf.iter_sections()
                   if sec['sh_type'] in ('SHT_DYNSYM', 'SHT_SYMTAB')
                   for s in sec.iter_symbols() if s['st_shndx'] != 'SHN_UNDEF'}
        functions = []
        for name in FUNCTIONS.get(path.name, []):
            symbol = symbols[name]
            value = symbol['st_value']
            va = value & ~1
            segment = next(s for s in loads if s['p_vaddr'] <= va < s['p_vaddr'] + s['p_filesz'])
            offset = va - segment['p_vaddr'] + segment['p_offset']
            code = raw[offset:offset + symbol['st_size']]
            decoder = capstone.Cs(capstone.CS_ARCH_ARM,
                                   capstone.CS_MODE_THUMB if value & 1 else capstone.CS_MODE_ARM)
            instructions = [dict(elf_va=hex(i.address), file_offset=hex(offset + i.address-va),
                                 bytes=i.bytes.hex(), instruction=i.mnemonic + ' ' + i.op_str)
                            for i in decoder.disasm(code, va)]
            functions.append(dict(symbol=name, symbol_value=hex(value), elf_va=hex(va),
                                  file_offset=hex(offset), thumb=bool(value & 1),
                                  symbol_bytes=len(code), code_sha256=sha(code), instructions=instructions,
                                  limitations='Symbol-bounded linear disassembly may include literal pools; no control-flow or ABI proof.'))
        strings = []
        for match in re.finditer(rb'[ -~]{4,}', raw):
            if not STRINGS.search(match.group()):
                continue
            offset = match.start()
            segment = next((s for s in loads if s['p_offset'] <= offset < s['p_offset']+s['p_filesz']), None)
            strings.append(dict(file_offset=hex(offset),
                                elf_va=hex(offset-segment['p_offset']+segment['p_vaddr']) if segment else None,
                                value=match.group().decode('ascii')))
        literals = []
        literal_pairs = {
            'libsysman.so.0.2.0': [(0x1db4, 0x1daa), (0x1884, 0x165c)],
            'libmmfmodules.so': [(0x2d778, 0x2d220)],
            'libmicom-node.so.0.1': [(0x128c, 0x1246), (0x15b8, 0x157c)],
        }
        if path.name in literal_pairs:
            for literal_va, pc_operand in literal_pairs[path.name]:
                segment = next(s for s in loads if s['p_vaddr'] <= literal_va < s['p_vaddr'] + s['p_filesz'])
                offset = literal_va - segment['p_vaddr'] + segment['p_offset']
                value = struct.unpack_from('<I', raw, offset)[0]
                string_va = (value + pc_operand) & 0xffffffff
                segment = next(s for s in loads if s['p_vaddr'] <= string_va < s['p_vaddr'] + s['p_filesz'])
                string_offset = string_va - segment['p_vaddr'] + segment['p_offset']
                literals.append(dict(literal_elf_va=hex(literal_va), literal_file_offset=hex(offset),
                                     little_endian_u32=hex(value), added_pc_operand=hex(pc_operand),
                                     string_elf_va=hex(string_va), string_file_offset=hex(string_offset),
                                     value=raw[string_offset:raw.index(b'\0', string_offset)].decode('ascii')))
        return dict(original_path=original, sha256=sha(raw), bytes=len(raw),
                    functions=functions, selected_raw_strings=strings, selected_pc_relative_literals=literals)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--rootfs', type=Path, required=True)
    parser.add_argument('--opt', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    inputs = json.loads((args.work/'input-manifest.json').read_text())
    binaries = [elf_record(Path(r['local_input']), r['original_path']) for r in inputs]
    configs = []
    for partition, root, prefix in [('rootfs', args.rootfs, 'usr/etc'), ('opt', args.opt, 'etc')]:
        for name in ['mmfw_camcorder.ini', 'mmfw_camcorder_dev_video_pri.ini',
                     'mmfw_camcorder_dev_video_sec.ini', 'mmfw_player.ini']:
            path = root/prefix/name
            assert path.is_file() and not path.is_symlink()
            raw = path.read_bytes()
            configs.append(dict(partition=partition, original_path='/' + prefix + '/' + name,
                                runtime_path=('/opt' if partition == 'opt' else '') + '/' + prefix + '/' + name,
                                sha256=sha(raw), bytes=len(raw),
                                lines=[dict(line=i, text=line) for i, line in
                                       enumerate(raw.decode('utf-8').splitlines(), 1)]))
    selected_ghidra = []
    selected_names = {'cMmfRecorder::SetVideoPipeline', 'cMmfVideoEncoder::OnStart',
                      'iVideoEncoder::Create', 'cHalHevcVideoEncoder::Configure',
                      'sysman_request_poweroff', 'sysman_call_predef_action',
                      'get_micom_status', 'get_body_bat_soc', 'fw_validate',
                      'fw_start_upgrade', 'fw_upgrade_crc32'}
    for base in [args.work/'outputs/ghidra', args.work/'hevc-followup/outputs/ghidra']:
        for summary_path in sorted(base.glob('*/summary.json')):
            summary = json.loads(summary_path.read_text())
            artifact = summary_path.parent/'decompiled.jsonl'
            assert sha(artifact.read_bytes()) == summary['artifacts']['decompiled.jsonl']['sha256']
            for line in artifact.read_text().splitlines():
                row = json.loads(line)
                if row['name'] in selected_names:
                    row.pop('instructions', None)  # independent original-VA disassembly is above
                    selected_ghidra.append(dict(source_sha256=summary['sha256'],
                                                export_run_id=summary['run_id'],
                                                export_path=str(artifact), function=row))
    result = dict(schema_version=1, static_only=True,
                  method='pyelftools ELF symbols/PT_LOAD translation; Capstone original-VA disassembly; literal config lines',
                  capstone_version=capstone.__version__, binaries=binaries, configurations=configs,
                  selected_ghidra_decompilation=selected_ghidra,
                  limitations=['No target execution, camera I/O or flashing.',
                               'Raw strings do not prove active code paths or configuration consumption.',
                               'Original ELF VAs are distinct from Ghidra rebased program VAs and file offsets.'])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
