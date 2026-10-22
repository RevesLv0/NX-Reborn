#!/usr/bin/env python3
"""Collect bounded offline capture completion evidence; never execute target ELFs."""
import argparse
import hashlib
import json
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from elftools.elf.elffile import ELFFile


def collect(path, names):
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        syms = list(elf.get_section_by_name('.dynsym').iter_symbols())
        result = dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest(), functions=[], relocations=[], bounded_windows=[])
        for sym in syms:
            if sym.name not in names or sym['st_shndx'] == 'SHN_UNDEF':
                continue
            va = sym['st_value'] & ~1
            seg = next(s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD' and s['p_vaddr'] <= va and va + sym['st_size'] <= s['p_vaddr'] + s['p_filesz'])
            off = seg['p_offset'] + va - seg['p_vaddr']
            stream.seek(off)
            md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if sym['st_value'] & 1 else CS_MODE_ARM)
            ins = [dict(elf_va=hex(i.address), bytes=i.bytes.hex(), mnemonic=i.mnemonic, operands=i.op_str) for i in md.disasm(stream.read(sym['st_size']), va)]
            covered = sum(len(bytes.fromhex(i['bytes'])) for i in ins)
            omitted = max(0, len(ins) - 160)
            if omitted:
                ins = ins[:80] + ins[-80:]
            result['functions'].append(dict(symbol=sym.name, elf_va=hex(va), file_offset=hex(off), symbol_bytes=sym['st_size'], disassembled_bytes=covered, instructions_omitted_for_bounded_evidence=omitted, instructions=ins,
                limitations='Linear symbol disassembly may include literal pools; indirect ABI and runtime ordering are not verified.'))
        windows = {'di-camera-app': [(0x214af0, 328)], 'libmm-photo.so': [(0x93b60, 48)],
                   'libsif.so': [(0x2d2f8, 72), (0x313e0, 68), (0x5a858, 100), (0x5ad4c, 80)]}
        for va, size in windows.get(path.name, []):
            seg = next(s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD' and s['p_vaddr'] <= va and va + size <= s['p_vaddr'] + s['p_filesz'])
            off = seg['p_offset'] + va - seg['p_vaddr']
            stream.seek(off)
            ins = [dict(elf_va=hex(i.address), bytes=i.bytes.hex(), mnemonic=i.mnemonic, operands=i.op_str) for i in Cs(CS_ARCH_ARM, CS_MODE_ARM).disasm(stream.read(size), va)]
            result['bounded_windows'].append(dict(elf_va=hex(va), file_offset=hex(off), bytes=size, instructions=ins))
        for sec in elf.iter_sections():
            if sec['sh_type'] not in ('SHT_REL', 'SHT_RELA'):
                continue
            table = elf.get_section(sec['sh_link'])
            for rel in sec.iter_relocations():
                sym = table.get_symbol(rel['r_info_sym'])
                if any(s in sym.name for s in ['onNextShotReady', 'onWriteDone', 'execStillNotify', 'arpStillNtfyFnc', 'arpCategoryTbl', 'captureSaveDone', 'm_pFileSaveDoneNotification', 'm_fileSaveDoneParam', 'fclose', 'fwrite', 'captureNotify']):
                    result['relocations'].append(dict(section=sec.name, elf_va=hex(rel['r_offset']), symbol=sym.name, type=rel['r_info_type'], symbol_value=hex(sym['st_value'])))
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    targets = {
        'usr/lib/libcapture-fw-prod.so': ['_ZN14CNotifyHandler15onNextShotReadyEv', '_ZN14CNotifyHandler11onWriteDoneEv', '_ZN14CNotifyHandler14notifyCategoryEv', '_ZNK14CNotifyHandler14notifyCategoryEv', '_ZNK14CNotifyHandler11subCategoryEv', '_ZN14CNotifyHandler15execStillNotifyEv', '_ZN14CNotifyHandler3RunEPhi', '_ZN12CCapNotifyCb10OnCallbackEml', '_ZN17CCapturePublisher15SendAppCallbackEiii', '_ZN12CCapNotifyCb14publishConvertEil'],
        'usr/apps/com.samsung.di-camera-app/bin/di-camera-app': ['_Z30UI_Get_Cb_Flag_Next_Shot_Raedyv', '_Z30UI_Set_Cb_Flag_Next_Shot_Raedyi', '_Z26UI_Capture_File_Write_Donev', '_Z34UI_Set_Mm_Photo_Captue_Callback_FnllPv'],
        'usr/lib/libuser-spec.so': ['_Z39User_Spec_Get_Rtos_Pref_Next_Shot_Readyv'],
        'usr/lib/libmm-photo.so': ['_ZN14ImageGenerator15captureSaveDoneEv', '_ZN14ImageGenerator13captureNotifyE13eNotificationPFvllPvEll', '_ZN14ImageGeneratorC1Ev'],
        'usr/lib/libsif.so': ['_ZN14DscFileHandler8taskMainEv', '_ZN14DscFileHandler7operateEP13tImage_buffer', '_ZN14DscFileHandler11writeChunksEv', '_ZN14DscFileHandler5writeERKSsljm', '_ZN11DscOsalFile5closeEv', '_ZN11DscOsalFile5writeEPKvPm', '_ZN11DscOsalFileD1Ev'],
    }
    result = dict(method='pyelftools original PT_LOAD mapping and Capstone 5 ARM/Thumb disassembly; Ghidra evidence is separate', sources=[collect(args.root / p, names) for p, names in targets.items()])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({s['path']: [x['symbol'] for x in s['functions']] for s in result['sources']}, indent=2))


if __name__ == '__main__':
    main()
