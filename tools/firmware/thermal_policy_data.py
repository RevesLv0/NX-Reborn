#!/usr/bin/env python3
"""Recover temperature descriptor/default words and preference backing records.

Reads original ELF data and relocations only. Never opens a camera device or
uses a firmware function to obtain a value.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from elftools.elf.elffile import ELFFile


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class OriginalELF:
    def __init__(self, source, blocks):
        self.source = source
        self.stream = Path(source['staged_path']).open('rb')
        self.elf = ELFFile(self.stream)
        self.blocks = blocks

    def symbol(self, name):
        matches = [s for s in self.elf.get_section_by_name('.dynsym').iter_symbols()
                   if s.name == name and s['st_shndx'] != 'SHN_UNDEF']
        assert len(matches) == 1
        return matches[0]

    def read(self, va, size, label):
        segment = next(s for s in self.elf.iter_segments()
                       if s['p_type'] == 'PT_LOAD' and s['p_vaddr'] <= va
                       and va + size <= s['p_vaddr'] + s['p_filesz'])
        offset = segment['p_offset'] + va - segment['p_vaddr']
        self.stream.seek(offset)
        raw = self.stream.read(size)
        assert len(raw) == size
        self.blocks.append(dict(source_sha256=self.source['sha256'],
            source_path=self.source['path'], label=label, original_elf_va=hex(va),
            file_offset=hex(offset), raw_hex=raw.hex()))
        return raw

    def pointer(self, va, label):
        raw = self.read(va, 4, label)
        matches = []
        for section in self.elf.iter_sections():
            if section['sh_type'] != 'SHT_REL':
                continue
            for relocation in section.iter_relocations():
                if relocation['r_offset'] == va:
                    symbol = self.elf.get_section(section['sh_link']).get_symbol(relocation['r_info_sym'])
                    matches.append((relocation, symbol))
        assert len(matches) == 1
        relocation, symbol = matches[0]
        assert relocation['r_info_type'] == 2  # R_ARM_ABS32
        addend = struct.unpack('<I', raw)[0]
        target = (symbol['st_value'] + addend) & 0xffffffff
        return dict(source_sha256=self.source['sha256'], original_elf_va=hex(va),
            type=2, symbol=symbol.name, symbol_value=hex(symbol['st_value']),
            raw_addend=hex(addend), resolved_original_elf_va=hex(target))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('.work/run009'))
    parser.add_argument('--output', type=Path, default=Path('analysis/evidence/thermal-policy-data-run009.json'))
    args = parser.parse_args()
    sources = []
    for subsystem, filename in [('factory', 'libfactory-mode.so'), ('pref', 'libprefman.so')]:
        rows = json.loads((args.root/subsystem/'input-manifest.json').read_text())
        source = next(r for r in rows if Path(r['staged_path']).name == filename)
        original = Path('.work/full/extracted')/source['partition']/source['path'].lstrip('/')
        assert digest(original) == source['sha256'] == digest(source['staged_path'])
        sources.append(source)
    result = dict(schema_version=1, static_only=True, sources=sources, ghidra=[],
        windows=[], data_blocks=[], relocations=[], settings=[], limitations=[
            'Factory defaults, prefman embedded defaults and live mapped preferences are distinct.',
            'No device NVD contents or runtime threshold selection have been observed.',
            'Preference addresses are configured physical mappings, not observed host/camera addresses.',
            'Physical units and actual sensor conversion require separate driver evidence.'])
    factory = OriginalELF(sources[0], result['data_blocks'])
    pref = OriginalELF(sources[1], result['data_blocks'])
    try:
        info = factory.symbol('dfms_adjdata_sys_info')
        raw = factory.read(info['st_value'], info['st_size'], 'System adjustment descriptors, 96-byte records')
        defaults = factory.symbol('dfms_adjdata_sys_default')
        group = 4
        default_pointer = pref.pointer(0x65a280 + group*0x24, 'Group 4 embedded default pointer')
        result['relocations'].append(default_pointer)
        assert default_pointer['symbol'] == 'pref_sys_default'
        pref_default = int(default_pointer['resolved_original_elf_va'], 16)
        for offset in range(0, len(raw), 0x60):
            record = raw[offset:offset+0x60]
            name = record[:0x50].split(b'\0')[0].decode('ascii')
            if not name.startswith('TEMP_SENSOR_'):
                continue
            low, high, size, extra = struct.unpack('<4I', record[0x50:])
            assert high == 0x85600000 and size == 4
            assert low + size <= defaults['st_size']
            factory_va = defaults['st_value'] + low
            pref_va = pref_default + 0x200 + low
            factory_word = factory.read(factory_va, size, name+' factory default')
            pref_word = pref.read(pref_va, size, name+' prefman embedded default')
            result['settings'].append(dict(name=name, descriptor_original_elf_va=hex(info['st_value']+offset),
                id_low=hex(low), id_high=hex(high), id_uint64=hex((high<<32)|low), size=size,
                factory_default_original_elf_va=hex(factory_va), factory_default_signed=struct.unpack('<i',factory_word)[0],
                prefman_default_original_elf_va=hex(pref_va), prefman_default_signed=struct.unpack('<i',pref_word)[0]))
        assert len(result['settings']) == 7
        mapping_va = 0x65a3f4 + group*0xc
        physical, length, initial_pointer = struct.unpack('<3I', pref.read(mapping_va,12,'Group 4 physical mapping record'))
        result['shared_mapping'] = dict(record_original_elf_va=hex(mapping_va), physical_base=hex(physical),
            requested_bytes=length, mmap_rounded_bytes=(length+0xfff)&~0xfff, embedded_initial_pointer=hex(initial_pointer))
        nvd_va = 0x651114 + group*0xb8
        nvd = pref.read(nvd_va,0xb8,'Group 4 NVD backing record')
        pref.read(0x65192c,3,'NVD path formatting string')
        result['nvd_backing'] = dict(record_original_elf_va=hex(nvd_va),
            name=nvd[:0x28].split(b'\0')[0].decode('ascii'), slots=[])
        for selector, path_offset, sector_offset in [(0,0x28,0x50),(1,0x58,0x80),(2,0x88,0xb0)]:
            sector, trailing_word = struct.unpack_from('<2I',nvd,sector_offset)
            result['nvd_backing']['slots'].append(dict(selector=selector,
                path=nvd[path_offset:path_offset+0x28].split(b'\0')[0].decode('ascii'),
                sector_offset=sector, byte_offset=sector<<9,
                trailing_word=hex(trailing_word), trailing_word_units='not established'))
    finally:
        factory.stream.close()
        pref.stream.close()
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(settings=result['settings'], shared_mapping=result['shared_mapping'], nvd_backing=result['nvd_backing'])))


if __name__ == '__main__':
    main()
