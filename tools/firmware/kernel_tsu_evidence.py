#!/usr/bin/env python3
"""Offline original-byte TSU producer and thermometer conversion/failure evidence."""
import hashlib
import io
import json
import math
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from elftools.elf.elffile import ELFFile

BASE = 0xc0008000
KERNEL = Path('.work/full/kernel-2.raw')
SENSOR = Path('.work/run008/sensor/inputs/libdi-sensor.so')
EXPECTED = {
    'kernel': '25bdca5cde4a5c10710d02dbaa904c62cd77b0b4562b8bf4d73c675f50bdb587',
    'sensor': '75541051bc8e6090ec32d75e1b1b921a965b5a1cad26bf9a0683f7feb93bed07',
}

def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    raw = {'kernel': KERNEL.read_bytes(), 'sensor': SENSOR.read_bytes()}
    for key, data in raw.items():
        assert digest(data) == EXPECTED[key], key
    elf = ELFFile(io.BytesIO(raw['sensor']))
    catalog = Path('.work/run004/kernel/kernel-2-symbols.json')
    syms = json.loads(catalog.read_text())
    names = {s['address']: s['name'] for s in syms}
    def offset(source, va, size):
        if source == 'kernel':
            result = va - BASE
            assert 0 <= result and result + size <= len(raw[source])
            return result
        for seg in elf.iter_segments():
            if seg['p_type'] == 'PT_LOAD' and seg['p_vaddr'] <= va and va + size <= seg['p_vaddr'] + seg['p_filesz']:
                return seg['p_offset'] + va - seg['p_vaddr']
        raise ValueError(hex(va))
    def block(source, start, end, label):
        off = offset(source, start, end - start)
        data = raw[source][off:off + end - start]
        return dict(source=source, va=hex(start), file_offset=off, size=len(data),
                    label=label, raw_hex=data.hex(), sha256=digest(data))
    rel = elf.get_section_by_name('.rel.plt')
    dynsym = elf.get_section(rel['sh_link'])
    plt = elf.get_section_by_name('.plt')
    plt_rows = []
    for index, r in enumerate(rel.iter_relocations()):
        va = plt['sh_addr'] + 20 + 12 * index
        symbol = dynsym.get_symbol(r['r_info_sym'])
        if va in [0x2f28, 0x3030, 0x3078, 0x3090, 0x30cc, 0x3114, 0x3174, 0x3210, 0x327c, 0x32f4, 0x3378]:
            row = block('sensor', va, va + 12, 'PLT veneer')
            row.update(symbol=symbol.name, relocation_type=r['r_info_type'], got_va=hex(r['r_offset']),
                       relocation_file_offset=rel['sh_offset'] + index * rel['sh_entsize'],
                       relocation_raw_hex=raw['sensor'][rel['sh_offset'] + index * 8:rel['sh_offset'] + (index+1)*8].hex(),
                       symbol_defined_va=hex(symbol['st_value']))
            plt_rows.append(row)
    plt_names = {int(r['va'], 16): r['symbol'] for r in plt_rows}
    regions = []
    for source, start, end, label in [
        ('kernel', 0xc02e3b98, 0xc02e3bb0, 'Platform driver registration'),
        ('kernel', 0xc02e3c1c, 0xc02e3d10, 'ISP, CPU and combined calibrated sysfs shows'),
        ('kernel', 0xc02e3d10, 0xc02e3ee8, 'Probe through final branch; literal pool excluded'),
        ('kernel', 0xc02e3ef4, 0xc02e3f54, 'Store mapped device information and initialize'),
        ('kernel', 0xc02e4060, 0xc02e4148, 'Calibrated and raw TSU helpers'),
        ('kernel', 0xc001fb0c, 0xc001fb24, 'ADC raw helper: unmasked register read'),
        ('kernel', 0xc027b064, 0xc027b380, 'CMOS read: ten scaled words, copy, failure paths; pool excluded'),
        ('sensor', 0x3838, 0x3848, 'Lock/unlock wrappers'),
        ('sensor', 0x4728, 0x4a5c, 'Entire update body including sqrt fallback; padding/pool excluded'),
    ]:
        row = block(source, start, end, label)
        insns = list(Cs(CS_ARCH_ARM, CS_MODE_ARM).disasm(bytes.fromhex(row['raw_hex']), start))
        assert sum(i.size for i in insns) == end-start
        row['instructions'] = []
        for i in insns:
            target = None
            if i.mnemonic in ('b','bl') and i.op_str.startswith('#0x'):
                target = (names if source == 'kernel' else plt_names).get(int(i.op_str[1:],16))
            row['instructions'].append(dict(va=hex(i.address), raw_hex=i.bytes.hex(), mnemonic=i.mnemonic,
                                            operands=i.op_str, target_symbol=target))
        regions.append(row)
    data_blocks = []
    for source, start, end, label in [
        ('kernel', 0xc02e3ee8, 0xc02e3ef4, 'Probe literal pointers to attribute records'),
        ('kernel', 0xc071ecd0, 0xc071ed50, 'TSU driver and three attribute records'),
        ('kernel', 0xc07000a8, 0xc07001c8, 'Platform device, memory and IRQ resource records'),
        ('kernel', 0xc027b380, 0xc027b384, 'CMOS read literal pointer to sample words'),
        ('sensor', 0x4a60, 0x4a84, 'Conversion double and PC-relative literals'),
    ]:
        row = block(source,start,end,label)
        row['words_le'] = [hex(x[0]) for x in struct.iter_unpack('<I',bytes.fromhex(row['raw_hex']))]
        data_blocks.append(row)
    strings = []
    for va in [0xc0647628,0xc0673f5c,0xc06436a4,0xc06454d4,0xc064f774,0xc0673e1c,0xc0673f28]:
        off=offset('kernel',va,1);end=raw['kernel'].index(0,off)
        row=block('kernel',va,va+end-off+1,'Original name or format')
        row['value']=raw['kernel'][off:end].decode('ascii');strings.append(row)
    # Resolve update's PC-relative string literals independently of Ghidra.
    for literal, add_insn in [(0x4a6c,0x4784),(0x4a70,0x479c),(0x4a74,0x4928),(0x4a78,0x495c),(0x4a80,0x4a28)]:
        delta=struct.unpack_from('<I',raw['sensor'],offset('sensor',literal,4))[0]
        va=(add_insn+8+delta)&0xffffffff
        off=offset('sensor',va,1);end=raw['sensor'].index(0,off)
        row=block('sensor',va,va+end-off+1,'PC-relative endpoint/error string')
        row.update(value=raw['sensor'][off:end].decode('ascii'),literal_va=hex(literal),add_instruction_va=hex(add_insn))
        strings.append(row)
    constant = struct.unpack_from('<d',raw['sensor'],offset('sensor',0x4a60,8))[0]
    assert constant == 1482.0
    # Check the arithmetic interpretation, not sensor hardware characteristics.
    max_no_overflow = 0xffffffff // 1000
    assert all(((x*1000*0x399d336d)>>41)==(x*1000)//2275 for x in range(max_no_overflow+1))
    arithmetic = dict(tsu_cal_cpu='((register_0x10 >> 16) & 255) - 21',
        tsu_cal_isp='(register_0x10 >> 24) - 21', tsu_error=255,
        cmos_kernel_word='((((adc_register_word * 1000) & 0xffffffff) * 0x399d336d) >> 41)',
        conditional_division_check=dict(input_min=0,input_max=max_no_overflow,all_values_checked=True,
            equivalent='floor(adc_register_word * 1000 / 2275)',hardware_range_established=False),
        cmos_user='trunc_to_signed_int(sqrt(double(signed32(2676588 - 469 * signed_nonzero_average))) - 1482.0)',
        radicand_constant=0x28d76c, subtract_double=constant,
        all_zero_cmos_result=int(math.sqrt(0x28d76c)-constant),
        dsp_zero_buffer_result=153)
    limitations=['Static original-byte reconstruction only; no device operations or firmware modification.',
        'Packaged Kernel2 active boot selection, successful driver binding and live node existence remain unverified.',
        'degC is the producer format label, not externally validated accuracy or calibration.',
        'ADC raw helper imposes no mask; ADC physical range and electrical units are not established.',
        'PLT binding is conditional on ordinary dynamic resolution; runtime interposition is unobserved.',
        'Path omissions are proved locally; actual lock acquisition, failed opens and resulting stalls/leaks are not observed.',
        'Negative-radicand floating-point exceptional result and downstream policy are not assigned a temperature.']
    out=Path('analysis/evidence/kernel-tsu-run010.json')
    result=dict(schema_version=1,static_only=True,sources={k:dict(path=str(KERNEL if k=='kernel' else SENSOR),sha256=EXPECTED[k],size=len(v)) for k,v in raw.items()},
        kernel_link_base=hex(BASE),symbol_catalog=dict(path=str(catalog),sha256=digest(catalog.read_bytes())),
        method='SHA-checked original bytes; kernel VA minus link base; ELF PT_LOAD mapping; bounded ARM Capstone disassembly; original dynamic relocations and recovered kernel symbols.',
        code_regions=regions,data_blocks=data_blocks,strings=strings,plt_bindings=plt_rows,arithmetic=arithmetic,limitations=limitations)
    out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(output=str(out),sha256=digest(out.read_bytes()),code_regions=len(regions),
                         instructions=sum(len(r['instructions']) for r in regions),strings=len(strings))))

if __name__ == '__main__':
    main()
