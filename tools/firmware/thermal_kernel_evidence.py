#!/usr/bin/env python3
"""Reproduce bounded packaged-kernel CMOS thermister and power attribute bytes."""
import hashlib
import json
import struct
from pathlib import Path

from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM


def main():
    source=Path('.work/full/kernel-2.raw');raw=source.read_bytes()
    expected='25bdca5cde4a5c10710d02dbaa904c62cd77b0b4562b8bf4d73c675f50bdb587'
    assert hashlib.sha256(raw).hexdigest()==expected
    symbols=Path('.work/run004/kernel/kernel-2-symbols.json')
    syms=json.loads(symbols.read_text());names={r['address']:r['name'] for r in syms}
    base=0xc0008000
    def block(lo,hi,label):
        data=raw[lo-base:hi-base]
        assert len(data)==hi-lo
        return dict(label=label,kernel_link_va=hex(lo),decoded_offset=lo-base,raw_hex=data.hex(),
                    sha256=hashlib.sha256(data).hexdigest())
    regions=[]
    # The read function ends at the following literal pool; the word at b380
    # is retained below as data, never decoded as an instruction.
    for lo,hi,label in [(0xc027b01c,0xc027b038,'CMOS attribute reads cached word and formats it'),
                         (0xc027b064,0xc027b380,'Thermister read: ADC calls, samples, cache and userspace copy'),
                         (0xc06d5d78,0xc06d5da8,'Probe binds miscdevice and platform attribute'),
                         (0xc0055754,0xc00557a4,'Bootmode show bounded entry; remaining branches not analyzed'),
                         (0xc0055674,0xc00556c4,'Wakeup source show bounded entry; remaining branches not analyzed')]:
        row=block(lo,hi,label)
        instructions=list(Cs(CS_ARCH_ARM,CS_MODE_ARM).disasm(bytes.fromhex(row['raw_hex']),lo))
        assert sum(i.size for i in instructions)==hi-lo
        row['instructions']=[dict(va=hex(i.address),bytes=i.bytes.hex(),mnemonic=i.mnemonic,
            operands=i.op_str,branch_target_symbol=names.get(int(i.op_str[1:],16)) if i.mnemonic in ('b','bl') and i.op_str.startswith('#0x') else None) for i in instructions]
        regions.append(row)
    blocks=[]
    for lo,hi,label in [(0xc027b380,0xc027b384,'Read function PC-relative literal'),
                         (0xc071b280,0xc071b290,'Device attribute: name,mode,show,store words'),
                         (0xc071b290,0xc071b2b4,'Miscdevice leading words'),
                         (0xc0586110,0xc0586140,'Thermister file-operation leading words')]:
        row=block(lo,hi,label);row['little_endian_words']=[hex(x[0]) for x in struct.iter_unpack('<I',bytes.fromhex(row['raw_hex']))];blocks.append(row)
    strings=[]
    for va in [0xc0667388,0xc0667398,0xc065b41c]:
        start=va-base;end=raw.index(0,start)+1;row=block(va,base+end,'Original NUL-terminated name/format')
        row['value']=raw[start:end-1].decode('ascii');strings.append(row)
    result=dict(schema_version=1,static_only=True,source=str(source),source_sha256=expected,
        decoded_base=hex(base),symbol_catalog=dict(path=str(symbols),sha256=hashlib.sha256(symbols.read_bytes()).hexdigest()),
        code_regions=regions,data_blocks=blocks,strings=strings,
        method='Original decoded kernel SHA checked; bounded ARM code stops at known literal pool; original data words and recovered kallsyms targets.',
        limitations=['Packaged kernel2 only; active boot selection unverified.',
                     'ADC samples/cache are not automatically Celsius or a user-visible temperature.',
                     'Read-size, userspace conversion, configuration and callback policy require separate evidence.',
                     'No kernel execution, device access, sensor measurement or power operation.'])
    out=Path('analysis/evidence/thermal-kernel-run008.json');out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(windows=len(regions),instructions=sum(len(r['instructions']) for r in regions),data_blocks=len(blocks),strings=len(strings),sha256=hashlib.sha256(out.read_bytes()).hexdigest())))


if __name__=='__main__':
    main()
