#!/usr/bin/env python3
"""Reproduce original packaged Kernel2 card-event bindings and bounded producers."""
import hashlib
import json
import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

SOURCE = Path('.work/full/kernel-2.raw')
SHA = '25bdca5cde4a5c10710d02dbaa904c62cd77b0b4562b8bf4d73c675f50bdb587'
BASE = 0xc0008000


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    raw = SOURCE.read_bytes()
    assert digest(raw) == SHA and len(raw) == 7474108
    catalog = Path('.work/run004/kernel/kernel-2-symbols.json')
    syms = json.loads(catalog.read_text())
    names = {s['address']: s['name'] for s in syms}
    def block(a,b,label):
        assert BASE <= a <= b <= BASE + len(raw)
        data=raw[a-BASE:b-BASE]
        return dict(va=hex(a),decoded_file_offset=a-BASE,size=b-a,label=label,
                    raw_hex=data.hex(),sha256=digest(data))
    def word(a):
        return struct.unpack_from('<I',raw,a-BASE)[0]
    def string(a):
        end=raw.index(0,a-BASE)
        row=block(a,end+BASE+1,'Original NUL-terminated string')
        row['value']=raw[a-BASE:end].decode('ascii')
        return row
    ranges=[
        (0xc0301d08,0xc0301ebc,'Vendor EVENT arrays, emission guards and state transitions'),
        (0xc02fc910,0xc02fca30,'Event-bit worker: ordered conditional callbacks'),
        (0xc02fcfe0,0xc02fd034,'MMC error callback sets event bits and queues worker'),
        (0xc0301b48,0xc0301b54,'SD card probe selects driver callbacks'),
        (0xc0300510,0xc0300600,'Platform register stores device and driver callback pointers'),
        (0xc0302c7c,0xc0302ea8,'SD card init: private state, sysfs creation; pool excluded'),
        (0xc0302fa8,0xc0303008,'Protection and online sysfs getters'),
        (0xc0302f58,0xc0302f7c,'State sysfs getter'),
        (0xc0301a90,0xc0301ac8,'Online sysfs writer'),
        (0xc0301c40,0xc0301cc0,'Resume resets state and reconstructs online flag'),
        (0xc02fd7f4,0xc02fe194,'Core probe: work callback setup, MMC ops binding; pool excluded'),
        (0xc02ff0bc,0xc02ff5a8,'Interrupt queues card-detect worker on status bit 0'),
        (0xc02ffb3c,0xc02ffddc,'Card-detect worker before inline jump table'),
        (0xc02ffdf0,0xc02ffee4,'Card-detect worker after inline jump table'),
        (0xc02fc7bc,0xc02fc850,'Card detect getter and register polarity'),
        (0xc02ebb04,0xc02ebf70,'MMC rescan retries and init-error callback'),
        (0xc02fa248,0xc02fa33c,'Block request body before status jump table'),
        (0xc02fa35c,0xc02fada8,'Block request body after status jump table, data-error callback'),
        (0xc02f8f64,0xc02f9034,'Block reset helper: reset-use bitmask and result'),
        (0xc02fcdc8,0xc02fce20,'MMC set-card callback forwarding'),
        (0xc0302b40,0xc0302b68,'SD set-card selector2 invokes power control with 50 ms sleep'),
        (0xc06d7d4c,0xc06d7d54,'Driver initcall code; literal excluded'),
        (0xc06c9ce0,0xc06c9d7c,'Board initializer through platform_add_devices call'),
        (0xc0268e24,0xc0268e74,'Platform device bus binding and name construction'),
        (0xc0263a98,0xc0263abc,'Device uevent subsystem name from bus'),
        (0xc01b499c,0xc01b4b38,'Generic uevent action lookup and environment insertion'),
    ]
    code=[]
    for a,b,label in ranges:
        row=block(a,b,label)
        ins=list(Cs(CS_ARCH_ARM,CS_MODE_ARM).disasm(bytes.fromhex(row['raw_hex']),a))
        assert sum(i.size for i in ins)==b-a, (hex(a),hex(b))
        row['instructions']=[]
        for i in ins:
            target=None
            if i.mnemonic in ['bl','b'] and i.op_str.startswith('#0x'):
                target=names.get(int(i.op_str[1:],16))
            row['instructions'].append(dict(va=hex(i.address),raw_hex=i.bytes.hex(),mnemonic=i.mnemonic,
                                            operands=i.op_str,target_symbol=target))
        code.append(row)
    data=[]
    for a,b,label in [
        (0xc058be50,0xc058be88,'SD callback table; generate_event slot +0x24'),
        (0xc058bc30,0xc058bc8c,'MMC host ops; error_event slot +0x44'),
        (0xc07200e4,0xc0720134,'Platform driver object'),
        (0xc07203e4,0xc0720464,'Online/protect/name/state and neighboring sysfs attributes'),
        (0xc0302ea8,0xc0302ecc,'SD init attribute literal pool'),
        (0xc02fe194,0xc02fe1a8,'Core probe literal pool including MMC ops'),
        (0xc02fa33c,0xc02fa35c,'Block status absolute jump table (not instructions)'),
        (0xc02ffddc,0xc02ffdf0,'Card worker absolute jump table (not instructions)'),
        (0xc058af60,0xc058af70,'Rescan clock candidate table'),
        (0xc0420704,0xc042071c,'kobject action-name pointer table'),
        (0xc071a7e0,0xc071a7e4,'Platform bus name pointer'),
        (0xc05859f8,0xc0585a04,'Device uevent callback pointers'),
        (0xc0269030,0xc0269034,'Platform bus binding literal'),
        (0xc06d7d54,0xc06d7d58,'Driver registration literal'),
        (0xc06e0c4c,0xc06e0c50,'Level6 driver initcall pointer'),
        (0xc06de78c,0xc06de808,'Board platform-device pointer array'),
        (0xc06fd2c0,0xc06fd3f8,'SD platform data and platform device; id0'),
        (0xc06dcb50,0xc06dcb98,'Machine descriptor includes board-init pointer'),
    ]:
        row=block(a,b,label)
        row['words_le']=[hex(v[0]) for v in struct.iter_unpack('<I',bytes.fromhex(row['raw_hex']))]
        data.append(row)
    string_addrs=[0xc0676c78,0xc0676c90,0xc0676ca8,0xc0676cbc,
        0xc06474a8,0xc06474b8,0xc064f774,0xc0676ee8,0xc0676ef8,0xc0676f14,
        0xc065b84c,0xc065b858,0xc065b864,0xc067b18c,0xc0666278,
        0xc0676ce4,0xc0676d08,0xc0676d2c,0xc0676d50,word(0xc071a7e0)]
    string_addrs += [word(0xc0420704+4*n) for n in range(6)]
    strings=[string(a) for a in sorted(set(string_addrs))]
    assert word(0xc058be74)==0xc0301d08
    assert word(0xc058bc74)==0xc02fcfe0
    assert word(0xc02fe198)==0xc058bc30
    assert word(0xc07200e4)==0xc0301b48
    assert word(0xc06fd310)==word(0xc07200f8)==0xc06474a8
    assert word(0xc06fd314)==0
    assert word(0xc06de78c)==0xc06fd310
    assert word(0xc06e0c4c)==0xc06d7d4c
    assert word(0xc06d7d54)==0xc07200e4
    assert word(0xc0269030)==0xc071a7e0
    assert string(word(0xc0420708))['value']=='remove'
    events=[dict(selector=0,event='sdcard_insert',env_va='0xc0676ca8',call_va='0xc0301dfc',
        emission_guard='private +4 == 0',state_after=1),
        dict(selector=1,event='sdcard_remove',env_va='0xc0676cbc',call_va='0xc0301ea8',
        emission_guard='global host mapped register +0x50 != 0',state_after=0),
        dict(selector=2,event='sdcard_init_error',env_va='0xc0676c78',call_va='0xc0301e94',
        emission_guard='private +0xc != 0 and != 2',state_after=2),
        dict(selector=3,event='sdcard_data_error',env_va='0xc0676c90',call_va='0xc0301de0',
        emission_guard='private +0xc != 0 and != 2',state_after=2)]
    for event in events:
        event.update(action_number=1,action_name='remove',environment_array='one EVENT= string pointer followed by NULL')
    out=Path('analysis/evidence/kernel-card-events-run011.json')
    result=dict(schema_version=1,static_only=True,source=str(SOURCE),source_sha256=SHA,source_size=len(raw),
        decoded_link_base=hex(BASE),symbol_catalog=dict(path=str(catalog),sha256=digest(catalog.read_bytes())),
        method='SHA-checked original raw ARM image; VA-base file mapping; Capstone bounded disassembly; recovered kallsyms names; data pools/tables excluded from code.',
        code_regions=code,data_blocks=data,strings=strings,event_mapping=events,
        limitations=['Packaged Kernel2 active selection and machine/driver execution are unverified.',
            'Direct/indirect call bindings establish static paths, not successfully delivered uevents.',
            'All four vendor events use platform action remove; this does not itself remove a block device.',
            'Worker order applies only to that local invocation; interrupt/workqueue/udev/vconf timing is unobserved.',
            'State suppression and pending bits can merge/drop distinct conditions; no per-file/capture identity is present.',
            'Selected retry branches are not a complete card recovery policy or a measured recovery guarantee.',
            'The cdn-sdhci consumer alternative is not resolved to a producer in this task.',
            'No firmware changes, target execution, device I/O, Ghidra mutations, commits or pushes.'])
    out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(output=str(out),sha256=digest(out.read_bytes()),regions=len(code),
                         instructions=sum(len(r['instructions']) for r in code),data_blocks=len(data),strings=len(strings))))

if __name__=='__main__':
    main()
