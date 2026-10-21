#!/usr/bin/env python3
"""Reproduce bounded raw NX500 RTOS observer, frame, ring-write and signal evidence."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

from boot_sections import bounded_disassembly, verified_sections
from rtos_readiness import branch_target

BASE = 0x80000000  # Inferred link base, not a measured runtime mapping.
RANGES = [
    ('adapter_subscription_observer_and_ready', 0x58110, 0x58224),
    ('adapter_initialization_to_subscription', 0x587e8, 0x58828),
    ('adapter_constructor_vtable_binding', 0x59940, 0x59978),
    ('publisher_singleton', 0x610e4, 0x61140),
    ('publisher_subscription_list_selector', 0x5f350, 0x5f36c),
    ('register_callback_guard_and_lock', 0x96340, 0x96388),
    ('register_callback_existing_match', 0x960d4, 0x9613c),
    ('register_callback_record_stores', 0x96200, 0x96250),
    ('register_callback_list_growth', 0x96310, 0x96324),
    ('dispatch_observer_slot', 0x96630, 0x96660),
    ('observer_thunk', 0x58ef8, 0x58f04),
    ('observer_event_conversion_full_body', 0x58828, 0x58ef8),
    ('sender_singleton', 0x5e108, 0x5e168),
    ('send_api_to_sender', 0x5e17c, 0x5e1b8),
    ('sender_build_gate_queue_and_send', 0x5e824, 0x5e8f4),
    ('packet_header_builder', 0x5e650, 0x5e6e4),
    ('packet_constructor', 0xe7340, 0xe7368),
    ('packet_allocation_zeroing_and_align', 0xe71b4, 0xe72b8),
    ('packet_header_and_payload_copy', 0xe738c, 0xe7468),
    ('copy_small_byte_loop', 0x509eec, 0x509f04),
    ('copy_small_byte_loop_body', 0x509fa4, 0x509fd0),
    ('sender_immediate_and_queue_paths', 0x5e6e4, 0x5e80c),
    ('sender_queued_retry', 0x5e900, 0x5e98c),
    ('packet_send_buffer_and_length', 0xe7158, 0xe7178),
    ('driver_channel_three_send', 0x5d740, 0x5d7a8),
    ('driver_channel_capacity', 0x4cf224, 0x4cf264),
    ('driver_send_wrapper', 0x4cf338, 0x4cf38c),
    ('channel_translation', 0x379c4, 0x37a04),
    ('ring_free_capacity', 0x37538, 0x37590),
    ('ring_frame_copy_publish_signal', 0x37ac8, 0x37e9c),
    ('driver_hook_registration', 0x37398, 0x373d8),
    ('driver_initialization_hook_binding', 0x36eac, 0x36ed8),
    ('concrete_signal_mmio_store', 0x383bc, 0x383d4),
]
DATA = [
    ('adapter_vtable_and_rtti', 0x56ddc8, 0x56de80),
    ('adapter_vtable_literal', 0x59a54, 0x59a58),
    ('publisher_singleton_literals', 0x61140, 0x6114c),
    ('sender_singleton_literals', 0x5e168, 0x5e17c),
    ('sender_gate_literals', 0x5e8f4, 0x5e900),
    ('ring_descriptor_and_hook_literals', 0x37e9c, 0x37eb8),
    ('driver_initialization_literals', 0x3700c, 0x37018),
    ('driver_function_table', 0x56aae0, 0x56aafc),
]
BRANCH_TARGETS = (0x58110, 0x5f350, 0x96340, 0x37398)
LIMITS = [
    'Raw section evidence, separate from ELF/Ghidra coverage; no import, decompilation or target execution.',
    'Inferred link base is not an observed runtime mapping. Code-selected globals outside the section are not file-backed data.',
    'Aligned ARM B/BL scans are encoding candidates only; no exhaustive Thumb, indirect-call, relocation or executable-region scan.',
    'Selected code windows stop before adjacent literal pools; recorded data blocks are never decoded as code.',
    'Frame bytes are reconstructed conditional on the inspected initialized normal path, allocation and available ring space, not a device capture.',
    'Ring-wrap and queue/error branches are retained; detailed conclusions describe the reviewed contiguous successful submission path.',
    'No peer acknowledgement, runtime visibility/cacheability, memory ownership, file durability or capture/transfer safety is established.',
]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True)
    p.add_argument('--manifest', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    blob = a.bin.read_bytes()
    spec, data = verified_sections(blob, json.loads(a.manifest.read_text()))[5]
    origin = spec['offset_decimal']
    def block(label, lo, hi):
        raw = data[lo:hi]
        return dict(label=label, section_start=lo, section_end_exclusive=hi,
                    bin_offset=origin+lo, inferred_link_va=hex(BASE+lo),
                    bytes=raw.hex(), sha256=hashlib.sha256(raw).hexdigest())
    regions = []
    for name, lo, hi in RANGES:
        row = bounded_disassembly(data, lo, hi, 'ARM', BASE, origin)
        if row['bytes_covered'] != hi-lo:
            raise ValueError(f'Incomplete selected decode: {name} {row["bytes_covered"]}/{hi-lo}')
        row.update(block(name, lo, hi)); regions.append(row)
    blocks = [block(*x) for x in DATA]
    for row in blocks:
        raw = bytes.fromhex(row['bytes'])
        row['little_endian_words'] = [hex(v[0]) for v in struct.iter_unpack('<I', raw)]
    branches=[]
    for off in range(0,len(data)-3,4):
        word=struct.unpack_from('<I',data,off)[0]
        target=branch_target(word,off)
        if target in BRANCH_TARGETS:
            branches.append(dict(section_offset=off,bin_offset=origin+off,
                                 inferred_link_va=hex(BASE+off),bytes=data[off:off+4].hex(),
                                 target_section_offset=target))
    result=dict(schema_version=1,run='RUN006',static_only=True,
        source=dict(bin_path=str(a.bin),bin_bytes=len(blob),bin_sha256=hashlib.sha256(blob).hexdigest(),
                    section_index=5,section_bin_start=origin,section_bytes=len(data),
                    section_sha256=hashlib.sha256(data).hexdigest(),inferred_link_base=hex(BASE)),
        address_convention='section offsets index exact section5 bytes; BIN=0xef4301+section; inferred VA=0x80000000+section, not a runtime mapping',
        method='whole BIN and all section hashes verified; bounded Capstone ARM; original literal/vtable words; manual register/control-flow review; aligned ARM B/BL candidate scan',
        code_regions=regions,data_blocks=blocks,
        branch_scan=dict(start=0,end_exclusive=len(data),stride=4,targets=list(BRANCH_TARGETS),candidates=branches),
        reconstructed_ready_frame=dict(kind='conditional static derivation, never captured traffic',
            event='0x01010006',channel_api=3,channel_internal=2,
            inner_bytes='82000a0200000000',outer_bytes='ff7f0a000003',
            combined_bytes='ff7f0a00000382000a0200000000',
            basis_sections=['0x58828','0x58990','0x58afc','0x5892c','0x5e650','0xe738c','0xe7280','0x37ac8']),
        limitations=LIMITS)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(windows=len(regions),data_blocks=len(blocks),
        instructions=sum(len(r['instructions']) for r in regions),branch_candidates=len(branches),
        section_sha256=result['source']['section_sha256'])))


if __name__=='__main__':main()
