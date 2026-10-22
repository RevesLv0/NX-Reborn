#!/usr/bin/env python3
"""Extract bounded RTOS publication paths from hash-verified NX500 source bytes."""
import argparse
import hashlib
import json
from pathlib import Path

from boot_sections import bounded_disassembly, verified_sections


BASE = 0x80000000  # Inferred link base; not an observed runtime mapping.
RANGES = [
    ('ready_flag_then_local_publish', 0x6144c, 0x614f0),
    ('named_capture_publish', 0x602ac, 0x60408),
    ('observer_match_and_virtual_call', 0x96574, 0x9667c),
    ('observer_temporary_list_growth', 0x9679c, 0x967ac),
    ('observer_empty_list_return', 0x9686c, 0x96878),
    ('publish_gate_helper', 0x45fb8, 0x45ff8),
    ('observer_entry_helper', 0x95848, 0x95860),
    ('observer_exit_helper', 0x95864, 0x9587c),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    blob = args.bin.read_bytes()
    spec, data = verified_sections(blob, json.loads(args.manifest.read_text()))[5]
    origin = spec['offset_decimal']
    regions = []
    for name, lo, hi in RANGES:
        row = bounded_disassembly(data, lo, hi, 'ARM', BASE, origin)
        if row['bytes_covered'] != hi - lo:
            raise ValueError(f'Incomplete linear decode of selected window: {name}')
        row.update(label=name, section_start=lo, section_end_exclusive=hi,
                   bytes=data[lo:hi].hex(), sha256=hashlib.sha256(data[lo:hi]).hexdigest())
        regions.append(row)
    result = dict(schema_version=1, run='RUN005', static_only=True,
                  source=dict(bin_path=str(args.bin), bin_bytes=len(blob),
                              bin_sha256=hashlib.sha256(blob).hexdigest(),
                              section_index=5, section_bin_start=origin,
                              section_bytes=len(data), section_sha256=hashlib.sha256(data).hexdigest(),
                              inferred_link_base=hex(BASE)),
                  address_convention='section offsets index raw section 5; BIN offset = section start + section offset; inferred link VA = 0x80000000 + section offset, not observed runtime memory',
                  method='whole BIN/section SHA checks, bounded Capstone ARM disassembly, original PC-relative literal resolution and manual register/control-flow review',
                  code_regions=regions,
                  limitations=[
                      'Only selected code windows were reviewed; linear decode does not establish a whole-program control-flow graph.',
                      'The gate helper, entry/exit helper semantics and virtual subscriber binding are not established.',
                      'No serialized IPC frame, Linux receiver correspondence or peer acknowledgement is recovered here.',
                      'No device execution, runtime ordering, shared-memory visibility or storage durability is observed.'])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(section_sha256=result['source']['section_sha256'], windows=len(regions),
                          instruction_rows=sum(len(r['instructions']) for r in regions))))


if __name__ == '__main__':
    main()
