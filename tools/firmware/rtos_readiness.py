#!/usr/bin/env python3
"""Reproduce bounded NX500 T-Kernel readiness producer evidence; never execute target code."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

from boot_sections import bounded_disassembly, verified_sections

BASE = 0x80000000  # Inferred by RUN003; not a recovered runtime mapping.
TARGETS = [0x85400000, 0x85401c4d, 0x1c4d]
RANGES = [
    ('readiness_named_setter', 0xc8430, 0xc8484),
    ('readiness_named_getter', 0xc8484, 0xc8498),
    ('direct_base_zero_store', 0x4e2b90, 0x4e2ba4),
    ('selector_to_base', 0x4e2ba4, 0x4e2c20),
    ('generic_byte_setter', 0x4e2f48, 0x4e2f94),
    ('generic_byte_getter_word_load_then_uxtb', 0x4e30d8, 0x4e3120),
    ('preference_zeroing_helper', 0x4e2c20, 0x4e2c4c),
    ('preference_init_before_poll', 0x4e2c4c, 0x4e2cc0),
    ('preference_init_success', 0x4e2d94, 0x4e2dcc),
    ('notify_next_shot_ready', 0x6144c, 0x614f0),
    ('clear_before_other_notification', 0x6150c, 0x61548),
    ('raw_buffer_check', 0x73224, 0x732c8),
    ('raw_buffer_recheck', 0x732dc, 0x733bc),
    ('other_one_tailcall', 0xa3950, 0xa3998),
    ('capture_state_exit', 0xc97ac, 0xc9870),
    ('predicate_compares_two_object_words', 0xcada8, 0xcadc0),
]
CALLS = [(0x61484, 1), (0x6151c, 0), (0x73294, 1), (0x733ac, 0),
         (0xa3994, 1), (0xc9810, 1), (0xc9840, 0), (0xc9864, 0)]
PATTERN = rb'(?i)(NextShot|next_shot|CaptureReady|capture_ready|save.{0,12}(done|complete|finish)|file.{0,8}(write|clos)|raw.{0,8}save|capture.{0,8}(done|complete|finish))'


def mov_half(word):
    """Return ARM MOVW/MOVT encoded immediate and destination; not a code classifier."""
    kind = word & 0x0ff00000
    if kind not in (0x03000000, 0x03400000) or word >> 28 == 15:
        return None
    return dict(kind='movw' if kind == 0x03000000 else 'movt',
                register=(word >> 12) & 15,
                immediate=(word & 0xfff) | ((word >> 4) & 0xf000),
                condition=word >> 28)


def branch_target(word, offset):
    """ARM B/BL only, not BLX-immediate or Thumb. Return section-relative target."""
    if word & 0x0e000000 != 0x0a000000 or word >> 28 == 15:
        return None
    immediate = word & 0xffffff
    if immediate & 0x800000:
        immediate -= 0x1000000
    return (offset + 8 + immediate * 4) & 0xffffffff


def scan(data, origin=0):
    exact = {hex(v): [dict(section_offset=m.start(), bin_offset=origin + m.start(),
                          aligned_to_section_word=m.start() % 4 == 0)
                       for m in re.finditer(re.escape(struct.pack('<I', v)), data)]
             for v in TARGETS}
    moves, branches, literals = [], [], []
    wanted_literals = {BASE + x for x in [0x56e6b0, 0x56e6c4, 0x57b270, 0x70914c, 0x5735e8]}
    for off in range(0, len(data) - 3, 4):
        word = struct.unpack_from('<I', data, off)[0]
        half = mov_half(word)
        if half and half['immediate'] in (0x8540, 0x1c4d):
            moves.append(dict(section_offset=off, bin_offset=origin + off, bytes=data[off:off + 4].hex(), **half))
        target = branch_target(word, off)
        if target in (0xc8430, 0xc8484, 0x4e2f48):
            branches.append(dict(section_offset=off, bin_offset=origin + off,
                                 target_section_offset=target, bytes=data[off:off + 4].hex()))
        # Immediate, preindexed, word LDR [pc,+/-imm12], without writeback.
        if word >> 28 != 15 and word & 0x0f7f0000 == 0x051f0000:
            disp = word & 0xfff
            loc = off + 8 + (disp if word & (1 << 23) else -disp)
            if 0 <= loc <= len(data) - 4:
                value = struct.unpack_from('<I', data, loc)[0]
                if value in wanted_literals or value in TARGETS:
                    literals.append(dict(section_offset=off, bin_offset=origin + off,
                                         literal_section_offset=loc, literal_bin_offset=origin + loc,
                                         literal_value=hex(value), bytes=data[off:off + 4].hex()))
    return dict(exact_little_endian_byte_patterns=exact, arm_mov_half_candidates=moves,
                arm_branch_candidates=branches, arm_pc_literal_candidates=literals)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bin', type=Path, required=True)
    p.add_argument('--manifest', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--raw-output-dir', type=Path, required=True)
    args = p.parse_args()
    blob = args.bin.read_bytes()
    spec, data = verified_sections(blob, json.loads(args.manifest.read_text()))[5]
    origin = spec['offset_decimal']
    args.raw_output_dir.mkdir(parents=True, exist_ok=True)
    all_strings = [dict(section_offset=m.start(), bin_offset=origin + m.start(),
                        inferred_link_va=hex(BASE + m.start()), text=m.group().decode('ascii'))
                   for m in re.finditer(rb'[\x20-\x7e]{5,}', data)]
    (args.raw_output_dir / 'all-strings.json').write_text(json.dumps(all_strings, indent=2) + '\n')
    regions = []
    for label, lo, hi in RANGES:
        region = bounded_disassembly(data, lo, hi, 'ARM', BASE, origin)
        region.update(label=label, section_start=lo, section_end_exclusive=hi,
                      bytes=data[lo:hi].hex(), sha256=hashlib.sha256(data[lo:hi]).hexdigest())
        regions.append(region)
    out = dict(schema_version=1, run='RUN004', kind='bounded-static-rtos-readiness-producer',
               source=dict(bin_path=str(args.bin), bin_bytes=len(blob), bin_sha256=hashlib.sha256(blob).hexdigest(),
                           section_index=5, section_bin_start=origin, section_bytes=len(data),
                           section_sha256=hashlib.sha256(data).hexdigest(), inferred_link_base=hex(BASE)),
               address_convention='section_offset indexes exact raw section bytes; bin_offset = section_bin_start + section_offset; inferred_link_va = 0x80000000 + section_offset, not measured runtime address.',
               survey=scan(data, origin), code_regions=regions,
               selected_strings=[s for s in all_strings if re.search(PATTERN, s['text'].encode())],
               reviewed_setter_calls=[dict(section_offset=o, bin_offset=origin + o,
                                          inferred_link_va=hex(BASE + o), input_low_byte=v,
                                          basis='bounded ARM register/control-flow interpretation, no target execution')
                                      for o, v in CALLS],
               limitations=['Whole-section 4-byte-aligned ARM encoding candidate scan is not executable-region discovery.',
                            'Data and instruction boundaries are manually reviewed only in selected bounded windows; code-like bytes elsewhere remain candidates.',
                            'No exhaustive Thumb, indirect-call, alias, relocation, or whole-program analysis.',
                            'No device observation, target execution, file durability, capture completion, or complete shared-memory ownership proof.'])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(out, indent=2) + '\n')
    print(json.dumps(dict(source=out['source'], code_regions=len(regions),
                          selected_strings=len(out['selected_strings']),
                          arm_mov_half_candidates=len(out['survey']['arm_mov_half_candidates']),
                          arm_branch_candidates=len(out['survey']['arm_branch_candidates']),
                          arm_pc_literal_candidates=len(out['survey']['arm_pc_literal_candidates']))))


if __name__ == '__main__':
    main()
