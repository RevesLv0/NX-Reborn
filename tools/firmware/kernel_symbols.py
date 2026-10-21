#!/usr/bin/env python3
"""Recover validated pre-relative ARM32 kallsyms from decoded kernels, offline.

An address-like run is only a candidate. Acceptance requires the adjacent count,
every compressed name, every 256-name marker, all 256 tokens and the entire
16-bit token index to agree. Absence is limited to this format/search envelope.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def padded_starts(data, end, alignment=4):
    """Accept at most 15 zero alignment bytes, without skipping payload."""
    for offset in range(end, min(end + 16, len(data))):
        if offset % alignment == 0 and not any(data[end:offset]):
            yield offset


def address_runs(data, minimum=1024):
    start, previous, distinct = None, None, 0
    for offset in range(0, len(data) - 3, 4):
        value = u32(data, offset)
        valid = 0x80000000 <= value < 0xffff0000
        if start is not None and (not valid or value < previous):
            count = (offset - start) // 4
            if count >= minimum and distinct >= min(16, minimum) and previous - u32(data, start) <= 0x10000000:
                yield start, count
            start, previous, distinct = None, None, 0
        if valid:
            if start is None:
                start = offset
            if previous != value:
                distinct += 1
            previous = value
    if start is not None:
        count = (len(data) // 4 * 4 - start) // 4
        if count >= minimum and distinct >= min(16, minimum) and previous - u32(data, start) <= 0x10000000:
            yield start, count


def validate_structure(data, addresses_offset, count, count_offset, names_offset):
    """Return all symbols only after complete mutually consistent validation."""
    if count_offset + 4 > len(data) or u32(data, count_offset) != count:
        raise ValueError('symbol count mismatch')
    if addresses_offset + count * 4 > count_offset:
        raise ValueError('address/count overlap')
    addresses = [u32(data, addresses_offset + 4 * i) for i in range(count)]
    if not addresses or any(a > b for a, b in zip(addresses, addresses[1:])):
        raise ValueError('addresses not sorted')
    cursor, compressed, markers = names_offset, [], []
    for i in range(count):
        if i % 256 == 0:
            markers.append(cursor - names_offset)
        if cursor >= len(data) or not data[cursor]:
            raise ValueError('empty/truncated compressed name')
        size = data[cursor]
        cursor += 1
        if cursor + size > len(data):
            raise ValueError('truncated compressed name')
        compressed.append(data[cursor:cursor + size])
        cursor += size
    names_end = cursor
    marker_bytes = struct.pack('<%dI' % len(markers), *markers)
    for marker_offset in padded_starts(data, names_end):
        if data[marker_offset:marker_offset + len(marker_bytes)] != marker_bytes:
            continue
        marker_end = marker_offset + len(marker_bytes)
        for token_offset in padded_starts(data, marker_end):
            tokens, index, cursor = [], [], token_offset
            try:
                for _ in range(256):
                    index.append(cursor - token_offset)
                    end = data.index(0, cursor, min(cursor + 256, len(data)))
                    token = data[cursor:end]
                    if any(c < 33 or c > 126 for c in token):
                        raise ValueError('nonprintable token')
                    tokens.append(token.decode('ascii'))
                    cursor = end + 1
            except (ValueError, UnicodeError):
                continue
            if index[-1] > 65535:
                continue
            index_bytes = struct.pack('<256H', *index)
            for index_offset in padded_starts(data, cursor, alignment=2):
                if data[index_offset:index_offset + 512] != index_bytes:
                    continue
                symbols = []
                for i, encoded in enumerate(compressed):
                    expanded = ''.join(tokens[c] for c in encoded)
                    if not re.fullmatch(r'[A-Za-z?][A-Za-z0-9_.$]+', expanded):
                        raise ValueError('invalid expanded symbol')
                    symbols.append(dict(index=i, address=addresses[i], type=expanded[0], name=expanded[1:]))
                return dict(addresses_offset=addresses_offset, count_offset=count_offset,
                            names_offset=names_offset, names_end=names_end,
                            markers_offset=marker_offset, markers_count=len(markers),
                            token_table_offset=token_offset, token_table_end=cursor,
                            token_index_offset=index_offset, symbol_count=count,
                            validation='all addresses, compressed names, markers, 256 tokens and 256 index entries checked',
                            symbols=symbols)
    raise ValueError('no matching complete markers/token table/index')


def recover(data, minimum=1024):
    accepted, candidates = [], []
    for start, count in address_runs(data, minimum):
        candidates.append(dict(addresses_offset=start, symbol_count=count))
        end = start + count * 4
        for count_offset in padded_starts(data, end):
            if count_offset + 4 > len(data) or u32(data, count_offset) != count:
                continue
            for names_offset in padded_starts(data, count_offset + 4):
                try:
                    result = validate_structure(data, start, count, count_offset, names_offset)
                except ValueError:
                    continue
                if not any(x['addresses_offset'] == start for x in accepted):
                    accepted.append(result)
    return accepted, candidates


def infer_mapping(data, symbols):
    """Anchor to embedded _text, then independently verify exported-name bytes."""
    bases = {s['address'] for s in symbols if s['name'] == '_text'}
    if len(bases) != 1:
        return None
    base = bases.pop()
    matches, mismatches = [], []
    for symbol in symbols:
        if not symbol['name'].startswith('__kstrtab_'):
            continue
        text = symbol['name'][len('__kstrtab_'):].encode('ascii') + b'\0'
        offset = symbol['address'] - base
        row = dict(symbol=symbol['name'], address=symbol['address'], file_offset=offset)
        if 0 <= offset <= len(data) - len(text) and data[offset:offset + len(text)] == text:
            matches.append(row)
        else:
            mismatches.append(row)
    if len(matches) < 10 or mismatches:
        return None
    return dict(base=base, method='_text anchor agrees with every __kstrtab_* exact name byte string',
                matched_export_strings=len(matches), mismatched_export_strings=0,
                examples=matches[:6])


def verify_input(path, metadata, section):
    rows = [r for r in metadata['kernels'] if r['section_index'] == section]
    if len(rows) != 1 or len(rows[0]['kernel_streams']) != 1:
        raise ValueError('expected exactly one recorded kernel stream')
    stream = rows[0]['kernel_streams'][0]
    data = path.read_bytes()
    if len(data) != stream['decompressed_bytes'] or hashlib.sha256(data).hexdigest() != stream['sha256']:
        raise ValueError('decoded kernel length/SHA-256 mismatch')
    return data, rows[0], stream


def handler_evidence(data, symbols, mapping, raw_output_dir):
    """Reproduce analyst-selected original ARM windows, only on validated mapping."""
    import capstone
    base = mapping['base']
    by_name = {s['name']: s for s in symbols}
    by_address = {}
    for symbol in symbols:
        by_address.setdefault(symbol['address'], []).append(symbol['name'])
    disassembler = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)

    def window(label, start, end):
        offset = start - base
        if offset < 0 or end - base > len(data) or start % 4 or end % 4:
            raise ValueError('invalid bounded ARM window')
        rows = []
        for insn in disassembler.disasm(data[offset:end - base], start):
            row = dict(address=hex(insn.address), file_offset=insn.address - base,
                       bytes=insn.bytes.hex(), mnemonic=insn.mnemonic, operands=insn.op_str)
            if insn.mnemonic in ('bl', 'b') and insn.op_str.startswith('#0x'):
                row['target_symbols'] = by_address.get(int(insn.op_str[1:], 16), [])
            literal = re.search(r'\[pc, #(-?0x[0-9a-f]+)\]', insn.op_str)
            if insn.mnemonic == 'ldr' and literal:
                address = insn.address + 8 + int(literal.group(1), 16)
                value = u32(data, address - base)
                row['literal'] = dict(address=hex(address), file_offset=address - base,
                                      value=hex(value), symbols=by_address.get(value, []))
            rows.append(row)
        return dict(label=label, address=hex(start), file_offset=offset, end_exclusive=hex(end), instructions=rows)

    # Offsets are bounded review selections relative to recovered named entries.
    selections = {
        'ipcc_ioctl': [('dispatch', 0, 0x84), ('write_record', 0x208, 0x294),
                       ('read_record', 0x294, 0x320), ('copy_input', 0xb10, 0xb64),
                       ('copy_write_output', 0xb98, 0xbb0), ('copy_read_output', 0xbe4, 0xbfc)],
        'd5_hevc_ioctl': [('dispatch', 0x8c, 0xd0), ('main_record', 0x414, 0x4c8),
                          ('copy_input', 0x7e4, 0x800), ('copy_output', 0x778, 0x790),
                          ('translate_8_12', 0x7c4, 0x7e4), ('translate_0_4', 0x6f4, 0x710)],
        'host_model_main': [('selectors', 0, 0x28), ('initialization', 0x104, 0x168)],
        'ipcc_probe': [('misc_register', 0xcc, 0xe4)],
        'd5_hevc_probe': [('misc_register', 0x98, 0xb8)],
    }
    windows, full_windows = [], []
    for name, ranges in selections.items():
        if name not in by_name or by_name[name]['type'] not in 'Tt':
            raise ValueError('expected recovered code symbol missing')
        start = by_name[name]['address']
        end = min(s['address'] for s in symbols if s['address'] > start)
        full_windows.append(window(name, start, end))
        for label, lo, hi in ranges:
            if start + hi > end:
                raise ValueError('selection crosses next symbol')
            windows.append(window(name + ':' + label, start + lo, start + hi))
    for name in ('_ipcc_read_srj', '_ipcc_write_srj'):
        start = by_name[name]['address']
        end = min(s['address'] for s in symbols if s['address'] > start)
        full_windows.append(window(name, start, end))
    full_path = raw_output_dir / 'kernel-2-handler-windows.json'
    full_path.write_text(json.dumps(full_windows, indent=2) + '\n')
    tables = []
    for name in ('ipcc_ops', 'd5_hevc_ops'):
        start = by_name[name]['address']
        entries = []
        for i in range(16):
            value = u32(data, start - base + i * 4)
            entries.append(dict(offset=i * 4, value=hex(value), symbols=by_address.get(value, [])))
        tables.append(dict(symbol=name, address=hex(start), file_offset=start - base, entries=entries))
    devices = []
    for name in ('ipcc_miscdev', 'd5_hevc_miscdev'):
        start = by_name[name]['address']
        minor, name_pointer, ops_pointer = struct.unpack_from('<3I', data, start - base)
        name_end = data.index(0, name_pointer - base)
        devices.append(dict(symbol=name, address=hex(start), file_offset=start - base,
                            first_three_words=[hex(minor), hex(name_pointer), hex(ops_pointer)],
                            name_string=dict(address=hex(name_pointer), file_offset=name_pointer - base,
                                             text=data[name_pointer - base:name_end].decode('ascii')),
                            ops_symbols=by_address.get(ops_pointer, [])))
    return dict(section_index=2, capstone_version=capstone.__version__, mapping=mapping,
                method='bounded original ARM32 little-endian instructions; direct-call labels only from validated embedded kallsyms',
                windows=windows, pointer_tables=tables, device_records=devices, full_windows_path=str(full_path),
                full_windows_sha256=hashlib.sha256(full_path.read_bytes()).hexdigest(),
                limitations=['All handler evidence concerns packaged section 2; active boot role unknown.',
                             'Linear next-symbol windows may include literal pools, not proven executable instructions.',
                             'Pointer table names/values do not alone establish C structure layout or live registration.'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel-dir', type=Path, required=True)
    parser.add_argument('--headers', type=Path, required=True)
    parser.add_argument('--raw-output-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--handler-output', type=Path)
    args = parser.parse_args()
    metadata = json.loads(args.headers.read_text())
    args.raw_output_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for section in (0, 2, 3):
        path = args.kernel_dir / f'kernel-{section}.raw'
        data, source, stream = verify_input(path, metadata, section)
        tables, candidates = recover(data)
        row = dict(section_index=section, binary_path=str(path), sha256=stream['sha256'],
                   bytes=len(data), source_section_sha256=source['section_sha256'],
                   compressed_stream_bin_offset=stream['offset_in_bin'],
                   address_candidates=candidates, validated_tables=[])
        strings = []
        for match in re.finditer(rb'[ -~]{5,}', data):
            if re.search(rb'ipcc|hevc|micom|drime5', match.group(), re.I):
                strings.append(dict(file_offset=match.start(), text=match.group().decode('ascii')))
        string_catalog = args.raw_output_dir / f'kernel-{section}-driver-strings.json'
        string_catalog.write_text(json.dumps(strings, indent=2) + '\n')
        row['driver_string_catalog'] = dict(path=str(string_catalog), count=len(strings),
                                            sha256=hashlib.sha256(string_catalog.read_bytes()).hexdigest())
        row['keyword_string_counts'] = {key: sum(key in x['text'].lower() for x in strings)
                                        for key in ('ipcc', 'hevc', 'micom', 'drime5')}
        row['selected_driver_strings'] = [x for x in strings if re.search(r'ipcc|hevc|micom', x['text'], re.I)][:24] + [x for x in strings if 'drime5' in x['text'].lower()][:4]
        row['aligned_literal_word_hits'] = {hex(value): [offset for offset in range(0, len(data) - 3, 4)
                                                         if u32(data, offset) == value]
                                            for value in (0xc0107406, 0xc0107407, 0xc10c7408, 0x80044d00, 0x80044d05)}
        for number, table in enumerate(tables):
            symbols = table.pop('symbols')
            catalog = args.raw_output_dir / f'kernel-{section}-symbols.json'
            catalog.write_text(json.dumps(symbols, indent=2) + '\n')
            table['catalog_path'] = str(catalog)
            table['catalog_sha256'] = hashlib.sha256(catalog.read_bytes()).hexdigest()
            table['mapping'] = infer_mapping(data, symbols)
            table['keyword_symbol_counts'] = {key: sum(key in s['name'].lower() for s in symbols)
                                               for key in ('ipcc', 'hevc', 'micom', 'drime5')}
            selected_names = {'ipcc_ioctl', 'ipcc_ops', 'ipcc_miscdev', '_conv_coretoid', '_ipcc_read_srj',
                              '_ipcc_write_srj', 'd5_hevc_ioctl', 'd5_hevc_ops', 'd5_hevc_miscdev',
                              'host_model_main', 'd5_uservirt_to_phys', '__copy_from_user', '__copy_to_user',
                              'hevc_init', 'setHEVCEncOption', 'Send_HOST_to_FW', 'Receive_FW_to_HOST', '_text', '_stext', 'stext'}
            table['selected_symbols'] = [s for s in symbols if s['name'] in selected_names]
            if section == 2 and args.handler_output:
                if table['mapping'] is None:
                    raise ValueError('handler review requires validated mapping')
                handlers = handler_evidence(data, symbols, table['mapping'], args.raw_output_dir)
                handlers['binary_path'], handlers['sha256'] = str(path), stream['sha256']
                args.handler_output.parent.mkdir(parents=True, exist_ok=True)
                args.handler_output.write_text(json.dumps(handlers, indent=2) + '\n')
            row['validated_tables'].append(table)
        row['status'] = 'validated absolute ARM32 kallsyms' if tables else 'no validated table in stated search envelope'
        rows.append(row)
    result = dict(schema_version=1, bin_sha256=metadata['bin_sha256'], method=__doc__,
                  search_envelope=dict(word_bits=32, endian='little', format='pre-relative absolute kallsyms',
                                       minimum_symbols=1024, address_min='0x80000000', address_max_exclusive='0xffff0000',
                                       maximum_address_span='0x10000000', maximum_zero_alignment_bytes=15),
                  kernels=rows,
                  limitations=['No recovered table is proof of loaded boot slot or live mapping.',
                               'No candidate found is not proof CONFIG_KALLSYMS is disabled.',
                               'Symbol names identify metadata; handler semantics need original instruction review.',
                               'Decoded offsets cannot be directly converted into compressed firmware BIN offsets.'])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print('Verified three kernel hashes; recovered %d complete kallsyms table(s)' % sum(len(r['validated_tables']) for r in rows))


if __name__ == '__main__':
    main()
