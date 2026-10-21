#!/usr/bin/env python3
"""Record selected NX500 raw boot and shipped systemd evidence without target execution."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import zlib


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def verified_sections(blob, manifest):
    if len(blob) != manifest['bin_size'] or sha256(blob) != manifest['bin_sha256']:
        raise ValueError('Firmware size or SHA-256 mismatch')
    rows = {}
    for row in manifest['sections']:
        offset, length = row['offset_decimal'], row['length_bytes']
        if offset < 0 or length < 0 or offset + length > len(blob):
            raise ValueError('Section outside firmware')
        data = blob[offset:offset + length]
        if sha256(data) != row['sha256']:
            raise ValueError('Section SHA-256 mismatch')
        rows[row['index']] = (row, data)
    return rows


def selected_strings(data, pattern, origin=0):
    """Keep full printable runs, preserving exact offsets (including leading spaces)."""
    return [dict(offset_in_input=m.start(), absolute_file_offset=origin + m.start(),
                 text=m.group().decode('ascii'))
            for m in re.finditer(rb'[\x20-\x7e]{5,}', data)
            if re.search(pattern, m.group())]


def bounded_disassembly(data, start, end, mode, address_base=0, file_origin=0):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
    if not 0 <= start < end <= len(data):
        raise ValueError('Disassembly bounds outside input')
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM if mode == 'ARM' else CS_MODE_THUMB)
    md.detail = True
    instructions = []
    literal_registers = {}
    for ins in md.disasm(data[start:end], address_base + start):
        offset = ins.address - address_base
        row = dict(address=hex(ins.address), file_offset=file_origin + offset,
                   bytes=ins.bytes.hex(), mnemonic=ins.mnemonic, operands=ins.op_str)
        # Literal words are data, even when a linear decoder could render opcodes.
        from capstone.arm import ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC
        prior_literals = dict(literal_registers)
        for register in ins.regs_access()[1]:
            literal_registers.pop(register, None)
        if ins.mnemonic.startswith('ldr') and len(ins.operands) > 1:
            operand = ins.operands[1]
            if operand.type == ARM_OP_MEM and operand.mem.base == ARM_REG_PC:
                pc = ins.address + (8 if mode == 'ARM' else 4)
                if mode == 'THUMB':
                    pc &= ~3
                literal = pc + operand.mem.disp - address_base
                if 0 <= literal <= len(data) - 4:
                    row['pc_literal'] = dict(file_offset=file_origin + literal,
                                             value=hex(struct.unpack_from('<I', data, literal)[0]))
                    value = struct.unpack_from('<I', data, literal)[0]
                    literal_registers[ins.operands[0].reg] = value
                    pointed = value - address_base
                    if 0 <= pointed < len(data):
                        end_string = data.find(b'\0', pointed, pointed + 300)
                        text = data[pointed:end_string] if end_string >= 0 else b''
                        if text and all(32 <= x < 127 or x in (9, 10, 13) for x in text):
                            row['pc_literal']['points_to_ascii'] = dict(file_offset=file_origin + pointed, text=text.decode('ascii'))
        if ins.mnemonic == 'add' and len(ins.operands) == 2 and all(o.type == ARM_OP_REG for o in ins.operands):
            register = ins.operands[0].reg
            if ins.operands[1].reg == ARM_REG_PC and register in prior_literals:
                target = (prior_literals[register] + ins.address + (8 if mode == 'ARM' else 4)) & 0xffffffff
                offset = target - address_base
                if 0 <= offset < len(data):
                    end_string = data.find(b'\0', offset, offset + 300)
                    text = data[offset:end_string] if end_string >= 0 else b''
                    if text and all(32 <= x < 127 or x in (9, 10, 13) for x in text):
                        row['pc_relative_string'] = dict(address=hex(target), file_offset=file_origin + offset, text=text.decode('ascii'))
        if ins.mnemonic.startswith('bl'):
            literal_registers.clear()
        instructions.append(row)
    return dict(start_address=hex(address_base + start), end_address_exclusive=hex(address_base + end),
                mode=mode, instructions=instructions,
                bytes_covered=sum(len(bytes.fromhex(r['bytes'])) for r in instructions),
                requested_bytes=end - start)


RAW_RANGES = {
    1: [('startup_vbar', 0x80, 0x98), ('copy_string', 0x2740, 0x278c),
        ('linux_upgrade_selection', 0x38d4, 0x393c),
        ('linux_upgrade_join', 0x39a8, 0x39ac), ('root_argument_append', 0x40ec, 0x40f4),
        ('atag_command_line', 0x40f8, 0x41dc)],
    4: [('reset', 0x140, 0x158)],
    5: [('arm_reset_vector', 0, 0x1c), ('vector_base', 0x1e4, 0x1ec),
        ('kernel_banner_reference', 0x13968, 0x13984)],
}
ELF_RANGES = {
    'usr/lib/systemd/system-generators/systemd-fstab-generator': [
        ('main_output_argv1', 0xa2a0, 0xa2a8),
        ('add_mount_output', 0xa96c, 0xa9a0), ('parse_fstab_open', 0xaf44, 0xaf84)],
    'usr/lib/systemd/systemd': [
        ('generator_directories', 0x13bfe, 0x13c64),
        ('lookup_arguments', 0x13d28, 0x13d46),
        ('lookup_priority_paths', 0x45bf6, 0x45c48),
        ('lookup_environment_override', 0x45b58, 0x45b6a),
        ('pid1_generator_path', 0x1203e, 0x12056),
        ('priority_list_builder', 0x4a7c2, 0x4a7f6),
        ('lookup_priority_log', 0x45ba4, 0x45bbe),
        ('load_first_matching_path', 0x184c0, 0x18516),
        ('load_next_path_if_enoent', 0x185d2, 0x185e6)],
}


def elf_evidence(path, ranges):
    from elftools.elf.elffile import ELFFile
    data = path.read_bytes()
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        if elf['e_machine'] != 'EM_ARM' or not elf.little_endian:
            raise ValueError('Expected little-endian ARM ELF')
        segments = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD']
        def offset(va, size=1):
            for seg in segments:
                if seg['p_vaddr'] <= va and va + size <= seg['p_vaddr'] + seg['p_filesz']:
                    return seg['p_offset'] + va - seg['p_vaddr']
            raise ValueError('VA not file-backed')
        symbols = elf.get_section_by_name('.dynsym')
        imports = [dict(name=s.name, elf_va=hex(s['st_value'])) for s in symbols.iter_symbols()
                   if s.name in ('fopen64', 'getmntent', 'setmntent', '__fprintf_chk', 'open64')] if symbols else []
        code = []
        for label, lo, hi in ranges:
            off = offset(lo, hi - lo)
            # Use the full file as backing for PC literals beyond each code range.
            region = bounded_disassembly(data, off, off + hi - lo, 'THUMB', lo - off)
            region['label'] = label
            code.append(region)
        strings = []
        for sec in elf.iter_sections():
            if not sec['sh_flags'] & 2 or sec['sh_type'] == 'SHT_NOBITS':
                continue
            for row in selected_strings(sec.data(), rb'/etc/fstab|wxe|SourcePath=|higher priority first|SYSTEMD_UNIT_PATH|^/etc/systemd/system$|^/run/systemd/system$|^/usr/(local/)?lib/systemd/system$|^generator(\.early|\.late)?$|^lookup_paths_init$|^load_from_path$|^/usr/lib/systemd/system-generators$'):
                row['elf_va'] = hex(sec['sh_addr'] + row.pop('offset_in_input'))
                row['file_offset'] = sec['sh_offset'] + row.pop('absolute_file_offset')
                strings.append(row)
    return dict(path=str(path), sha256=sha256(data), selected_dynamic_symbols=imports, selected_strings=strings, code_regions=code,
                limitations='Original ELF link-time VAs; bounded linear Thumb disassembly and manual register/control-flow interpretation. No target execution or dynamic relocation simulation.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--kernel-dir', type=Path, required=True)
    parser.add_argument('--rootfs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--raw-output-dir', type=Path, required=True)
    args = parser.parse_args()
    blob = args.bin.read_bytes()
    manifest = json.loads(args.manifest.read_text())
    sections = verified_sections(blob, manifest)
    args.raw_output_dir.mkdir(parents=True, exist_ok=True)
    raw = []
    pattern = rb'DRIMe5|NX500|T-[Kk]ernel|Starting (A7|A9|M4)|root=|console=|hibernate=|noresume|user_debug=|snapshot boot|warm boot|cold boot|nvd_|/dev/mmcblk'
    for index in (1, 4, 5):
        spec, data = sections[index]
        origin = spec['offset_decimal']
        strings = selected_strings(data, pattern, origin)
        (args.raw_output_dir / f'section-{index}.strings.txt').write_text('\n'.join(
            f'{m.start():08x} {origin + m.start():08x} {m.group().decode("ascii")}'
            for m in re.finditer(rb'[\x20-\x7e]{5,}', data)) + '\n')
        code = []
        for label, lo, hi in RAW_RANGES[index]:
            row = bounded_disassembly(data, lo, hi, 'THUMB' if index == 4 else 'ARM', file_origin=origin)
            row['label'] = label
            code.append(row)
        raw.append(dict(section_index=index, bin_offset=origin, length=len(data), sha256=sha256(data),
                        first_words_le=[hex(x) for x in struct.unpack_from('<8I', data)],
                        selected_strings=strings, code_regions=code))
    kernels = []
    for index in (0, 2, 3):
        path = args.kernel_dir / f'kernel-{index}.raw'
        data = path.read_bytes()
        source_spec, source_data = sections[index]
        decoder = zlib.decompressobj(31)
        decoded = decoder.decompress(source_data[21952:], 128 * 1024 * 1024)
        if not decoder.eof or decoded != data:
            raise ValueError('Decoded kernel differs from verified section gzip stream')
        selected = selected_strings(data, rb'console=ttyAMA0|/dev/mmcblk0p[0-9]+')
        for row in selected:
            row['offset_in_decoded_file'] = row.pop('offset_in_input')
            row.pop('absolute_file_offset')
        kernels.append(dict(section_index=index, decoded_path=str(path), decoded_sha256=sha256(data),
                            source_section_sha256=source_spec['sha256'],
                            source_gzip_offset_in_bin=source_spec['offset_decimal'] + 21952,
                            selected_strings=selected,
                            offset_semantics='Offsets are within decoded gzip output, not absolute BIN offsets. The compressed stream/container anchors are in kernel-headers.json.'))
        (args.raw_output_dir / f'kernel-{index}-boot-strings.txt').write_text(json.dumps(selected, indent=2) + '\n')
    rootfs = []
    for rel in ('etc/fstab', 'etc/systemd/system/opt.mount', 'etc/systemd/system/opt-usr.mount'):
        path = args.rootfs / rel
        data = path.read_bytes()
        offset = 0
        lines = []
        for number, line in enumerate(data.splitlines(keepends=True), 1):
            if re.search(rb'nx1 partitions|mmcblk|/dev/root|^Where=|^What=', line):
                lines.append(dict(line=number, file_offset=offset, text=line.decode().rstrip('\r\n')))
            offset += len(line)
        rootfs.append(dict(path='/' + rel, sha256=sha256(data), selected_lines=lines))
    result = dict(bin_path=str(args.bin), bin_sha256=sha256(blob),
                  method='Manifest-verified exact section slices, printable-string offsets, bounded Capstone ARM/Thumb disassembly, original ELF PT_LOAD VA mapping; manual interpretation in companion report.',
                  raw_sections=raw, decoded_kernels=kernels, rootfs_configuration=rootfs,
                  shipped_elfs=[elf_evidence(args.rootfs / rel, ranges) for rel, ranges in ELF_RANGES.items()],
                  limitations='No camera access, target execution, device I/O, disk partition-table recovery or boot-slot observation. Raw section instruction addresses are SECTION OFFSETS, not verified runtime VAs. SLP section indices are not eMMC partition numbers. Printable matches and untraced code do not prove runtime selection.')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(f'Recorded {len(raw)} raw boot sections and {len(result["shipped_elfs"])} shipped ELF evidence sets')


if __name__ == '__main__':
    main()
