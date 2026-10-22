#!/usr/bin/env python3
"""Inventory available firmware bytes and inherited filesystem listings separately."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from elftools.elf.elffile import ELFFile


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def inventory_elf(path):
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        dyn = elf.get_section_by_name('.dynamic')
        needed, soname = [], None
        if dyn:
            for tag in dyn.iter_tags():
                if tag.entry.d_tag == 'DT_NEEDED':
                    needed.append(tag.needed)
                elif tag.entry.d_tag == 'DT_SONAME':
                    soname = tag.soname
        symbol_counts = {}
        for name in ('.dynsym', '.symtab'):
            section = elf.get_section_by_name(name)
            if section:
                symbol_counts[name] = section.num_symbols()
        return dict(machine=elf['e_machine'], elf_class=elf.elfclass,
                    little_endian=elf.little_endian, type=elf['e_type'],
                    entry=hex(elf['e_entry']), soname=soname, needed=needed,
                    symbol_tables=symbol_counts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--legacy', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--additional-manifest', type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((args.input / 'EVIDENCE_MANIFEST.json').read_text())
    files = []
    items = list(manifest['items'])
    if args.additional_manifest:
        items.extend(json.loads(args.additional_manifest.read_text())['items'])
    root=args.input.resolve(strict=True)
    identities, archive_paths = set(), set()
    for item in items:
        relative=Path(item['archive_path'])
        original=Path(item['original_path'])
        identity=(item['partition'],item['original_path'])
        if item['partition'] not in ('rootfs','opt') or not original.is_absolute() or '..' in original.parts:
            raise ValueError('Invalid firmware source identity')
        if relative.is_absolute() or '..' in relative.parts or str(relative)=='.':
            raise ValueError('Unsafe archive_path')
        if identity in identities or relative.as_posix() in archive_paths:
            raise ValueError('Duplicate firmware identity or archive_path')
        identities.add(identity); archive_paths.add(relative.as_posix())
        path=root/relative
        if not path.resolve(strict=True).is_relative_to(root) or not path.is_file():
            raise ValueError('archive_path escapes input or is not a regular file')
        if any(part.is_symlink() for part in (path,*list(path.parents)[:len(relative.parts)-1])):
            raise ValueError('Symlinks are not accepted as verified extracted bytes')
        row = dict(item, measured_sha256=sha256(path), measured_bytes=path.stat().st_size)
        row['manifest_matches'] = row['measured_sha256'] == item['sha256'] and row['measured_bytes'] == item['bytes']
        if not row['manifest_matches']:
            raise ValueError(f"Input mismatch: {item['archive_path']}")
        with path.open('rb') as stream:
            magic = stream.read(4)
        if magic == b'\x7fELF':
            row['elf'] = inventory_elf(path)
        row['byte_verification'] = 'measured_against_inherited_manifest'
        files.append(row)
    trees, summary = [], {}
    for partition in ('rootfs', 'opt'):
        path = args.legacy / f'{partition}_tree.json'
        tree = json.loads(path.read_text())
        summary[partition] = dict(entries=len(tree), types=dict(Counter(hex(x['type']) for x in tree)),
                                  source_sha256=sha256(path), verification='inherited_not_reextracted')
        trees.extend(dict(item, partition=partition, byte_status='not_yet_reextracted') for item in tree)
    edges = [dict(binary=x['archive_path'], needed=n) for x in files if 'elf' in x for n in x['elf']['needed']]
    for name, value in [('selected_inventory.json',files), ('filesystem_inventory.json',trees),
                        ('dependency_edges.json',edges), ('inventory_summary.json',dict(
                            available_files=len(files), available_elfs=sum('elf' in x for x in files),
                            selected_manifest_matches=all(x['manifest_matches'] for x in files),
                            filesystem_listings=summary, original_zip_revalidated=False,
                            whole_firmware_semantically_analyzed=False))]:
        (args.output / name).write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n')
    print((args.output / 'inventory_summary.json').read_text())


if __name__ == '__main__':
    main()
