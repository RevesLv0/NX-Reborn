#!/usr/bin/env python3
"""Catalog named ELF symbols once per source SHA without running firmware code."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def versions(elf):
    result = {}
    section = elf.get_section_by_name('.gnu.version_r')
    if section:
        for required, auxiliaries in section.iter_versions():
            for auxiliary in auxiliaries:
                result[auxiliary['vna_other'] & 0x7fff] = dict(name=auxiliary.name, provider=required.name, kind='required')
    section = elf.get_section_by_name('.gnu.version_d')
    if section:
        for definition, auxiliaries in section.iter_versions():
            names = [a.name for a in auxiliaries]
            result[definition['vd_ndx'] & 0x7fff] = dict(name=names[0] if names else None, kind='defined')
    return result


def inspect(path):
    with Path(path).open('rb') as stream:
        elf = ELFFile(stream)
        version_names = versions(elf)
        version_section = elf.get_section_by_name('.gnu.version')
        rows, tables = [], {}
        for table in elf.iter_sections():
            if not isinstance(table, SymbolTableSection):
                continue
            tables[table.name] = table.num_symbols()
            for index, symbol in enumerate(table.iter_symbols()):
                name = symbol.name
                kind, binding = symbol['st_info']['type'], symbol['st_info']['bind']
                if not name or kind in ('STT_FILE', 'STT_SECTION') or name in ('$a', '$t', '$d') or name.startswith(('$a.', '$t.', '$d.')):
                    continue
                defined = symbol['st_shndx'] != 'SHN_UNDEF'
                value = symbol['st_value']
                function = kind in ('STT_FUNC',)
                version = None
                if table.name == '.dynsym' and version_section:
                    raw = version_section.get_symbol(index)['ndx']
                    if isinstance(raw, int):
                        version = dict(index=raw & 0x7fff, hidden=bool(raw & 0x8000), **version_names.get(raw & 0x7fff, {}))
                rows.append(dict(name=name, table=table.name, symbol_index=index, symbol_type=kind,
                                 binding=binding, visibility=symbol['st_other']['visibility'],
                                 defined=defined, section_index=symbol['st_shndx'], value=hex(value), bytes=symbol['st_size'],
                                 address_kind='section_relative' if elf['e_type'] == 'ET_REL' else 'original_elf_va',
                                 code_address=hex(value & ~1) if function and elf['e_machine'] == 'EM_ARM' else hex(value),
                                 arm_thumb_bit=bool(value & 1) if function and elf['e_machine'] == 'EM_ARM' else None,
                                 version=version,
                                 dynamic_export_candidate=defined and table.name == '.dynsym' and binding in ('STB_GLOBAL', 'STB_WEAK', 'STB_GNU_UNIQUE') and symbol['st_other']['visibility'] in ('STV_DEFAULT', 'STV_PROTECTED')))
        functions = [r for r in rows if r['defined'] and r['symbol_type'] in ('STT_FUNC',)]
        addresses = {(r['section_index'], r['code_address']) for r in functions}
        return rows, dict(machine=elf['e_machine'], type=elf['e_type'], tables=tables,
                          named_symbol_entries=len(rows), named_function_symbol_entries=len(functions),
                          distinct_declared_function_locations=len(addresses),
                          dynamic_import_entries=sum(r['table'] == '.dynsym' and not r['defined'] for r in rows),
                          dynamic_export_candidates=sum(r['dynamic_export_candidate'] for r in rows))


def source_path(root, relative):
    logical = PurePosixPath(relative)
    if not logical.is_absolute() or '..' in logical.parts:
        raise ValueError('Unsafe original path')
    root = Path(root).resolve(strict=True)
    path = root.joinpath(*logical.parts[1:])
    part = root
    for component in logical.parts[1:]:
        part = part / component
        if part.is_symlink():
            raise ValueError('Symlink in source path')
    if not path.is_file():
        raise ValueError('Source is not a regular file')
    return path


def catalog(inventory, roots, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    # A failed refresh must not leave an apparently current complete catalog.
    (output / 'named_symbols.jsonl').unlink(missing_ok=True)
    (output / 'symbol_summary.json').write_text(json.dumps(dict(completed=False, state='running')) + '\n')
    grouped = {}
    for row in inventory:
        if row.get('elf'):
            grouped.setdefault(row['sha256'], []).append(row)
    programs, errors, totals = [], [], Counter()
    partial = output / 'named_symbols.jsonl.partial'
    with partial.open('w') as writer:
        for digest, aliases in sorted(grouped.items()):
            aliases = sorted(aliases, key=lambda r: (r['partition'], r['original_path']))
            item = aliases[0]
            try:
                path = source_path(roots[item['partition']], item['original_path'])
                if sha256(path) != digest:
                    raise ValueError('Source SHA-256 mismatch')
                symbols, info = inspect(path)
                paths = [dict(partition=r['partition'], original_path=r['original_path']) for r in aliases]
                programs.append(dict(sha256=digest, paths=paths, **info))
                totals.update({key: info[key] for key in ('named_symbol_entries', 'named_function_symbol_entries', 'distinct_declared_function_locations', 'dynamic_import_entries', 'dynamic_export_candidates')})
                for symbol in symbols:
                    writer.write(json.dumps(dict(sha256=digest, **symbol), separators=(',', ':')) + '\n')
            except Exception as error:
                errors.append(dict(sha256=digest, partition=item['partition'], original_path=item['original_path'], error_type=type(error).__name__, error=str(error)))
    summary = dict(schema_version=1, expected_unique_elf_contents=len(grouped), cataloged_unique_elf_contents=len(programs),
                   error_count=len(errors), completed=not errors, totals=dict(totals),
                   limitations='Declared ELF symbol metadata only; function counts use STT_FUNC, preserving OS-specific types separately without interpreting them. Tables may duplicate names/locations; stripped or hidden implementation functions are absent. Dynamic export candidates do not prove binding or calls. ET_REL values are section-relative; other values are original ELF VAs, not file offsets. ARM Thumb low bits are preserved separately. No semantic completion percentage.')
    if not errors:
        partial.replace(output / 'named_symbols.jsonl')
        summary['catalog_sha256'] = sha256(output / 'named_symbols.jsonl')
    for name, value in [('symbol_programs.json', programs), ('symbol_errors.json', errors), ('symbol_summary.json', summary)]:
        (output / name).write_text(json.dumps(value, indent=2) + '\n')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--rootfs', type=Path, required=True)
    parser.add_argument('--opt', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = catalog(json.loads(args.inventory.read_text()), dict(rootfs=args.rootfs, opt=args.opt), args.output)
    print(json.dumps(result, indent=2))
    if not result['completed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
