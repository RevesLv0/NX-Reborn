#!/usr/bin/env python3
"""Hash extracted firmware trees and describe static ELF dependency candidates.

Never follows extracted symlinks or executes target programs. Host inode numbers
are extraction identities, not original ext4 inode numbers. Runtime dependency
resolution is a static default-path model; environment and dlopen remain unknown.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import os
from pathlib import Path
import posixpath
import stat
from elftools.elf.elffile import ELFFile


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def elf_metadata(path):
    with path.open('rb') as stream:
        elf = ELFFile(stream)
        row = dict(machine=elf['e_machine'], elf_class=elf.elfclass,
                   little_endian=elf.little_endian, type=elf['e_type'],
                   entry=hex(elf['e_entry']), needed=[], soname=None,
                   rpath=None, runpath=None, interpreter=None)
        dynamic = elf.get_section_by_name('.dynamic')
        if dynamic:
            for tag in dynamic.iter_tags():
                name = tag.entry.d_tag
                if name == 'DT_NEEDED': row['needed'].append(tag.needed)
                elif name == 'DT_SONAME': row['soname'] = tag.soname
                elif name == 'DT_RPATH': row['rpath'] = tag.rpath
                elif name == 'DT_RUNPATH': row['runpath'] = tag.runpath
        for segment in elf.iter_segments():
            if segment['p_type'] == 'PT_INTERP':
                row['interpreter'] = segment.get_interp_name()
        row['symbol_tables'] = {}
        for name in ('.dynsym', '.symtab'):
            section = elf.get_section_by_name(name)
            if section:
                row['symbol_tables'][name] = section.num_symbols()
        modinfo = elf.get_section_by_name('.modinfo')
        if modinfo:
            row['module_info'] = [x.decode('utf-8', 'replace')
                                  for x in modinfo.data().split(b'\0') if x]
        return row


def scan_tree(root, partition):
    """Walk directories with lstat; symlink targets never become host read paths."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Extraction root must be a real directory')
    root = root.resolve(strict=True)
    rows, errors = [], []
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            children = sorted(os.scandir(directory), key=lambda x: x.name)
        except OSError as error:
            errors.append(dict(partition=partition, path='/' + directory.relative_to(root).as_posix(),
                               stage='list_directory', error=str(error)))
            continue
        for item in children:
            path = Path(item.path)
            relative = path.relative_to(root).as_posix()
            row = dict(partition=partition, original_path='/' + relative,
                       runtime_path=('/opt/' if partition == 'opt' else '/') + relative)
            try:
                info = item.stat(follow_symlinks=False)
                row.update(mode=oct(info.st_mode), extracted_bytes=info.st_size,
                           extracted_inode=info.st_ino, extracted_device=info.st_dev,
                           inode_provenance='host_extracted_tree_only')
                if stat.S_ISDIR(info.st_mode):
                    row['type'] = 'directory'; pending.append(path)
                elif stat.S_ISLNK(info.st_mode):
                    row['type'] = 'symlink'; row['target'] = os.readlink(path)
                elif stat.S_ISREG(info.st_mode):
                    row['type'] = 'regular'; row['sha256'] = digest(path)
                    with path.open('rb') as stream: magic = stream.read(4)
                    if magic == b'\x7fELF':
                        try: row['elf'] = elf_metadata(path)
                        except Exception as error:
                            errors.append(dict(partition=partition, path=row['original_path'],
                                               stage='parse_elf', error=str(error)))
                            row['elf_error'] = str(error)
                    if (relative.startswith(('etc/init', 'etc/systemd/', 'usr/lib/systemd/')) or
                            relative.endswith(('.service', '.socket', '.target'))):
                        row['configuration_role'] = 'boot_or_service_candidate'
                else:
                    row['type'] = ('char_device' if stat.S_ISCHR(info.st_mode) else
                                   'block_device' if stat.S_ISBLK(info.st_mode) else
                                   'fifo' if stat.S_ISFIFO(info.st_mode) else
                                   'socket' if stat.S_ISSOCK(info.st_mode) else 'other')
            except OSError as error:
                row['read_error'] = str(error)
                errors.append(dict(partition=partition, path=row['original_path'],
                                   stage='stat_or_read', error=str(error)))
            rows.append(row)
    return sorted(rows, key=lambda x: x['original_path']), errors


def normalize(path):
    return posixpath.normpath('/' + path.lstrip('/'))


def runtime_namespace(rows):
    """Apply the opt mount without treating hidden rootfs /opt bytes as installed."""
    namespace = {}
    for row in rows:
        path = row['runtime_path']
        if row['partition'] == 'rootfs' and path.startswith('/opt/'):
            continue
        namespace[path] = row
    return namespace


def resolve_virtual(path, namespace):
    """Resolve links in the firmware namespace, never using Path.resolve()."""
    path = normalize(path)
    seen = set()
    for _ in range(64):
        if path in seen: return None, 'symlink_cycle'
        seen.add(path)
        pieces = path.strip('/').split('/') if path != '/' else []
        changed = False
        for index in range(len(pieces)):
            prefix = '/' + '/'.join(pieces[:index + 1])
            item = namespace.get(prefix)
            if item and item.get('type') == 'symlink':
                target = item['target']
                if not target.startswith('/'):
                    target = posixpath.join(posixpath.dirname(prefix), target)
                path = normalize(posixpath.join(target, *pieces[index + 1:]))
                changed = True
                break
        if not changed:
            return (path, None) if path in namespace else (None, 'missing_path')
    return None, 'symlink_depth_exceeded'


def compatible(first, second):
    return all(first.get(key) == second.get(key)
               for key in ('machine', 'elf_class', 'little_endian'))


def join_source_tree(rows, source, partition):
    """Add native inode metadata, preserving unmaterialized device-node entries."""
    host = {row['original_path']: row for row in rows}
    joined, errors, names = [], [], set()
    for item in source:
        path = item['path']
        if (not path.startswith('/') or normalize(path) != path or path in names or
                any(ord(character) < 32 for character in path)):
            raise ValueError('Invalid or duplicate native source path')
        names.add(path)
        row = dict(host[path]) if path in host else dict(partition=partition, original_path=path,
            runtime_path=('/opt' if partition == 'opt' else '') + path, extracted=False)
        source_type = stat.S_IFMT(item['mode'])
        type_name = ('directory' if stat.S_ISDIR(item['mode']) else
                     'regular' if stat.S_ISREG(item['mode']) else
                     'symlink' if stat.S_ISLNK(item['mode']) else
                     'char_device' if stat.S_ISCHR(item['mode']) else
                     'block_device' if stat.S_ISBLK(item['mode']) else
                     'fifo' if stat.S_ISFIFO(item['mode']) else
                     'socket' if stat.S_ISSOCK(item['mode']) else 'other')
        row.update(source_inode=item['inode'], source_mode=oct(item['mode']),
                   source_uid=item['uid'], source_gid=item['gid'], source_bytes=item['size'],
                   source_type=type_name, source_metadata_method='native_debugfs_read_only_ls_by_inode')
        if source_type == stat.S_IFREG and 'sha256' in item:
            source_hash = item['sha256']
            if (len(source_hash) != 64 or any(character not in '0123456789abcdef'
                                              for character in source_hash)):
                raise ValueError('Invalid native source inode SHA256')
            row.update(source_sha256=source_hash,
                       source_byte_verification=item.get('byte_verification'),
                       source_bytes_match_extracted=row.get('sha256') == source_hash)
            if not row['source_bytes_match_extracted']:
                errors.append(dict(partition=partition, path=path, stage='source_join',
                                   error='source_inode_sha256_mismatch'))
        elif source_type == stat.S_IFLNK and 'link' in item:
            row.update(source_target=item['link'], source_link_matches_extracted=row.get('target') == item['link'])
            if not row['source_link_matches_extracted']:
                errors.append(dict(partition=partition, path=path, stage='source_join',
                                   error='source_symlink_target_mismatch'))
        elif source_type in (stat.S_IFCHR, stat.S_IFBLK):
            for field in ('device_major', 'device_minor'):
                if field in item: row['source_' + field] = item[field]
        if path in host:
            row['extracted'] = True
            if row.get('type') != type_name:
                errors.append(dict(partition=partition, path=path, stage='source_join', error='type_mismatch'))
            if source_type in (stat.S_IFREG, stat.S_IFLNK) and row.get('extracted_bytes') != item['size']:
                errors.append(dict(partition=partition, path=path, stage='source_join', error='size_mismatch'))
        else:
            row.update(type=type_name, byte_status='source_metadata_only_not_materialized')
            if source_type in (stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK):
                errors.append(dict(partition=partition, path=path, stage='source_join', error='missing_extracted_path'))
        joined.append(row)
    for path in sorted(set(host) - names):
        errors.append(dict(partition=partition, path=path, stage='source_join', error='unexpected_extracted_path'))
        joined.append(host[path])
    return sorted(joined, key=lambda row: row['original_path']), errors


def dependency_edges(rows, default_dirs=('/lib', '/usr/lib', '/usr/local/lib')):
    namespace = runtime_namespace(rows)
    sonames = defaultdict(list)
    for path, item in namespace.items():
        if item.get('elf', {}).get('soname'):
            sonames[item['elf']['soname']].append(path)
    edges = []
    for source in rows:
        elf = source.get('elf')
        if not elf: continue
        runtime = source['runtime_path']
        hidden = namespace.get(runtime) is not source
        custom = elf.get('runpath') if elf.get('runpath') is not None else elf.get('rpath')
        search, unsupported = [], []
        for directory in custom.split(':') if custom else []:
            directory = directory.replace('${ORIGIN}', posixpath.dirname(runtime)).replace(
                '$ORIGIN', posixpath.dirname(runtime))
            if not directory.startswith('/') or '$' in directory:
                unsupported.append(directory)
            else: search.append(normalize(directory))
        search.extend(default_dirs)
        for needed in elf['needed']:
            edge = dict(partition=source['partition'], binary=source['original_path'],
                        runtime_binary=runtime, binary_sha256=source['sha256'], needed=needed,
                        search_directories=search, unsupported_search_entries=unsupported,
                        status='unresolved', static_candidates=[])
            for candidate in sonames.get(needed, []):
                if compatible(elf, namespace[candidate]['elf']):
                    canonical, error = resolve_virtual(candidate, namespace)
                    edge['static_candidates'].append(dict(path=candidate, canonical=canonical,
                                                          symlink_error=error))
            locations = ([needed] if needed.startswith('/') else
                         [posixpath.join(directory, needed) for directory in search]
                         if '/' not in needed else [])
            failures = []
            if hidden:
                edge['status'] = 'hidden_by_opt_mount'
            else:
                for location in locations:
                    canonical, error = resolve_virtual(location, namespace)
                    if error:
                        if error != 'missing_path': failures.append(dict(path=location, error=error))
                        continue
                    target = namespace[canonical]
                    if target.get('elf') and compatible(elf, target['elf']):
                        edge.update(status='resolved_static_default_search', target=canonical,
                                    target_partition=target['partition'], target_sha256=target['sha256'])
                        break
                    failures.append(dict(path=location, error='not_compatible_elf'))
                else:
                    candidates = {x['canonical'] for x in edge['static_candidates'] if x['canonical']}
                    if len(candidates) == 1: edge['status'] = 'soname_candidate_outside_search'
                    elif len(candidates) > 1: edge['status'] = 'ambiguous_soname_candidates'
                    elif '/' in needed and not needed.startswith('/'):
                        edge['status'] = 'relative_needed_runtime_cwd_unknown'
            if failures: edge['lookup_errors'] = failures
            edges.append(edge)
    return edges


def inventory(rootfs, opt, output, images=None, source_trees=None):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    rows, errors = [], []
    for partition, root in (('rootfs', rootfs), ('opt', opt)):
        found, problems = scan_tree(root, partition)
        if source_trees and source_trees.get(partition):
            found, reconciliation = join_source_tree(found, json.loads(
                Path(source_trees[partition]).read_text()), partition)
            problems.extend(reconciliation)
        rows.extend(found); errors.extend(problems)
    edges = dependency_edges(rows)
    regular = [row for row in rows if row.get('type') == 'regular']
    symlinks = [row for row in rows if row.get('type') == 'symlink']
    elfs = [row for row in rows if 'elf' in row]
    source_inode_hashes = defaultdict(set)
    for row in regular:
        if 'source_inode' in row and 'sha256' in row:
            source_inode_hashes[(row['partition'], row['source_inode'])].add(row['sha256'])
    for (partition, inode), hashes in source_inode_hashes.items():
        if len(hashes) > 1:
            errors.append(dict(partition=partition, source_inode=inode, stage='source_inode_content',
                               error='same_source_inode_has_different_extracted_hashes'))
    elf_contents = {}
    for row in elfs:
        content = elf_contents.setdefault(row['sha256'], dict(sha256=row['sha256'],
            bytes=row['extracted_bytes'], elf=row['elf'], paths=[]))
        content['paths'].append(dict(partition=row['partition'], original_path=row['original_path'],
                                    runtime_path=row['runtime_path']))
    summary = dict(schema_version=1, path_entries=len(rows),
                   partitions={partition:dict(path_entries=sum(x['partition'] == partition for x in rows),
                       types=dict(Counter(x.get('type', 'error') for x in rows if x['partition'] == partition)))
                       for partition in ('rootfs', 'opt')},
                   regular_file_paths=len(regular), hashed_regular_file_paths=sum('sha256' in x for x in regular),
                   regular_paths_verified_against_source_inode=sum(
                       row.get('source_bytes_match_extracted') is True and
                       row.get('source_byte_verification') == 'native_debugfs_dump_by_source_inode_matches_rdump_file'
                       for row in regular),
                   symlink_paths=len(symlinks),
                   symlink_targets_verified_against_source=sum(row.get('source_link_matches_extracted') is True
                                                               for row in symlinks),
                   unique_regular_content_sha256=len({x['sha256'] for x in regular if 'sha256' in x}),
                   host_extracted_path_entries=sum(x.get('extracted', True) for x in rows),
                   metadata_only_source_paths=sum(x.get('extracted') is False for x in rows),
                   unique_extracted_regular_inodes=len({(x['partition'], x['extracted_device'], x['extracted_inode'])
                                                       for x in regular if 'extracted_inode' in x}),
                   elf_paths=len(elfs), unique_elf_contents=len({x['sha256'] for x in elfs}),
                   elf_types=dict(Counter(x['elf']['type'] for x in elfs)),
                   elf_machines=dict(Counter(x['elf']['machine'] for x in elfs)),
                   kernel_module_paths=sum('module_info' in x['elf'] for x in elfs),
                   dependency_edges=len(edges), dependency_status=dict(Counter(x['status'] for x in edges)),
                   errors=len(errors), inode_provenance=('separate_host_extracted_inode_and_native_source_inode'
                       if source_trees and any(source_trees.values()) else 'host_extracted_tree_only'),
                   source_inode_inventory_complete=bool(source_trees and all(source_trees.get(x)
                       for x in ('rootfs', 'opt')) and not errors),
                   extraction_completeness='Requires independent source directory/inode comparison',
                   whole_firmware_semantically_analyzed=False,
                   dependency_limitations='Static rootfs + mounted /opt namespace; default /lib /usr/lib /usr/local/lib plus object RPATH/RUNPATH. Does not model ld.so.cache, inherited RPATH, LD_LIBRARY_PATH, dlopen or runtime mount changes. SONAME candidates outside search are not resolved calls.')
    if images:
        summary['source_images'] = {name:dict(bytes=Path(path).stat().st_size, sha256=digest(Path(path)))
                                    for name, path in images.items() if path}
    if source_trees:
        summary['source_tree_metadata'] = {name:dict(sha256=digest(Path(path)))
                                           for name, path in source_trees.items() if path}
        summary['unique_source_regular_inodes'] = len({(row['partition'], row['source_inode'])
                                                       for row in regular if 'source_inode' in row})
        summary['all_regular_data_and_symlink_targets_source_verified'] = bool(
            summary['source_inode_inventory_complete'] and
            summary['regular_paths_verified_against_source_inode'] == len(regular) and
            summary['symlink_targets_verified_against_source'] == len(symlinks))
        summary['source_inventory_limitation'] = ('Source inode SHA256 from native debugfs dump is separately '
            'compared with extracted rdump-file SHA256, and native symlink targets are compared with readlink. '
            'Both extraction paths use the same debugfs implementation; this is not an independent filesystem '
            'parser or runtime verification. Host ownership/modes are not authoritative.')
        if summary['source_inode_inventory_complete']:
            summary['extraction_completeness'] = 'Every source path inventoried; ordinary file/directory/symlink path types and sizes match. Special nodes may be source metadata only.'
    for name, value in (('full_filesystem_inventory.json', rows), ('full_dependency_edges.json', edges),
                        ('full_elf_contents.json', list(elf_contents.values())),
                        ('full_inventory_errors.json', errors), ('full_inventory_summary.json', summary)):
        (output / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', type=Path, required=True)
    parser.add_argument('--opt', type=Path, required=True)
    parser.add_argument('--rootfs-image', type=Path)
    parser.add_argument('--opt-image', type=Path)
    parser.add_argument('--rootfs-source-tree', type=Path)
    parser.add_argument('--opt-source-tree', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = inventory(args.rootfs, args.opt, args.output,
                       dict(rootfs=args.rootfs_image, opt=args.opt_image),
                       dict(rootfs=args.rootfs_source_tree, opt=args.opt_source_tree))
    raise SystemExit(1 if result['errors'] else 0)


if __name__ == '__main__': main()
