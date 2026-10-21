#!/usr/bin/env python3
"""Inventory ext filesystems with native read-only debugfs and check an rdump tree.

Source inode/mode/owner metadata stays in JSON; host ownership is not authoritative.
The extractor never executes camera files and never follows extracted symlinks.
"""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from full_slp import digest

ENTRY = re.compile(r'^/(\d+)/([0-7]+)/([0-9]+)/([0-9]+)/([^/]*)/([0-9]*)/$')
COMMAND = re.compile(r'^debugfs: ls -p <(\d+)>$')


def list_entries(text):
    result = {}
    current = None
    for line in text.splitlines():
        if not line:
            continue
        command = COMMAND.fullmatch(line)
        if command:
            current = int(command[1])
            if current in result:
                raise ValueError('Duplicate debugfs command result')
            result[current] = []
            continue
        item = ENTRY.fullmatch(line)
        if current is None or not item:
            raise ValueError('Unrecognized debugfs listing: ' + line[:160])
        inode, mode, uid, gid, name, size = item.groups()
        if int(inode) == 0:
            continue  # unused/deleted directory slot, not a live source path
        if not name:
            raise ValueError('Live directory entry has an empty name')
        if name in ('.', '..'):
            continue
        if any(ord(x) < 32 or ord(x) == 127 for x in name):
            raise ValueError('Control character in source filename')
        result[current].append(dict(inode=int(inode), mode=int(mode, 8), uid=int(uid), gid=int(gid),
                                    name=name, size=int(size) if size else None))
    return result


def run_debugfs(debugfs, image, commands, env):
    process = subprocess.run([str(debugfs), '-f', '/dev/stdin', str(image)], input='\n'.join(commands)+'\n',
                             text=True, encoding='utf-8', errors='strict', capture_output=True, env=env, check=True)
    errors = [line for line in process.stderr.splitlines() if line and not line.startswith('debugfs ')]
    if errors:
        raise ValueError('debugfs reported an error: ' + '\n'.join(errors[:20]))
    return process.stdout


def inventory(debugfs, image, env, limit=100000):
    pending = [('', 2)]
    seen_dirs = {2}
    result = []
    while pending:
        wave, pending = pending, []
        for start in range(0, len(wave), 256):
            batch = wave[start:start+256]
            listings = list_entries(run_debugfs(debugfs, image, [f'ls -p <{inode}>' for _, inode in batch], env))
            if set(listings) != {inode for _, inode in batch}:
                raise ValueError('Missing debugfs listing')
            for prefix, inode in batch:
                names = set()
                for item in listings[inode]:
                    if item['name'] in names:
                        raise ValueError('Duplicate source directory name')
                    names.add(item['name'])
                    row = dict(item, path=prefix+'/'+item['name'], type=stat.S_IFMT(item['mode']))
                    result.append(row)
                    if len(result) > limit:
                        raise ValueError('Directory inventory limit exceeded; no partial result accepted')
                    if stat.S_ISDIR(row['mode']):
                        if row['inode'] in seen_dirs:
                            raise ValueError('Directory inode cycle/multiple links')
                        seen_dirs.add(row['inode'])
                        pending.append((row['path'], row['inode']))
    return sorted(result, key=lambda row: row['path'])


def enrich_metadata(rows, debugfs, image, env):
    inodes = sorted({row['inode'] for row in rows if row['type'] != stat.S_IFREG})
    metadata = {}
    for start in range(0, len(inodes), 256):
        batch = inodes[start:start+256]
        output = run_debugfs(debugfs, image, [f'stat <{inode}>' for inode in batch], env)
        for block in output.split('debugfs: stat <')[1:]:
            inode = int(block.split('>', 1)[0])
            size = re.search(r'^User:.*?Size: (\d+)', block, re.MULTILINE)
            if not size or f'Inode: {inode} ' not in block:
                raise ValueError('Missing inode stat size/identity')
            item = dict(size=int(size[1]))
            link = re.search(r'^Fast link dest: "(.*)"$', block, re.MULTILINE)
            if link:
                item['link'] = link[1]
                if len(os.fsencode(item['link'])) != item['size']:
                    raise ValueError('Symlink stat target length mismatch')
            device = re.search(r'Device major/minor number: .*?\(hex ([0-9a-fA-F]+):([0-9a-fA-F]+)\)', block)
            if device:
                item.update(device_major=int(device[1], 16), device_minor=int(device[2], 16))
            metadata[inode] = item
        if not set(batch).issubset(metadata):
            raise ValueError('Incomplete inode stat results')
    for row in rows:
        row.update(metadata.get(row['inode'], {}))
        if row['type'] == stat.S_IFLNK and 'link' not in row:
            raise ValueError('Long/non-fast source symlink unsupported; not silently accepted')


def verify_regular_bytes(rows, root, debugfs, image, env):
    groups = {}
    for row in rows:
        if row['type'] == stat.S_IFREG:
            groups.setdefault(row['inode'], []).append(row)
    inodes = sorted(groups)
    with tempfile.TemporaryDirectory(prefix='nx-source-readback-') as scratch:
        for start in range(0, len(inodes), 128):
            batch = inodes[start:start+128]
            run_debugfs(debugfs, image, [f'dump <{inode}> {scratch}/{inode}' for inode in batch], env)
            for inode in batch:
                native = Path(scratch)/str(inode)
                value = digest(native)
                for row in groups[inode]:
                    if native.stat().st_size != row['size'] or digest(root/row['path'].lstrip('/')) != value:
                        raise ValueError('Source inode vs extracted file byte mismatch: ' + row['path'])
                    row['sha256'] = value
                    row['byte_verification'] = 'native_debugfs_dump_by_source_inode_matches_rdump_file'
                native.unlink()
    return dict(regular_paths_verified=sum(len(x) for x in groups.values()),
                unique_source_inodes_verified=len(inodes), byte_hashes_verified=True)


def check_tree(rows, root):
    root = root.resolve(strict=True)
    expected = {row['path']: row for row in rows}
    actual = {}
    def walk(path, prefix=''):
        with os.scandir(path) as entries:
            for entry in entries:
                key = prefix+'/'+entry.name
                actual[key] = entry.stat(follow_symlinks=False)
                if entry.is_dir(follow_symlinks=False):
                    walk(Path(entry.path), key)
    walk(root)
    missing = sorted(set(expected)-set(actual))
    omitted_special = [path for path in missing if expected[path]['type'] not in (stat.S_IFDIR, stat.S_IFREG, stat.S_IFLNK)]
    missing_materializable = sorted(set(missing)-set(omitted_special))
    extra = sorted(set(actual)-set(expected))
    errors = []
    for path in sorted(set(expected) & set(actual)):
        row, host = expected[path], actual[path]
        if stat.S_IFMT(host.st_mode) != row['type']:
            errors.append(dict(path=path, error='type_mismatch'))
        elif row['type'] in (stat.S_IFREG, stat.S_IFLNK) and host.st_size != row['size']:
            errors.append(dict(path=path, error='size_mismatch', source_size=row['size'], host_size=host.st_size))
        elif row['type'] == stat.S_IFLNK and 'link' in row and os.readlink(root/path.lstrip('/')) != row['link']:
            errors.append(dict(path=path, error='symlink_target_mismatch'))
    return dict(source_paths=len(rows), host_paths=len(actual), source_types=dict(Counter(oct(row['type']) for row in rows)),
                missing=missing, extra=extra, errors=errors, all_paths_types_sizes_match=not (missing or extra or errors),
                missing_materializable=missing_materializable, unmaterialized_special_paths=omitted_special,
                all_regular_directory_symlink_paths_match=not (missing_materializable or extra or errors),
                metadata_warning='Host owner/mode/timestamps may differ; use source inode metadata in this inventory',
                byte_hashes_verified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--debugfs', type=Path, required=True)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--library-dir', type=Path)
    parser.add_argument('--tree', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--verify-regular-bytes', action='store_true', help='Read every regular source inode with dump and compare SHA-256')
    args = parser.parse_args()
    env = os.environ.copy()
    if args.library_dir:
        env['LD_LIBRARY_PATH'] = str(args.library_dir.resolve())
    version_result = subprocess.run([str(args.debugfs.resolve()), '-V'], text=True,
                                    capture_output=True, env=env, check=True)
    version_lines = (version_result.stdout + version_result.stderr).splitlines()
    tool_version = next((line for line in version_lines if line.startswith('debugfs ')), None)
    if tool_version is None:
        raise ValueError('Cannot establish debugfs version')
    rows = inventory(args.debugfs.resolve(), args.image.resolve(), env)
    enrich_metadata(rows, args.debugfs.resolve(), args.image.resolve(), env)
    report = check_tree(rows, args.tree)
    if args.verify_regular_bytes and report['all_regular_directory_symlink_paths_match']:
        report.update(verify_regular_bytes(rows, args.tree.resolve(), args.debugfs.resolve(), args.image.resolve(), env))
    report.update(source_image_bytes=args.image.stat().st_size, source_image_sha256=digest(args.image),
                  debugfs_version=tool_version,
                  source_method='native debugfs read-only ls -p/stat/dump by inode; no host symlink traversal')
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output/'source-tree.json').write_text(json.dumps(rows, indent=2)+'\n')
    (args.output/'extraction-check.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))
    if not report['all_regular_directory_symlink_paths_match']:
        raise SystemExit('Extraction check failed')


if __name__ == '__main__':
    main()
