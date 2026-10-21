#!/usr/bin/env python3
"""Read extracted boot configuration without executing target files or following links.

Configured unit edges are declarations; they are not an observed systemd transaction.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path

UNIT_DIRS = ('etc/systemd/system', 'usr/lib/systemd/system')
EDGE_KEYS = ('After', 'Before', 'Wants', 'Requires', 'Requisite', 'BindsTo', 'Conflicts')
SELECTED = (
    'etc/fstab', 'initrd/sbin/init', 'usr/bin/hibernation.sh',
    'usr/sbin/fw_upgrade_start', 'usr/sbin/fw_upgrade_display.sh',
    'etc/dbus-1/system.conf', 'etc/deviced/mmc.conf', 'etc/modules',
    'etc/modprobe.conf', 'etc/inittab', 'usr/bin/allshare-dms.sh',
    'usr/bin/hib_tmp.sh', 'etc/init.d/rd3starter',
    'usr/share/dbus-1/services/net.connman.service',
    'usr/share/dbus-1/services/net.netconfig.service',
)


def walk_no_links(root):
    """Yield paths, retaining symlinks as entries and never traversing them."""
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            yield Path(directory) / name


def parse_unit(text):
    section = ''
    rows = []
    pending = ''
    start = 0
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(('#', ';')):
            continue
        if not pending:
            start = number
        pending += line
        if pending.endswith('\\'):
            pending = pending[:-1] + ' '
            continue
        line, pending = pending, ''
        if line.startswith('[') and line.endswith(']'):
            section = line[1:-1]
        elif '=' in line:
            key, value = line.split('=', 1)
            rows.append(dict(section=section, key=key.strip(), value=value.strip(), line=start))
    return rows


def file_record(root, path):
    data = path.read_bytes()
    record = dict(path='/' + path.relative_to(root).as_posix(), bytes=len(data),
                  sha256=hashlib.sha256(data).hexdigest())
    if b'\0' in data:
        record['text_status'] = 'binary; line evidence not generated'
    else:
        record['lines'] = [dict(line=i, text=line) for i, line in
                           enumerate(data.decode('utf-8', errors='replace').splitlines(), 1)]
    return record


def catalog(root):
    root = root.resolve()
    units, links, edges, selected = [], [], [], []
    for unit_dir in UNIT_DIRS:
        base = root / unit_dir
        if base.is_symlink() or not base.is_dir():
            continue
        for path in walk_no_links(base):
            firmware_path = '/' + path.relative_to(root).as_posix()
            if path.is_symlink():
                links.append(dict(path=firmware_path, target=os.readlink(path)))
            elif path.is_file():
                record = file_record(root, path)
                record['directives'] = parse_unit('\n'.join(row['text'] for row in record.pop('lines', [])))
                units.append(record)
                for row in record['directives']:
                    if row['section'] == 'Unit' and row['key'] in EDGE_KEYS:
                        for target in row['value'].split():
                            edges.append(dict(source=firmware_path, relation=row['key'],
                                              target=target, line=row['line']))
    for relative in SELECTED:
        path = root / relative
        # Refuse any link component, including an absolute target that the host
        # would otherwise resolve outside the extracted image.
        if any(p.is_symlink() for p in (path, *list(path.parents)[:len(Path(relative).parts)-1])):
            continue
        if path.is_file():
            selected.append(file_record(root, path))
    modules = []
    base = root / 'lib/modules'
    if base.is_dir() and not base.is_symlink():
        for path in walk_no_links(base):
            if path.is_file() and not path.is_symlink():
                data = path.read_bytes()
                if path.suffix == '.ko':
                    modinfo = []
                    offset = 0
                    for value in data.split(b'\0'):
                        if value.startswith((b'vermagic=', b'depends=', b'name=', b'alias=')):
                            modinfo.append(dict(file_offset=offset,
                                                value=value.decode('utf-8', errors='replace')))
                        offset += len(value) + 1
                    modules.append(dict(path='/' + path.relative_to(root).as_posix(),
                                        sha256=hashlib.sha256(data).hexdigest(), modinfo=modinfo))
    namespace_links = []
    for relative in ('sbin/init', 'sdcard', 'pref'):
        path = root / relative
        if path.is_symlink():
            namespace_links.append(dict(path='/' + relative, target=os.readlink(path)))
    return dict(schema_version=1, method='read extracted configuration and raw module strings; no target execution',
                limitations=['Unit declarations are not evaluated as a systemd transaction.',
                             'No runtime target selection, conditions, generator output or D-Bus traffic observed.',
                             'Module metadata strings are not proof of module loading.'],
                units=units, symlinks=links, namespace_symlinks=namespace_links, declared_unit_edges=edges,
                selected_sources=selected, modules=modules)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rootfs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = catalog(args.rootfs)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({key: len(result[key]) for key in
                      ('units', 'symlinks', 'declared_unit_edges', 'selected_sources', 'modules')}))


if __name__ == '__main__':
    main()
