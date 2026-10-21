#!/usr/bin/env python3
"""Restore hash-pinned Debian amd64 LZO/e2fsprogs into ignored workspace storage."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work', type=Path, default=Path('.work'))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    tools = args.work.resolve() / 'tools'
    downloads, native = tools / 'debs', tools / 'native'
    downloads.mkdir(parents=True, exist_ok=True)
    native.mkdir(parents=True, exist_ok=True)
    packages = json.loads((root / 'manifests/native-tools.json').read_text())
    for item in packages:
        archive = downloads / item['url'].rsplit('/', 1)[1]
        if not archive.exists():
            partial = archive.with_suffix('.partial')
            with urllib.request.urlopen(item['url'], timeout=90) as response, partial.open('wb') as output:
                while chunk := response.read(1024 * 1024):
                    output.write(chunk)
            with partial.open('rb') as stream:
                downloaded_digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            if downloaded_digest != item['sha256']:
                raise ValueError(f"Package hash mismatch: {item['package']}")
            partial.replace(archive)
        with archive.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if archive.stat().st_size != item['bytes'] or digest != item['sha256']:
            raise ValueError(f"Package integrity mismatch: {item['package']}")
        subprocess.run(['dpkg-deb', '-x', str(archive), str(native)], check=True)
    print(f'Native tools restored to {native}; use its usr/lib/x86_64-linux-gnu as LD_LIBRARY_PATH')


if __name__ == '__main__':
    main()
