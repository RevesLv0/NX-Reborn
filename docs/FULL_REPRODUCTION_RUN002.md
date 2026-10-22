# Reproduce whole-source extraction and inventory

Linux x86_64, Python 3.12 and `dpkg-deb`. Host analysis tools are used below;
extracted camera executables are never run. Use a new ignored work directory for
a fresh reproduction; reconstruction/decode refuse to overwrite completed outputs.

## Inputs and pinned tools

Read `manifests/full-source-layout.json`. Fetch its four `deliverables` by their
recorded Drive IDs using the connected Drive metadata/fetch tools, then materialize
fresh authenticated references into `.work/downloads/`. Do not retain signed URLs
in Git or reuse expired references. Two different rootfs split families exist in
Drive; use only the four filenames, sizes, ordering and hashes in this manifest.
The connector may append `.bin` to `.binpart`; restore the exact manifest filename.
Original preserved files remain in `1차 시도`; do not move or duplicate them in Drive.

```sh
python tools/bootstrap_research.py --work .work
python tools/bootstrap_native.py --work .work
python tools/firmware/full_slp.py reconstruct \
  --manifest manifests/full-source-layout.json --input .work/downloads \
  --output .work/full/NX500.bin --receipt .work/full/reconstruction.json
```

The native bootstrap restores e2fsprogs 1.47.2 and liblzo2 2.10 with pinned package
SHA-256s. It does not install system packages or change environment configuration.

## Decode every LZOP section

```sh
python - <<'PY'
import json, pathlib, subprocess, sys
m = json.loads(pathlib.Path('manifests/full-source-layout.json').read_text())
for index, name in [(6, 'rootfs'), (7, 'opt'), (9, 'swap')]:
    section, expected = m['sections'][index], m['decompressed'][str(index)]
    suffix = 'raw' if name == 'swap' else 'ext4'
    subprocess.run([sys.executable, 'tools/firmware/full_slp.py', 'decode',
        '--input', '.work/full/NX500.bin', '--offset', str(section['offset_decimal']),
        '--length', str(section['length_bytes']), '--expected-bytes', str(expected['bytes']),
        '--expected-sha256', expected['sha256'],
        '--lzo-library', '.work/tools/native/usr/lib/x86_64-linux-gnu/liblzo2.so.2',
        '--output', f'.work/full/{name}.{suffix}', '--receipt', f'.work/full/{name}-decode.json'], check=True)
PY
```

## Extract and independently read back each reachable source inode

```sh
for partition in rootfs opt; do
  mkdir -p ".work/full/extracted/$partition"
  LD_LIBRARY_PATH=.work/tools/native/usr/lib/x86_64-linux-gnu \
    .work/tools/native/usr/sbin/debugfs \
    -R "rdump / .work/full/extracted/$partition" ".work/full/$partition.ext4" \
    > ".work/full/$partition-rdump.stdout.log" 2> ".work/full/$partition-rdump.stderr.log"
  python tools/firmware/native_ext4.py \
    --debugfs .work/tools/native/usr/sbin/debugfs \
    --library-dir .work/tools/native/usr/lib/x86_64-linux-gnu \
    --image ".work/full/$partition.ext4" --tree ".work/full/extracted/$partition" \
    --verify-regular-bytes --output ".work/full/$partition-native"
done
```

Unprivileged rdump reported inability to restore original ownership and create
12 character devices in this run. Native path/type/size checks, regular inode
dump hashes and symlink target readback are the completion gates; a debugfs
exit code alone is insufficient. Keep original inode/owner/mode/device metadata
in the source-tree JSON. Both dump paths share debugfs; no independent ext4
implementation or runtime behavior is claimed.

Optionally repeat `e2fsck -fn` using the same native library path and preserve
logs, return code and before/after image hashes. Run002 rootfs returned 0; opt
returned 4 for an xattr block reference count discrepancy, with journal recovery
skipped in read-only mode. Both image hashes remained unchanged. Do not substitute
a repaired image for these inputs.

## Inventory and static analysis

```sh
PYTHONPATH=.work/python python tools/firmware/full_inventory.py \
  --rootfs .work/full/extracted/rootfs --opt .work/full/extracted/opt \
  --rootfs-image .work/full/rootfs.ext4 --opt-image .work/full/opt.ext4 \
  --rootfs-source-tree .work/full/rootfs-native/source-tree.json \
  --opt-source-tree .work/full/opt-native/source-tree.json --output .work/full/inventory
python tools/firmware/boot_catalog.py \
  --rootfs .work/full/extracted/rootfs --output .work/full/boot_catalog.json
python tools/firmware/kernel_headers.py --bin .work/full/NX500.bin \
  --manifest manifests/full-source-layout.json --output .work/full/kernel-headers.json
PYTHONPATH=.work/python python -m unittest discover -s tests -v
```

`full_elf_contents.json` groups all ELF paths by SHA-256 for deduplicated analysis.
Original rootfs and opt paths are retained separately; the dependency resolver
projects opt under `/opt` for its static model. Its output describes declared
loader requirements and candidate paths, not resolved runtime calls.

Use `tools/ghidra/run_headless.py` with a distinct project name and work directory
for each survey, preserving input manifest, run receipt, timeouts, failures and
`summary.json` hashes. Run002's eight-file and bounded followup exports are
described in `analysis/architecture/EXPANDED_GHIDRA_20261021.md`.
Archive Ghidra databases only after lock files have disappeared.

Complete source-byte reproduction does not mean complete semantic reverse
engineering. Unclassified raw sections, indirect/cross-core calls, driver
behavior and the actual camera state remain follow-up work.
