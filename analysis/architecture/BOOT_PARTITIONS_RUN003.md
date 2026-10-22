# NX500 RUN003: raw boot images, command line and mount precedence

Recorded 2026-10-21 UTC. **Newly reproduced offline static evidence.** No camera,
firmware execution, device I/O, flashing, or runtime systemd transaction was used.

The shipped systemd code supplies a concrete reason to prefer the explicit
`/opt` and `/opt/usr` units over conflicting fstab-generated units in the normal
system-manager search path. That conditional precedence result does **not**
recover the camera's physical partition table or prove its actual mounts.

## Inputs and reproduction

Full input `.work/full/NX500.bin` SHA-256:
`f4c238e811970cf858b5d734119477ea191d35cd29d9f84b584157ecfc4ee997`.
The tool verifies the full BIN and every section against
`manifests/full-source-layout.json` before selecting evidence.

| SLP section | Absolute BIN start | Bytes | Section SHA-256 |
|---|---:|---:|---|
| 1 | `0x005e0220` | 56,289 | `c1069c67fe05308957490ea3df80d8a14cb86fc9371455d859d396fad7c71c1e` |
| 4 | `0x00ed7941` | 117,184 | `eef8232942a6fd8dcb4ce5b6073511e5d5f78d71c08444f1e540b30964483b52` |
| 5 | `0x00ef4301` | 12,075,648 | `f8e417cb5b55768851ba7e2b8017d3a98dc0b0c8444cc0a5061265cc08dbbf7f` |

Extracted rootfs image SHA-256:
`9c66f76f3124acb3b8d0c31374ca209d333fcb76267bb86ed9bc18c9e8ea73f7`.
Selected evidence, exact bytes, instruction/file offsets, per-file hashes and
configuration line offsets are in
[`boot-partitions-run003.json`](../evidence/boot-partitions-run003.json).
Full derived printable-string listings stay ignored under `.work/run003/boot/`.

```sh
PYTHONPATH=.work/python python tools/firmware/boot_sections.py \
  --bin .work/full/NX500.bin --manifest manifests/full-source-layout.json \
  --kernel-dir .work/full --rootfs .work/full/extracted/rootfs \
  --output analysis/evidence/boot-partitions-run003.json \
  --raw-output-dir .work/run003/boot
PYTHONPATH=.work/python python -m unittest discover -s tests -p test_boot_sections.py -v
```

Five tests pass: input hash/bounds rejection, exact string offsets across an
unaligned section origin, ARM literal addressing, Thumb PC alignment and Thumb
PC-relative string addressing. The three decoded kernel inputs are compared
byte-for-byte against bounded complete gzip decoding from their verified source
sections. Code regions are bounded Capstone disassembly; labels are analyst
labels unless a source/function-name string is explicitly noted.

## 1. Section 1 constructs a Linux command line; this is more than a string hit

For section 1 and its SHA above:

| String | Section offset | Absolute BIN offset |
|---|---:|---:|
| `DRIMe5 bootloader` (trailing spaces preserved in JSON) | `0xd216` | `0x5ed436` |
| ` root=/dev/mmcblk0p10 rw rootfstype=ext4 rootwait ` | `0xd544` | `0x5ed764` |
| `console=ttyAMA0,115200n8 mem=512M` | `0xd577` | `0x5ed797` |
| ` hibernate=nocompress` | `0xd599` | `0x5ed7b9` |
| ` noresume` | `0xd5af` | `0x5ed7cf` |
| ` user_debug=255` | `0xd5b9` | `0x5ed7d9` |

ARM code at section `0x40ec` (BIN `0x5e430c`) loads the root-argument pointer
`0x0200d744`, then tail-branches to a bytewise append-until-NUL helper at section
`0x275c` (BIN `0x5e297c`). The neighboring `0x2740` helper copies through NUL.
Section `0x40f8` (BIN `0x5e4318`) writes tag IDs `0x54410001`, `0x54410002` and
`0x54410009`, consistent with ARM ATAG_CORE, ATAG_MEM and ATAG_CMDLINE. It writes
memory size `0x20000000` and start `0x86000000`, constructs a command string at
`0x8600012c` by the copy/append helpers, adds the root, noresume and user_debug
strings, writes a terminating tag, and calls through literal `0x86008000`.
`hibernate=nocompress` is appended to the console string before that is copied.
The literal pool is recorded as data attached to the referring instructions,
not promoted to executable instructions.

A **link/load-base inference** of `0x02000200` makes these string pointers agree
with exact section offsets. Independent support: section `0x84` (BIN
`0x5e02a4`) loads the literal at section `0x1c8` (BIN `0x5e03e8`), value
`0x02000200`, and writes it to CP15 VBAR at section `0x88`. The evidence JSON
keeps raw instruction addresses as section offsets. This does not prove the
actual mapping at reset or any later relocation.

The call sites around section `0x38d4` (BIN `0x5e3af4`) branch on byte `[r4+6]`:
one path prints `Starting A9 for upgrade.`, the other prints
`Starting A9 for linux.`. Both reach callsite `0x39a8` (BIN `0x5e3bc8`), which invokes the
command-line/tag routine at section `0x40f8`.
A separate `Starting A9 for recovery.` string exists at section `0xd1d1`
(BIN `0x5ed3f1`); this pass does not establish the condition selecting that path.
Image parameters are fetched through pointers, so the strings alone cannot
assign SLP kernel sections 0/2/3 to normal, recovery or upgrade slots.

**Supported implication:** this boot-code path supplies `root=/dev/mmcblk0p10`.
It does not establish that this path boots on every device, that p10 holds the
archived section 6 on a particular camera, or that kernel command-line override
configuration preserves every argument.

## 2. The fstab disagreement has a conditional code-level explanation

The original configuration disagreement is reproduced with exact file offsets:

| Input path | SHA-256 | Location | Declaration |
|---|---|---|---|
| `/etc/fstab` | `62fd39efedbc22cbfbd09d97ed9f1b08f02c8cab854d02ecd12c5dbe4c57c734` | line 30, byte 1153 | `# nx1 partitions` |
| same | same | line 32, byte 1211 | p7 at `/opt` |
| same | same | line 33, byte 1263 | p11 at `/opt/usr` |
| `/etc/systemd/system/opt.mount` | `7d6fa1e8d64ed030c34e734df01f0db8245cd729da4c0c9a396e99248ba21770` | line 8, byte 130 | `What=/dev/mmcblk0p11` |
| `/etc/systemd/system/opt-usr.mount` | `bc689508974c3846662d79418f44cd69e38ff12ae3240f9fc439281eb4d8c503` | line 8, byte 149 | `What=/dev/mmcblk0p14` |

The shipped `/usr/lib/systemd/system-generators/systemd-fstab-generator` has
SHA-256 `07ed714dc7e7af36945125abd022f5240279a29d4c790ecd85536ed32163bd2b`.
Original ELF VA `0xa2a2` loads `argv[1]` and `0xa2a6` stores it to the output
path cell at VA `0x1a000`. VA `0xaf52` references `/etc/fstab` (VA `0xe620`),
`0xaf6c` calls imported `setmntent`, and `0xaf7a` calls `getmntent`. The mount
writer at `0xa96c` loads the same output cell; `0xa98c` calls imported
`fopen64` with mode `wxe` at VA `0xe418`. Its format strings include `.mount`
and `[Mount]\nWhat=%s\nWhere=%s...`. This generator creates unit files in its
provided output directory; it does not directly perform a mount in this path.
The exclusive-create diagnostic concerns an existing file **in that output
directory** and is not an explicit check of `/etc/systemd/system`.

The shipped `/usr/lib/systemd/systemd` has SHA-256
`240d910b3c8ef7824b864f7c19a57b9bf456cb4500b710502135a2b0f0c1333d`.
The following are original ELF VAs, not Ghidra-rebased addresses:

- `0x13c06`, `0x13c1a`, `0x13c2e` resolve `generator`, `generator.early`,
  `generator.late`; their pointers occupy manager offsets `0x178`, `0x17c`,
  `0x180`. The PID1 directory branch at `0x1203e` references `/run/systemd/`.
- `0x13c3a` through `0x13c60` supply the generator helper an argv array whose
  slots after the executable placeholder are ordinary, early, then late output
  directories. This agrees with the fstab generator's `argv[1]` output cell.
- `0x13d28` through `0x13d42` pass ordinary output as argument 4, early as
  argument 5 and late as argument 6 to the path-list builder at `0x45b3c`.
- `0x45bf6` through `0x45c44` constructs the system-manager list in this order:
  early generator directory; `/etc/systemd/system` (twice before deduplication);
  `/run/systemd/system`; ordinary generator directory;
  `/usr/local/lib/systemd/system`; `/usr/lib/systemd/system` (twice);
  `/lib/systemd/system`; late generator directory. The list helper at
  `0x4a7c2` through `0x4a7f4` copies the variadic entries in order, skipping
  `-1` placeholders. The builder's log at `0x45bb6` explicitly says
  `Looking for unit files in (higher priority first):`.
- The loader at `0x184c0` reads that manager path list. After an open helper,
  `0x184fe`/`0x18502` leaves the search on a nonnegative result. `-ENOENT`
  (`-2`) reaches `0x185d2` through `0x185e0`, advances one pointer and loops.
  Thus a later ordinary-generator copy does not replace an earlier successful
  explicit-unit lookup.

**Conditional conclusion:** with the shipped normal system-manager path, no
`SYSTEMD_UNIT_PATH` override, and successfully readable explicit mount units,
`opt.mount` and `opt-usr.mount` from `/etc/systemd/system` take precedence over
same-named ordinary fstab-generator outputs. That selects the **configured**
p11/p14 declarations. The environment override is real code: VA `0x45b5a`
references `SYSTEMD_UNIT_PATH`, followed by an imported environment lookup.
An early generator unit can also precede `/etc`; altered files, masks, failed
loads, initrd configuration and a different transaction remain possible.
No claim of actual mounted devices follows from this static precedence result.

## 3. Raw non-Linux roles have evidence, with bounded confidence

| Section | Candidate role | Byte/code evidence and limits |
|---|---|---|
| 1 | DRIMe5 bootloader | Banner at BIN `0x5ed436`; ATAG construction and Linux jump above; strings `Starting M4 for device init.` at `0x5ed214` and `Starting A7 for T-kernel.` at `0x5ed283`. Static role is strongly supported; selection of exact packaged images remains unresolved. |
| 4 | M4 device-initializer image | `DRIMe5 M4 dev-initializer [NX500]` at section `0x18f74`, BIN `0xef08b5`. First little-endian words are `0x1f290`, `0x141`, `0x169`, `0x1c1`; odd handler pointers and Thumb reset code at section `0x140`, BIN `0xed7a81`, are consistent with a Cortex-M vector table. No runtime SRAM mapping or launch association is proven. |
| 5 | T-Kernel-side raw image | ARM reset branch at section 0, BIN `0xef4301`, targets section `0x140`; section `0x1e4`, BIN `0xef44e5`, sets VBAR to `0x80000000`. `T-Kernel Version 2.01.03` is at section `0x56a3f4`, BIN `0x145e6f5`. ARM code at section `0x1396c`, BIN `0xf07c6d`, loads pointer `0x8056a3f4` and calls a function with that banner as argument. This independently supports a section-base inference `0x80000000`, not a recovered runtime memory map. |

Section 1 also contains repeated `nvd_*` records and `/dev/mmcblk0p1`, p2, p3,
p5 strings (all offsets in the evidence). These are not a complete eMMC
partition table. Their interpretation and units require tracing their consumers;
this pass does not promote adjacent numbers into sector boundaries.

## 4. Kernel strings constrain, but do not settle, the boot map

The decoded kernels are rechecked against the full BIN gzip streams:

| Section | Decoded SHA-256 | Decoded-file offset | Selected string |
|---|---|---:|---|
| 0 | `942492550b303d203a5ab43614aafd46bc4644ae8afa474f3676db3b809a072b` | `0x453d6c` | `console=ttyAMA0,115200n8 mem=512M@0xC0000000` |
| 2 | `25bdca5cde4a5c10710d02dbaa904c62cd77b0b4562b8bf4d73c675f50bdb587` | `0x6d5aa4` | same console/memory string |
| 2 | same | `0x6fae24`, `0x6fb018` | `/dev/mmcblk0p9`, `/dev/mmcblk0p12` |
| 3 | `fc38d13a10fdf4ae964f5100c0f043c7650f3e11385c90d7e07d58e9a3fecf9c` | `0x453d6c` | same console/memory string |

These are **decoded-file offsets**. A gzip transformation prevents a direct
absolute BIN offset for each decoded string; exact compressed stream origins
are BIN 22,256 / 6,239,169 / 9,415,209 respectively, with source-section hashes
in the JSON and prior `kernel-headers.json`. No consumer of these selected
kernel strings was traced here. In particular, the `mem=512M@0xC0000000`
string must not override the separately traced bootloader ATAG interpretation,
and the p9/p12 strings do not identify mounted partitions or kernel roles.

## Remaining unknowns

The actual eMMC partition table, bootloader image-information pointer provenance,
packaged section-to-slot correspondence, kernel command-line override behavior,
boot mode selection, and live unit/mount transaction remain unresolved.
The new result resolves the **static configuration precedence question under
stated conditions**, while preserving those runtime and physical-layout limits.
