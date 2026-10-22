# NX500 v1.12: boot, service and IPC configuration cross-check

Recorded: 2026-10-21 KST. Evidence level: **newly reproduced static configuration**.
No camera access, firmware execution or runtime systemd transaction was performed.

## Inputs and reproduction

- Reconstructed firmware BIN SHA-256:
  `f4c238e811970cf858b5d734119477ea191d35cd29d9f84b584157ecfc4ee997`.
- Decoded rootfs ext4 SHA-256:
  `9c66f76f3124acb3b8d0c31374ca209d333fcb76267bb86ed9bc18c9e8ea73f7`.
- Files were read from the native debugfs extraction of this image. Extracted host
  ownership is not original filesystem ownership; ownership is not used below.
- `tools/firmware/boot_catalog.py` reads both `/etc/systemd/system` and
  `/usr/lib/systemd/system` without traversing symlinks. It records 203 regular
  configuration files, 70 symlink entries, 507 declared Unit-section relationships,
  11 selected source files and 6 kernel modules. These are configuration record
  counts, not running service counts. Drop-in application and unit transactions
  are not evaluated.

```sh
python tools/firmware/boot_catalog.py \
  --rootfs .work/full/extracted/rootfs --output .work/full/boot_catalog.json
python -m unittest discover -s tests -p test_boot_catalog.py -v
```

Selected records, complete per-file SHA-256, line-addressed directives and module
string file offsets are in `analysis/evidence/boot-services-20261021.json`.
All paths below refer to the original rootfs unless an opt image is explicitly named.
Line numbers apply to configuration text, not virtual addresses.

## 1. A concrete mount-configuration disagreement must be retained

`/etc/fstab` lines 31–33 declares `/dev/root` at `/`, `/dev/mmcblk0p7` at `/opt`
and `/dev/mmcblk0p11` at `/opt/usr`. In contrast:

| Explicit unit | What, line 8 | Where, line 9 | Options, line 11 |
|---|---|---|---|
| `/etc/systemd/system/opt.mount` | `/dev/mmcblk0p11` | `/opt` | `errors=panic,nosuid` |
| `/etc/systemd/system/opt-usr.mount` | `/dev/mmcblk0p14` | `/opt/usr` | `errors=panic,nosuid` |

Both explicit units are symlinked from `/etc/systemd/system/local-fs.target.wants/`.
`opt-usr.mount` line 5 orders itself after `opt.mount`. The fstab section is
commented `nx1 partitions` on line 30, which is a useful discrepancy marker, not
proof that either configuration is unused. A mask for
`/etc/systemd/system/systemd-remount-fs.service -> /dev/null` is also present.

**Implication:** do not turn either set of partition numbers into the physical
NX500 partition map. Systemd version/generator precedence, kernel command line,
bootloader partition definitions and actual mounts must be checked together.
The extracted rootfs `/sdcard -> /mnt/mmc` and `/pref -> /opt/pref` links describe
namespace intent; they do not settle which block devices are mounted.

## 2. Camera startup is explicitly configured, with separate readiness mechanisms

Rootfs `/sbin/init` is an absolute symlink to `/usr/lib/systemd/systemd`.
Within the inspected vendor unit directory, `default.target -> graphical.target`.
`graphical.target` lines 11–12 requires and orders after `multi-user.target`.
`multi-user.target` lines 11–13 requires/orders after `basic.target`,
`tizen-boot.target`, `tizen-system.target` and `tizen-runtime.target`.
This is a declared target graph, not an observed boot order.

`default.target.wants/di-camera-app.service -> ../di-camera-app.service` is present.
The camera unit declares:

- line 3: `After=hib_ready.service xorg.service default.target wm_ready.service deviced.service`;
- line 6: `ExecStart=/usr/apps/com.samsung.di-camera-app/bin/di-camera-app`;
- line 8: `EnvironmentFile=/run/tizen-mobile-env`.

`wm_ready.service` line 8 executes a shell loop waiting for `/tmp/.wm_ready`.
The camera unit's `After` entries are ordering declarations; they do not by
themselves pull those units into a transaction or prove that each readiness check
has succeeded. No file or symlink named `hib_ready.service` was found in either
inspected system unit directory. Runtime-generated units remain unexamined.

`starter.service` uses a different readiness path: line 7 invokes
`/etc/init.d/rd3starter`; that script lines 9–12 loops until `/tmp/amd_ready`, then
lines 14–23 writes the vconf safemode value according to `/opt/etc/.safeboot`, and
line 26 starts `/usr/bin/starter` in the background. Hence the starter path and
direct camera service must be traced separately; a filename-level startup list
cannot replace these conditions.

## 3. Hibernation preparation has observable static branches and storage effects

`hibernation.service` lines 13–15 orders the script before `local-fs-pre.target`
and `local-fs.target`; line 20 invokes `/usr/bin/hibernation.sh`. Its
`local-fs.target.wants` symlink is present.

The script is a cold-boot/snapshot preparation path with these exact branches:

- lines 3–8: if `/sys/power/bootmode` equals `4`, create `/tmp/.hib_ready` and exit;
- lines 10–13: if `/etc/snapshot` is absent, create that marker and exit;
- line 17: otherwise set `SNAPSHOT_DEV=/dev/mmcblk0p9`;
- lines 54–61: configure a 50 MiB zram swap area and write/reinitialize the
  snapshot swap device;
- line 78: remount `/` read-only; line 93: create `/tmp/.hib_ready`.

These are script contents only; none of these writes was executed. `/etc/snapshot`
on a device and the sysfs bootmode value determine which path is reached.
The script's marker name does not prove that the missing `hib_ready.service` is
generated or that camera startup waits for it.

`hib_tmp.service` line 15 runs `/usr/bin/hib_tmp.sh`, which lines 3–7 moves an
existing `/opt/dbspace` to `/opt/_dbspace` if needed, creates the `/tmp/dbspace`
symlink and copies `/opt/_dbspace` into `/tmp/dbspace`. This supplies a concrete
RAM-backed database staging candidate; live database durability still requires
tracing the writers and shutdown paths.

`hib_post.path` line 7 watches `/tmp/.hib_post`; its service line 8 runs
`/sbin/swapoff -a` after the camera/deviced/window readiness units named on line 4.
None of this establishes fast-boot timing, power use or safe interruption behavior.

## 4. The DMS service name does not establish a running network server

`allshare-dms.service` lines 3–4 requires/orders after `tizen-runtime.target`,
and line 8 invokes `/usr/bin/allshare-dms.sh`. That script contains only its shebang
and line 2:

```text
/usr/bin/vconftool set -t bool db/allshare/status 0 -f
```

It does not directly launch a DMS process. This newly reproduced result corrects
a possible inference from the service description `NearbyDevices DMS`. The
previously located RVF/DLNA library call paths remain necessary to determine when
the server is created, and whether they coexist with capture.

`connman.service` line 9 first requests `net.netconfig.auto.activate` through
D-Bus, then line 10 starts `/usr/sbin/connmand`, with `BusName=net.connman` on
line 7. A separate D-Bus activation file
`/usr/share/dbus-1/services/net.connman.service` line 3 names
`Exec=/usr/sbin/connman.service`, whereas the netconfig activation file line 3
names `/usr/sbin/net-config`. The former should be checked as a distinct path;
it must not silently be treated as the systemd unit or connmand executable.

The extracted `nfc-manager.service` lines 3–4 still names
`After=system-server.service` and `Requires=system-server.service`. No file or
symlink with that unit name was found in either scanned unit directory. This is
a static dependency gap, not proof of NFC failure: generated/other unit search
paths and explicit app activation have not been evaluated.

## 5. IPC and driver boundaries now have byte-backed anchors

`dbus.socket` line 5 declares `/var/run/dbus/system_bus_socket`.
`dbus.service` line 7 starts dbus-daemon with `--system --address=systemd:` and
`--systemd-activation`. `/etc/dbus-1/system.conf` line 32 names EXTERNAL
authentication, line 38 a Unix socket, line 71 includes `system.d`, and line 75
includes optional `system-local.conf`. These declarations identify a local IPC
boundary. They do not establish effective access control or network exposure;
all included policy and service-side checks would need to be evaluated.

Six `.ko` files were read: bt8887, cfg80211, mlan, sd8xxx, exfat_core and exfat_fs.
Each contains a `vermagic=3.5.0 preempt mod_unload ARMv7 p2v8` string.
`sd8xxx.ko` contains `depends=cfg80211,mlan`; `exfat_fs.ko` contains
`depends=exfat_core`. SDIO alias strings are recorded for bt8887 and sd8xxx.
The evidence JSON records each module's SHA-256 and exact file offsets for these
strings. These metadata records are compatible with the wireless/storage
neighborhoods already identified, but do not prove that a module is loaded or
that its hardware aliases match the actual camera.

## 6. Three kernel sections provide independent container-level evidence

`analysis/evidence/kernel-headers.json`, generated by
`tools/firmware/kernel_headers.py`, records uImage header and payload CRC32
validation for SLP sections 0, 2 and 3. All three headers name `Linux-3.5.0` and
load/entry address `0x86008000`. Although the outer header's compression ID is
zero, each payload has ARM zImage magic and a complete gzip stream at section
file offset 21,952. Thus compression ID zero must not be read as an uncompressed
Linux image.

| Section | Gzip offset in full BIN | Decoded bytes | Decoded SHA-256 |
|---|---:|---:|---|
| 0 | 22,256 | 9,201,060 | `942492550b303d203a5ab43614aafd46bc4644ae8afa474f3676db3b809a072b` |
| 2 | 6,239,169 | 7,474,108 | `25bdca5cde4a5c10710d02dbaa904c62cd77b0b4562b8bf4d73c675f50bdb587` |
| 3 | 9,415,209 | 9,201,060 | `fc38d13a10fdf4ae964f5100c0f043c7650f3e11385c90d7e07d58e9a3fecf9c` |

Each decoded stream contains a Linux 3.5.0 PREEMPT build banner. No IKCONFIG
start/end markers were found by this inspection. These measurements neither
identify a normal/recovery boot role nor establish which section the bootloader
selects. The module vermagic/kernel-banner agreement is a static compatibility
hint and requires actual symbol/configuration checks before stronger conclusions.

## Remaining work

1. Recover kernel command lines/boot partition definitions and evaluate the
   shipped systemd generator behavior to resolve the mount conflict.
2. Trace di-camera-app/starter/hibernation marker producers and consumers in code;
   distinguish normal boot, snapshot creation and snapshot resume paths.
3. Resolve DMS initialization from the RVF/DLNA call paths and vconf consumers.
4. Inspect generated-unit paths and system-server/hib_ready references before
   reporting those dependency gaps as on-device failures.
5. Trace device IOCTLs, multicore bridge messages and driver entry points. The
   metadata above is a navigation base, not a recovered hardware protocol.

This report promotes prior inherited path hints to inspected configuration
evidence. It does not claim whole-firmware semantic completion or device validation.
