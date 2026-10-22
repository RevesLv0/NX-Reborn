# RUN003 video, power, MICOM and update survey

Twelve additional original rootfs ELF files were imported into
`NX500_RUN003_VIDEO_POWER` with Ghidra 12.1.4 / JDK 21.0.12.1+1.
The useful new results are a concrete HEVC encoder selection and device interface,
the service boundary of the poweroff wrapper, distinct MICOM status/SOC requests,
and the argument that controls optional CRC checking in one updater-library path.
These are reproduced static findings, not observations on a camera.

The authoritative source, input hashes, validated export hashes, receipts and four
bounded reviewed-finding records are in
[`ghidra-video-power-run003.json`](../../manifests/ghidra-video-power-run003.json).
Selected original-ELF disassembly, resolved literals, decompilation and configuration
lines are retained in [`video-power-run003.json`](../evidence/video-power-run003.json).
The input files are regular extracted files hardlinked into
`.work/run003/video-power/inputs`; every SHA was checked against
`.work/full/inventory/full_filesystem_inventory.json` before analysis.

## Scope and completion accounting

| Original rootfs path | Functions | Strings | Initial selected decompilation |
|---|---:|---:|---:|
| `/usr/lib/libmmfcore.so` | 1,335 | 2,172 | 5/5 |
| `/usr/lib/libmmfmodules.so` | 1,478 | 1,911 | 3/3 |
| `/usr/lib/libmm-displayer.so` | 190 | 264 | 3/3 |
| `/usr/lib/libsysman.so.0.2.0` | 115 | 110 | 4/4 |
| `/usr/lib/libhibernation.so` | 124 | 231 | 5/5 |
| `/usr/lib/libmicom-node.so.0.1` | 106 | 159 | 4/4 |
| `/usr/lib/libfirmware-upgrade.so` | 256 | 479 | 5/5 |
| `/usr/bin/deviced` | 791 | 1,267 | 0/0 |
| `/usr/bin/resourced` | 711 | 1,179 | 0/0 |
| `/usr/bin/hib_tool` | 56 | 104 | 0/0 |
| `/usr/bin/micom_updater` | 113 | 128 | 0/0 |
| `/usr/sbin/fw_upgrade` | 188 | 375 | 0/0 |

The initial pass exported 5,463 function entries, 8,379 defined strings and 29/29
completed selected decompilations. A second export with analysis disabled adds three
distinct HEVC functions, giving **32/32 selected decompilations**. It re-exports the
same twelve programs; its import/function/string counts must not be added again.
Both generations passed expected SHA/run-ID, artifact SHA/byte-length, row-count and
selection-accounting validation. Neither generation has a reported analyzer timeout,
decompiler failure or budget omission. All processes have exited and the database is
unlocked for a snapshot.

The five executable programs had no function matching the bounded name pattern;
their import, auto-analysis, symbol/call/string survey includes **no selected
decompilation**. They are explicit followup gaps. Function/string totals include
stubs, inferred functions and metadata; none is a semantic-completion denominator.
Missing external DWARF, incomplete demangled tables and unresolved project
dependencies were logged. Indirect/vtable calls and inferred signatures remain
limitations, even when the decompiler reports completion. For example,
`CDisplayLCD::SetVisible` has an apparently oversized decompiled body compared with
its ELF symbol; its inferred body is not used for a reviewed behavior claim.

All code addresses below are **original ELF link-time VAs**. For these shared
objects Ghidra rebases by `0x10000`; e.g. original `0x2d92c` is program VA
`0003d92c`. Neither is inherently a file offset. Evidence records separately map
file offsets through `PT_LOAD`; ARM Thumb symbol values have their low bit cleared
for instruction addresses. Raw symbol-bounded Capstone listings can include literal
pools, which are not executable-instruction claims.

## VP003-01: HEVC uses a concrete HAL class and device request

Primary input `/usr/lib/libmmfmodules.so`, SHA-256
`e40d3c7fdbab8ea7f67d0e876468c2a31fa8572d602d969d32348f3fd0f45de7`.
Supporting input `/usr/lib/libmmfcore.so`, SHA-256
`b3e7cd2987282d856a8f95b8768d44ea2f4f3804684a391de0567c10dada73c8`.

`iVideoEncoder::Create` starts at `0x2d92c`. Independent instructions show
`CMP r0,#0xb` at `0x2d940`, branching at `0x2d944` to allocation of `0x178`
bytes and a constructor call through the HEVC constructor PLT at `0x2d9a8`.
The `8` branch constructs the MJPEG class; the other branch builds a different
base implementation. The concrete class selection is stronger evidence of the
HEVC route than the generic INI label alone.

`cHalHevcVideoEncoder::Configure` starts at `0x2d1f0`. Its PC-relative literal at
`0x2d778`, added to PC operand `0x2d220`, resolves to string `/dev/d5_hevc`
at `0x3fbac`. The call at `0x2d21c` opens it with argument `2`.
The function calls `SetHevcEncMode`, locks the encoder, and at `0x2d364` calls
`ioctl` with request `0xc10c7408` and an object-relative parameter buffer.
`Initialize` at `0x2ceb4` calls `ipccInit`; `Configure` also conditionally calls
`load_m4(1)`. This establishes a user-space hardware/IPC interface, not the driver
or M4 protocol. No request was actually issued.

In the supporting core ELF, `cMmfRecorder::SetVideoPipeline` at `0x3fb10`
constructs video or time-lapse sources, conditional encoder objects and an AV muxer
or time-lapse sink. Its buffer configuration connects source/encoder/mux objects
through virtual calls and sysconfig lookups. `cMmfVideoEncoder::OnStart` at
`0x36b80` calls `iVideoEncoder::Create` and invokes object virtual operations.
The topology and selection are static; field types, all virtual targets and mode
selection still require ABI/vtable validation. No resolution, bitrate, frame-rate,
recording-duration or thermal capability is established here.

Configuration crosscheck: rootfs `/usr/etc/mmfw_camcorder.ini` SHA-256
`a98e2932276d4f55fdd17bce2258a544f34640b41c189657182a7490e86dadf8`
and opt partition `/etc/mmfw_camcorder.ini` (runtime `/opt/etc/...`) SHA-256
`d8b2f36d4caf4ba2b57686fd690ceea1f5f0a3daf768d37a966a435e4f5578c5`
both contain `HEVC = omx_h264enc | 0,0` on line 65. The only line difference is
rootfs line 123, `RTSP_MJPEG = rtpmp4vpay | 0,0`, absent in opt. The primary,
secondary and player INI pairs are byte-identical between these locations.
For example the primary INI SHA-256
`3f22c23dcad890fee2de36231ad03c98685b4d14a4b02e367e8d31453baf8f3e`
lists large preview sizes on line 26 and `FPS = 3,120000 || 30` on line 28.
Those generic declarations do not establish active limits or that this concrete
HAL consumes either copy. Next trace the sysconfig provider, M4 loading and kernel
HEVC ioctl handler before changing video parameters.

## VP003-02: the poweroff wrapper requests a service action

Input `/usr/lib/libsysman.so.0.2.0`, SHA-256
`f3df0b8c6e3200ed7cd607f8094446f45d0ddc5e7804fcd946e467b96f6f074a`.

`sysman_request_poweroff` at `0x1da0` loads an action string, sets `r1=0` and
tail-branches through the helper PLT at `0x1dae`. Its literal word `0xdae` at
`0x1db4` plus PC operand `0x1daa` resolves to **`pwroff-popup`** at `0x2b58`.
The helper is `sysman_call_predef_action` at `0x1518`; Ghidra infers an unreliable
void return type, so no source-level signature is asserted.

The helper invokes `socket(1,1,0)` at `0x1634`, constructs a Unix address, and
calls `connect` at `0x166a`. Literal `0x1470` at `0x1884` plus PC operand
`0x165c` resolves to **`/tmp/sn`** at `0x2acc`. The function writes the PID,
numeric/action framing and action bytes through separate writes, then calls
`read(fd,...,4)` at `0x1766` and closes the socket. Independent Capstone agrees
with the callsites and four-byte read size.

Thus this public wrapper reaches a popup/service request boundary. The response
word's meaning, listener implementation, actual shutdown, and any wait for capture
or transfer completion remain unresolved. Next identify the `/tmp/sn` listener and
`pwroff-popup` action handler; the wrapper alone does not prove quiescence.

## VP003-03: MICOM status and body battery SOC are different ioctl wrappers

Input `/usr/lib/libmicom-node.so.0.1`, SHA-256
`26f7304fca29d9e24da3e9147805a494a79eb3752f128158523c5674b2294454`.

`get_micom_status` at `0x122c` and `get_body_bat_soc` at `0x1564` check
`micom_has_device`, open `/dev/micom-ctrl` with argument `2`, issue an ioctl and
close the descriptor on the inspected success/error routes. Independent literal
resolution for both functions reaches the same device string at `0x36d0`.

The status ioctl call at `0x1256` uses request **`0x80044d00`** and a zeroed
two-word local buffer. At `0x1260` the second word is compared with `0xa5`;
the wrapper writes output zero when equal and one otherwise. The body-SOC ioctl
at `0x158c` uses **`0x80044d05`** and copies its returned local word into the
caller output (`STR` at `0x1598`). This is wrapper interpretation, not a verified
kernel or microcontroller packet layout. SOC units, scaling, freshness and low
battery thresholds are not established. Next inspect the MICOM driver and
`deviced` battery decision routines; no device battery reading was performed.

## VP003-04: one updater-library call selects validation without its optional CRC pass

Input `/usr/lib/libfirmware-upgrade.so`, SHA-256
`7639927b05e4290198d53d8a14ebb219e36f71dcc73693c3cf09988337c522d7`.

`fw_start_upgrade` starts at `0x359c`. Instructions at `0x35ec` set **`r2=0`**,
`0x35ee` passes the returned project-name pointer as the second argument, and
`0x35f2` calls the `fw_validate` PLT. It then checks the return before obtaining
image information and selecting the flash plugin. This is static inspection only.

`fw_validate` at `0x31d4` reads a 64-byte header and checks an image count in
the range 1–15, accepted tag alternatives, an optional supplied project-name
comparison and a 24-byte-per-image table. Decompilation contains a type-propagation
warning; these observations were crosschecked against the symbol-bounded
instructions. `CMP r8,#0` at `0x3350` selects the per-section branch: with a zero
third argument it calls `fseek` at `0x3448`; with a nonzero third argument it
calls `fw_upgrade_crc32` at `0x3362` and compares the computed word with the table value. The CRC helper
starts at `0x4700` and reads chunks up to `0x1000` bytes.

The bounded conclusion is that **this library caller selects the seek-over-data
route rather than this validator's optional CRC calculation**. It is not a claim
of an update bypass, missing firmware authentication or a safe flashing path.
The separate `/usr/sbin/fw_upgrade`, flash plugins, all prior callers, bootloader
verification and possible cryptographic checks have not been fully reviewed.
Those remain required before any whole-update security conclusion.

## Reproduction and remaining gaps

The manifest preserves both exact runner commands/patterns and their completed
receipts. Initial settings were analysis timeout 150 seconds per file, selected
decompilation budget 10 per file, decompiler timeout 25 seconds, heap `1536M`
and CPU limit 1. The followup used the same project with `--process
--skip-analysis` and a HEVC-specific name pattern. Full exports/logs are under
`.work/run003/video-power/`; the database is
`ghidra-projects/NX500_RUN003_VIDEO_POWER.{gpr,rep}`. All twelve initial/followup
exports were separately checked with `tools/ghidra/validate_exports.py` logic.

Reproduce the selected original-address evidence from the repository root:

```sh
PYTHONPATH=.work/python python tools/firmware/video_power_evidence.py \
  --work .work/run003/video-power \
  --rootfs .work/full/extracted/rootfs --opt .work/full/extracted/opt \
  --output analysis/evidence/video-power-run003.json
```

Hibernation imports now expose selected `hib_post`, `hib_has_hibdata`,
`hib_register_exmem` and pre/post partition wrappers, but snapshot validity and
resume behavior are not reviewed findings. `resourced` and `deviced` have no
selected named decompilation in this pass. Raw string selection does not close
thermal, battery shutdown, freezer or power ownership gaps. No target execution,
camera I/O or flashing was performed.
