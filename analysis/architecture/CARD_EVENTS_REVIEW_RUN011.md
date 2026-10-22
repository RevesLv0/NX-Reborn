# RUN011 independent review of RUN007 card/OEM claims

Reviewed 2026-10-22. All six bounded findings in [review-run007.json](../../manifests/review-run007.json) are independently supported by original ELF bytes, subject to the limits below. One sentence in the historical architecture report overstates null handling; the narrower correction is recorded here without changing the old report or manifest.

This review does not establish kernel emission, event ordering, successful callback registration, live sysfs availability, notification coalescing, active mounted-device selection or the identity of a failed file. Separate ongoing kernel-producer work is not assumed as evidence here. No target code, device operation, Ghidra mutation, threshold change, commit or push was performed.

## Source identity, byte audit and method

| Original rootfs source | Independently recomputed SHA-256 |
|---|---|
| `/usr/bin/deviced` | `7df5d80e88e6668dff2274f86a550e480250d95dce1d3da29b489aa5e5d40f59` |
| `/usr/lib/libdevice-node.so.0.1` | `843ecf26516114370e16cd2ebc742f515cdd8b590812947b1063daa61565389e` |
| `/usr/lib/libdeviced.so.0.1.0` | `df70b308f88d6c0eb038e2e67b69b4825ef12dec60230b6fd1c3dab942989f5d` |
| `/usr/lib/libslp_devman_plugin.so` | `a88cb8130ba246b45c077cf25f0c5944077e41b780eee20f5a5a675b35a15588` |
| `/usr/lib/libmm-photo.so`, supplementary consumer check | `ea4ae65608a6f9ea0761e35c18764401cf7b876652f7949c322e880fa9f68ca9` |

The four RUN007 staged originals were SHA-checked against their extracted rootfs counterparts. Every saved window in [card-events-run007.json](../evidence/card-events-run007.json) was independently reread through the containing file-backed `PT_LOAD`: **71 ARM/Thumb instruction windows**, **four data blocks** and **14 relocation records** match. The evidence file retains SHA-256 `e8cd1a9c49f4ca87457997fa27f091ef8a3a1a10c58f394b9babc7ca997ddfcd`, agreeing with the historical review manifest and OEM index binding.

The review used pyelftools and Capstone against original bytes. Addresses below are original ELF link VAs, not Ghidra's additional `0x10000` DSO rebase. Examples: deviced `0x260c0` maps to file `0x1e0c0`; device-node descriptor `0xc5cc` maps to file `0x45cc`; the reviewed low DSO code VAs equal their file offsets. Thumb pointer bit 0 is removed when identifying the even code address. Inline TBB entries and literal pools were interpreted as data.

In addition to checking the 14 saved relocation records, original ARM veneer arithmetic independently resolves **15 selected PLT calls** to their actual GOT relocation symbols. This includes a mixed Thumb/ARM veneer: plugin `sys_get_int` entry `0x46a8` contains `bx pc; nop`, then ARM body `0x46ac` resolves GOT `0x1519c`. A uniform 12-byte PLT-index formula would not be reliable across these interworking veneers.

Saved C was used for navigation; the semantic checks below use independently decoded instruction operands, branches, embedded strings, pointer records and GOT bindings. The byte audit covers more code than the six semantic findings: it does not mean every handler in every audited window was fully reviewed.

## Disposition of the six historical claims

| Claim ID | Disposition | Independently checked original locations | Remaining boundary |
|---|---|---|---|
| `CARD007-UEVENT` | Supported for accepted events; null-handling qualification below | deviced `0x260c0–0x2657c`; platform key/argument calls at `0x264a8`, `0x264d4`, `0x26500`, `0x2652c` | Producer emission, monitor installation and runtime ordering remain unobserved. |
| `CARD007-REGISTRY` | Supported | deviced `0x25f94–0x25fb0` registers keys 2/3; helper `0xb530`; record stores/list append `0xb9fc–0xba38`; dispatcher `0xbcc8–0xbdf0` | Registration success and actual invocation remain unobserved; returned dispatch count is not callback success. |
| `CARD007-STATE` | Supported, including guard and non-atomic state limits | deviced mount cases `0x2050c–0x20534`, setter groups `0x20550–0x2056c`, `0x206c0–0x206f0`, `0x20844–0x20874`, `0x209c8–0x209f8`, `0x20b4c–0x20b7c`; event callback `0x23ba8–0x2439c`; timer `0x23374` | No per-buffer/file correlation, no guarantee of retry/recovery, no atomic vconf pair or observed delivery. |
| `CARD007-LOAD` | Supported on inspected loader paths | device-node Thumb `0x1570–0x163a`; loader calls `0x157c`, `0x1590`, `0x1596`; selected result at `0x15e2–0x15ea`; fallback `0x15c6–0x15d4` | Runtime interposition, actual initialization and selected table remain unobserved. |
| `CARD007-DISPATCH` | Supported by original Thumb/data, independently of absent recovered functions | device-node descriptor `0xc5cc`; initializer `0x1710`; getter `0x3378–0x33f6`; TBB data `0x3386`; selected slot loads `0x33bc/0x33da` | This remains manual original-byte evidence, not a newly completed Ghidra decompilation. |
| `CARD007-READ` | Supported; return ABI independently confirmed | plugin getters `0x5290/0x52a0`; table stores `0x9542/0x954e`; reader `0x48f4–0x492e`; wrapper `0x49dc–0x4a1a`, especially `0x4a06` | Live node existence, actual content, parse validity and physical card state remain unobserved. |

### Accepted udev events and the null-handling correction

Original deviced literals identify `*/mmcblk[0-9]` at `0x51f50`, `*/dw_mmc_sdcard.[0-9]` at `0x51fec`, `*/cdn-sdhci.[0-9]` at `0x52004`, and property key `EVENT` at `0x52030`. The dispatch arguments independently decode as:

| Accepted input | Call to dispatcher `0xbcc8` |
|---|---|
| Block add with accepted path, action and devnode | key 2, devnode pointer |
| Block remove with accepted path, action and non-null devnode | key 2, 0 |
| `sdcard_insert`, literal `0x52038` | `0x264a0–0x264a8`: key 3, 1 |
| `sdcard_remove`, literal `0x52048` | `0x264cc–0x264d4`: key 3, 0 |
| `sdcard_init_error`, literal `0x52058` | `0x264f8–0x26500`: key 3, 2 |
| `sdcard_data_error`, literal `0x5206c` | `0x26524–0x2652c`: key 3, 3 |

The historical sentence “Missing monitor/device/property values and unmatched events do not take these branches” should be narrowed. This function checks the **received device** (`0x26108–0x26114`), the selected block action/devnode pair, and platform `EVENT` (`0x2647c–0x26480`). It does **not** locally check the monitor pointer before `udev_monitor_receive_device` at `0x260fc`, nor the returned subsystem before `strcmp` (`0x2611c–0x26130`), nor the returned devpath before `fnmatch` (`0x26144–0x2615c`). The corresponding libudev/library behavior is outside this local null-guard claim. This correction does not change the accepted-event mapping.

The call identities are independently bound through original type-22 relocations, including `0xacd0→0x5826c` (`udev_monitor_receive_device`), `0xacc4→0x58268` (`udev_device_get_subsystem`), `0xaef8→0x58324` (`udev_device_get_devpath`), `0xabec→0x58220` (`fnmatch`), `0xb354→0x58498` (`strcmp`), and `0xb1b0→0x5840c` (`udev_device_get_property_value`).

### Registry, error guard and mount state

At `0x25f94–0x25fa0`, deviced loads key 2 and callback `0x23558`; at `0x25fa4–0x25fb0`, it loads key 3 and callback `0x23ba8`. Both call registration helper `0xb530`. That helper's original code rejects a null function, checks duplicate key/function pairs, obtains an eight-byte record, writes key/function at offsets 0/4 and appends it to list pointer `0x586f0`. Dispatcher `0xbd38–0xbd68` matches the stored key, checks the function and passes its supplied argument in `r0` to `blx r3`. The following increment counts invocations; callback return values do not determine that count.

The reviewed callback writes raw MMC state 0 for arguments 0 and 1 (`0x23d34–0x23d40`, `0x23e9c–0x23ea8`). Argument 2 writes `0xcb` to `memory/sysman/mmc_err_status` (`0x24004–0x24010`). Argument 3 retries only when global `0x58870==0` and signed budget `0x5885c>0`: `0x24034` branches away when the first guard fails and `0x24048` uses signed `BLE` for the second. The retry body decrements that budget, sets flag `0x58860`, and creates or delays timer `0x23374`; otherwise it writes the same `0xcb` immediately at `0x24374`. The timer writes that error only when the retry flag is still set and clears timer handle `0x58864`. No fixed initial retry budget is derived here.

Original `vconf_set_int` PLT `0xafc4` resolves GOT relocation `0x58368`. The actual key literals are `mmc` at `0x51654`, `mmc_mount` at `0x51668` and `mmc_err_status` at `0x51698`. The mount branch instructions reproduce this table:

| Mount result | Error key | MMC key | Mount key |
|---|---:|---:|---:|
| `-0x1e` | `0x1e` | 1 | 0 |
| `-0xc9` | `0xc9` | 2 | 2 |
| `-0xca` | `0xca` | 2 | 2 |
| Other selected negative/failure route | `0xc9` | 2 | 2 |
| Nonnegative | No explicit error-key write in this branch | 1 | 0 |

These are consecutive calls, not a single atomic state publication. Vconf call return values and device-side notification delivery were not observed. The supplementary unmount/cleanup windows `0x21994` and `0x22b08` agree with their reported state writes; this review does not reinterpret those as file-worker completion results.

### Supplementary original-byte libmm-photo consumer check

The original dynamic symbol `_Z13card_callbackP10_keynode_tPv` is VA `0x8a198`, size 2,420. Its code through epilogue `0x8a9bc–0x8a9c0` was independently inspected; PC-relative state literals resolve to original global `0xfbe6c`.

| Selected original instruction route | State effect |
|---|---|
| `0x8a1f8–0x8a210`, raw MMC -1 | Stores 0. |
| `0x8a214–0x8a244`, raw MMC 0 | Stores 1 only when current state is not 4. |
| `0x8a248–0x8a264`, raw MMC 1 | Stores 2, including when the prior state was 4. |
| `0x8a268–0x8a280`, raw MMC 2 | Stores 3, including when the prior state was 4. |
| `0x8a630–0x8a648`, error-key value | Signed `BLE` skips nonpositive values; positive values store 4. |

This confirms the historical ordering/coalescing qualification. Error 4 is not a permanently dominant state: later raw MMC 1/2 can overwrite it, while raw zero alone is suppressed. The inspected callback has vconf reads, comparisons, state stores and diagnostics; it does not correlate a particular outstanding SIF write. These local effects do not establish the runtime sequence or a per-file error identity.

### Type 11, original TBB decoding and OEM table construction

Device-node descriptor VA `0xc5cc` / file `0x45cc` contains original words `[11,0x4244,0x3405,0x3379]`. Its name/setter/getter pointer fields have original type-23 `R_ARM_RELATIVE` relocations at `0xc5d0/0xc5d4/0xc5d8`. Thus normal relocation preserves the odd Thumb pointers to even code `0x3404/0x3378`. Initializer `0x1710` passes the descriptor to its append helper.

Getter instructions `0x337e–0x3382` unsigned-check property ≤3 and execute `TBB [pc,r0]`. The four original data bytes at `0x3386` are `18 27 0c 02`; using table/PC base `0x3386` plus twice each byte gives the exact original branch targets:

| Property | Target | Interface offset | Null-slot fallback |
|---:|---|---|---|
| 0 | `0x33b6` | `+0x2b8` | `0x33c4–0x33cc` |
| 1 | `0x33d4` | `+0x2bc` | `0x33e2–0x33ea` |
| 2 | `0x339e` | `+0x2c0` | `0x33ac–0x33b4` |
| 3 | `0x338a` | `+0x2c8` | `0x33ec–0x33f4` |

The getter's selected plugin slot is tested for zero before using the fallback slot; this is distinct from a new dynamic loader invocation for every property. The generic `device_get_property` code at `0x183c` finds the device record and calls record slot +12 with property/output arguments, consistent with this getter ABI.

Original Thumb builder instructions at `0x8e98` were independently evaluated through their PC literals, register arithmetic and original GOT relocations. The temporary base in `r4` is `0x1562c`; the interface base is `0x15830`, so the builder's literal instruction offsets must not be confused with offsets relative to the returned interface table. The important stores reproduce [the OEM navigation index](../evidence/oem-interface-index-run007.json):

| Store instruction | Original table slot | Offset from `0x15830` | Original pointer / even code |
|---|---|---:|---|
| `0x9542` | `0x15ae8` | `0x2b8` | `0x52a1` / online `0x52a0` |
| `0x954e` | `0x15aec` | `0x2bc` | `0x5291` / protect `0x5290` |
| `0x955a` | `0x15af0` | `0x2c0` | `0x5281` / support `0x5280` |
| `0x9572` | `0x15af8` | `0x2c8` | `0x5271` / UHS2 support `0x5270` |

The selected `R_ARM_GLOB_DAT` records bind GOT `0x15354/0x154ec/0x154a0/0x153dc` to those four exported symbols. This verifies runtime initialization instructions, not preinitialized on-disk table pointers or observed table contents. The index's 230 entries/222 named targets/eight unresolved expressions are confirmed as artifact counts; independent functional understanding of all 230 handlers is not claimed.

### OEM paths and integer status ABI

Original online getter `0x52a0` resolves its PC-relative path literal at `0x52ac` to string VA `0xa7c8`, `/sys/devices/platform/dw_mmc_sdcard.0/sdcard_online`. Protect getter `0x5290` uses literal `0x529c` resolving to string VA `0xa790`, `/sys/devices/platform/dw_mmc_sdcard.0/sdcard_protect`. Both transfer the output pointer to `r1` and tail-branch to `sys_get_int` through the Thumb interworking veneer `0x46a8`.

Reader `0x48f4` opens read-only, requests 255 bytes, then unsigned-compares the returned count to 254 (`0x490e–0x4912`). Counts 0–254 are NUL-terminated and closed; negative bit patterns and counts ≥255 follow failure. Wrapper `0x49dc` saves that status in `r4`, parses base 10 with null end pointer only on reader success, writes the output and explicitly moves saved status into return register `r0` at `0x4a06` (`2046`). Its failure branch `0x4a12–0x4a18` sets status/output to -1 before that same return. This confirms the status ABI despite the inferred void C prototype.

The original PLT/GOT resolutions are `open 0x4684→0x15190`, `read 0x45f0→0x15160`, `close 0x47f8→0x15204`, `strtol 0x45e4→0x1515c`, and `sys_get_int 0x46a8→ARM 0x46ac→0x1519c`. No parse-end or errno validation is present in this wrapper; successful reader status is not proof of valid numeric content or physical card state.

## Review artifacts and remaining scope

Independent scratch scripts/data are `.work/run011/review-card/{audit.py,audit.json,windows.txt,builder.py,builder.json,plt.py,plt.json,photo-windows.txt}`. They read firmware data and perform host-side decoding only. The historical collector was not rerun because it may populate missing per-generation input manifests; this audit instead independently checks the completed evidence against original inputs without modifying those artifacts.

The six claim dispositions close this specific historical independent-semantic-review gap. They do not retroactively complete other RUN006–RUN008 reviews, establish all OEM handlers, incorporate unreviewed new kernel-producer results, or remove the runtime/per-file limitations stated above. The old report's historical reviewer-unavailability statement remains an accurate description of its original checkpoint; this document supplies the later review.
