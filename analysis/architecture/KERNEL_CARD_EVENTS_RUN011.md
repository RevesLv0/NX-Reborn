# Kernel card-event producers and retry boundaries — RUN011

Packaged Kernel2 supplies a concrete producer for the four platform `EVENT`
strings accepted by deviced in RUN007. Its `dw_mmc_sdcard` driver emits insertion,
removal, initialization error and data error through `kobject_uevent_env` on the
platform device's kobject. **All four use action number 1, whose original action
name is `remove`**, including `EVENT=sdcard_insert`. These vendor platform messages
must therefore be distinguished from an actual block-device removal notification.

The producer has conditional emission and shared error suppression. Kernel work
scheduling, generic MMC retries and deviced's later retry timer are separate stages;
none establishes a per-file or per-capture acknowledgment.

## Original source and method

| Input | Identity |
|---|---|
| `.work/full/kernel-2.raw` | 7,474,108 bytes; SHA-256 `25bdca5cde4a5c10710d02dbaa904c62cd77b0b4562b8bf4d73c675f50bdb587` |
| Recovered symbol catalog | `.work/run004/kernel/kernel-2-symbols.json`; identity retained in evidence |

Every kernel VA below maps to decoded file offset `VA - 0xc0008000`. The base is
an image/link mapping, not a live address observation. The collector verifies the
whole original source SHA before decoding. [Evidence](../evidence/kernel-card-events-run011.json)
contains 2,940 ARM instructions in 26 bounded regions, 18 separate data blocks and
26 original strings, with raw bytes, exact decoded offsets and per-block hashes.
Inline absolute jump tables and trailing literal pools are explicitly excluded
from instruction regions. Kallsyms names guide navigation; original instructions
and pointer records establish the selected call bindings.

```sh
PYTHONPATH=.work/python python tools/firmware/kernel_card_events_evidence.py
```

[Collector](../../tools/firmware/kernel_card_events_evidence.py) and
[manifest](../../manifests/kernel-card-events-run011.json) are reproducible offline
artifacts. No Ghidra project, firmware byte or device was changed or executed.
The initial private helper was renamed after its name `dis.py` shadowed Python's
standard `dis` module; that failed import contributed no evidence. The corrected
collector completed with full byte coverage for every selected code region.

## Platform device and callback bindings

The image has a static boot-registration chain, conditional on this image and
board initializer actually being selected:

1. The machine descriptor at `0xc06dcb50` contains board-init pointer
   `0xc06c9ce0` (`drime5_es_init`) at `+0x38`.
2. That initializer passes `d5_devices` (`0xc06de78c`) and count 31 to
   `platform_add_devices` at `0xc06c9d78`. The first array word is
   `drime5_device_sdcard`, `0xc06fd310`.
3. The platform device contains name pointer `0xc06474a8`, string
   `dw_mmc_sdcard`, and ID 0. `platform_device_add` at `0xc0268e24` stores
   `platform_bus_type` into the device's bus field and uses original format
   `"%s.%d"` at `0xc0666278` for a nonnegative ID. Thus the intended name is
   `dw_mmc_sdcard.0`.
4. Level-6 initcall record `0xc06e0c4c` points to `0xc06d7d4c`, whose literal
   `0xc06d7d54` supplies driver `0xc07200e4` to `platform_driver_register`.
   The driver name matches `dw_mmc_sdcard`, and its probe is `0xc0301b48`.
5. Probe supplies `sdcard_drv_data` (`0xc058be50`) to
   `dw_mci_pltfm_register` (`0xc0300510`). That stores the callback table at
   controller `+0xf8` and the platform `device` pointer at controller `+0xf0`.
   Table slot `+0` is init `0xc0302c7c`; slot `+0x24` is event generator
   `0xc0301d08`.

The generic core probe `0xc02fd7f4` installs `dw_mci_ops` (`0xc058bc30`) into
MMC host `+0xdc` at `0xc02fdc94`, using literal `0xc02fe198`. It stores the
controller pointer at MMC host `+0x244`. The operations table's `+0x44` entry
is `dw_mci_error_event` (`0xc02fcfe0`), while its `+0x20` entry is
`dw_mci_set_card` (`0xc02fcdc8`). This makes the later indirect error and retry
calls concrete for this host configuration.

The platform bus name pointer `0xc071a7e0` resolves to `platform`.
`dev_uevent_name` (`0xc0263a98`), referenced by the device uevent callback table,
returns the bus name when present. The event generator adds 8 to its saved
platform `device` pointer before calling `kobject_uevent_env`, matching that
function's kobject argument and the device-name callback's subtraction of 8.
These are the intended `SUBSYSTEM=platform` and `dw_mmc_sdcard.0` source identity
accepted by RUN007 deviced, conditional on successful registration and delivery.

This does not resolve selection among packaged kernels 0, 2 and 3. RUN004's
container/header evidence leaves that selection unknown, and this boot descriptor
only establishes registration within Kernel2. The `cdn-sdhci` alternative accepted
by deviced is not resolved to a producer here.

## Exact event payload, guards and shared state

`dw_mci_sdcard_generate_event` starts at `0xc0301d08` (decoded offset `0x2f9d08`).
It constructs four stack arrays, each holding one pointer followed by NULL:

| Callback selector | Original string VA | Exact environment string | Emission call VA |
|---:|---|---|---|
| 0 | `0xc0676ca8` | `EVENT=sdcard_insert` | `0xc0301dfc` |
| 1 | `0xc0676cbc` | `EVENT=sdcard_remove` | `0xc0301ea8` |
| 2 | `0xc0676c78` | `EVENT=sdcard_init_error` | `0xc0301e94` |
| 3 | `0xc0676c90` | `EVENT=sdcard_data_error` | `0xc0301de0` |

Each call passes action 1. For the removal-selector branch, r1 remains the
incoming selector value 1 through the call; the other branches explicitly load
1. `kobject_uevent_env` loads `kobject_actions[action]` at `0xc01b49a8`; original
table entry `0xc0420708` points to string `remove`. At `0xc01b4ab8`, that string is
inserted using `ACTION=%s`. The same body adds `DEVPATH=%s` and `SUBSYSTEM=%s`,
then iterates the supplied NULL-terminated array and adds its strings with `%s`.
This is byte-backed payload construction, not an inference from diagnostics.

Let `P` be the private structure at controller `+0xfc`. Its `P+4` word is returned
by `sdcard_online`; its `P+0xc` word is returned by `sdcard_state`.

| Selector | Condition for calling the uevent helper | Local state afterward |
|---:|---|---|
| 0, insertion | `P+4 == 0` | `P+0xc = 1`, also when the helper is skipped |
| 1, removal | global SD host's mapped register at `+0x50` is nonzero | `P+0xc = 0`, also when the helper is skipped |
| 2, init error | `P+0xc` differs from both 0 and 2 | `P+0xc = 2` after the call; unchanged when suppressed |
| 3, data error | `P+0xc` differs from both 0 and 2 | `P+0xc = 2` after the call; unchanged when suppressed |

Initialization at `0xc0302cec..0xc0302d00` sets online to 1 and state to 0.
Resume `0xc0301c40` also clears state. Normal selected transitions use states
0/1/2, but the error condition is precisely “neither 0 nor 2,” not an equality
check against 1. The two error kinds share the same suppression field: after an
admitted error, another init or data error is skipped until a state-changing
path rearms it. The emission return value is not checked before the state store.
A helper invocation therefore does not prove delivery, and an unsuccessful
attempt can still leave local suppression state 2.

The functions' “generate … event” diagnostics occur on paths that can suppress
the actual helper call. A printed diagnostic alone would not prove a transmitted
event. The source strings carry an event category, with no filename, capture ID,
request pointer, sector number or per-file completion result.

## Card-detect and queued error producers

The core probe initializes event work at controller `+0xac`, with function
pointer `dw_mci_work_event_work` (`0xc02fc910`) at `+0xb8`. It separately
initializes card-detect work at `+0xbc`, with
`dw_mci_work_routine_card` (`0xc02ffb3c`) at `+0xc8`.

The interrupt body `0xc02ff0bc` tests status bit 0 and reaches
`0xc02ff500..0xc02ff510`, acknowledging that bit and queuing the card-detect
work. That worker calls `dw_mci_get_cd` and compares the result with its saved
slot state. On the reviewed platform-flag `0x10` path, an insertion transition
calls controller callbacks `+0x24` with selector 0 at `0xc02ffc10`; a removal
transition calls selector 1 at `0xc02ffdb4`. A separate guarded removal path
calls selector 1 at `0xc02ffec8`. The original SD platform-data flags are `0x30`,
which include `0x10`; runtime modification is not observed. The getter's default
register path interprets the relevant zero detect bit as present and nonzero as
absent, while other callback/flag paths remain in the preserved body.

The inspected worker calls `mmc_detect_change` later at `0xc02ffe8c`, after the
selected callback and local request cleanup. This establishes order inside that
worker invocation, not a global ordering between vendor messages, block device
registration/removal, userspace monitor installation and vconf callbacks.

For errors, `dw_mci_error_event` accepts:

- Selector 0: sets bit 2 (`0x4`) in controller `+0xcc`.
- Selector 1: sets bit 3 (`0x8`) in controller `+0xcc`.
- Other selectors: return without the selected queue operation.

The accepted branches queue event work at controller `+0xac`. Its callback
clears/tests bits 0, 1, 2, 3 in that order and, for each observed set bit, calls
the selected driver's `+0x24` callback with selector 0, 1, 2, 3 respectively.
The error queue therefore reaches the exact init/data environment strings above.
The worker supports insertion/removal bits too, but this report does not assign
an unproven writer to those bits; the card-detect path already invokes the
generator directly.

Pending state is a bitmask, not an event-count queue. Multiple reports before a
bit is processed can collapse into one observed bit. If both error bits are
observed in one invocation while state permits errors, selector 2 runs first
and sets state 2, which suppresses selector 3. Concurrent state changes can alter
that outcome; no delivery order across invocations or udev ingress is claimed.

## Generic MMC recovery reaches the same error channel

Two independent callers of host operations `+0x44` are now concrete.

`mmc_rescan` (`0xc02ebb04`, offset `0x2e3b04`) reaches the call at
`0xc02ebf48` with argument 0 after the reviewed attachment attempts fail. Its
local retry structure starts with pass flag r8=1 and table index r5=0. The table
at `0xc058af60` contains 400000, 300000, 200000 and 100000. It tries up to four
entries, with success exits and a comparison against the host minimum, then
allows one further pass by setting r8=0 and resetting the index. Thus this
selected sequence permits up to eight candidate iterations; it does not promise
eight attempts for every card or define deviced's retry count.

The attempts include `mmc_attach_uhs2_sd`, followed on selected failure paths by
power-up/reset/idle/interface-condition operations and attachment attempts for
SDIO, SD and MMC. Failures invoke `mmc_power_off`. Where the set-card callback
exists and the reviewed guards permit it, call `0xc02ebeb8` passes selector 2.
The installed `dw_mci_set_card` forwards through SD callbacks slot `+8` to
`dw_mci_sdcard_set_card` (`0xc0302b40`). Selector 2 calls the named
`_sdcard_set_power_ctrl(0)`, waits with `msleep(50)`, then calls
`_sdcard_set_power_ctrl(1)`. This is static recovery intent, not measured power
behavior, elapsed recovery duration or guaranteed re-enumeration.

`mmc_blk_issue_rw_rq` (`0xc02fa248`, offset `0x2f2248`) calls host operations
`+0x44` with argument 1 at `0xc02fa728`. Its numeric request-status jump table
at `0xc02fa33c` has eight entries; the collector keeps this table as data.
Selected concrete examples are:

- Status 4 reaches `0xc02fa6e8`, tries `mmc_blk_reset`, and reaches the error
  call if that reset returns nonzero; a zero result branches back toward retry.
- Status 7 reaches `0xc02fa704`, then the error call directly.
- Status 5 has further reset/result/request guards. Other preserved branches
  can reach the same call, including an out-of-range-status diagnostic path.

No unsupported source enum names are assigned to these numeric statuses. This
is a block read/write request function, so the event is not established as a
write-only or capture-only error. The reset helper at `0xc02f8f64` tests a
reset-use mask at object `+0x2a4`, rejects an already-used selected bit with -17,
otherwise sets it and calls `mmc_hw_reset`; additional paths return hardware or
partition-switch results. Those guards are a kernel recovery policy layer.
They do not specify the later deviced retry budget or associate its timer with
a particular file request.

## Sysfs correspondence and remaining boundaries

The SD init body registers original attribute records:

| Attribute record | Name | Show | Store |
|---|---|---|---|
| `0xc07203e4` | `sdcard_online` | `0xc0302fe4` | `0xc0301a90` |
| `0xc07203f4` | `sdcard_protect` | `0xc0302fa8` | null |
| `0xc0720444` | `sdcard_state` | `0xc0302f58` | null |

Their original name strings and handler pointers bind the RUN007 OEM paths
`/sys/devices/platform/dw_mmc_sdcard.0/sdcard_online` and `sdcard_protect` to this
producer's driver. The first sysfs creation failure aborts the selected init
path with -1; mere presence of records does not establish live files.

Online reads the private software word. Its store accepts leading character
`0` or `1` and updates that word, while resume reconstructs it from a detect
register. It must not be treated as an immutable direct physical-presence
measurement. Protection returns zero under controller flag `0x200`; otherwise
it returns whether mapped register `+0x54` is nonzero. Both format decimal text
with `"%d\n"`.

RUN007 independently proves that accepted vendor events enter deviced notifier
key 3, and that its data-error case has mount/retry-budget guards before delayed
error publication. This task closes the static Kernel2 producer/name/payload
boundary. Active kernel selection, driver execution, monitor timing, delivery
loss/coalescing, mounted namespace, exact userspace retry budget, physical card
behavior and per-capture correlation remain unobserved or separate work.
