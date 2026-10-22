# Independent review of Kernel2 card events — RUN013

**The four requested RUN011 claim categories are supported within their stated
static limits. No material correction is required.** In particular, insertion
really uses `ACTION=remove`; the shared error-state suppression and local
bit-processing order are byte-backed; and the eight-candidate rescan bound is
separate from deviced's timer/retry policy.

This reviewer did not author RUN011. The review read the original kernel image
and recovered symbol/data records, independently decoded the selected ARM
instructions, and manually traced register values, indirect-call bindings and
control-flow conditions. It did not rely on generated C or execute target code.
The decoder is the same Capstone implementation used by the author, so this is
independent interpretation/readback, not a second disassembler implementation.

## Source and artifact checks

- Original `.work/full/kernel-2.raw`: **7,474,108 bytes**, SHA-256
  `25bdca5cde4a5c10710d02dbaa904c62cd77b0b4562b8bf4d73c675f50bdb587`.
- Mapping throughout: **decoded offset = kernel VA − `0xc0008000`**. These
  are packaged-image link VAs, not live addresses.
- Reviewed [RUN011 report](KERNEL_CARD_EVENTS_RUN011.md), SHA-256
  `2463e27d9c5b78f22889865bdb53fba222ec3179356370ae1eb889a2795d8bde`;
  [evidence](../evidence/kernel-card-events-run011.json), SHA-256
  `ed9b3e2241aee7c14af03be967d376f0ff7f3dfd3f3a0547e39780fe20f24157`;
  [collector](../../tools/firmware/kernel_card_events_evidence.py), SHA-256
  `36d2019e25bb1ced1122892be1a0cee9b15d1511c198d09e311b0a3810fc278f`;
  and [manifest](../../manifests/kernel-card-events-run011.json).
- Fresh source comparisons reproduced **26 code regions / 2,940 instruction
  rows, 18 data blocks and 26 original strings**, including their offsets,
  bytes/hashes, decoded operands and little-endian words. Manifest artifact
  sizes/hashes and the saved symbol-catalog hash also agree.

Readback receipts are under `.work/run013/review-card/byte-audit.json`.
Five supplementary original-byte regions (72 instructions) bind the device
kset path, saved as `supplemental-kset-binding.json`; these do not change RUN011
or add Ghidra/ELF decompilation coverage. The private review helper is
`.work/run013/review-card/audit.py`; it reads the source and verifies the saved
artifact without invoking the author's collector or modifying its output.

## 1. Driver, board registration and platform kobject — supported

The machine descriptor word at `0xc06dcb88` (offset `0x6d4b88`) points to
`drime5_es_init`, `0xc06c9ce0`. At `0xc06c9d70..0xc06c9d78`, original instructions
load count 31, pass array `0xc06de78c` and call `platform_add_devices`.
That array's first original word is `0xc06fd310`; its name word points to
`dw_mmc_sdcard` at `0xc06474a8`, and its ID word is zero. The registration
routine calls `device_initialize(pdev + 8)` before `platform_device_add`.

`platform_device_add` (`0xc0268e24`, offset `0x260e24`) stores the pointer from
literal `0xc0269030` into `pdev + 0x48`. That literal is `platform_bus_type`,
`0xc071a7e0`. It calls `dev_set_name` with original format `"%s.%d"`, name and
ID zero, establishing intended `dw_mmc_sdcard.0` naming on successful registration.

Initcall record `0xc06e0c4c` points to `0xc06d7d4c`; the code loads literal
`0xc06d7d54 == 0xc07200e4` and branches to `platform_driver_register`. Its name
matches the device and its probe pointer is `0xc0301b48`. Probe selects callback
table `0xc058be50`, whose event slot `+0x24` is `0xc0301d08`.
`dw_mci_pltfm_register` stores this table at controller `+0xf8`, and stores
`pdev + 8` at controller `+0xf0`. The event producer then passes that saved
pointer plus 8, i.e. the device's kobject, to `kobject_uevent_env`.

The device/bus relationship also matches the generic uevent path:

- `dev_uevent_name` (`0xc0263a98`, offset `0x25ba98`) subtracts 8 from its kobject
  argument, reads the device's bus at `+0x40`, and returns its first pointer.
  The platform bus's first pointer names `platform`.
- Supplementary fresh source at `devices_init`, `0xc06d4c64` (offset
  `0x6ccc64`), supplies `device_uevent_ops == 0xc05859f8` to
  `kset_create_and_add` at `0xc06d4c7c` and stores the returned kset at
  `devices_kset == 0xc07534a4`.
- `kset_create_and_add`, at `0xc01b43e8`/`0xc01b442c`, preserves its second
  argument and stores it at returned kset `+0x2c`, the same field loaded by the
  generic event helper. Its trailing literal at `0xc01b4470` is excluded from
  the supplementary instruction window.
- `device_initialize`, `0xc0264cd0` (offset `0x25ccd0`), loads that global and
  stores it at device `+0x18`, which is kobject `+0x10`. The generic event helper
  finds that kset and uses its name callback; table `0xc05859fc` points to
  `dev_uevent_name`.

This independently closes the intended `SUBSYSTEM=platform` class binding.
Successful initialization, allocation/registration, active Kernel2 selection,
matching/driver execution and runtime kobject state remain conditions. No
`cdn-sdhci` producer is established.

## 2. Exact environment and action mapping — supported

Producer `0xc0301d08` (offset `0x2f9d08`) explicitly builds four two-word stack
arrays: one string pointer followed by NULL. Fresh original strings and argument
tracing give:

| Selector | Exact supplied environment string | Helper call VA / decoded offset | R1 action |
|---:|---|---|---:|
| 0 | `EVENT=sdcard_insert` | `0xc0301dfc` / `0x2f9dfc` | 1 |
| 1 | `EVENT=sdcard_remove` | `0xc0301ea8` / `0x2f9ea8` | 1 |
| 2 | `EVENT=sdcard_init_error` | `0xc0301e94` / `0x2f9e94` | 1 |
| 3 | `EVENT=sdcard_data_error` | `0xc0301de0` / `0x2f9de0` | 1 |

The selector-1 branch does **not** need another `mov r1,#1`: it preserves the
incoming selector in R1 through that branch, with no intervening call. The other
three emission branches explicitly load action 1.

At `0xc01b49a8` (offset `0x1ac9a8`), generic `kobject_uevent_env` indexes the
original pointer table at `0xc0420704` by `action << 2`. Entry 1, at
`0xc0420708`, points to `0xc064d088`, original string `remove`. The string becomes
`ACTION=%s` at call `0xc01b4ab8`. The same selected body adds `DEVPATH=%s` and
`SUBSYSTEM=%s`, then traverses the supplied NULL-terminated array and appends
its literal environment string with `%s`.

No correction to `remove` is warranted, including for insertion. Replacing it
with an assumed `add`/`change` action would contradict the source. These are
vendor platform-device messages; their action argument does not itself establish
block-device removal. Generic early returns/filtering and allocation/error
branches also make a helper call distinct from successful emission or receipt.
The single supplied `EVENT` string has no per-file/capture identifier; this
review does not infer a complete runtime environment or delivery record.

## 3. Admission state and local worker order — supported

Let P be controller `+0xfc`. The reviewed producer behaves exactly as follows:

| Selector | Emission admission | Local state word `P+0xc` |
|---:|---|---|
| 0 | `P+4 == 0` | Becomes 1 after the branch, including a skipped emission |
| 1 | Global host's mapped register `+0x50 != 0` | Becomes 0 after the branch, including a skipped emission |
| 2 or 3 | State differs from **both 0 and 2** | Becomes 2 after a helper call; suppressed branch leaves it unchanged |

The error test is the actual `cmp state,#0; cmpne state,#2; beq` sequence. It
does not require equality to 1. `P+4 = 1` and state 0 are set by init at
`0xc0302cf0`/`0xc0302d00`; resume clears state at `0xc0301c7c`. Online software
state and hardware detection must therefore remain distinct.

At both error callsites, instructions store state 2 without checking the
returned R0. The init/data kinds share this word, so a failed helper invocation
can still suppress later errors until a state-changing path rearms it. The
diagnostic `_dev_info` calls occur before some suppression tests; a diagnostic
is not an emission receipt.

`dw_mci_error_event` (`0xc02fcfe0`, offset `0x2f4fe0`) maps incoming selector
0 to pending bit `0x4`, selector 1 to `0x8`, and queues controller work `+0xac`.
Other selectors return without the selected queue call. Probe installs worker
`0xc02fc910` in that work item's function slot; the worker subtracts `0xac`
from its work pointer and uses work `+0x20`, hence controller `+0xcc`.

Fresh register tracing confirms four separate read/clear/test stages, in order:

| Pending bit | Driver callback selector | Indirect call VA |
|---:|---:|---|
| `0x1` | 0 | `0xc02fc95c` |
| `0x2` | 1 | `0xc02fc9a0` |
| `0x4` | 2 | `0xc02fc9e4` |
| `0x8` | 3 | `0xc02fca28` |

Each call uses controller callback table `+0xf8`, event slot `+0x24`, whose
original pointer record resolves to the producer above. Clearing is protected
by local interrupt save/disable/restore; the report does not need or establish
a global serialization guarantee. Pending flags are bits, so repeated writes
can coalesce. The separate loads mean the whole word is not one entry snapshot.
If bits 2 and 3 are observed, callback 2 precedes 3; absent intervening state
changes, its state-2 store suppresses the latter error emission.

The card-detect worker is separate, installed at controller `+0xc8` for work
`+0xbc`. The platform flag-`0x10` transition path calls selectors 0/1 at
`0xc02ffc10`/`0xc02ffdb4`, and the additional guarded removal path calls selector
1 at `0xc02ffec8`. The source platform flags `0x30` include `0x10`. Later
`mmc_detect_change` call `0xc02ffe8c` is a local worker ordering anchor, after the
selected callbacks/cleanup. This does not order all workqueue invocations,
block-device events, monitor installation, udev reception or vconf callbacks.
RUN011 correctly leaves writers of pending insertion/removal bits unassigned.

## 4. Generic MMC error producers and retry boundaries — supported

Host-ops binding is explicit: core probe stores pointer `0xc058bc30` in MMC host
`+0xdc` at `0xc02fdc94`, and controller in MMC host `+0x244`. Original ops slot
`+0x44 == 0xc02fcfe0` therefore binds both selected generic error calls to the
pending-bit producer. Slot `+0x20 == 0xc02fcdc8` binds set-card recovery to SD
callback table slot `+8 == 0xc0302b40`.

For `mmc_rescan` (`0xc02ebb04`, offset `0x2e3b04`), fresh branch/register review
supports the stated **upper bound of eight candidate iterations**:

- At `0xc02ebd64..0xc02ebd70`, R8 starts at 1, index R5 at 0, and a table word
  is loaded for each candidate. Original table `0xc058af60` contains 400000,
  300000, 200000 and 100000.
- Success paths leave the attempt loop. The host-minimum comparison at
  `0xc02ebe44..0xc02ebe48` can end a pass early. Otherwise the index increments
  and is compared with 4 at `0xc02ebebc..0xc02ebec4`.
- Pass end tests R8; the first end sets it to zero and returns to index reset.
  The next end reaches `0xc02ebf28`. Error callback call `0xc02ebf48` receives
  R1 = R8 = 0.

This counts selected candidate-loop iterations, not guaranteed full attachment
sequences, a time budget, every invocation's attempt count or userspace retries.
The selected code tries UHS2 and, on reviewed failure paths, SDIO/SD/MMC with
power/reset/idle operations. Its set-card call at `0xc02ebeb8` passes selector 2
when the callback/guards allow it. The SD callback at `0xc0302b40` calls
`_sdcard_set_power_ctrl(0)`, `msleep(50)`, then `_sdcard_set_power_ctrl(1)`; the
instructions establish request sequencing, not measured rail transitions or a
guaranteed 50-ms physical recovery interval.

For `mmc_blk_issue_rw_rq` (`0xc02fa248`, offset `0x2f2248`), the original eight
absolute jump-table words at `0xc02fa33c` map numeric status 4 to `0xc02fa6e8`
and status 7 to `0xc02fa704`. Status 4 invokes `mmc_blk_reset` and branches
toward retry on zero; nonzero reaches the error path. Status 7 reaches that
path directly. At `0xc02fa728`, a present host error callback receives selector
1. Numeric labels remain appropriate: no additional source enum interpretation
is needed, and the read/write request context does not make this a write-only
or capture-only event.

Reset helper `0xc02f8f64` (offset `0x2f0f64`) tests the selected mask against
object `+0x2a4`, returns `-17` when already used, otherwise records it and calls
`mmc_hw_reset`. Its other result/partition branches remain distinct. Neither
that mask nor the rescan pass flag establishes deviced's later timer budget.
The report's separation of kernel recovery, bit-worker publication and deviced
retry/publication is necessary and supported.

## Verdict boundary

This review approves these **four cohesive static categories**, not every
possible card-driver path or all adjacent sysfs semantics. It supplies no
active-kernel selection, driver-execution, successful netlink delivery,
mount/filesystem outcome, hardware recovery, global event ordering or per-file
completion proof. The image has conditional paths, shared suppression and
coalescing that explicitly prevent those stronger conclusions.

Original RUN011 artifacts and all Ghidra projects were left unchanged. No target
program, device I/O, firmware edit, commit or push was performed.
