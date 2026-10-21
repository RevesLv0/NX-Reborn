# Card event producers and OEM property getters — RUN007

The external card-error source left open in RUN006 now has a concrete static
route: a udev platform `EVENT` string enters a registered deviced notifier and
can update `memory/sysman/mmc_err_status`. Libmm-photo watches this key and changes
its admission state. This channel is distinct from the SIF file worker's local
`fwrite` result and does not identify which outstanding capture failed.

The card online/protection prechecks also reach concrete OEM sysfs readers.
The common library dynamically loads a previously unprocessed plugin; one new
ELF content has now been imported and analyzed. Two intermediate Thumb targets
were missing from Ghidra's recovered function set and are documented with manual
original-byte evidence, without counting them as completed decompilations.

## Sources and method

| Original rootfs source | SHA-256 |
|---|---|
| `/usr/bin/deviced` | `7df5d80e88e6668dff2274f86a550e480250d95dce1d3da29b489aa5e5d40f59` |
| `/usr/lib/libdevice-node.so.0.1` | `843ecf26516114370e16cd2ebc742f515cdd8b590812947b1063daa61565389e` |
| `/usr/lib/libdeviced.so.0.1.0` | `df70b308f88d6c0eb038e2e67b69b4825ef12dec60230b6fd1c3dab942989f5d` |
| `/usr/lib/libslp_devman_plugin.so` | `a88cb8130ba246b45c077cf25f0c5944077e41b780eee20f5a5a675b35a15588` |
| Libmm-photo consumer, reused RUN006 | `ea4ae65608a6f9ea0761e35c18764401cf7b876652f7949c322e880fa9f68ca9` |

All addresses below are original ELF link VAs. DSO Ghidra VAs add `0x10000`;
deviced Ghidra VAs equal original addresses. PT_LOAD mapping determines each file
offset independently. ARM versus Thumb is taken from saved Ghidra TMode contexts
for recovered functions. Manual getter/setter targets use descriptor pointer bit
0 to select Thumb; their even code addresses are distinguished from odd pointers.

[Evidence](../evidence/card-events-run007.json) retains source hashes, completed
run receipts, selected C, original code windows, descriptor/jump-table/literal
data and relocation records. The extraction tool independently maps original
bytes and decodes contiguous recovered instruction addresses, splitting at gaps.
Inline TBB entries and literal pools are kept as data. Review is by the primary
agent; the separate independent reviewer remains unavailable after its actual
quota failure. There is no runtime/device observation here.

```mermaid
flowchart LR
  U[udev platform EVENT] --> D[deviced notifier key 3]
  D --> V[vconf card error/state]
  V --> P[libmm-photo admission state]
  P --> G[device_get_property type 11]
  G --> O[OEM plugin getter]
  O --> S[SD card sysfs node]
```

This is a static dependency diagram. The admission state and property checks are
separate inputs; the diagram does not imply synchronous event delivery or a
per-capture transaction.

## udev event strings reach a concrete registered callback

Deviced function `0x25dd4`, whose diagnostics name `mmc_init`, registers notifier
key 2 with callback `0x23558` and key 3 with callback `0x23ba8`. Registration
helper `0xb530` rejects null/duplicate function pairs, allocates an eight-byte
key/function record and appends it to list `0x586f0`. The unregister helper is
`0xba68`. Incoming-reference evidence distinguishes these registrations from
the function's instrumentation references to itself.

Dispatcher `0xbcc8` traverses that list, matches its key and invokes each non-null
function with its supplied argument. Its returned count is the number invoked,
not an error/success result from those callbacks.

The udev receive callback `0x260c0` supplies concrete keys and arguments:

| Inspected udev condition | Dispatcher call |
|---|---|
| Subsystem `block`, path matches `*/mmcblk[0-9]`, action `add`, non-null devnode | key 2, devnode pointer |
| Same block filter, action `remove` | key 2, zero |
| Subsystem `platform`, path matches `*/dw_mmc_sdcard.[0-9]` or `*/cdn-sdhci.[0-9]`, `EVENT=sdcard_insert` | key 3, 1 |
| Same platform filter, `EVENT=sdcard_remove` | key 3, 0 |
| Same platform filter, `EVENT=sdcard_init_error` | key 3, 2 |
| Same platform filter, `EVENT=sdcard_data_error` | key 3, 3 |

Missing monitor/device/property values and unmatched events do not take these
branches. This proves how an accepted event is interpreted; the kernel producer,
monitor installation timing and actual emitted sequence remain separate work.

Callback `0x23ba8` writes MMC state 0 for arguments 0 and 1. Argument 2 writes
error `0xcb`. Argument 3 conditionally decrements retry counter `0x5885c`, sets
retry flag `0x58860`, and schedules/delays timer callback `0x23374` when the
reviewed mount/budget guards permit retry; otherwise it writes error `0xcb`
immediately. Timer `0x23374` writes `0xcb` while the retry flag remains set, then
clears timer handle `0x58864`. No fixed retry budget or guaranteed recovery is
inferred from this conditional path.

Block callback `0x23558` handles removal/retry state and conditionally schedules
`0x23178`; that timer either calls the mount helper or changes property `(11,2)`.
These setters are inspected camera code and were not executed on the host.

## Mount and unmount publish admission state, not file-write results

Mount worker `0x203fc` calls mount helper `0x201d0` for
`/opt/storage/sdcard`. It publishes these explicit combinations:

| Local mount result | `mmc_err_status` | `mmc` | `mmc_mount` |
|---|---:|---:|---:|
| `-0x1e`, diagnostic read-only filesystem | `0x1e` | 1 | 0 |
| `-0xc9`, diagnostic unsupported device | `0xc9` | 2 | 2 |
| `-0xca`, diagnostic needs format | `0xca` | 2 | 2 |
| Other reviewed failure path | `0xc9` | 2 | 2 |
| Nonnegative result | No explicit error-key clear in this branch | 1 | 0 |

Unmount worker `0x21994` clears the error key and writes MMC state 2 on success;
its failure branch writes state 1. Cleanup `0x22b08` clears error, writes MMC -1
and requests unmount. The format path also publishes progress/status, but no
formatting operation was performed during analysis. These function bodies do
not consume a SIF buffer or its `fwrite` result.

Libmm-photo `card_callback` (`0x8a198`, RUN006 evidence) maps raw MMC -1/0/1/2 to
internal state 0/1/2/3, with the raw-zero transition suppressed while internal
state is 4. Any positive error-key value sets internal state 4. Raw MMC 1 or 2
can still assign state 2 or 3. Separate key updates are therefore not treated as
an atomic pair; notification order/coalescing and later key reads remain runtime
questions. The callback does not push `StorageStateQueue`, replace a pending
write result or set the worker's storage-exception byte in its inspected body.

## Type 11 reaches a dynamically loaded OEM interface

Libdevice-node initializer `0x1570` opens
`/usr/lib/libslp_devman_plugin.so` with flag 2, resolves
`OEM_sys_get_devman_plugin_interface`, and stores the returned table pointer.
Failure paths select its local fallback table. `device_get_property` (`0x183c`)
finds a registered device record and invokes record slot `+12` with property ID
and output pointer. The similarly shaped setter is `0x198c` using slot `+8`.

Initializer `0x1710` appends descriptor original VA `0xc5cc`, file offset
`0x45cc`: `[11, 0x4244, 0x3405, 0x3379]`. Thus type 11's getter code is `0x3378`
and setter code is `0x3404`, with Thumb bit 1 on their pointers. These two code
targets are absent from the saved Ghidra function export. A selected-decompile
query matching their would-be names completed with zero matches; it is not a
decompiler failure or proof the code is absent.

The getter's four-byte TBB table at `0x3386` gives these concrete property routes:

| Property | Branch target | OEM interface offset | Newly selected implementation |
|---|---|---|---|
| 0 | `0x33b6` | `+0x2b8` | `OEM_sys_get_mmc_sdcard_online`, code `0x52a0` |
| 1 | `0x33d4` | `+0x2bc` | `OEM_sys_get_mmc_sdcard_protect`, code `0x5290` |
| 2 | `0x339e` | `+0x2c0` | `OEM_sys_get_mmc_sdcard_supportcard`, code `0x5280` |
| 3 | `0x338a` | `+0x2c8` | `OEM_sys_get_mmc_uhs2_sdcard_supportcard`, code `0x5270` |

The getter tests the selected plugin slot and uses its fallback slot when null.
The OEM interface builder (`0x8e98`) stores the online/protect pointers at table
base `0x15830 + 0x2b8/0x2bc`. These are runtime-initialized table fields, not
file-backed initialized pointer bytes. Its final helper `0x65cc` selects UART/USB
node paths in the inspected body, not replacement card getters.

The online getter reads
`/sys/devices/platform/dw_mmc_sdcard.0/sdcard_online`; the protection getter reads
`/sys/devices/platform/dw_mmc_sdcard.0/sdcard_protect`. This completes the static
dispatch correspondence to libmm-photo helpers `0x81464` and `0x81884`, which
request device 11 properties 0 and 1 respectively. Availability of those sysfs
nodes on an active boot remains unobserved.

## Integer-read ABI requires original instructions

OEM `sys_get_int` (`0x49dc`) calls reader `0x48f4`. The reader opens the supplied
path read-only, reads up to 255 bytes, accepts a count below 255, terminates the
buffer and closes it. The integer wrapper parses base 10 with `strtol`, writes
the output, and returns 0; read failure writes -1 and returns -1. It does not
check `strtol`'s end pointer or errno in this body.

Ghidra inferred a void return for the integer wrapper. Original Thumb instruction
`0x4a06` moves the saved status into r0 before return; the failure branch sets
that status to -1. The inspected ABI, not the inferred C prototype, supports the
status claim. No malformed-input behavior beyond these explicit checks is
generalized.

## Reproduction and remaining work

```sh
PYTHONPATH=.work/python python tools/firmware/card_events_evidence.py
```

The evidence records exact input manifests, Ghidra generation commands and
SHA-bound address-reference/TMode queries. Use `tools/ghidra/run_headless.py` for
import or process exports and `tools/ghidra/run_address_references.py` for the
saved queries. Failed preliminary reference-query attempts are retained in the
private run archive; only completed queries contribute evidence.

`tools/firmware/oem_interface_index.py` also indexes the interface builder's 230
assignments, resolving 222 exact exported targets and retaining eight expressions
unresolved. This is an address-navigation artifact for broader hardware work,
not a claim that all handlers have been understood or that every named feature
is present on the camera.

Remaining boundaries are actual kernel emission of the udev `EVENT` strings,
monitor/initialization order, mounted namespace and physical device selection,
notification coalescing, retry timing and per-capture correlation with SIF.
Separate vconf state writes and OEM property reads do not establish that every
short write is reported, or that every card notification refers to a failed file.
