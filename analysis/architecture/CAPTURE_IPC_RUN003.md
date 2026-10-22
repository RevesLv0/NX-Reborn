# Capture, preference and cross-core boundary survey — RUN003

This is a newly reproduced offline static survey of eight original rootfs ELFs. It
extends the capture/AF/lens boundary map; it does not establish RTOS message semantics,
a RAW format, completed capture behavior or hardware operation. The eight inputs were
copied as regular files from the verified extraction and SHA-256 checked against
`.work/full/inventory/full_filesystem_inventory.json`, including the original inode dump
hashes. Firmware BIN SHA-256 is
`f4c238e811970cf858b5d734119477ea191d35cd29d9f84b584157ecfc4ee997`; rootfs SHA-256 is
`9c66f76f3124acb3b8d0c31374ca209d333fcb76267bb86ed9bc18c9e8ea73f7`.

The complete source paths/hashes, export hashes, commands and reviewed-finding ledger
are in `manifests/ghidra-capture-run003.json`. Selected decompilations and independent
Capstone listings are preserved in `analysis/evidence/capture-ipc-run003.json`.

## Survey scope

| Original path under `/usr/lib/` | Function entries | Initial selected decompilation |
|---|---:|---:|
| `libmulticore-bridge.so` | 390 | 12/12 |
| `libdiosal.so` | 237 | 2/2 |
| `libprefman.so` | 174 | 9/9 |
| `libuser-spec.so` | 379 | 7/7 |
| `libdi-sensor.so` | 251 | 3/3 |
| `libudd5.so` | 1,017 | 5/5 |
| `libdi-alg-ipplatform.so` | 70 | 2/2 |
| `libpalm.so` | 2,390 | 2/2 |

Ghidra 12.1.4 / JDK 21.0.12.1+1 imported and auto-analyzed the eight new byte identities
in `NX500_RUN003_CAPTURE`. Initial exports contain 4,908 function entries, 6,905 strings
and 42/42 completed selected decompilations. No initial analyzer timed out at 180 seconds;
no matches were omitted by the 12-function per-file budget. A subsequent analysis-disabled
export traces the mapping helper and frame/send/receive boundaries; its counts refer to
the same programs and must not be added to discovery counts. The followup completed 6/6 additional distinct selected decompilations, giving 48/48
selected functions across both stages; exact attempts and failures are in the manifest.

Every output passed the existing schema-v2 validator, including run identity, input hash,
artifact hash/size and row-count checks. Function entries include stubs and inferred
functions; counts describe discovery and bounded decompilation, not semantic completion.
Missing external DWARF, unresolved external libraries, incomplete demangled vtables and
an analyzer p-code warning in `libpalm.so` were retained in logs. Selected decompilation
success does not repair these limitations.

All original ELF VAs below are link-time addresses, not runtime addresses or file offsets.
These ET_DYN imports have Ghidra image base `0x10000` and original base `0`; subtract
`0x10000` from Ghidra instructions/C addresses to obtain the original ELF VA. Thumb
symbols in `libprefman.so` encode bit zero in `st_value`; code VA and file mapping clear
that bit. The evidence records file offsets separately. ARM/Thumb Capstone disassembly
and ELF relocation/PLT names independently check the selected callsites; linear symbol
listings can include literal pools after the final code instruction.

## RTOS-named preferences read a mapped region

Input `/usr/lib/libuser-spec.so`, SHA-256
`2d04ab487cc9980cb87e513b25ff09011839203756d28857eedfd50a9cc730ec`.

`pref_rtos_get_fd` starts at ELF VA/file offset `0x10668`. Its `BL` at `0x106ac`
calls `open` through PLT `0x3360`, passing flags `2` and `/dev/mem` (string ELF
VA/file offset `0x28a38`). Instructions `0x106b8`–`0x106d0` pass base `0x85400000`
and requested length `0x80000` to the local `get_virtual_address_` helper (body
`0x105e0`, through PLT `0x37b0`). The helper calls `mmap` at `0x10638` through PLT
`0x339c`, with protection `3` and flags `1`, rounding the requested mapping range
using 4 KiB boundaries. The caller returns the cached mapped address, despite the
function's `get_fd` name. This is an observed userland mapping request, not a verified
physical memory ownership map.

`pref_rtos_get_bytes` (`0x107ec`) calls that getter, then copies `length` bytes from
mapped-base-plus-offset through `memcpy` (callsite `0x10828`). Its inspected body does
not take a lock or perform a request/acknowledgement exchange. The corresponding
`pref_rtos_set_bytes` (`0x10960`) copies to the cached mapped-base-plus-offset for
nonzero length and non-null source; this inspected body does not itself initialize
the mapping. Caller setup and cross-core synchronization remain unresolved.

`User_Spec_Get_Rtos_Pref_Next_Shot_Ready` (`0x8a24`) sets offset `0x1c4d`, length
`1`, and calls `pref_rtos_get_bytes` at `0x8a38`, then normalizes the returned buffer
byte to a Boolean. This is a concrete location for a consumer of a readiness-named
byte. The byte's producer, lifetime, ordering with SD/file completion and effect on
capture/transfer coexistence have not been established.

`User_Spec_Get_Rtos_Pref_Lens_Info` (`0x3e10`) similarly reads four bytes at offset
`0xd28` and compares them with `0x330033` and `0x11223344`; it logs a branch and returns
the read word. These values do not identify a lens model or a lens command protocol.

## Packet I/O has a userland wrapper and a separate driver result

Inputs:

- `/usr/lib/libmulticore-bridge.so`, SHA-256
  `f14a12e4d9172989d73c8dff0fd59580c65ccd1972264c9d94c8d1a736820390`.
- `/usr/lib/libudd5.so`, SHA-256
  `8c56bea30a591fbfb8e9e86c237504f5e28f464f74c18cffc8bbaa7f717b0ea1`.

`CIPCCDriverIf::Send` starts at ELF VA/file offset `0x5194`. At `0x51ac` it calls
`ipcc_get_write_available` through PLT `0x49cc`. The inspected ARM instructions use signed comparisons: `CMP r4,#0x18c`
at `0x51b4` followed by `BGE` at `0x51b8`, and `CMP r0,r4` at `0x51bc` followed
by `BLT` at `0x51c0`. An availability value of `-1` returns `-1`; for a length
interpreted as nonnegative signed 32-bit, values at least `0x18c` (396) return `-1`
and insufficient capacity returns `-2`. Lengths with bit 31 set compare as negative
and are not excluded by that size comparison. At `0x51d8` a tail branch reaches
`ipcc_write_pkt` through PLT `0x4744`, passing the buffer, destination identifier and
length. The caller length domain remains unverified, so this is a description of the
signed checks, not an effective unsigned size bound or a verified protocol limit.

In `libudd5.so`, `ipcc_read_pkt` (`0x46168`) and `ipcc_write_pkt` (`0x461d0`) build
16-byte stack records with input words at offsets `0`, `4` and `12`. Their respective
`ioctl` callsites are `0x461b8` with request `0xc0107406` and `0x46220` with request
`0xc0107407` (PLT `0x87f4`). Both load their function return value from record offset
`8` after the call (`0x461bc` and `0x46224`), rather than propagate the `ioctl` return
register. These bodies do not initialize that output word before calling the driver.
The driver contract and error paths must be examined before judging correctness or
assigning semantic names to all record fields. No driver execution was performed.

`CIPCCDriverIf::Receive` (`0x5158`) calls `ipcc_read_pkt` at `0x5178` and maps positive
results to zero and nonpositive results to `-1`. Thus three separate observations
matter: Linux ioctl result, driver-updated record result, and higher wrapper result.
None by itself proves RTOS command acknowledgement or completed capture.

The targeted followup also distinguishes immediate and deferred sender paths.
`CSender::Send` (`0x7898`) calls `createFrame`; if its first supplied identifier is
not `0x10` and a global byte is zero, it reaches `CFrameQueue::Push` at `0x7968`,
then sets the wrapper result to `-1` at `0x796c`. The inspected alternate path
enters a critical section and calls the sender at `0x78fc`. The queue insertion
result, global-byte lifecycle and later delivery remain unverified; a negative result
from this wrapper alone cannot establish that the supplied frame was discarded.
This is an internal code branch, not an assigned meaning for command `0x10`.

## Sensor notifications use a Linux message queue

Input `/usr/lib/libdi-sensor.so`, SHA-256
`75541051bc8e6090ec32d75e1b1b921a965b5a1cad26bf9a0683f7feb93bed07`.

`csensor_module::sendDfmsMsgq` starts at ELF VA/file offset `0x39ac`. It calls
`access(path,4)` at `0x39d0`, `ftok(path,0x722)` at `0x39e4`, and
`msgget(key,0x1b6)` at `0x39ec`. The shared path argument resolves to `/tmp`
(string ELF VA/file offset `0x87b4`). It writes message type `0x38`, copies the supplied
string and two supplied words into a local record, then calls `msgsnd` at `0x3a24`
with payload length `0x1c` and flags `0`. Instruction `0x3a28` sets return value `1`
without testing `msgsnd`'s result; the failed-access branch returns `0`.

Consequently this wrapper's true return is insufficient evidence of successful queue
submission or consumer processing. The queue recipient, command-string domain and
any relationship to capture cancellation remain untraced. Numeric queue arguments
here describe internal Linux IPC, not an identified network or RTOS wire protocol.

## OS abstraction send modes differ; preference access is separately lockable

Input `/usr/lib/libdiosal.so`, SHA-256
`fb27249f43b671484e4c6bc028eb42b6d9c579daac30e516c7eefe0b20b3d95f`.

`_msgqueue_send` (`0x43b8`) calls `msgsnd` at `0x43f4` with flags `0`;
`_msgqueue_trysend` (`0x4544`) calls the same PLT entry `0x2644` at `0x4580` with
flags `0x800` (`IPC_NOWAIT` on this Linux ABI). Both reject a null payload or zero
length and test `msgsnd == -1`, returning `-1` on failure and `0` on submission.
Ghidra does not recover their full calling convention reliably; the flags and
callsites agree with the original ARM instructions. The blocking send path cannot
be treated as equivalent to the try-send path. Successful submission still does not
establish completed downstream processing.

Input `/usr/lib/libprefman.so`, SHA-256
`c44802d1983bd07eaf53f02761cf402143bce245b7e5d20499c62ce1164df18d`.

`pref_get_bytes` (Thumb code VA/file offset `0x21bc`; symbol value `0x21bd`) and
`pref_set_bytes` (`0x241c`; symbol value `0x241d`) validate that the first argument is
at most `10`, call `pref_get_shm` and use `memcpy` at `0x21f2` / `0x2450` if the
returned shared pointer is nonzero. The inspected bodies contain no lock call or
copy-length-versus-region bounds comparison. Separate `pref_lock_sync` (`0x561c`)
and `pref_unlock_sync` (`0x5638`) validate the same index range and route to
`lock_sync`/`unlock_sync` through PLT. This identifies a caller-responsibility
boundary; it does not establish that any caller omits a required lock or supplies
an invalid offset/length. Full caller and shared-memory lifecycle review is pending.

## Remaining work

Trace the writer of mapped byte `0x1c4d`, the driver handling of the two packet ioctl
records and sender retry/receiver dispatch before interpreting RTOS completion. Follow
lens preference offsets to their producers and actual command consumers. Review the
sensor queue consumer and compare its result semantics with the OS abstraction wrappers.
`libpalm.so` and `libdi-alg-ipplatform.so` received bounded selected decompilation, but
palm-trigger behavior, callback ABI, image-buffer ownership, RAW encoding and capture
integration are not semantically completed by this survey.

No camera program was executed, no camera or target device was accessed, and no firmware
was installed. Ghidra databases must be snapshotted only after the process exits and its
project lock files disappear; the manifest records the final local snapshot check.
