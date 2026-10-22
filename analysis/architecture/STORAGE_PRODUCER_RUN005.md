# Storage producer and callback binding — RUN005

The inspected capture save route now has a concrete static callback chain from the
SIF file worker to `ImageGenerator::captureSaveDone`. The worker callback transports
a notification selector, not its write result. The normal producer queues storage
status zero before saving; a separate exception producer queues an earlier check's
status. This does not establish a successful write, close, or durable file.

## Sources and method

| Original rootfs ELF | SHA-256 |
|---|---|
| `/usr/lib/libsif.so` | `9790fc02fe5b9793fc09da7eb5fd9453c730a55880654c84caf02dd3d1001109` |
| `/usr/lib/libmm-photo.so` | `ea4ae65608a6f9ea0761e35c18764401cf7b876652f7949c322e880fa9f68ca9` |

The two original inputs and staged copies match the filesystem inventory and its
source inode-dump hashes. All addresses below are original ELF link-time VAs, not
runtime addresses. The selected code windows have explicitly mapped file offsets, verified
through PT_LOAD; for example JpegDoneEx VA `0x7cef0` maps to file offset
`0x74ef0`. The evidence also maps GOT/literal offsets explicitly. Raw Ghidra
C addresses add `0x10000`.

Four fresh `NX500_FW112` generations used existing programs, `--process
--skip-analysis`, Ghidra 12.1.4, JDK 21.0.12.1+1, 1536M heap, one CPU and 30-second
selected decompilation limits. They completed 32/32 selected attempts, with no
budget omissions or decompiler failures. Eight schema-v2 exports independently
validated. These are repeated exports of two identities, not new imports or
inventory coverage. An initial standalone validation command mistakenly targeted
four parent export directories instead of their program subdirectories; all eight
correct program-directory validations then passed. No Ghidra run was affected.

The large JPEG worker C is inherited from the completed RUN003 expanded-payload
export; its callback-copy instructions are newly reproduced from original bytes.
Its historical timeout/payload failures and unresolved function-recovery extent
remain documented in [JPEG_WORKER_RUN003.md](JPEG_WORKER_RUN003.md).

[Evidence](../evidence/storage-producer-run005.json) separates selected Ghidra C
from 35 original-byte Capstone windows, ELF relocations and four evaluated GOT
literal proofs. [Manifest](../../manifests/ghidra-storage-run005.json) retains
receipts, commands, hashes and reviewed findings. Reproduction:

```sh
PYTHONPATH=.work/python python tools/firmware/storage_producer_evidence.py \
  --root .work/full/extracted/rootfs \
  --output analysis/evidence/storage-producer-run005.json
```

## Concrete callback installation

In `libmm-photo.so`, `runFromCapture` calls `DscImage::Notify` at `0x9677c`
with notification type 2, `SIFListener`, 3, 0. The callback load resolves through
GOT slot `0xfbbf4`, whose `R_ARM_GLOB_DAT` relocation names
`ImageGenerator::SIFListener`. In `libsif.so`, `DscImage::Notify` (`0x89e00`)
stores the type-2 callback and parameters at object offsets `+0x24`, `+0x28`,
`+0x2c`. The constructor initializes callback `+0x24` to zero.

The filename overload of `DscImage::SaveExifImage` (`0x86eb0`) calls
`DscJPEG::notify` at `0x8826c` with type 2 and `DscImage::JpegDoneEx`.
Original literal arithmetic resolves this callback load to GOT slot `0xa6bdc`,
whose `R_ARM_GLOB_DAT` relocation names `JpegDoneEx`. `DscJPEG::notify`
(`0x3e378`) stores this callback at worker `+0x20`. `SaveExifImage` copies the
registered 3 and 0 parameters into message `+0x10` and `+0x14` at
`0x882a4`/`0x882b8`, sets mode `+4` to zero and submits the message.

In JPEG worker case 3, instructions `0x38d6c`–`0x38d9c` copy those message
parameters into the newly allocated type-10 buffer and copy worker `+0x20` into
`[buffer+0x2c]+0x10`. The corresponding case-7 C and byte window preserve the
MPF branch as well. `tImage_buffer` creates `sFileOp` at `+0x2c`; its constructor
initializes its vector and filename, while the reviewed JPEG worker explicitly
sets the callback slot. This is a stored function pointer route, not an inferred
vtable target. The case-3 call at `0x38e48` submits the file buffer when the
input message mode `+4` equals zero.

`DscFileHandler::taskMain` invokes the nonnull slot at `0x2d32c` with
`(buffer,0,0)`. `DscImage::JpegDoneEx` (`0x7cef0`) ignores those supplied zero
arguments, reads buffer `+0x10` and `+0x14`, and calls the current singleton's
callback at `+0x24` with those two values and zero. With the inspected
registrations this is `SIFListener(3,0,0)`. Its case 3 moves a nonempty file path
from `FilePathQueue` to `FilePathQueue2`, updates remaining-message accounting,
releases capture resources, and calls `g_idle_add(captureSaveDone,0)` at
`0xa09a0`. The function pointer resolves to GOT slot `0xfbb70` and the
`captureSaveDone` relocation. Scheduling is not evidence that the main loop
already executed the function.

This is a conditional static chain: dynamic symbol interposition, singleton
replacement and concurrent re-registration were not observed. `JpegDoneEx`
consults the current singleton callback rather than a captured per-message copy.
No claim is made that every save, JPEG mode or runtime invocation uses this chain.

## StorageStateQueue producers and numeric statuses

The exported direct-call map identifies two `ImageGenerator` callers of the
`StorageState` queue push wrappers. `runFromCapture` stores zero into its local
status and pushes it at `0x98bd0`, then increments `m_SIFMsgRemainCount` and
calls `SaveExifImage` at `0x98c24`. The queue load resolves through the
`StorageStateQueue` relocation at `0xfbb60`.

`afterStorageException` (`0x9ec3c`) waits while `m_SIFMsgRemainCount > 0`, sleeping
200 ms on each iteration. It then pushes its supplied status at `0x9efd8` and
calls `SIFListener(3,1,0)` at `0x9efe8`. In listener case 3, second argument 1
bypasses the positive-count assertion and decrement, but still schedules
`captureSaveDone`. Thus an exception notification can reach the same completion
emitter without a successful worker write, or a worker submission at all on that
exception route. The polling loop proves no bounded completion or synchronization
beyond its instructions.

The reviewed `runFromCapture` checks produce these numeric statuses. Names beyond
literal diagnostics are intentionally not assigned to an unverified enum.

| Status | Observed producer condition |
|---|---|
| 0 | Normal save submission queues zero before worker execution. Space check also returns zero when its registered callback returns byte value 1. |
| 1 | Missing filename callback; also one result from helper `0x81ca4`. |
| 2 | Helper `0x81ca4` sees global `0xfbe6c == 2` and helper `0x81884` returns 3. |
| 5 | `checkStorageSpace` (`0x8d8e0`) calls object callback `+0x40`; a returned byte other than 1 maps to 5 (`blx` at `0x8e118`). |
| 6 | Filename callback `+0x3c` returns nonzero; logged as `dcf full!`; sets 6 unless the current status is 8. The later `status != 6` guard skips the ordinary save block. |
| 8 | Helper `0x81ca4` returns 8 for selected state/helper combinations. This is an admission exception: the route admits 0 or 8 and, when saving, still queues zero. |
| 12 | ImageGenerator field `+0x90` equals 2 before the normal checks. |

Helper `0x81ca4`, called with zero, returns 1 immediately for global `0xfbe6c == 4`;
otherwise it may return 8 when helper `0x81464` returns 1 and the global is not 3.
It polls global states 0/3 for at most ten 500-ms sleeps, then returns 8 for state 1,
2 or 0 for state 2 according to helper `0x81884`, and 1 otherwise. The global's
producer and these helper semantics are unresolved. This describes numeric tests,
not verified card-state meanings. `runFromCapture` also forces the checked status
to zero for object mode field `+0x90` equal to 1 or 3. After the admission block,
nonzero statuses other than 8 call `afterStorageException` at `0x98d2c`.

Statuses 3, 4, 7, 9, 10 and 11 have no explicit producer in this bounded path.
The direct-call search does not exclude inlined, indirect, external or aliased
queue mutations. No exhaustive global mutation proof or queue concurrency proof
is asserted.

## Write and close errors do not enter this callback's status argument

The newly re-exported worker confirms the RUN004 result: worker byte `+0x64`
can skip `writeChunks`; a non-one write result or skip logs `File write error`.
Both routes proceed to the same callback with zero trailing arguments.
`storageException` (`0x338e0`) only sets this skip byte; `DscImage::StorageException`
(`0x89d74`) forwards the supplied Boolean to it. Neither is a storage queue setter.
No worker write result is passed through `JpegDoneEx` or used by listener case 3
to replace the queued zero in the inspected chain.

`writeChunks` calls the file destructor on the successful return route after
selecting return value 1. The destructor calls `close` and discards its result;
`close` calls `fclose` and clears its FILE pointer. The worker callback therefore
still cannot prove close success. This result applies to the traced capture
case-3 listener route. Listener case 4 separately calls `sync()` before scheduling
`pbSaveComplete`; this run neither generalizes the capture path's behavior to that
playback route nor establishes its durability guarantees.

The registered application emitter remains distinct: `mm_photo_capture_callback`
(`0x2eeb4`) passes supported notification types to `captureNotify` (`0x90874`).
Type 1 stores the callback and both registration parameters. `captureSaveDone`
(`0x924f4`) obtains a queued storage value or defaults it to zero and invokes
`m_pFileSaveDoneNotification(m_fileSaveDoneParam1, storage, path)` at `0x93b84`,
then pops nonempty queues. The second registration parameter is not that storage
argument. The corresponding app interpretation is documented by the separate
RUN005 app report.

No target program was executed, no camera was accessed, and no firmware was
installed. The Ghidra database is closed and project lock files were absent at
final verification. Static evidence narrows the error propagation boundary; it
does not establish runtime ordering, successful file transfer or durable storage.
