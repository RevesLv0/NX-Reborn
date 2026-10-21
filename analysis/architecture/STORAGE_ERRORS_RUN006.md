# Storage errors, cancellation and queue ownership — RUN006

The inspected file worker does not turn a short `fwrite`, a failed open, or its
storage-exception skip flag into a different callback or a replacement
`StorageStateQueue` value. Cancellation has another distinction: two cancel
branches return **1** from `writeChunks` without completing the file. These are
bounded findings for the traced worker and capture callback route, not a claim
that the camera has no other error notification.

Capture also has synchronization calls that RUN005 did not enumerate:
`SIFListener` case 3 calls `sync()` when its normal pending-message count reaches
zero, and the chunked writer calls `sync()` under a memory-manager mode test.
Playback case 4 has its own unconditional call. None transports a checked
per-file close result to the capture completion callback.

## Inputs and reproducibility

| Original rootfs ELF | SHA-256 |
|---|---|
| `/usr/lib/libsif.so` | `9790fc02fe5b9793fc09da7eb5fd9453c730a55880654c84caf02dd3d1001109` |
| `/usr/lib/libmm-photo.so` | `ea4ae65608a6f9ea0761e35c18764401cf7b876652f7949c322e880fa9f68ca9` |

All addresses in this report are original ELF VAs. Ghidra C/instruction addresses
add `0x10000`; file offsets are independently mapped through PT_LOAD. For these
code mappings the file offset is ordinarily VA minus `0x8000`, not VA itself.
The two verified copies under `.work/run006/storage/inputs` are the only staged
inputs. Every generation has a paired path/hash/partition/staged-path manifest.

Five fresh generations (`initial`, `followup`, `ownership`, `closure`, `cancel`)
process the existing `NX500_FW112` programs without analysis. They use Ghidra
12.1.4, JDK 21, a 1536M heap, one CPU and a 30-second selected decompilation
limit. There are 72 completed selected attempts, zero failed attempts and zero
budget omissions across ten exports. Repeated functions are not new inventory
coverage or additive discoveries. No target code was executed.

The [evidence](../evidence/storage-errors-run006.json) retains selected C, source
identities, direct-call candidate maps, relocation/constant searches and original
byte windows. [The manifest](../../manifests/ghidra-run006.json)
contains run receipts and hashes; bounded primary-agent reviewed findings are
registered separately in `manifests/review-run006.json`. Independent RUN006
semantic review remains incomplete after an actual reviewer usage-limit error.
The extractor uses recovered
instruction addresses to split byte windows at gaps; it does not linearly decode
known literal pools. Reproduce with:

```sh
PYTHONPATH=.work/python python tools/firmware/storage_errors_evidence.py
```

## Worker result and cancellation paths

`DscFileHandler::taskMain` (`0x2c3c4`) waits on its work semaphore at object `+0x50`,
takes the front buffer from queue `+0x28`, pops it, and stores it at `+0x18`.
`operate` (`0x31c44`) pushes a buffer and posts that semaphore. It does not wait
for file completion.

| `writeChunks` (`0x2d590`) condition | Local result and continuation |
|---|---|
| Worker state `+0x24 == 2` at entry | Logs cancellation, returns 1 at `0x2d914`; does not open a file. |
| Sum of chunk sizes is zero | Returns 0. The reduction helper `0x34534` calls `0x31458`, which adds chunk `+4`. |
| `create(...,2)` fails | Logs open error, returns 0 through the file destructor. Mode 2 is `fopen64(path,"wb")`. |
| Storage-exception byte `+0x64` becomes nonzero at a chunk boundary | Returns 0 through the file destructor. |
| Any reviewed `DscOsalFile::write` returns other than 1 | Logs write error, returns 0; chunk-loop failure branches release their semaphore, and mapped-buffer branches unmap their temporary mapping first. |
| State `+0x24 == 2` after acquiring chunk semaphore `+0x58` | Releases semaphore, selects return 1 at `0x2edec`, then destroys the file object. |
| Ordinary completed chunk traversal | Selects return 1 at `0x3140c`, then destroys the file object. |

The constructor (`0x2c060`) initializes chunking byte `+0x1c` to 1, block size
`+0x20` to `0x100000`, cancellation state to zero and the exception byte to zero.
The chunk loop handles direct buffers, a staging buffer at `+0x60` and temporary
mapped buffers; its five write sites converge on the same local Boolean result.
The short-write wrapper (`0x5a858`) calls `fwrite(data,1,requested,FILE*)`, updates
the supplied length to the actual count on mismatch, logs `ferror`, and returns
zero. The inspected wrapper has no separately installed error function pointer.

Worker skip byte nonzero bypasses `writeChunks`; either that skip or result other
than 1 logs `File write error`. The callback invocation at `0x2d32c` remains
`buffer->sFileOp.callback(buffer,0,0)` on both paths. The previously bound
`JpegDoneEx` route reads its saved notification selector and reaches listener case
3 as documented in [RUN005](STORAGE_PRODUCER_RUN005.md). The callback receives
neither the local write result nor `errno`/`ferror`.

Afterward `memoryRelease` (`0x31490`) destroys the buffer and clears worker
`+0x18`. The type-10 destructor branch (`tImage_buffer::~tImage_buffer`, `0xfc48`)
destroys `sFileOp`; that destructor (`0x12410`) destroys its filename and chunk
vector. No additional storage-error callback occurs in that reviewed cleanup
branch. The file destructor calls `close` and discards its result; `close`
(`0x5ad4c`) calls `fclose` and clears the FILE pointer. No close-result check was
found in this chain.

## Exception entry and precheck state

The direct call map gives two local callers of `DscImage::StorageException`:
`ImageGenerator::init` passes false (`r1=0`, call `0x8aeec`), and
`setCaptureException(CaptureException)` (`0xa18d0`) passes true (`r1=1`, call
`0xa1900`) only for condition 2. Original registers matter here: inferred
decompiler prototypes incorrectly display the singleton pointer as a Boolean in
these callers. `DscImage::StorageException` (`0x89d74`) forwards to
`DscFileHandler::storageException` (`0x338e0`), which stores the byte at `+0x64`.

`mm_photo_capture_set_storage_condition` (`0x2f868`) forwards values 0..3 to that
setter; the setter always stores the condition in ImageGenerator `+0x90`.
Passing 0, 1 or 3 does not itself reset the worker exception byte. `init` supplies
the reviewed reset. The similarly named `mm_photo_capture_set_storage_state`
(`0x300b8`) only logs in its inspected body and does not update the status queue.
These setter paths do not retroactively replace a status already queued for an
outstanding normal submission.

`init` also registers `card_callback` (`0x8a198`) for
`memory/sysman/mmc` and `memory/sysman/mmc_err_status`. For the first key, values
-1, 0, 1 and 2 map to internal global `0xfbe6c` values 0, 1, 2 and 3, with the
0-to-1 update suppressed while the global is 4. A positive error-key value sets
the global to 4. The callback does not push or rewrite `StorageStateQueue` and
does not call `StorageException` in its inspected body. It changes the state
consulted by subsequent admission checks.

The previously unnamed helpers are now concrete: `0x81464` calls
`device_get_property(0xb,0,&value)` with diagnostic `SDCARD_ONLINE`; it returns
2 on API failure, 0 for value 1, otherwise 1. `0x81884` calls property `(0xb,1)`
with diagnostic `SDCARD_PROTECT`; it returns 5 on failure, 3 for value 1,
otherwise 4. Their integration into admission status helper `0x81ca4` is retained
in the evidence. This does not identify the operating system producer of every
device/vconf event or its timing relative to an in-flight write.

Filename registration (`0x8e2dc`) and space-check registration (`0x8fedc`) reject
null pointers and install ImageGenerator `+0x3c` and `+0x40`. Their exported API
wrappers are `mm_photo_register_get_file_name` (`0xd9238`) and
`mm_photo_register_is_storage_space_available` (`0xda8a8`). The app-side concrete
callback bindings are independently traced by the RUN006 app work; these APIs
provide admission callbacks, not an asynchronous `fwrite` result callback.

## Queue lifecycle and pending messages

The four queues are exported global 40-byte objects. Initialization helper
`0xa1918` constructs them and registers their destructors with `__aeabi_atexit`.
They are not members of the ImageGenerator singleton. The streamed full-ELF
symbol catalog found their named definitions only in libmm-photo, with no other
named imports. This does not exclude stripped direct references, aliases,
`dlsym`, symbol interposition or writes through an escaped pointer.

| Object, original VA | Discovered application-level mutation paths |
|---|---|
| `StorageStateQueue`, `0xfbcc8` | `runFromCapture` pushes zero before submission; `afterStorageException` pushes its checked status; `captureSaveDone` pops after the app callback. `end` reads its front without popping. |
| `FilePathQueue`, `0xfbcf0` | `runFromCapture` pushes the generated/selected path before saving; listener case 3 transfers front to Queue2 and pops. `stopFileSave` polls for empty. |
| `FilePathQueue2`, `0xfbd18` | Listener case 3 pushes the transferred path; `captureSaveDone` reads front and pops after the app callback. |
| `FilePathQueueForModeChange`, `0xfbd40` | `makeQuickPBItemList` pushes generated paths; `runFromCapture` reads/pops front in its quick-playback branch. |

The direct queue-call inventory and aligned GOT-offset literal search agree on
these candidate functions plus initialization. The latter searches executable
PT_LOAD data and assigns the nearest preceding recovered function; it is
corroborating discovery, not an exhaustive memory-mutation proof.

`runFromCapture` holds a `tint::ScopedLock` using original global `0xfbe4c` across
the admitted filename/path preparation and submission block.
`makeQuickPBItemList` uses the same lock. The inspected `SIFListener`,
`afterStorageException`, `captureSaveDone`, `end` and `stopFileSave` bodies do not
acquire that lock. Queue push/pop wrappers delegate to standard deque methods.
This shows the lock calls and their scope; it does not prove race freedom or a
runtime race, because execution/thread ordering and external synchronization are
not observed.

Normal submission increments `m_SIFMsgRemainCount` (`0xfbdc0`) after queuing zero
and before `SaveExifImage`. Listener case 3 increments a separate diagnostic
SaveCB counter, transfers a path if present, asserts a positive pending count for
second argument other than 1, and decrements it. `afterStorageException` polls
the count with 200-ms sleeps until no normal messages remain, then pushes its
status and calls `SIFListener(3,1,0)`. That special argument bypasses the pending
count assertion/decrement and its conditional sync; it still releases capture
resources and schedules completion. The polling has no proven upper bound.

`captureSaveDone` is scheduled with `g_idle_add`, not executed synchronously by
the worker. It defaults an empty path to null and an empty status queue to zero,
reads available fronts, calls the registered app function, then pops each
nonempty queue. `isCaptureNotProcessing` (`0xa14a8`) tests only whether the
pending count equals zero; it does not test whether idle callbacks ran or queues
were drained. Consequently count zero is a worker-accounting boundary, not proof
of application delivery or successful storage.

Resource release (`0x99010`) consumes `CaptureReleaseInfoQueue`, calls
`ReleaseCaptureBuffer` for the appropriate resource types, logs nonzero return
values and pops the records. The reviewed function does not rewrite storage
status when release fails. Its independent buffer-release errors are not
per-file `fwrite` errors.

## Synchronization, pause and stop

Original bytes identify three synchronization contexts:

* Chunked `writeChunks`: `sync` at `0x303dc` after a full block when
  `DscMemoryManager::getMode()` equals zero, before releasing semaphore `+0x58`.
  The final remainder write and later `fclose` are distinct operations.
* Capture listener case 3: normal decrement at `0x9fd90`; count-zero comparison
  at `0x9fda0`; `sync` at `0xa05a0`, then resource release and idle callback
  scheduling at `0xa09a0`. Nonzero remaining count bypasses that sync. The quick
  playback cleanup is optional inside this count-zero branch.
* Playback listener case 4: `sync` at `0xa09a8`, then schedules `pbSaveComplete`
  at `0xa0cf4`. `runFromPlayback` registers selector 4 at `0x9d010` before its
  filename save. `pbSaveComplete` calls a separate registered no-argument
  function; it does not consume the capture status queue.

These calls correct the incomplete enumeration in RUN005. `sync()` has no
per-file success result here; even execution of this call cannot make the
unchecked `fclose` return into a checked completion status. Static presence also
does not establish that a particular runtime failure traversed the call.

`DscImage::StopFileSave` calls `DscJPEG::stopFileSave` (`0x363cc`), which forwards
to file-handler `stop` (`0x33910`). Stop sets state 2, polls in up to 1,000
one-millisecond sleeps and, on timeout, resets state to zero and returns zero.
The outer `ImageGenerator::stopFileSave` ignores that result and polls
`FilePathQueue` until empty. This can only establish the inspected polling
conditions, not bounded successful cancellation or completed app callbacks.

`pauseOrResume` (`0x344d4`) stores its state, takes the block semaphore for state
3, and posts it otherwise. The libcapture notification registered by the
ImageGenerator constructor at API ID `0x2010011` reaches `captureNotifyCB`
(`0x84a74`): a zero payload word enqueues pause, a nonzero word enqueues resume.
That inspected callback is a pause/resume entrance, not a storage-status setter.

## Concrete remaining limits

The reviewed file-worker path has a supported local error-propagation boundary:
failed/skipped writes and cancellation converge on the same installed callback,
and the discovered capture queue producers use admission status. No separate
asynchronous write-error callback appears in these bodies or their reviewed
cleanup. External card events can still influence later admission, and the app
has an independently traced `CB_STL_SKIP_FILE_WRITE` entrance from mm-camera.
Their relationship to a particular buffer cannot be inferred from the names or
from separate accounting decrements.

The remaining concrete evidence requirements are runtime queue/thread ordering,
the card/device service event sequence relative to failed writes, whether a
single capture can emit both the mm-camera skip notification and SIF completion,
dynamic callback/singleton replacement, and actual filesystem/medium persistence.
Device observations would need correlation identifiers and timestamps for worker
result, queued status/path, pending count, both notification entrances, `fclose`
and relevant sync calls. No device access or installation has been performed.
