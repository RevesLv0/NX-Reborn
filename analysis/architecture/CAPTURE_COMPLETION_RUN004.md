# Capture completion boundaries — RUN004

New offline static evidence separates three conditions: next-shot admission,
file-worker notification, and successful file close. They are not interchangeable.
The app itself combines a file counter with the RTOS readiness getter before one
remote file-end notification. The inspected SIF worker can invoke its callback
after a failed or skipped write, and its file destructor discards the close result.
This is a bounded route review, not completion of the capture feature.

## Sources and reproduction

All sources are original rootfs bytes, checked against
`.work/full/inventory/full_filesystem_inventory.json`, including inode-dump hashes.
The firmware/rootfs identities and original extraction provenance remain those in
[CAPTURE_IPC_RUN003.md](CAPTURE_IPC_RUN003.md). Full source and artifact hashes,
commands, receipts, summaries and seven reviewed findings are in
[ghidra-capture-run004.json](../../manifests/ghidra-capture-run004.json).

| Original ELF | SHA-256 |
|---|---|
| `/usr/lib/libcapture-fw-prod.so` | `a07867292610ac6376e29e3cd64bc79a274452412387fb7853c5a3fb3f96bba5` |
| `/usr/apps/com.samsung.di-camera-app/bin/di-camera-app` | `55dcc78143724435a2e38b9e0d809960bd728668634bbcf7532ce137f882eb04` |
| `/usr/lib/libuser-spec.so` | `2d04ab487cc9980cb87e513b25ff09011839203756d28857eedfd50a9cc730ec` |
| `/usr/lib/libmm-photo.so` | `ea4ae65608a6f9ea0761e35c18764401cf7b876652f7949c322e880fa9f68ca9` |
| `/usr/lib/libsif.so` | `9790fc02fe5b9793fc09da7eb5fd9453c730a55880654c84caf02dd3d1001109` |

The tools were Ghidra 12.1.4/JDK 21.0.12.1+1, pyelftools 0.32 and Capstone
5.0.6. Every Ghidra generation processed existing programs with `-noanalysis`,
30-second selected decompilation timeout, budget 12 per program, 1536M heap and
one Ghidra CPU. No new imports or inventory coverage are counted. All emitted
schema-v2 summaries independently pass hash, identity and row-count validation.

| Generation | Existing project | Exported ELFs | Selected completed/attempted |
|---|---|---:|---:|
| `capture/initial` | `NX500_FW112_SURVEY` | 11 | 12/12 |
| `capture/followup` | `NX500_FW112_SURVEY` | 11 | 14/14 |
| `capture-photo` | `NX500_FW112` | 2 | 11/11 |
| `capture-photo/detail` | `NX500_FW112` | 2 | 8/8 |
| `capture-photo/close` | `NX500_FW112` | 2 | 4/4 |

The initial staging mistakenly included 13 identities, while SURVEY actually
contains 11: `libsif.so` and `libmm-photo.so` belong to the other project. After
11 successful exports the runner raised `FileNotFoundError` for the missing
libsif summary. The incomplete receipt and full console remain preserved. The
followup used exactly the 11 SURVEY inputs, with an additive paired
`capture/followup/input-manifest.json`; the original 13-input manifest and staged
files are retained. Photo generations use their own two-input manifest. Repeated
exports describe the same 13 identities, and their function/discovery counts must
not be added. There were 49/49 completed selected attempts across the five
generations, covering 48 distinct source-SHA/function-VA pairs; these counts are
selected decompilation coverage, not distinct semantic findings.
All processes exited and project lock files were absent at final check.

Addresses below are original ELF link-time VAs. For the ET_DYN libraries, raw
Ghidra C/instruction addresses add `0x10000`; app addresses already equal original
ELF VAs. These are not runtime addresses. The independent evidence explicitly maps
each inspected original VA to its PT_LOAD file offset. Large linear symbol
disassemblies can stop at literal data and are bounded to first/last 80 instructions;
explicit windows preserve the important later indirect calls and close sequence.

## Next-shot notification is distinct from buffer-write notification

In `libcapture-fw-prod.so`, `CNotifyHandler::Run` (`0x8a628`) stores the supplied
packet pointer at object `+8` and supplied length at `+4`. `notifyCategory`
(`0x8dacc`) reads the high byte of the packet halfword at `+4`; `subCategory`
(`0x8db54`) reads its low byte. The category function table at `0xb1f54` has an
`R_ARM_ABS32` relocation at `0xb1f64` binding index 2 to `execStillNotify`.
That function (`0x8a838`) indexes an eight-byte member-function record table at
`0xb2004`, with an upper check of 21. This does not independently validate the
packet length or every malformed-input case.

The relocation at `0xb2054` binds still index 10 to `onNextShotReady`, so the
inspected header halfword is `0x020a`. `onNextShotReady` (`0x8b93c`) requires
supplied length zero. Capstone reproduces its compare at `0x8b95c` and call at
`0x8b974` through PLT `0x27300`, passing `0x1010006, 0, 0` to
`CCapturePublisher::SendAppCallback`. The latter (`0x80cd8`) obtains the publisher
and calls `Publish`; its third supplied argument is not forwarded by this body.

`CCapNotifyCb::publishConvert` (`0x7768c`) maps internal event `0x1010006` to API
event `0x2010006`. `RegCallback` (`0x5fefc`) stores a callback pointer at object
`+4`; `RegCallbackId` (`0x775ec`) converts the subscribed API ID before calling
publisher `Subscribe`. `OnCallback` (`0x77520`) calls the registered pointer with
the converted ID and the object's parameter pointer/size. This identifies concrete
conversion and registration machinery, but not the entire application callback
installation or outer RTOS transport message identifier.

Still table index 7 has a separate relocation at `0xb203c` to `onWriteDone`
(`0x8b804`), corresponding to header halfword `0x0207`. That handler requires
length two, reads a ushort from packet `+8`, and at `0x8b854` calls
`ReleaseCaptureBuffer` through PLT `0x282a8` with that value and zero. Its inspected
body does not send the next-shot callback or inspect a filesystem close result.
The buffer-release implementation and originating packet producer remain unreviewed.

## The app uses separate readiness and file-accounting conditions

The newly disassembled `libuser-spec.so` getter (`0x8a24`) confirms the RUN003
read of one byte at RTOS preference offset `0x1c4d`; mapped-base initialization,
physical address request `0x85400000`, and synchronization limitations are inherited
from the reproduced RUN003 report. The T-Kernel writer work is maintained separately
in [RTOS_READINESS_RUN004.md](RTOS_READINESS_RUN004.md); this report does not infer
cross-core ordering from the shared offset alone.

App `UI_Get_Cb_Flag_Next_Shot_Raedy` (`0x214ae4`) forwards to that imported getter.
The similarly named setter (`0x215b48`) instead writes the supplied integer to local
global `0x44b48c`; the getter does not read that global. Ghidra incorrectly presents
the getter as returning void, while the ARM wrapper preserves the callee's r0 result.
The scalar return ABI is corroborated by callers and instructions; broader inferred
types remain unverified.

App helper `0x214af0`, whose log calls it `__ui_wifi_cb_rvf_capture_end`, requires
UI value `0x1e2 == 1`, file-accounting value `0x29d < 1`, readiness getter nonzero,
and capture-run-state 10 zero before it dispatches a remote remaining-shot-count
or last-file-write-end callback. Its full 328-byte Ghidra body and independent
Capstone window preserve those branches. It calls the getters more than once;
this is not evidence of an atomic snapshot.

`UI_Capture_File_Write_Done` (`0x217cac`) decrements value `0x29d`, conditionally
updates UI/power/LED state and calls helper `0x214af0` on one route. It does not
perform or verify the original file close. `UI_Set_Mm_Photo_Captue_Callback_Fn`
(`0x21b978`) handles event 1 by converting the supplied storage-status parameter.
Converted values 1 through 6 take a separate helper path; other converted values
clear a local flag and call File_Write_Done. `UI_BT_Send_Contents` follows either
branch. The status conversion enumeration and all downstream error guards remain
unresolved. Another app dispatcher (`0x218920`) also calls File_Write_Done in
case `0x39`; this second entrance is not assigned an unverified producer meaning.

## File-worker callbacks do not prove a successful close

In `libmm-photo.so`, `mm_photo_capture_callback` (`0x2eeb4`) accepts notification
types 1 or 2 and routes to `ImageGenerator::captureNotify` (`0x90874`). Type 1
stores `m_pFileSaveDoneNotification`, `m_fileSaveDoneParam1` and
`m_fileSaveDoneParam2`; type 2 stores the corresponding start notification.
`captureSaveDone` (`0x924f4`) checks the registered callback, takes a queued path
and storage-state value if present (otherwise initializes them to zero), and invokes
the callback at `0x93b84` with the registered first parameter, storage state and
path. It then pops nonempty queues. The API's fourth registration argument is
stored but is not the second argument emitted by this inspected done callback.
Capstone separately corroborates the indirect call window.

In `libsif.so`, `DscFileHandler::operate` (`0x31c44`) pushes the buffer into a
queue and signals a semaphore. Its return is submission to that local worker.
`taskMain` (`0x2c3c4`) takes a queued buffer, calls `writeChunks` only when worker
byte `+0x64` is zero, and logs `File write error` if that call does not return one
or the call was skipped. The subsequent nonnull buffer-record callback is still
invoked at `0x2d32c` with `(buffer, 0, 0)` before `memoryRelease`. Consequently this
callback is not gated on successful writing. Its concrete target is unresolved;
the evidence does not assert that this slot necessarily points to captureSaveDone.

`writeChunks` (`0x2d590`) uses `DscOsalFile::create` and `write`, includes cancel,
empty-size and write-error branches, and destroys its local file object before
returning. `DscOsalFile::write` (`0x5a858`) calls `fwrite`, returns one when the
returned byte count equals the requested count, and otherwise updates the supplied
length and returns zero. This is a stdio write result, not close success.

`DscOsalFile::close` (`0x5ad4c`) calls `fclose` at `0x5ad7c` when its FILE pointer
is nonnull and clears the pointer at `0x5ad88`. The destructor (`0x5a1e4`) calls
close at `0x5a214` and then discards that result. The successful writeChunks path
sets its own return one before destruction; neither its caller nor the callback
branch compares a close-success value. The null-FILE branch of close also must
not be interpreted as a defined Boolean return. This bounded path therefore cannot
establish successful close or durability from its completion callback. Other
writers, filesystem/kernel behavior and any separate fsync path remain untraced.

## Evidence and remaining boundary

[Selected Ghidra C](../evidence/capture-completion-run004.json) preserves the
reviewed routines with source/export hashes.
[Capstone/relocation evidence](../evidence/capture-completion-run004-capstone.json)
is reproducible with `PYTHONPATH=.work/python python
tools/firmware/capture_completion_evidence.py --root .work/full/extracted/rootfs
--output analysis/evidence/capture-completion-run004-capstone.json`.

The strongest next step is to resolve the SIF buffer callback installation and
storage-state producer, then join the exact RTOS notification sender to the Linux
header dispatch. No target executable was run, no camera was accessed, and no
firmware was installed. Static callback names and successful decompilation do not
establish runtime ordering, completed capture, successful transfer or data durability.
