# App storage-status and callback boundary — RUN005

The app installs the same concrete callback for photo save-start and save-done.
Its status conversion preserves values 1–12 and maps every other value to zero.
Save-done values 1–6 use an error-accounting helper; zero and 7–12 use the normal
file-accounting helper. Both routes decrement the same UI count and then call the
BT contents consumer. Neither route establishes a successful file close.

## Source and method

The source is original rootfs
`/usr/apps/com.samsung.di-camera-app/bin/di-camera-app`, SHA-256
`55dcc78143724435a2e38b9e0d809960bd728668634bbcf7532ce137f882eb04`.
All addresses below are original ELF link-time VAs, equal to this app's Ghidra VAs.
They are not file offsets or runtime addresses. Selected original instructions,
PT_LOAD file offsets, relocation, jump-table bytes and fresh selected Ghidra C are
preserved in [app-storage-run005.json](../evidence/app-storage-run005.json).
The [manifest](../../manifests/ghidra-app-storage-run005.json) records source and
artifact hashes, all commands, summaries, reviewed claims and limitations.

Exactly eleven original/staged SHA pairs were checked against RUN004's corrected
`capture/followup/input-manifest.json`, and staged under `.work/run005/app/inputs`.
The unrelated photo/SIF pair was excluded from this survey project. Three fresh
generations (`app-initial`, `app-followup`, `app-counter`) processed the eleven
existing `NX500_FW112_SURVEY` programs, with no imports or new inventory coverage.
Ghidra 12.1.4/JDK 21.0.12.1+1 used `--process --skip-analysis`, 30-second selected
decompilation timeout, 1536M heap, one CPU and budgets 12/8/5. Fifteen selected
attempts completed (8/3/4), with no budget omissions or emitted failures. Repeated
program discovery counts are not additive. Every emitted summary was independently
revalidated; all three runner receipts completed with return code zero. The project
was unlocked at final check.

## Registration carries a concrete callback and event argument

`UI_Manage_Power_On_Before_SnapShot` (`0x12d700`) loads `0x21b978` into r4 at
`0x12dc10–0x12dc14`. At `0x12dc20` and `0x12dc2c` it calls
`UI_Mm_Photo_Set_Cb_Cap_File_Save` (`0x1dc2d4`), supplying respectively `(2,
0x21b978)` and `(1, 0x21b978)` in r0/r1. The wrapper copies the supplied id into
r2, sets r0 to 1 when that id equals 1 and otherwise to 2, sets r3 to zero and
calls app PLT `0xac604` at `0x1dc2ec`. Therefore these two calls pass:

| Notification type r0 | Callback r1 | Registered parameter r2 | Registered parameter r3 |
|---|---|---|---|
| 2 | `0x21b978` | 2 | 0 |
| 1 | `0x21b978` | 1 | 0 |

The original PLT instructions calculate GOT slot `0x449038`; its
`R_ARM_JUMP_SLOT` (22) relocation binds
`_Z25mm_photo_capture_callback13eNotificationPFvllPvEll`. This is an ELF linkage
and argument proof, rather than a name-only callback association. It establishes
the intended import contract; runtime loader interposition and execution are not
observed. The separate producer report owns the libmm-photo body and its stored
callback/parameter slots. RUN004 had already inspected that body's type-1/type-2
registration; this report does not count that inherited review as a new app finding.

Ghidra prints a spurious fifth argument in the wrapper's inferred call. The ARM
r0–r3 sequence above is the evidence for the four scalar arguments. It also prints
the error-helper call without its argument; instructions show the converted status
remains in r0 at `0x21bb94`, and the helper saves it in r4 at `0x2103d4`.

## The conversion is numerical, with a bounded error classification

`UI_Mm_Photo_Convert_Storage_Error_Type` (`0x1dc3fc`) subtracts one and performs an
unsigned comparison against 11. Inputs 1–12 index the twelve words at `0x1dc40c`;
their return blocks return the same input value. Other inputs use `0x1dc43c`, which
returns zero. The evidence decodes every table word and its original return-block
bytes. This includes negative and out-of-range 32-bit inputs through the unsigned
bound; zero is a default mapping, not a validated successful-write status.

`UI_Set_Mm_Photo_Captue_Callback_Fn` (`0x21b978`) handles supplied event 1 by first
calling `UI_WiFi_RVF_Shot_Result(1, raw_status, path)` if UI value `0x1e2` equals 1.
It then converts the supplied second argument. At `0x21bb88–0x21bb90`, subtract-one
and unsigned compare-five classify converted 1–6 as errors. Error routing calls
`0x2103cc`; the other route clears global `0x44b494` then calls
`UI_Capture_File_Write_Done` (`0x217cac`). At `0x21bbb4`, both routes call
`UI_BT_Send_Contents` with the supplied path. Event 2 instead sets the LED/start-log
state; it does not take this status/accounting path. The numeric event meanings
are corroborated by `get_mm_photo_cap_cb` (`0x20b2b0`), which returns the strings
`FILE_SAVE_DONE` and `FILE_SAVE_START` for 1 and 2.

The app's consumer effects refine the error classification without inventing
unverified producer enum names:

| Converted status | Error-helper effect after its guard |
|---|---|
| 1 | UI `0x7e8=1`, `0x249=-1`, display card error |
| 2 | UI `0x7df=1`, redraw memory info |
| 3 | UI `0x7e8=2`, `0x249=-1`, display card error |
| 4 | UI `0x7e8=3`, `0x249=-1`, display card error |
| 5 | logs `no space !!!!`, UI `0x7e9=1`, `0x249=0`, redraw memory info |
| 6 | UI `0x7ea=1`, redraw memory info |

`get_ui_card_error_str` (`0x209ac0`) names UI `0x7e8` values 1/2/3 as
`eUI_MEM_ERROR_MEDIA`, `eUI_MEM_ERROR_NEED_FORMAT`, `eUI_MEM_ERROR_SUPORT_CARD`.
These are downstream UI error names, not proof of every storage producer's enum.

## Error handling decrements accounting before displaying an error

Helper `0x2103cc` logs `__ui_cb_file_write_done_error`. At entry it reads UI
`0x29d`, subtracts one and writes it back (`0x2103d8–0x2103e8`), before its
error-display guard. If the resulting count is below one, it requests LED state
`(2,3,0,0)`. It calls stop-action helper `0x20ffe8`; only when that returns zero
and latch `0x44b494` is zero does it set that latch to one and perform the tabled
UI updates. It stops capture for UI `0x27a=2`, or cancels Lock3A for `0x27a=9`,
then requests status-LCD item `0x249` update. Repeated errors can therefore still
decrement accounting while the latch suppresses repeated error-display effects.

`0x20ffe8` returns zero when neither common-run-state mask `0x400000` nor capture
state 8 is set. When either is set, it waits for count `<1` and capture states
4/`0x13`/10 all zero before calling `UI_Callback_Stop_Fn`; that route returns one,
including its waiting branches. No atomicity, lower-bound saturation or balanced
event delivery is established by these repeated scalar getter/setter calls.

Normal `UI_Capture_File_Write_Done` also unconditionally subtracts one at
`0x217cc0–0x217cd0`. Its broader UI/readiness behavior remains as bounded in
[CAPTURE_COMPLETION_RUN004.md](CAPTURE_COMPLETION_RUN004.md). Count decrement is
file-accounting behavior and does not inspect close success.

The increment helper `0x212448` (log name `__ui_set_capture_count`) reads prior
UI `0x29d`, `UI_Get_Multi_Capture_Count`, UI `0xd0`, and UI `0x29c`. For type 1,
mode values 3/4/6/9 add one when UI `0xd0<4` and otherwise two. For type 0,
modes 5/7/8/`0xc`/`0x15` add the multi-capture count; modes
`0x12`/`0x14`/`0x16`/`0x17` add one; the default adds one or two using the same
`0xd0` threshold. Mode `0x19` additionally branches on UI `0x138`, `0x29f` and
`0x139` and can leave the count unchanged or add one/two. These are selected
accounting producers, not a proof of all writers or one increment per image.

## Second entry and BT checks remain separate boundaries

Dispatcher `0x218920` subtracts one from its incoming id and bounds the table at
`0x218b54` to 67 entries. The word at `0x218c34`, index `0x39-1`, is `0x21b000`;
that instruction calls `0x217cac` and then joins the dispatch tail. Earlier
Wi-Fi/power, playback and UI-state guards can prevent this dispatch. This proves
the second entry for id `0x39`; its producer and relationship to the photo
save-done route remain unassigned. Counting both as independent successful files
would be unsupported.

The newly exported BT consumer `0x15f258` has its own gates: sample-capture UI
`0x1ea`, globals `0x4a0f5c`/`0x4a0fe0`, ML activity, nonnull path, a string-pattern
test, `ecore_file_exists` and later EXIF/shot-mode checks. The inspected call has
no storage-status argument. Its existence and metadata checks do not establish
that partial files are rejected, that an asynchronous transfer succeeds, or that
the file is durable. Further BT and Wi-Fi error-consumer review remains open.

Reproduction: `PYTHONPATH=.work/python python tools/firmware/app_storage_evidence.py`.
No extracted target program was executed, no camera was accessed and no firmware
was installed. The stronger cross-library worker/queue trace is maintained by
the separate storage-producer task; callback delivery and the queued status must
not be conflated with a worker's constant zero callback argument.
