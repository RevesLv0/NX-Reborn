# AF and lens command/callback boundaries — RUN010

This offline pass follows the camera app's lens callback registration through
the capture library, its message tables and the multicore bridge. It also
separates AF scan completion from generic lens event delivery. These are static
code and relocation findings; no camera program was executed or device accessed.

## Sources and addresses

| Original rootfs path | SHA-256 | Dynamic import entries | Dynamic export candidates |
|---|---|---:|---:|
| `/usr/apps/com.samsung.di-camera-app/bin/di-camera-app` | `55dcc78143724435a2e38b9e0d809960bd728668634bbcf7532ce137f882eb04` | 1,095 | 9,930 |
| `/usr/lib/libcapture-fw-prod.so` | `a07867292610ac6376e29e3cd64bc79a274452412387fb7853c5a3fb3f96bba5` | 152 | 1,828 |
| `/usr/lib/libmulticore-bridge.so` | `f14a12e4d9172989d73c8dff0fd59580c65ccd1972264c9d94c8d1a736820390` | 63 | 236 |
| `/usr/lib/libuser-spec.so` | `2d04ab487cc9980cb87e513b25ff09011839203756d28857eedfd50a9cc730ec` | 48 | 164 |

All addresses below are **original ELF link VAs**. The three shared objects use
Ghidra addresses `original + 0x10000`; app addresses are unchanged. File offsets
are separately mapped through PT_LOAD, and saved Ghidra TMode contexts determine
instruction decoding. Export candidates include objects and weak symbols; they
are not counts of understood functions or established runtime API bindings.

[Selected evidence](../evidence/af-lens-run010.json) preserves source SHA/path,
selected C, original instruction windows, dynamic relocations, original table
bytes and source-declared API metadata. [Generation manifest](../../manifests/ghidra-af-run010.json)
and [bounded review units](../../manifests/review-af-run010.json) keep measured
stages separate. All four inputs were already present in the earlier loaded
corpus, so this pass adds no unique loaded ELF contents.

## Public surface and callback ownership

The app declares `libcapture-fw-prod.so` and has 13 dynamic import names matching
its exports, including `mm_camera_ioctl` (capture `0x2ab30`), lifecycle functions,
notification registration and attribute setters. This gives a concrete link
candidate reinforced by the call/relocation evidence; actual loader resolution
and successful initialization are not observed.

App `UI_Mm_Camera_Set_Lens_Callback_Init` (`0x1e3f5c`) calls
`mm_camera_ioctl(handle,0x13,callback,4,0,0)` and logs an error on a nonzero return.
The original three instructions at app `0x12dbd4` load `0x220038` into R0 and
call `0x1e3f5c`, inside `UI_Manage_Power_On_Before_SnapShot`; saved incoming
references independently identify both the callback parameter and registration
call. This binds the selected UI callback to that registration site. Capture's
public-to-internal translator (`0x30b30`) maps request `0x13` to `0x1050007`, and
`mm_camera_ioctl` forwards the pointer with internal size 4.
Capture `ControlLens` (`0x43db4`) has a distinct registration case `0x1050007`
that forwards a nonnull function pointer to
`CMCBAdapter::RegisterLensEventListener` (`0x853a0`). That method stores one global
listener (`m_pLensEventListener`, symbol VA `0xb33d4`) and returns zero, or `-1`
for null. Registration overwrites the previous pointer; the inspected body does
not implement a listener list. Unregister (`0x85400`) clears it only when a
nonnull supplied pointer matches the stored pointer, otherwise returning `-1`.
`NotifyLensEvent` (`0x85478`) calls the pointer with three arguments when nonnull.
Concurrent registration, shutdown lifetime and runtime callback ownership remain
unverified.

App `UI_Mm_Camera_Remove_Lens_Callback` (`0x1e4478`) sends request `0x13` with
null pointer and zero public size. The selected capture ioctl branch still
passes internal size 4; `ControlLens` checks the pointer, skips registration
when null and retains its initial zero result. This path does not call
`UnregisterLensEventListener` or clear the listener. The wrapper's removal name
and zero return therefore cannot establish successful callback removal. This is
a bounded static behavior, without a claim about actual shutdown sequencing.

## Transport and registered receive dispatch

`CMCBAdapter::SendCommand` (`0x83e14`) calls the imported
`CMulticoreBridge::Send(0x83,opcode,size,payload)`. Its Send wrapper (`0x83dc8`)
simply forwards four arguments. Bridge `CMulticoreBridge::Send` (`0x6700`) calls
lowercase `send` (`0x66c8`), which fetches the sender and calls `CSender::Send`
(`0x7898`). `CSender::createFrame` (`0x73fc`) builds a header with fixed first
byte 2 and the supplied category/opcode/size fields before `CFrame::Build`.
`CSender::Send` has destination-alive and queue branches, so these call edges do
not prove delivery. Exact frame packing and error-path ABI still require
separate byte-level review. `SyncSendCommand` (`0x83f60`) sends then waits via
`waitReceiveData`; the wait outcome is not independently reviewed here.

Capture initialize (`0x838bc`) invokes `mcb_init`, installs a `0xb1` diagnostic
handler and calls `subscribe` (`0x85610`). That sequence calls `subscribeToMCB`,
then data-manager and publisher subscriptions only after zero results.
`subscribeToMCB` (`0x85688`) registers `OnReceiveEvent` for 13 categories including
`0x82` and `0x83`, OR-ing registration results. Bridge Register (`0x65f4`)
checks nonnull callback/category validity and uses semaphore-protected listener
storage, with duplicate and capacity checks. It is distinct from capture's
single lens listener.

`OnReceiveEvent` (`0x8390c`) fetches the adapter and calls `OnReceived`
(`0x83950`), which calls `CCategoryHandleHolder::Run` (`0x8e23c`). The category
mapper (`0x8e2f8`) selects holder index 2 for receive category `0x82`. Holder
constructor (`0x8dfa4`) puts a `CNotifyHandler` at field `+0xc`, that index's
object; its constructor (`0x8a524`) installs the vtable whose Run relocation is
saved with the evidence. This supplies the class binding for the indirect
holder call to `CNotifyHandler::Run` (`0x8a628`). The latter stores the supplied
message pointer and count/length, then dispatches by its category table.

## Lens messages and AF completion

Capture's category table at `0xb1f54` is 88 bytes: eleven 8-byte member-function
records. Category slot 5 has `R_ARM_ABS32` relocation to `execLensNotify`
(`0x8ab8c`). Its lens table at `0xb21b4` is 208 bytes: 26 such records, with
relocations every eight bytes. Original stored words are zero; ELF relocation
targets establish the named methods. Treating these on-disk zero words as null
runtime handlers would be incorrect.

`execLensNotify` bounds the selected subcategory against `0x1a` and dispatches
through the member-function record. Lens slots 13, 23 and 25 relocate to
`onInitializedFocus` (`0x8ce68`), `onLensModeChangeDone` (`0x8d204`) and
`onLensEvent` (`0x8d28c`), respectively. The first two selected bodies check
expected lengths 0 and 1 but otherwise return `-1` (or `-2` on mismatch); they
do not themselves publish a successful application completion.

`notifyCategory` (`0x8dacc`) takes the high byte of the halfword at message
`+4`, maps `0xaa` to table slot 10, and maps other values above 9 to slot 0.
`subCategory` (`0x8db54`) takes the low byte. Thus lens message `0x519` selects
category 5 and lens slot 25; the receive category `0x82` is a separate field.

`onLensEvent` requires stored payload length 8. It extracts two integer words
from message offsets `+8` and `+0xc` and calls
`NotifyLensEvent(first,second,null)`, returning zero; another length returns
`-2`. Thus the generic lens notification has a concrete two-word delivery path.
This does not identify every event ID or establish hardware success.

AF scan completion uses another path: liveview table `0xb20ac` slot 5 has a
relocation to `onAFScanDone`, selected by message code `0x305`.
`onAFScanDone` (`0x8bf5c`) requires stored
count/length 1, updates `CCommonProperty::SetFocusScanResult` from message `+8`, reads
the first byte and invokes `CCapturePublisher::SendAppCallback(0x1040001,byte,0)`.
This distinguishes the AF scan callback from the lens listener and from the
similarly named lens initialization/mode methods. Algorithm, focus convergence,
motor movement and the status byte's complete meaning remain unresolved.
In particular, `SetFocusScanResult` (`0x8855c`) copies three words (12 bytes),
while the calling handler tests the stored value against 1. Getter
`getAFScanResult` (`0x91c64`) sends 12 bytes with category `0x81`, opcode `0x365`.
The count/length relationship and backing-buffer bounds are unresolved; this
pass does not equate that tested value with a verified one-byte allocation or
assert a memory-safety flaw. The bridge frame routines have inferred types and
offset relationships requiring further review.

App `UI_Set_Lens_Callback_Fn` (`0x220038`) runs state/error gates and
`UI_Get_LensEvent_Mask_Unmask(id)` before scheduling GLib idle work. Most accepted
events are packed as `(id << 16) | status` for `g_idle_add`; IDs `0x12` and `0x1a`
use different idle functions, and ID `0xd` clears the status first. The third
pointer argument is unused in this selected body. Receipt by this callback
therefore does not imply a displayed UI transition: gates, masks and queue
processing still intervene.
The common idle helper (`0x223db0`) unpacks the high and low 16-bit halves and
calls app helper `0x221d64`; that downstream UI dispatch is an explicit next
review target.

## Concrete command encodings

`ControlLens` validates through its helper before dispatch. Its selected cases
establish the following transport encodings without assigning unverified
hardware meanings to each opcode:

| Capture command | Multicore command | Payload transformation |
|---|---|---|
| `0x1050002` / `0x1050004` / `0x105000b` | `0x501` / `0x502` / `0x504` | Low input word byte minus one, one byte |
| `0x1050005` | `0x503` | Input word equals 1, one byte |
| `0x1050006` | `0x307` | Low input word byte, one byte; diagnostic names lens enlarge |
| `0x1050008` | `0x308` | Low input word byte minus one, one byte |
| `0x1050009` / `0x105000a` | `0x505` / `0x507` | No payload |
| `0x105000d` / `0x105000f` | `0x509` / `0x506` | Eight bytes forwarded |
| `0x1050010` | `0x508` | No payload, `SyncSendCommand` |
| `0x1050011` | `0x50a` | One byte forwarded |

`Control3A` (`0x426d8`) is a separate dispatch surface. For example,
`0x1040005` converts the first input byte to `(byte == 0)` and sends one byte
with command `0x206`; `0x1040008` maps byte 1 to `0x01`, other values to `0x11`,
then sends `0x204`. The latter diagnostic says Lock/Unlock. This preserves the
actual numeric mapping without treating a boolean argument or command name as
proof of physical focus state. Null-payload and default/no-op cases vary; a zero
return alone is not proof that a transport request was sent.

The app CAF wrapper (`0x1e7240`) places its boolean in a 16-byte public payload
and uses request 5 through ioctl helper `0x1e2818`. The translator maps that to
`0x1040005`; ioctl rebuilds a four-byte internal argument before the one-byte
inversion and `0x206` send. App AF-lock wrapper (`0x1e5b3c`) similarly uses
request 9, translated to `0x1040009`, which sends `0x204` with byte `0x02` for
input 1 and `0x12` otherwise. These are concrete app-to-library encodings.

## Lens preferences are another boundary

`User_Spec_Get_Rtos_Pref_Lens_Info` (`0x3e10`) reads four bytes at preference
offset `0xd28` and distinguishes values `0x330033`, `0x11223344`, and other
values with diagnostics `LENS_INIT_END`, `LENS_NO_LENS`, and `LENS_NOT_INIT`.
Those names clarify source intent, not the freshness of a live reading.
`User_Spec_Get_Lens_Property` (`0x1df74`) requests `0x6c` bytes at `0x120`;
`User_Spec_Get_Lens_Info` (`0x1df84`) requests `0x38` bytes at `0x20`.
These lengths belong to these wrappers; the earlier capture GetLensData wrapper
requested `0x40` bytes from `0x20`, so the interfaces must not be assigned a
single assumed struct size. Writers, coherence and RTOS ownership remain open.

## Reproduction and limits

Inputs are copied from verified original filesystem bytes using
`.work/run010/af/core/input-manifest.json`; every generation has its own paired
manifest. Ghidra project is exclusively `NX500_RUN010_AF` under
`ghidra-projects`, Ghidra 12.1.4 / JDK 21, one CPU and 1024M heap. Selected
decompilation uses 45 seconds per function and explicit budgets, with receipts
retained under `.work/run010/af`.

Measured in this pass: four successful source-matching imports and completed
auto-analysis receipts, ten validated export generations, **59/59 completed
selected attempts / 59 distinct SHA+original-VA pairs**, zero selected failures,
zero budget omissions and no failed generations. Original-byte validation
checks 68 ARM code windows (including the separate three-instruction caller
window), four original data blocks and 24 selected strings. Seven saved
mode/reference queries cover all selected entries and the caller window.
There are nine bounded review units across the four source contents. These
counts are stage measurements, not a semantic completion percentage.

Rebuild the selected artifact after the saved export/mode generations:

```sh
PYTHONPATH=.work/python python tools/firmware/selected_elf_evidence.py \
  --root .work/run010/af --output analysis/evidence/af-lens-run010.json \
  --relocation-term CNotifyHandler --relocation-term CMCBAdapter \
  --relocation-term CCapturePublisher --relocation-term mm_camera_ioctl \
  --relocation-term CMulticoreBridge --relocation-term mcb_ \
  --relocation-term pref_rtos_get_bytes --relocation-term CCategoryHandleHolder \
  --string-term E_CAP_CMD_LENS --string-term LENS_INIT_END \
  --string-term LENS_NO_LENS --string-term LENS_NOT_INIT
PYTHONPATH=.work/python python tools/firmware/af_lens_evidence.py \
  --evidence analysis/evidence/af-lens-run010.json \
  --manifest .work/run010/af/core/input-manifest.json
PYTHONPATH=.work/python python tools/firmware/verify_selected_evidence.py \
  --evidence analysis/evidence/af-lens-run010.json \
  --output .work/run010/af/evidence-verification.json
```

The source corpus, symbol tables and pointer relocation records are static.
The method does not prove runtime library binding, callback ordering, active
boot selection, RTOS command handling, calibration, sensor/phase/contrast AF
implementation, physical motor protocol or focus accuracy. C signatures and
member-function ABI remain inferred. Primary-agent byte/artifact validation is
separate from independent semantic review.
The ioctl decompiler emitted a type-propagation warning while completing the
function; the saved pseudocode warning is retained, and it is not treated as
an ABI validation. The AF count/copy mismatch and frame packing are concrete
next-review items, along with downstream app dispatcher `0x221d64`.
