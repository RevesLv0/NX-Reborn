# App storage outcomes, skip accounting and URL notification — RUN006

The app has separate file-accounting, skip-write and network-notification paths.
The traced Wi-Fi path forwards a JPG pathname without branching on the converted
storage result. Its downstream API publishes URL information. These observations
do not establish successful storage or remote receipt, and do not show that all
network modes behave alike.

## Sources and method

| Original rootfs path | SHA-256 |
|---|---|
| `/usr/apps/com.samsung.di-camera-app/bin/di-camera-app` | `55dcc78143724435a2e38b9e0d809960bd728668634bbcf7532ce137f882eb04` |
| `/usr/lib/libcapture-fw-prod.so` | `a07867292610ac6376e29e3cd64bc79a274452412387fb7853c5a3fb3f96bba5` |
| `/usr/lib/libdi-network-bt-app.so` | `94a8f7ae05298d9a143d89c3b67cb1141ef3aea7c2cdc0004ef9799cda261eae` |
| `/usr/lib/libdi-network-dlna-rvf.so` | `a7c8f03e4fdcc035762f83a2168efbbb4a4d93ac34802d1d4e097eb74404f567` |
| `/usr/lib/libdi-network-dlna-api.so` | `cdd6ffee8b95ab688fb4180ae473feca557317af1310447cc80869c2c737dac1` |
| `/usr/apps/com.samsung.smart-wifi-app/bin/smart-wifi-app` | `1a3cd718c3554bc1f4ad53e6eb602176a7b3616a6d92699eea848309b3953b87` |

All VAs below are original ELF addresses, not runtime locations. DSO Ghidra
addresses add `0x10000`; app Ghidra addresses equal original VAs. Original file
offsets are mapped separately through PT_LOAD. The additional bridge/driver
sources and full pointer proof are in [RTOS_TRANSPORT_RUN006.md](RTOS_TRANSPORT_RUN006.md).

[App evidence](../evidence/app-error-consumers-run006.json) preserves selected C,
original ARM windows, three data-only jump tables, source checks and relocations.
[Network state evidence](../evidence/transfer-boundaries-run006.json) preserves
the selected API/state bodies and recovered-code windows. All completed runs are
in [the manifest](../../manifests/ghidra-run006.json). The primary agent checked
the original evidence and the bounded claims below. Independent RUN006 semantic
review did not finish because the reviewer hit the actual usage limit.

## Explicit skipped-write accounting entrance

Camera callback installation (`0x1e48ec`) passes the concrete
`UI_Set_Camera_Callback_Fn` (`0x217140`) with null user data to
`mm_camera_set_notification_callback`; the call uses the camera handle, function
pointer and user-data registers, not a guessed decompiler prototype. App storage
registration at `0x1dc294` and `0x1dc2b4` supplies filename and admission-space
callbacks to libmm-photo. These registrations are distinct API boundaries.

The original jump table at `0x1e45b8` maps raw mm-camera ID `0x3a` to UI ID
`0x39`. The callback-name jump table at `0x209318` names this
`CB_STL_SKIP_FILE_WRITE`. In `UI_Set_Camera_Callback_Fn`, UI ID `0x39` takes the
default zero-data packing path and is scheduled with `g_idle_add`, subject to the
function's early Wi-Fi/power-off guards. Idle trampoline `0x21b868` unpacks the
UI ID and data, reaches dispatcher `0x218920`, and its table at `0x218b54` selects
`0x21b000`, which calls `File_Write_Done` (`0x217cac`).

This is an explicit skipped-write accounting entrance. The separate libmm-photo
completion handler remains the [RUN005 path](APP_STORAGE_RUN005.md).
No static name or shared decrement proves that one capture emits both entrances,
or that a decrement alone means a successfully written file.

## Wi-Fi path reaches a URL state update

`UI_WiFi_RVF_Shot_Result` (`0x184c3c`) requires UI value `0xc33 == 0` and
`0xf8 == 1`, calls the storage-error conversion function and discards its result.
For event 1 it rejects null path objects and tests for the substring `.JPG`.
The successful string branch copies the path to global `0x4a4ddc` and calls
`DlnaRVFEvent(0x24,path)`. This body does not check file existence or successful
write/close. The test is a substring search, not a parsed extension guarantee.

`DlnaRVFEvent` (dlna-api `0x110a0`) first checks its termination byte at original
VA `0x8218c`. With termination inactive, case `0x24` calls
`RVFAppSendShotResultURLEvent` for a non-null path and returns 1 without checking
its result; a null path also returns 1 in that case. Its return is therefore not
proof of a delivered URL.

`RVFAppSendShotResultURLEvent` (dlna-rvf `0x3255c`) calls
`UPnPCDSRVFShotwithGPS::getURLInfo` (`0x59c1c`), passes the resulting pointer to
`SMPDMSUpdateStateVariableValue` for `RVF_LAST_PHOTO_URL_VALUE` under the
ContentDirectory service, frees the pointer, then returns 1. The update result
is not checked in this body.

The freshly selected URL builder gets an IP address, constructs string objects,
uses `CDSRVF_Sysfunc_get_card_status` to select a path/sub-string branch and
returns a string. Its inspected body has no `stat`, open/read, write/close or
remote-delivery check. String-wrapper ABI inference omits some arguments in C;
original ARM instructions are retained. The card-status helper's internals are
not proved here, so this is not a global claim that no descendant can query a
file or that no later HTTP request can fail.

## BT and smartphone-state limits

The photo callback's normal/error bookkeeping branches both reach the app BT
path with a pathname; they do not supply the storage status as a BT argument.
The selected app bodies include queue insertion, metadata lookups and separate
single/continuous messages. Library `bt_send_msgs` (`0x6644`) synchronously calls
`bt_msg_process` and returns 1. That wrapper is not a checked transfer result.
The downstream file sender has its own state and file handling; no remote
completion is inferred from this local wrapper or a queued pathname.

In smart-wifi, `CSAFStateMachine::dispatch` (`0x406c8`) calls the current state's
virtual slot `+8`; `CAPPUIApplication::dispatch` (`0x4cd30`) then conditionally
clears event byte `+0x14` for type `0x13`. The selected smartphone state
`handle` (`0x810a8`) has an empty type-`0x13` branch; its default branch forwards
to its parent. This describes that selected state, without proving it is the
active consumer at runtime.

`getNPushAllFileSendWait` (`0x7d490`) accepts client states 2 or 6 together with
UI value `0x1b3 == 0`; `getNPushEachFileCompleteCheck` (`0x7d174`) also accepts
other-client index/state conditions. The semantic definitions of these state
values and the final checked success producer remain unresolved. The earlier
aligned offset-constant scan found candidates only; no absence-of-writer or
global transfer-success claim is made from it.

## Reproduction and followup

```sh
PYTHONPATH=.work/python python tools/firmware/app_error_consumers_evidence.py
PYTHONPATH=.work/python python tools/firmware/transfer_boundaries_evidence.py
python tools/firmware/run006_manifest.py
PYTHONPATH=.work/python python tools/firmware/verify_run006_evidence.py
```

Remaining work includes concrete producer/correlation for mm-camera skip versus
SIF completion, BT result consumers and state transitions, final smartphone
state writers, string/helper contracts, and live delivery ordering. No camera
program was executed, no device was accessed and no firmware was installed.
