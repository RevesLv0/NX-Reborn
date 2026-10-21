# Transfer callback binding and APP outcome route — run004

This offline followup adds **46/46 distinct selected function decompilations** from
five no-analysis passes over the existing eight-program `NX500_FULL_RUN002` project.
These are export counts, not semantic coverage. No program was imported or executed,
and no camera, device I/O or firmware installation was involved.

The source API is `/usr/lib/libdi-network-dlna-api.so`, SHA-256
`cdd6ffee8b95ab688fb4180ae473feca557317af1310447cc80869c2c737dac1`;
the APP is `/usr/apps/com.samsung.smart-wifi-app/bin/smart-wifi-app`, SHA-256
`1a3cd718c3554bc1f4ad53e6eb602176a7b3616a6d92699eea848309b3953b87`.
Every address below is an original ELF link-time VA. API executable offsets equal
these VAs; APP executable offsets are VAs minus `0x8000`, independently checked
through `PT_LOAD`. Ghidra API C/instructions add `0x10000`; APP addresses do not.

The [manifest](../../manifests/ghidra-transfer-run004.json) records commands, receipts,
input pairing, artifact hashes, omissions and findings. The
[evidence](../evidence/transfer-callbacks-run004.json) retains 31 independently decoded
Capstone windows, dynamic relocation and visibility records, checked pointer/literal
calculations, and selected decompiled C. Its
[extractor](../evidence/transfer-callbacks-run004-extract.py) runs with
`PYTHONPATH=.work/python python analysis/evidence/transfer-callbacks-run004-extract.py`.

## File virtual calls resolve to a stdio-backed implementation in this ELF

API `SPFileStream` constructor `0x435e4` loads its vtable through GOT relocation
`0x82038` and installs `_ZTV12SPFileStream + 8`. Relocations at `0x81370`,
`0x81374`, and `0x81378` name `Open` (`0x4313c`), `Close` (`0x42fd4`) and
`GetData` (`0x42cec`). Those are vtable offsets `+8`, `+0xc`, and `+0x10`
relative to the installed address point. The worker constructs this stream at
`0x4c298`, invokes slot `+8` at `0x4c2bc`, reads through slot `+0x10` at
`0x4d41c`, and closes through slot `+0xc` at `0x4bd04`.

`Open` invokes `fopen64` at `0x4333c` with the independently resolved `rb`
literal, stores the FILE pointer at stream `+0x18`, and invokes `fileno` /
`__fxstat64` at `0x43364` / `0x43374`. `GetData` invokes `fread` at `0x42d58`
with element size one; a short read returns zero and reports zero output bytes.
`Close` calls `fclose` at `0x430ac` when that pointer is non-null, clears it,
and clears the remaining-byte count. Thus the intended file branch is a local
stdio read route. It does not identify the runtime mount, prove an immutable
file snapshot or identify every kernel/device resource released by closing it.

## Initialization binds the intended worker-to-SNPush notifier chain

API `SPClientManager::createFileTransfer` (`0x41d08`, previously inspected) passes
the manager as the notifier argument at constructor calls `0x41e54` / `0x42224`.
The selected handler constructor `0x4edd8` preserves that argument and stores it
at handler `+0x78` (`0x4eea8`). Manager constructor `0x41328` installs
`_ZTV15SPClientManager + 8`; dynamic relocation `0x81348` identifies its first
slot as `SPClientManager::notifyServiceStatus` (`0x40c14`). Worker success
notifier `0x4c184` loads handler `+0x78`, then the object's first vtable slot.

`SNPushStart` (`0x58f60`) obtains the manager and loads its callback pointer
through GOT `0x820e0` before calling `setCallback` at `0x59088`.
The GOT relocation names the defined `SNPushClientNotificationCallback`
(`0x55804`); the eight-byte setter `0x411f8` writes manager `+0x10`.
`notifyServiceStatus` loads that field, checks it and invokes event three at
`0x40d70`. The callback maps event three to event `0x49`, value 100, with
its client/path argument at `0x55af0`.

This closes the intended static binding gap from run003 using constructor
stores, vtable slots and ELF relocations, rather than matching names alone.
The referenced vtables, callbacks and methods are default-visible global ELF
symbols. Their relocation records do not prove runtime loader resolution,
exclude interposition, prove successful initialization, or prevent later callback
replacement. No runtime binding was observed.

## APP receives an asynchronous event route; terminal-state consumption remains open

APP `handleSmartphoneLink` (`0x59068`) passes callback address `0x5a368`
(independently checked at pointer literal `0x5952c`) to the imported NPush
initializer at `0x59468` for internal command `0x760`. API
`DlnaSelective_NPush_Initialize` (`0x21914`) calls `DlnaSelectivePushSetCallback`
on its successful initialization branch. Setter `0x16148` stores the supplied
pointer in `gSelectivePushCallback`. Its GOT reference and
`SelectivePushSendEventToUI` (`0x213a8`) independently resolve to the same
GOT `0x82100`, whose dynamic relocation names that global. The latter calls
the stored pointer at `0x213cc` if non-null.

APP callback code `0x5a368` is a label, not a separately exported Ghidra function.
The complete bounded 64-byte Capstone window shows it converting the event with
group `0x700`, converting the status, and tail-branching to `responseToUI`
(`0x58244`) at `0x5a3a4`. The inspected converter `0x59d88` maps API event
`0x49` to APP internal event `0x76c`; events `0x4b`, `0x4c`, `0x4d` map to
`0x76e`, `0x76f`, `0x770`. The status converter leaves this group's value
unchanged. These are internal APP events, not wire protocol identifiers.

`responseToUI` builds an event of type `0x13` and schedules
`UI_Event_Send_Manager` (`0x49fb0`) with `g_idle_add` at `0x58420`.
That idle callback dispatches through the application virtual slot `+0xc`
at `0x4a0d8`. The separately inspected `CAPPUIApplication::dispatch`
(`0x4cd30`) calls the state-machine dispatcher at `0x4cd38`.
The exact application vtable binding and active state-machine propagation remain
unverified; this is a concrete asynchronous delivery route, not a verified
per-client success-state update.

In particular, the inspected `CAPPNetworkSmartphoneLinkState::handle`
(`0x810a8`) has a type-`0x13` case that returns without a state write, and
its `handleNetworkEvent` (`0x7b0bc`) is only `bx lr`. The inspected top-level
handler's type-`0x13` branch checks shutdown event `0x102`; it does not establish
a consumer of `0x76c`. GUI popup methods also contain numeric `0x76c`, but
these are GUI emission routes, and their matching number does not establish
network-event consumption. The next target is the state-machine dispatch and
any additional GUI/global observers, then the per-client numeric-state writers.
The run003 predicate accepting states three through six remains insufficient
to establish that all transfers succeeded.

## Outcome notification still precedes thread completion

The run003 worker tail closes its socket/stream and frees its temporary chunk
buffer before dispatching outcome three/value 100, then returns later. The
new binding evidence above does not change that ordering. Independently decoded
stop windows still show the manager writing worker `+0x0a`, calling the join
helper and then deleting the handler (`0x4189c`–`0x418b0`). The join helper
(`0x47e6c`) skips `pthread_join` for self and does not check its return code.
The APP stop wrapper `0x64068` still submits internal command `0x763` through
the queue route. Request submission, local outcome callback, a successful
thread join, remote durable receipt and camera-wide quiescence are distinct
conditions; no new join acknowledgement or camera resource-release guarantee
was found here.

All five Ghidra runs returned zero with no decompiler failures or analyzer
execution. The first pass omitted one matched function by its per-ELF budget;
the second omitted 22 APP matches from a broader CSNetworkAPI pattern.
Those omissions remain recorded, and focused later passes recovered requested
binding/consumer functions. Repeated eight-program exports add no inventory
coverage. Local working directories are `.work/run004/transfer`,
`transfer-consumer`, `transfer-binding`, `transfer-outcome`, `transfer-dispatch`.
