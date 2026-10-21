# Selective push transfer and completion — run003

This offline followup separates queued requests, worker creation, transformed/file-backed
sending, and the worker's completion/stop routes. It adds **30/30 distinct selected
function decompilations**, using the eight existing run002 programs; it imports no new
program and enables no auto-analysis. These counts measure exported functions, not
semantic coverage. No extracted program was executed or camera accessed.

## Sources, addresses and reproduction

- **API**: original rootfs `/usr/lib/libdi-network-dlna-api.so`, SHA-256
  `cdd6ffee8b95ab688fb4180ae473feca557317af1310447cc80869c2c737dac1`.
- **APP**: original rootfs `/usr/apps/com.samsung.smart-wifi-app/bin/smart-wifi-app`,
  SHA-256 `1a3cd718c3554bc1f4ad53e6eb602176a7b3616a6d92699eea848309b3953b87`.

Every API/APP address below refers to that exact input. All reported VAs are original
ELF link-time VAs. For these inspected API executable locations, file offsets equal
ELF VAs; APP file offsets are ELF VAs minus `0x8000`. This was checked independently
through `PT_LOAD`, not inferred from Ghidra's display. Raw Ghidra API addresses add
`0x10000`; raw APP addresses already equal ELF VAs. Object offsets are inferred from
instructions and decompiled C, not validated source-level ABI definitions.

[Manifest](../../manifests/ghidra-transfer-run003.json) records all three commands,
run receipts, validated artifact hashes, and selected function counts.
[Selected evidence](../evidence/transfer-completion-run003.json) retains Capstone
instruction windows, byte offsets, selected C lines and literal-resolution checks.
Original and staged ELF hashes agree. The source BIN/rootfs hash chain is in the manifest.

The recursive `--process --skip-analysis` runs used existing `NX500_FULL_RUN002`,
12 functions per ELF maximum, 30 seconds per selected decompilation, Java heap 768M,
and CPU limit one. All three returned zero; 14 + 9 + 7 decompilations completed,
with no budget omissions or decompiler timeout. Eight repeated symbol/string exports
per run are not added to inventory coverage. Local working outputs are
`.work/run003/transfer`, `transfer-detail`, and `transfer-worker`.

## What start and stop return

**APP** `CUSLNetworkSmartphoneLink::SelectiveNPushStartFileTransfer` at ELF VA
`0x64044` / file offset `0x5c044` calls `CSNetworkAPI::NetworkAPI` at callsite
`0x64058` with command `0x762` and the fourth argument zero. The stop wrapper at
`0x64068` / offset `0x5c068` makes the corresponding `0x763` call at `0x6407c`.
Capstone independently reproduces both complete 36-byte symbols. These route through
the queued `NetworkAPI` path inspected in run002; their immediate success does not
acknowledge worker exit. See [prior route evidence](EXPANDED_GHIDRA_20261021.md).

**API** `DlnaSelective_NPush_StartFileTransfer` (`0x2204c`) calls
`SNPushTransferFile` for a non-null first argument. `SNPushTransferFile` (`0x59360`)
looks up data-server information and at callsite `0x594f4` invokes the
`SPClientManager::createFileTransfer` PLT (`0xf204`), then returns one without
checking a worker transfer result. `SPTransferFile` (`0x583ac`) reaches the same
manager entry at `0x58534` after its own server-information checks. Thus neither
start function's return establishes completed transmission.

## File bytes and resize-memory bytes are separate paths

**API** `SPClientManager::createFileTransfer(char const*,char const*,char const*,int)`
starts at `0x41d08`. Its mode field at object `+0x14` is written by
`setImageTransferSize` (`0x41200`). When that field equals one, the inspected
manager code checks the filename extension case-insensitively against `jpg`
(callsite `0x41fcc`, literal ELF/file `0x74c98`). A cache/path predicate and a
successful `NASLWifi_jpegResizeInMemory` call (callsite `0x42534`, PLT `0xf8dc`)
can supply the buffer/length later passed to `SPHTTPClientHandler::setResizeParams`
at `0x4224c`. Other branches construct the handler without this resize setup.
The manager starts the worker at `0x42258` on its normal start route.

`setResizeParams` (`0x4854c`) stores buffer at `+0x88`, length at `+0x84`, and the
mode byte at `+0x8c` (instructions `0x48558`–`0x48564`). Worker `entry` (`0x4b848`)
checks that byte at `0x4bae0`. Its file branch constructs an `SPFileStream` and
uses virtual open/read operations; the read call at `0x4d41c` requests chunks up
to `0x5000`, later passed to `sendData` at `0x4d4ac`. Its memory branch loads
`+0x84`/`+0x88` at `0x4dc74`/`0x4dc7c`, copies chunks up to `0x5000`, then calls
`sendData` at `0x4dd10`. Capstone independently agrees on these instructions.

This is implementation evidence that the transfer path can use resized memory,
so original-file byte identity cannot be assumed from a selected-push name.
The runtime mode setting, original pathname, JPEG encoder behavior, and actual
transmitted bytes remain unobserved. The file stream's virtual methods were not
resolved here, so this report does not establish filesystem/device semantics.

## Stop performs a join/delete route below the queue

**API** `SNPushStopFile` (`0x59658`) calls the manager's client-key stop helper at
`0x59764` (PLT `0x10344`) and then returns one. The helper at `0x416cc` iterates
its handler vector and compares the supplied key. For a match, it sets worker
byte `+0x0a` to one at `0x4189c`, calls `SPGenericThread::join` at `0x418a0`
(PLT `0xecd0`), then `deleteFileTransfer` at `0x418b0` (PLT `0x101f4`).
The helper also calls `ClearResizeHistory` at `0x419d0`.

`join` (`0x47e6c`) sets byte `+8`, calls `pthread_self` at `0x47e80`, and calls
`pthread_join` at `0x47e98` only if the stored worker ID differs from the caller.
Its return status is not checked. `deleteFileTransfer` (`0x41554`) finds the
pointer, dispatches a virtual slot at `+4`, shifts vector entries, and decrements
the vector end. The exported HTTP handler destructor contains subordinate
virtual cleanup and string/list cleanup, but runtime vtable targets were not
independently established. `ClearResizeHistory` (`0x412e8`) clears cached metadata;
its body does not itself call a buffer deallocator.

The worker polls the `+0x0a` flag, and `sendData` (`0x48bf0`) checks it at `0x48ca0`
before continuing its select/send loop. This establishes a stop request and a
conditional local thread-wait/cleanup route. It does **not** establish a checked
join acknowledgement, bounded cancellation latency, remote receipt, camera
capture/AF/SD/power quiescence, or release of every shared resource. No matching
handler is also possible, yet this outer stop function still returns one.

## Worker completion is later than submission

**API** worker `entry` reaches a post-payload response path at `0x4d618`, calls
`readResponse` at `0x4d63c`, parses the response, then compares the response string
with `200` at `0x4e310` (literal ELF/file offset `0x76374`). The matching branch
sets its local outcome to two at `0x4e3e0`; this is a local HTTP-level success
route, not evidence of durable storage on the receiver.

The common tail calls `SPGenericSocket::close` at `0x4bce8`, performs stream
virtual cleanup (`0x4bd04`, `0x4bd20`), clears the stream pointer, and frees its
temporary chunk buffer before dispatching the outcome notifier. Outcome two
passes event three and value 100 at indirect callsite `0x4c184`. The inspected
`SPClientManager::notifyServiceStatus` (`0x40c14`) forwards event three through
its registered callback when present; `SNPushClientNotificationCallback`
(`0x55804`) maps event three to UI event `0x49`, value 100, at `0x55af0`.
These are conditional callback implementations, not an independently verified
complete runtime callback-binding chain. The notifier runs before `entry`
returns, so it must not be treated as a successful `pthread_join` acknowledgement.

**APP** `nPushCheckSendComplete` (`0x7ddc0` / file offset `0x75dc0`) simply counts
client records whose `+0xac` state is in numeric range three through six, using
record stride `0x44`, and compares the count with the client count at `+0x64`.
It returns true for zero clients as well. Capstone confirms the complete symbol.
Its name therefore does not by itself prove all transfers succeeded; the state
writers and numeric enum meanings remain unresolved.

## Preserved limitations and next targets

Full-symbol Capstone decoding of `SNPushControlNotificationCallback` (`0x56298`,
3616-byte symbol) failed its complete-coverage check. The failure receipt is in
tracked evidence and the manifest. It is not a Ghidra decompiler failure. Bounded
instruction windows and other complete symbol disassemblies succeeded; no whole
control-callback independent validation is claimed.

Next resolve the handler's virtual file operations and notifier binding, the
resize-buffer allocator/releaser, caller settings for image-transfer mode, and
APP state writers/event consumers. Correlating these with capture/AF, SD writer
and power management remains separate work. This report makes no device-level
claim about shooting while a transfer starts, stops, or completes.
