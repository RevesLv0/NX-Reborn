# Transfer response errors and final outcome delivery — RUN010

The selective-push worker distinguishes a final HTTP `200` response, two
receiver-reported error subcodes, and generic failure. The receiver's
`Sub-ErrorCode` header, rather than an APP client-state enum, produces the two
specific errors traced here. The intended callback route reaches an asynchronous
APP type-`0x13` event. The selected smartphone state's empty handler for that type
still prevents concluding that its per-client state records consume the result.

## Sources and method

| Original rootfs path | SHA-256 |
|---|---|
| `/usr/lib/libdi-network-dlna-api.so` | `cdd6ffee8b95ab688fb4180ae473feca557317af1310447cc80869c2c737dac1` |
| `/usr/apps/com.samsung.smart-wifi-app/bin/smart-wifi-app` | `1a3cd718c3554bc1f4ad53e6eb602176a7b3616a6d92699eea848309b3953b87` |

All addresses below are original ELF VAs. API executable offsets equal their
VAs; APP executable offsets equal VA minus `0x8000`, checked through PT_LOAD.
Saved Ghidra API addresses add `0x10000`; APP addresses do not. The
[evidence](../evidence/transfer-state-run010.json) contains the selected C,
original ARM windows with file offsets, original strings, jump/vtables and ELF
relocations. Saved Ghidra mode queries establish ARM context for the selections.
Decompiler signatures and object layouts remain inferred; call arguments are
checked against original instructions where the C omits them.

Five validated process/noanalysis export generations produced **36/36 completed
selected attempts, 30 distinct SHA/VA pairs**, with no new import or analysis.
One generation's budget omitted one of seven matching constructor/manager
functions; its receipt and six completed exports are preserved under
`.work/run010/transfer-budget-attempts`. A complete seven-function repeat recovered
the omitted match. This is a recorded budget omission, not a decompiler failure.
The [manifest](../../manifests/ghidra-transfer-run010.json) records both attempts,
source pairing, artifact hashes and the two mode/reference queries. Counts
measure exports and selected functions, not semantic completeness.

## The response header is the concrete specific-error producer

API `SPHTTPClientHandler::readResponse` (`0x4873c`) appends data obtained through
`SPGenericSocket::read` into handler `+0x74` and returns one when it finds
`\r\n\r\n`. This is a local header-availability test. Socket-read implementation,
actual network traffic, timeout bounds and receiver persistence were not observed.

`SP_HTTP_Response::parse` (`0x4a9ec`) splits response lines and stores the status
token at response `+8`. For header name `Sub-ErrorCode` (`0x75f7c`), it invokes
`sscanf(value,"%d",...)` at `0x4b304`, then writes the parsed local word to
response `+0x10` at `0x4b3b8`. The worker supplies its embedded response object
at handler `+0x18`, so this word is handler `+0x28`. The `sscanf` return is not
checked; no malformed-input or general parser-correctness guarantee is inferred.
The decompiler reports two removed unreachable blocks; original recovered-code
windows remain in evidence.

Worker `entry` (`0x4b848`) first compares the parsed status string to `100`.
Its other branch checks for substring `500` in that status string, then loads
handler `+0x28` (`0x4ce20`). The comparisons at `0x4ce24`–`0x4ce38` select decimal
2502 (`0x9c6`) and 2503 (`0x9c7`). These are substring/string tests in this body,
not a general numeric HTTP validator. The two branches are labeled by original
diagnostics `STREAM_EXCEED_STORAGE_SPACE` (`0x761e4`) and `NOT Supported File`
(`0x76200`). Their meanings are inferred from those diagnostics and branches;
they are not independently sourced enum definitions or observed receiver errors.

## Worker-local final outcomes map to separate events

| Worker branch | Local outcome | Notifier event | API UI event / status | APP event |
|---|---:|---:|---|---|
| Post-payload response string equals `200` | 2 | 3 | `0x49` / 100 | `0x76c` |
| Initial non-`100` status contains `500`, subcode 2502 | 3 | 4 | `0x4d` / 0 | `0x770` |
| Initial non-`100` status contains `500`, subcode 2503 | 4 | 6 | `0x4c` / 0 | `0x76f` |
| Default failure outcome | 1 | 5 | `0x4b` / 0 | `0x76e` |

The specific-error branches assign outcome four at `0x4da58` and outcome three
at `0x4db84`, then branch to common cleanup `0x4bcd8`. That cleanup closes the
socket, invokes stream cleanup, clears the stream pointer and deletes the
temporary chunk buffer before outcome dispatch. Outcome tests begin at
`0x4bd3c`; notifier calls are `0x4c184` (event three), `0x4c1c8` (event four),
`0x4c3e0` (event six), and `0x4bd78` (event five). Original call instructions
preserve the zero/value plus client-key pair even where decompiled C elides
arguments. A send failure can set the stop byte at `0x4e1b0`; the shared
error-exit route overrides its local outcome to one when that byte is set.
Cancellation is therefore not established as an independent successful outcome.

`SPClientManager::notifyServiceStatus` (`0x40c14`) checks the supplied data pointer
and registered callback and forwards events three through six. Callback
`SNPushClientNotificationCallback` (`0x55804`) performs the API event mappings
in the table. APP converter `ConvertNetworkToUiEventId` (`0x59d88`) maps API
events `0x49`–`0x4d` to `0x76c`–`0x770`; status conversion `0x5a328` leaves this
group's status unchanged. The callback label `0x5a368`, retained as a bounded
64-byte original window, supplies group `0x700` and tail-branches to
`responseToUI` (`0x58244`).

These worker-local outcomes are distinct from the smartphone object's client
record field `+0xac`. Numeric equality does not connect the two representations.
HTTP `200` supports only this local success branch; it does not prove durable
remote storage, successful thread join or camera resource quiescence.

## The intended callback and APP singleton dispatch bindings are concrete

The refreshed manager/handler selections reproduce the
[RUN004 binding](TRANSFER_CALLBACKS_RUN004.md): `createFileTransfer` (`0x41d08`)
passes the manager to handler construction, and handler constructor `0x4edd8`
stores it at handler `+0x78`. Manager constructor `0x41328` computes GOT slot
`0x820e4`, whose relocation names `_ZTV15SPClientManager`, and installs its
address point `+8`. The relocation at `0x81348` identifies the first slot as
`notifyServiceStatus` (`0x40c14`). `SNPushStart` (`0x58f60`) obtains the callback
through GOT relocation `0x820e0`; setter `0x411f8` writes manager `+0x10`.
API callback-global relocation `0x82100` and event emitter `0x213a8` remain
consistent with that intended route. Default visibility permits runtime
interposition or replacement; initialization and active binding remain unobserved.

The additional APP constructor/singleton evidence closes a prior static gap:
`CAPPUIApplication::getInstance` (`0x4caac`) returns global object `0x143e94`,
constructing it through `0x4ca8c` on its guarded initialization branch. The
constructor's original literal at `0x4caa8` is `0x105170`, the vtable address
point. Its slot `+0xc`, original word at `0x10517c`, equals `0x4cd30`.
`UI_Event_Send_Manager` (`0x49fb0`) calls that slot. Thus its intended static
target is concretely `CAPPUIApplication::dispatch`, not a name-matched guess.

`responseToUI` sets the event type to `0x13` and submits it with `g_idle_add`.
The event constructor at `0x40be4`, vtable at `0xf5a40` and original getter/setter
windows verify that setter slot `+0x10` writes the type and getter slot zero
reads it. The application dispatcher invokes the current state through
`CSAFStateMachine::dispatch` (`0x406c8`). For the selected smartphone state's
`handle` (`0x810a8`), the original type table at `0x810d8` sends type `0x13` to
epilogue `0x81220`. This selection does not update a client state. It does not
prove which state is active, that all alternate delivery routes are absent, or
that a future runtime observer could not consume the event elsewhere.

## Remaining questions and reproduction

The concrete producer and route explain specific error notifications but leave
the APP terminal client-state writers unresolved. `nPushCheckSendComplete`
(`0x7ddc0`) still accepts numeric states three through six, including the
zero-client case; its name does not certify success. The earlier wait predicates
for two/six and each-file equality remain bounded RUN006 observations. No
absence-of-writer claim follows from the earlier offset scans.

Next identify the active state at delivery, any alternate result observer and
the concrete `+0xac` terminal writers, then correlate client identity, selected
file index, cancellation and next-file scheduling. Actual HTTP exchanges and
receiver persistence require separately scoped runtime evidence.

```sh
PYTHONPATH=.work/python python tools/firmware/transfer_state_evidence.py
PYTHONPATH=.work/python python tools/firmware/verify_selected_evidence.py \
  --evidence analysis/evidence/transfer-state-run010.json \
  --output .work/run010/transfer/verification.json
```

The verifier checks 48 original code windows, 11 data blocks and ten original
strings against source bytes, plus copied C/instructions and recorded
relocations. These are sub-agent original-byte/artifact checks and bounded
static interpretation. Independent semantic review remains incomplete. No target
program was executed, camera accessed, firmware modified or installed.
