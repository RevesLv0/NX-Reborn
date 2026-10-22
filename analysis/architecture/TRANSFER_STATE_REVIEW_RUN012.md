# RUN012 independent review of RUN010 transfer-state claims

Reviewed 2026-10-22. All three bounded claims in [review-transfer-run010.json](../../manifests/review-transfer-run010.json) are supported by independently decoded original ARM instructions, pointer/jump tables and ELF relocations. No central correction is required to [TRANSFER_STATE_RUN010.md](TRANSFER_STATE_RUN010.md).

The supported findings concern parsed response subcodes, worker-local outcome notifications and intended APP dispatch binding. They do not establish socket correctness, actual receiver responses, remote persistence, a universal HTTP status validator, active APP state, alternate observers or concrete terminal writers of the APP client field `+0xac`.

## Sources, addressing and original-byte audit

| Original rootfs source | Independently recomputed SHA-256 |
|---|---|
| `/usr/lib/libdi-network-dlna-api.so` | `cdd6ffee8b95ab688fb4180ae473feca557317af1310447cc80869c2c737dac1` |
| `/usr/apps/com.samsung.smart-wifi-app/bin/smart-wifi-app` | `1a3cd718c3554bc1f4ad53e6eb602176a7b3616a6d92699eea848309b3953b87` |

The staged files under `.work/run010/transfer/network/inputs` match original extracted rootfs bytes. Every audited address below is an original ELF link VA. File offsets were independently recomputed through the file-backed `PT_LOAD` containing each range, and instructions decoded in ARM mode using Capstone. API code offsets equal the reviewed VAs; APP code offset is VA minus `0x8000`. Data requires its own segment mapping: API vtable `0x81340`, for example, is file offset `0x79340`.

Independent checks reproduce **48 saved instruction windows, 11 data blocks, 22 saved relocation records, ten original strings and three status-comparison literal calculations** in [transfer-state-run010.json](../evidence/transfer-state-run010.json). Its SHA-256 remains `ae4c0286e28001f255ec659ed6376c4ec5f7817bf298cb939d28214a6885281e`, matching the historical review manifest. Original ARM veneer arithmetic also resolves **684 direct PLT call/branch sites** in the audited windows to their GOT relocation symbols; that count includes repeated calls to the same binding.

The byte audit is wider than the semantic review: it does not imply full understanding of every constructor/worker error path. Saved C provided navigation; the central conclusions below use original operands, control-flow targets, literal values and relocation records. No Ghidra project was opened, no analyzer/decompiler run was started, and no parent artifact was modified. There was no target execution, device I/O, commit or push.

## Three-claim disposition

| Claim ID | Disposition | Independently checked original evidence | Boundary retained |
|---|---|---|---|
| `TRANSFER010-SUBCODE` | Supported | API parse `0x4a9ec`, header match `0x4b2c0–0x4b304`, parsed store `0x4b3b8`; worker embedded response `0x4c654–0x4c664`; comparisons `0x4cdf0–0x4ce38` | Unchecked `sscanf` conversion, malformed input, socket-read semantics and actual traffic remain unverified. |
| `TRANSFER010-OUTCOME` | Supported | API outcome assignments `0x4da58/0x4db84/0x4e3e0`; cleanup `0x4bcd8`; dispatch `0x4bd3c`, notifier calls `0x4c184/0x4c1c8/0x4c3e0/0x4bd78`; callback `0x55804`; APP converter table `0x59f8c` | Worker-local values are not APP client states; success branch is not remote durability, thread join or quiescence. |
| `TRANSFER010-APP-SINGLETON` | Supported | APP constructor `0x4ca8c`, literal `0x4caa8`, singleton `0x4caac`, vtable slot `0x10517c`, idle manager `0x49fb0`, dispatch `0x4cd30`; selected type table `0x810d8` | Active state, alternate observers and concrete `+0xac` terminal-state writers remain unresolved. |

## Header parsing and handler +0x28

API parser `0x4a9f8` saves its response-object argument in `sl`. The literal loaded at `0x4b25c` is file word `0x4b7e8`; adding PC base `0x4b284` resolves exactly to original string `Sub-ErrorCode` at `0x75f7c`. The matching test at `0x4b2c0–0x4b2d0` uses `strcasecmp`, whose PLT `0xea54` resolves GOT relocation `0x8177c`.

The selected original conversion sequence is:

```text
0x4b2e8 ldr r1,[pc,#0x4fc]      # literal word at 0x4b7ec
0x4b2ec str r5,[ip,#-0xc]!      # local parsed word, initially zero here
0x4b2f4 add r1,pc,r1            # resolves format "%d" at 0x76038
0x4b2fc ldr r0,[r4,#0xc]        # header value
0x4b300 mov r2,ip               # destination local word
0x4b304 bl 0x10140              # sscanf; GOT 0x81f20
...
0x4b3b4 ldr r3,[sp,#0x134]
0x4b3b8 str r3,[sl,#0x10]
```

The conversion return is not tested before logging and storing the local word. This proves the source/store route, not general parser validity. The observed initialization also prevents inferring an uninitialized local merely from the unchecked conversion.

Worker entry preserves its handler pointer in `r5`. At `0x4c654–0x4c664`, it forms `r5+0x18`, saves that pointer at `sp+0x28`, and supplies it as the parser's response object. Therefore response field `+0x10` is handler field `+0x28`. That same saved response pointer is reused for the later parse at `0x4e2ec–0x4e2f4`.

Initial status comparison uses `strcasecmp(status,"100")` at `0x4cdfc`; its literal independently resolves to `0x75d64`. The non-equal branch performs `strstr(status,"500")` at `0x4ce14`, bound through GOT `0x81bfc`, with original literal `0x761e0`. Only a nonnull substring result reaches handler `+0x28` at `0x4ce20`. Comparisons then use original decimal subcodes 2502 (`0x9c6`) and 2503 (`0x9c7`) at `0x4ce24–0x4ce38`.

This is an exact string comparison followed by a substring test. It is not a general numeric HTTP-status validation rule, and no broader validator is inferred from it.

## Outcomes, notifier mappings and cleanup

The subcode-2502 route targets `0x4da90` and ultimately writes worker outcome 3 at `0x4db84`; its original diagnostic is `STREAM_EXCEED_STORAGE_SPACE` at `0x761e4`. The 2503 route targets `0x4d964`, writes outcome 4 at `0x4da58`, and uses `NOT Supported File` at `0x76200`. Those diagnostic strings support the intended associations; they are not independently recovered enum declarations or observed receiver conditions.

For the post-payload response path, `0x4e300` loads the status pointer from handler `+0x20` (embedded response +8), and `0x4e310` compares it to original string `200` at `0x76374` with `strcasecmp`. The equal branch eventually writes outcome 2 at `0x4e3e0` and branches to cleanup `0x4bcd8`.

The selected outcome routes are:

| Worker outcome | Notifier event / callsite | API UI event / status | APP converted event |
|---:|---|---|---|
| 2 | 3 / `0x4c184` | `0x49` / 100 | `0x76c` |
| 3 | 4 / `0x4c1c8` | `0x4d` / 0 | `0x770` |
| 4 | 6 / `0x4c3e0` | `0x4c` / 0 | `0x76f` |
| Default branch, including outcome 1 | 5 / `0x4bd78` | `0x4b` / 0 | `0x76e` |

Dispatch comparisons are actual `cmp r8,#2/#3/#4` at `0x4bd3c/0x4bd48/0x4bd64`. The default path loads manager object from handler `+0x78` and invokes virtual slot zero. The success path constructs data `(100,client-key)` at `0x4c15c–0x4c178`; failure paths construct `(0,client-key)` before their selected event calls. These register/stack operands establish the data passed even where C prototypes omit arguments.

Common cleanup at `0x4bcd8` handles the socket, selected stream cleanup and temporary buffer before the outcome dispatch. This local order does not establish remote persistence or globally quiescent resources. Stop byte handler `+0xa` is tested at `0x4d3d4–0x4d3dc` and can overwrite the local outcome with 1. Earlier provisional outcome-2 assignments elsewhere in the worker must not be generalized into proof that every successful notification implies the same final-response route.

`SPClientManager::notifyServiceStatus` (`0x40c14`) checks the supplied data pointer and follows event-specific branches for events 3–6. Its callback field is manager `+0x10`, written by setter `0x411f8`; selected forwarding branches check it before indirect calls. `SNPushClientNotificationCallback` (`0x55804`) uses original immediate API event values: `0x49` at `0x55aec`, `0x4d` at `0x55924`, `0x4c` at `0x55bbc`, and `0x4b` at `0x55c8c`.

The API manager binding is relocation-backed: constructor `0x41328` computes GOT `0x820e4`, whose type-21 relocation names `_ZTV15SPClientManager` at `0x81340`; it adds 8 before installing the vptr. Vtable word `0x81348` has type-2 ABS32 binding to `notifyServiceStatus` at `0x40c14`. GOT `0x820e0` binds the intended notification callback at `0x55804`. Original zero words do not mean null runtime virtual methods after relocation. Runtime interposition and active initialization remain unobserved.

APP converter group `0x700` selects an original indexed table at `0x59f8c`, using index `API-event-4`. Independent table reads resolve:

| API event | Original table word | Target / returned APP ID |
|---|---|---|
| `0x49` | `0x5a0a0` | `0x5a1f4` / `0x76c` |
| `0x4b` | `0x5a0a8` | `0x5a1e4` / `0x76e` |
| `0x4c` | `0x5a0ac` | `0x5a1dc` / `0x76f` |
| `0x4d` | `0x5a0b0` | `0x5a1d4` / `0x770` |

Status converter `0x5a328` returns its supplied status for this group. Callback label `0x5a368` supplies group `0x700`, converts the event/status and tail-branches to `responseToUI` (`0x58244`). The complete argument and table route is independently supported; worker outcomes and the APP client's record field `+0xac` remain distinct representations.

## APP singleton, event type and empty selected-state branch

The APP constructor at `0x4ca8c` loads original literal `0x4caa8 = 0x105170`, stores it as its vptr and returns. Singleton `getInstance` (`0x4caac`) has a guarded construction branch and returns global object `0x143e94`; the direct return and constructor literals were independently read.

The original word at address point `0x105170+0xc = 0x10517c` is `0x4cd30`, the selected dispatch implementation. `UI_Event_Send_Manager` calls singleton getter at `0x4a0c8`, loads that virtual slot at `0x4a0d4`, and calls it at `0x4a0d8`. This is a concrete object/vtable binding, conditional on the expected object and runtime memory, rather than matching function names alone.

`responseToUI` loads event type `0x13` at `0x582cc` and calls event setter slot +0x10 at `0x58300`. The original event vtable at `0xf5a40` and implementations `0x40c34–0x40c70` bind the type getter to field +4 and the setter to the same field. The response function queues the event with `g_idle_add`.

Application dispatch `0x4cd38` calls state-machine dispatch `0x406c8`; the latter loads its current-state object and invokes virtual handle slot +8. In the **selected smartphone state's** handle, `0x810c8–0x810d0` subtracts 1 from the event type and performs an unsigned indexed jump for types 1–19. Original table entry `0x810d8 + (0x13-1)*4 = 0x81120` contains `0x81220`. That target is exactly stack restore and return at `0x81220–0x81224`, with no selected handler body or client-state write.

Application dispatch subsequently has its own event-type/flag cleanup at `0x4cd4c–0x4cd60`; this does not turn the selected smartphone handler's empty route into a terminal client-record writer. This review does not identify the active state at delivery, eliminate alternate observers or claim that no writer exists elsewhere.

## Artifacts and remaining scope

Independent scratch artifacts are `.work/run012/review-transfer/{audit.py,audit.json,calls.py,calls.json,data.py,data.json}` and per-function original disassembly dumps. They perform host-side source decoding only. Completed parent evidence/report/manifest files were read and left unchanged.

The specific three-claim independent-review gap is closed to the stated static scope. Socket implementation, actual HTTP exchanges, remote storage durability, complete cancellation behavior, alternate APP observers, active state and the concrete `+0xac` terminal-state writers remain separate work. No universal success or absence-of-writer conclusion is inferred.
