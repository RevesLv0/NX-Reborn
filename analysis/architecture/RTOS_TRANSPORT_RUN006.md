# RTOS notification to packaged Linux receiver — RUN006

The inspected normal path supplies a concrete byte correspondence between the
RTOS readiness notification and the Linux notification parser. It does not prove
that the packaged kernel was booted, that a particular packet arrived, or that
the notification acknowledges a completed file write.

## Sources and address conventions

| Source | SHA-256 | Address convention |
|---|---|---|
| Complete `NX500.bin` | `f4c238e811970cf858b5d734119477ea191d35cd29d9f84b584157ecfc4ee997` | BIN byte offsets |
| SLP section 5 / T-Kernel | `f8e417cb5b55768851ba7e2b8017d3a98dc0b0c8444cc0a5061265cc08dbbf7f` | Section offset; BIN = `0xef4301 + section`; inferred link VA = `0x80000000 + section` |
| Decoded packaged kernel 2 | `25bdca5cde4a5c10710d02dbaa904c62cd77b0b4562b8bf4d73c675f50bdb587` | Link VA = decoded offset + `0xc0008000` |
| `/usr/lib/libmulticore-bridge.so` | `f14a12e4d9172989d73c8dff0fd59580c65ccd1972264c9d94c8d1a736820390` | Original ELF VA, independently mapped through PT_LOAD |
| `/usr/lib/libudd5.so` | `8c56bea30a591fbfb8e9e86c237504f5e28f464f74c18cffc8bbaa7f717b0ea1` | Original ELF VA |
| `/usr/lib/libcapture-fw-prod.so` | `a07867292610ac6376e29e3cd64bc79a274452412387fb7853c5a3fb3f96bba5` | Original ELF VA |

These are static link addresses, not measured runtime mappings. DSO Ghidra
addresses add `0x10000`; file offsets use each ELF's PT_LOAD mapping. Do not apply
one library's offset delta to another. Kernel and RTOS evidence are separate
from ELF inventory coverage.

Evidence: [RTOS bytes](../evidence/rtos-transport-run006.json),
[kernel prefix](../evidence/kernel-prefix-run006.json),
[userspace bytes/C/relocations](../evidence/app-error-consumers-run006.json).
The primary agent reproduced the RTOS extractor byte-for-byte and validated all
selected source windows. Independent RUN006 semantic review remains incomplete
because its agent returned an actual usage-limit error.

## Observer and packet construction

Section `0x58110` initializes the observer; `0x5821c` registers object `+8` for
event `0x01010006`, through `0x5f350` and `0x96340`. The adapter constructor at
`0x59940` installs the vtable at inferred VA `0x8056de04`. Slot `+8` names thunk
`0x80058efc`, which adjusts the object by minus 8 and reaches `0x58828` via
`0x58ef8`. This binds the local publisher route from RUN005 to a concrete sender.

The event branch at `0x589c4` reaches `0x58afc`, selecting notification halfword
`0x020a`, zero payload length and null payload. The common path at `0x5892c`
supplies category `0x82` to `0x5e1b4` and sender `0x5e824`.
Builder `0x5e650` and copy helper `0xe738c` construct the eight inner bytes below.
The zeroed allocation supplies the final two zero bytes; this is not an assumed
captured packet.

| Layer | Conditional bytes, little endian | Meaning on this path |
|---|---|---|
| Inner packet | `82 00 0a 02 00 00 00 00` | Category `0x82`; notification `0x020a`; length 0; zero tail |
| Ring prefix | `ff 7f 0a 00 00 03` | Four-byte prefix followed by channel framing bytes `00 03` |
| Complete ring record | `ff 7f 0a 00 00 03 82 00 0a 02 00 00 00 00` | 14 bytes |
| Destination after kernel reads | `00 03 82 00 0a 02 00 00 00 00` | 10 bytes; category at `+2`, notification at `+4` |

`0xe7158 → 0x5d740 → 0x4cf338 → 0x37ac8` sends on API channel 3;
`0x379f4` maps that to internal channel 2. The ring writer stores its write index
at `0x37c4c`, before invoking the hook at `0x37c68`. Initialization `0x36eac`
passes function table `0x8056aae0` to `0x37398`; slot `+0xc` binds `0x800383bc`.
That function writes bit `1 << 2` to the code-selected address `0x06001000`.
This identifies a signal submission, without inferring hardware acknowledgement,
cache visibility or ownership from an MMIO store.

Allocation failure, gate, capacity, queue/retry and ring-wrap branches remain in
the evidence. The reconstructed record describes the reviewed normal contiguous
submission path conditional on their success.

## Kernel removes four bytes by overwriting the same destination

The recovered kernel symbol `_ipcc_read_srj` at `0xc02cedc0` saves the supplied
destination and requested length. Its first ring-reader call at `0xc02cedd4`
requests four bytes into that destination. The normal nonempty ring reader
(`0xc02ced00..0xc02cedc0`) copies bytes and advances the shared read index by the
requested count modulo ring size. A second call at `0xc02cedfc` requests the
payload count into the **same** destination, overwriting the four prefix bytes.

For the record above, the second read therefore starts at record offset 4 and
delivers the ten-byte row in the table. Prefix checking is not a strict validation
claim: the first-byte equal branch can bypass the second-byte test. Empty,
partial and malformed ring cases are not generalized from this normal path.

## Userspace preserves the destination through dispatch

`libmulticore-bridge` receiver `0x6994` obtains size L and, while L is at least 8,
calls receiver `0x6940` with `L-8`. The integer `CFrame` constructor is **`0x5e50`**;
`0x5c14` is the separate default constructor. The integer constructor requests
`L-8+12` bytes from `allocateBuffer` (`0x5c68`), which stores requested size minus
4, hence L, and aligns the allocation pointer. Alignment is not another prefix
removal.

`CFrame::Receive` (`0x5ccc`) passes that buffer and L to driver `0x5158`, which
calls `libudd5` `ipcc_read_pkt` (`0x46168`), using ioctl `0xc0107406`. On successful
receive, `category` (`0x5ea4`) reads buffer halfword `+2`; `Handle` (`0x5eac`)
broadcasts the **same pointer** and length `L-10`. Thus L=10 gives category
`0x82`, unchanged packet origin, and a zero supplied payload length.

In libcapture, `subscribeToMCB` (`0x85688`) concretely registers category `0x82`
with `OnReceiveEvent` (`0x8390c`). This reaches `OnReceived` (`0x83950`) and holder
`Run` (`0x8e23c`) with the same packet pointer and supplied length. `toTableID`
(`0x8e2f8`) maps `0x82` to slot 2; holder constructor `0x8dfa4` installs a
`CNotifyHandler` in that slot. Its constructor `0x8a524` loads GOT slot `0xb1590`
for vtable symbol `0xb02b8`, then adds 8. The `R_ARM_ABS32` relocation at
`0xb02c8` binds virtual slot `+8` to `CNotifyHandler::Run` (`0x8a628`). The original
vtable bytes contain zero placeholders; relocation interpretation is necessary.

The [RUN004 parser proof](CAPTURE_COMPLETION_RUN004.md) then applies: packet
halfword `+4 == 0x020a` selects still index 10, `onNextShotReady` (`0x8b93c`),
which requires supplied length zero and publishes internal `0x01010006`,
converted to API `0x02010006`. This is a readiness notification. Still write-done
`0x0207` is a different handler and does not inspect a filesystem close result.

## Reproduction and remaining boundaries

```sh
PYTHONPATH=.work/python python tools/firmware/rtos_transport.py \
  --bin .work/full/NX500.bin --manifest manifests/full-source-layout.json \
  --output analysis/evidence/rtos-transport-run006.json
PYTHONPATH=.work/python python tools/firmware/app_error_consumers_evidence.py
PYTHONPATH=.work/python python tools/firmware/verify_run006_evidence.py
```

The RTOS proof has 33 code windows, 1,420 instruction rows, eight data-only
blocks, and 106 aligned branch-encoding candidates. Candidates are not exhaustive
callers. Kernel prefix evidence has 83 instruction rows in two regions.
Active kernel selection, live ring visibility, ordering between cores, event
delivery and acknowledgement need separate evidence. No camera access, target
execution or installation was performed.
