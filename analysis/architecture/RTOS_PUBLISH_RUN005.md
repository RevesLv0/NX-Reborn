# RTOS readiness publication and local observer dispatch — RUN005

Newly reproduced bounded offline evidence follows the RUN004 readiness producer
through a named publication routine into local virtual callbacks. It does not yet
join an exact RTOS transport frame to Linux's `0x020a` notification header.

## Source and reproduction

Input `.work/full/NX500.bin`, 352,121,435 bytes, SHA-256
`f4c238e811970cf858b5d734119477ea191d35cd29d9f84b584157ecfc4ee997`.
Section 5 starts at BIN `0xef4301`, contains 12,075,648 bytes, and has SHA-256
`f8e417cb5b55768851ba7e2b8017d3a98dc0b0c8444cc0a5061265cc08dbbf7f`.
The extractor verifies the full BIN and all ten section hashes before inspection.

Addresses below are section-relative offsets. Exact BIN offset is
`0xef4301 + section offset`; inferred link VA is `0x80000000 + section offset`.
The inferred base is inherited from RUN003 VBAR/string-pointer evidence and is
not a runtime measurement. The named addresses identify code by original
PC-relative diagnostic-string references, not a recovered symbol table.

```sh
PYTHONPATH=.work/python python tools/firmware/rtos_publish.py \
  --bin .work/full/NX500.bin --manifest manifests/full-source-layout.json \
  --output analysis/evidence/rtos-publish-run005.json
```

Eight windows contain 229 instruction records, with exact bytes, hashes, address
mapping and literal/string references in the selected evidence. Each window
decodes its full requested length. Literal pools after the selected code endings
are data; they are not presented as executable instructions. No Ghidra import,
decompilation or target execution was used for this raw-image followup.

## A flag write precedes a local publication request

The RUN004 `NotifyNextShotReady`-associated routine at `0x6144c` still sets the
preference byte to one through `0xc8430` at callsite `0x61484`. Following its
object-initialization branch, it supplies `r1 = 0x01010006`, preserves its incoming
second argument in `r2`, and tail-branches to `0x602ac` at `0x614b0`.
This is local instruction order; initialization, visibility and actual delivery
are not observed. No write/close result is checked in these selected operations.

## The named Publish routine has a context-related gate and chooses a list

At `0x602ac`, incoming object, event and parameter are preserved in `r6`, `r4`
and `r5`. Original PC-relative loads reference `Publish` and
`product/CaptureInterface/Publisher/CapturePublisher.cpp`. A helper call at
`0x60300` targets `0x45fb8`; `CMP r0,#0; BLE 0x60380` returns before the
observed dispatch route when its result is nonpositive. The helper has a
`_fx_thread_current_id` diagnostic reference. This establishes the branch and
the name association, not a complete thread-context contract.

Three special event comparisons (`0x01040001`, `0x01040002`, `0x01040006`)
lead to additional diagnostic paths. The readiness event does not match them.
The ordinary path calls `0xcbf14` with the event at `0x60340`; that helper's
effects remain unexpanded here. `UBFX` at `0x60344` then selects bits 16..23.
Group 7 uses the object at publisher `+0x24`; other groups use publisher `+4`.
Readiness `0x01010006` therefore selects `+4` on this path. Both routes preserve
the original event and parameter and tail-branch to `0x96574`.

## Local subscriber matching precedes a virtual callback

The routine at `0x96574` has literal references to
`CCallbackRegister::Dispatch(%x, %d)` diagnostics. Its inspected normal path
walks four-byte entries between object fields `+4` and `+8`. A nonnull entry
matches when its first word equals the supplied event or is `0xffffffff`.
Matching entries are gathered into a second list using fields `+0x10`, `+0x14`
and `+0x18`; a full-list branch calls `0x4fe334` at `0x967a4`.
These offsets and pointer arithmetic are concrete; exact source container types
and allocation behavior are not recovered.

For each selected record, `0x96638` loads an observer pointer from record `+4`.
The nonnull observer's first word supplies a vtable; `0x9664c` loads slot `+8`.
At `0x96654`, `BLX r3` is called with observer in `r0`, original event in `r1`
and original parameter in `r2`. Its return in `r0` is not tested before the
list loop continues. The list cursor is reset and the exit helper is called
before the inspected return. The empty-list route also calls that exit helper.

The entry/exit wrappers at `0x95848` and `0x95864` reference diagnostic names
`enterCriticalSection` and `exitCriticalSection` and pass object `+0x1c` to their
respective helpers. Their implementation and synchronization guarantees remain
unreviewed. Null-record/error paths, indirect targets and callbacks that do not
return normally are outside this selected normal-path interpretation.

## Completion boundary

This supplies a concrete local path from the readiness-named producer into a
matching observer's virtual call. It is not a delivery acknowledgement: the
callback return is untested on the inspected loop, and no exact transport packet
serialization is identified here. A subscriber may implement the missing bridge,
so the absence of serialization in these selected windows does not exclude one.
The next raw-image target is the concrete observer registration/vtable binding
and its transport implementation. Linux event-ID conversion and header dispatch
remain separate evidence until that link is established. No storage durability,
camera-wide quiescence or safe capture/transfer coexistence follows.
