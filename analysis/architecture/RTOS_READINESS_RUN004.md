# T-Kernel next-shot readiness producer — RUN004

Recorded 2026-10-21 UTC. **Newly reproduced offline static evidence.** A concrete
T-Kernel-side setter writes the same numerical address requested by the Linux
readiness getter: `0x85401c4d`. This closes the missing **static producer path**;
it does not establish runtime memory ownership, message delivery, file durability,
or a complete capture-completion contract.

## Inputs, addresses and reproduction

Full input `.work/full/NX500.bin`, 352,121,435 bytes, SHA-256
`f4c238e811970cf858b5d734119477ea191d35cd29d9f84b584157ecfc4ee997`.
SLP section 5 starts at absolute BIN `0x00ef4301`, has 12,075,648 bytes and SHA-256
`f8e417cb5b55768851ba7e2b8017d3a98dc0b0c8444cc0a5061265cc08dbbf7f`.
The tool verifies the complete BIN and all ten source sections against
`manifests/full-source-layout.json` before choosing section 5.

All section offsets below index exact raw section bytes. Absolute BIN offset is
`0x00ef4301 + section offset`. Inferred link VA is `0x80000000 + section offset`;
the latter base is supported by RUN003's VBAR and banner-pointer evidence, and is
**not a measured runtime mapping**. `0x85401c4d` is an address constructed by the
code, not an offset into this 12 MB section or into the firmware BIN.

```sh
PYTHONPATH=.work/python python tools/firmware/rtos_readiness.py \
  --bin .work/full/NX500.bin --manifest manifests/full-source-layout.json \
  --output analysis/evidence/rtos-readiness-run004.json \
  --raw-output-dir .work/run004/rtos
PYTHONPATH=.work/python python -m unittest discover -s tests -p test_rtos_readiness.py -v
```

The source-backed [evidence](../evidence/rtos-readiness-run004.json) records exact
bytes, per-window hashes, bounded Capstone ARM listings, literal-pool values,
selected full printable strings and all encoding-scan candidates. The
[manifest](../../manifests/rtos-run004.json) pins tools, artifacts, commands,
verification results and limits. Three focused fixtures pass. Sixteen selected
windows decode their full requested byte lengths. No Ghidra import, automatic
analysis or decompilation was performed in this pass. No target code was executed;
there was no device I/O or flashing.

## 1. A named setter reaches an actual byte store

| Observation | Section offset | Absolute BIN offset | Inferred link VA |
|---|---:|---:|---:|
| Named setter entry | `0xc8430` | `0xfbc731` | `0x800c8430` |
| Supplies offset `0x1c4d` | `0xc8470` | `0xfbc771` | `0x800c8470` |
| Tail branch to generic writer | `0xc8480` | `0xfbc781` | `0x800c8480` |
| Generic writer entry | `0x4e2f48` | `0x13d7249` | `0x804e2f48` |
| Conditional `STRB` | `0x4e2f70` | `0x13d7271` | `0x804e2f70` |
| Selector `0xff` base construction | `0x4e2c14` | `0x13d6f15` | `0x804e2c14` |

The entry at section `0xc8430` preserves its argument in `r4`, constructs pointers
to `PrefRtos_SetNextShotReady` (string section `0x57b270`) and
`PrefRtos_SetNextShotReady(%d)` (`0x70914c`) with ARM `MOVW`/`MOVT`, and calls the
logging helper at section `0x46484`. Thus the name association is a code reference,
not merely a nearby string. After logging it sets `r0 = 0xff`, `r1 = 0x1c4d` and
`r2 = UXTB(r4)`, then tail-branches to section `0x4e2f48`.

The generic writer preserves offset and value in `r4`/`r5`, checks a global
initialization byte, optionally calls section `0x4e2c4c`, and calls section
`0x4e2ba4` with the selector. That selector's `0xff` path executes
`MOV r0,#0; MOVT r0,#0x8540; BX lr`, yielding `0x85400000`. Its other observed
nonzero results are selector 0 → `0x85480000`, 2 → `0x85500000`, 3 → `0x85580000`,
and 4 → `0x85600000`. These are code-selected bases, not a recovered ownership map.

After the selector call, `CMP r0,#0` guards `STRBNE r5,[r0,r4]`. On the named
setter's path this is a store of the supplied low byte to
`0x85400000 + 0x1c4d = 0x85401c4d`. The generic writer returns zero after a nonzero
base result and `-1` after a zero base result. No offset-length bounds check or
explicit memory-barrier instruction appears in this inspected writer body; that
does not exclude ordering supplied by other code or memory attributes. The named
setter truncates to eight bits; it does not itself normalize arbitrary inputs to
Boolean values.

The Linux consumer was independently recovered in RUN003 from
`/usr/lib/libuser-spec.so` SHA-256
`2d04ab487cc9980cb87e513b25ff09011839203756d28857eedfd50a9cc730ec`:
its `User_Spec_Get_Rtos_Pref_Next_Shot_Ready` requests one byte at offset `0x1c4d`
from a `/dev/mem` mapping requested at `0x85400000`, length `0x80000`.
The two sides therefore agree numerically. A shared runtime mapping and visibility
still require evidence beyond these static paths.

A neighboring T-Kernel getter at section `0xc8484` supplies the same selector and
offset to section `0x4e30d8`. Record the exact access width: section `0x4e30fc`
(BIN `0x13d73fd`, inferred VA `0x804e30fc`) uses `LDRNE r0,[r0,r4]`, followed by
`UXTBNE`, rather than `LDRB`. Its failure value is `0xff`. Alignment and memory
attribute behavior are runtime questions; no fault or correctness judgment follows.

## 2. Both one and zero writes occur in resource/notification paths

The whole-section aligned ARM B/BL candidate scan finds eight direct references
to the named setter. Each has a reviewed bounded instruction window. These counts
exclude indirect calls and Thumb calls and are not an exhaustive caller graph.

| Setter callsite, section | Absolute BIN | Supplied low byte | Inspected context |
|---|---:|---:|---|
| `0x61484` | `0xf55785` | 1 | Routine references `NotifyNextShotReady` and `%s is send next_shot_ready.` |
| `0x6151c` | `0xf5581d` | 0 | Following a call to `0xc7c28`, before another notification path |
| `0x73294` | `0xf67595` | 1 | Conditional raw-buffer check, with `checkRawBufferForNextShot fail[pp]` / `[nr]` diagnostics |
| `0x733ac` | `0xf676ad` | 0 | Recheck path; preserved earlier flag equals 1, but current `r0` is zero from `0xcada8` |
| `0xa3994` | `0xf97c95` | 1 | Tail branch after several unexpanded calls; surrounding operation is not assigned a completion meaning |
| `0xc9810` | `0xfbdb11` | 1 | One branch after helper `0x7302c` returns zero |
| `0xc9840` | `0xfbdb41` | 0 | Alternate branch after `0x7302c` returns nonzero |
| `0xc9864` | `0xfbdb65` | 0 | Branch after helper `0xcada8` returns zero |

In particular, the value at `0x733ac` is **zero**, despite `r4` preserving an
earlier result of one. The intervening call to section `0xcada8` supplies current
`r0`; its zero result is required to reach the setter. That helper reads object
words at offsets `0x38` and `0x3c` and uses subtract/negate/carry arithmetic to
return one when the words are equal and zero otherwise. This does not identify those fields as saved files.

The full source name
`static void CCaptureMemoryManagerNX::RecheckRawBufferForNextShot(long unsigned int)`
is referenced by the routine at section `0x732dc`, at instructions `0x73364` and
`0x73370`. One path tail-branches to section `0x6144c`, which sets the flag to one.
Another path conditionally clears it as described above. These associations support
resource/admission use of the readiness flag; they do not define the complete
capture state machine or establish that every diagnostic describes the checked
object accurately.

## 3. Setting the flag and publishing an event are separate operations

The `NotifyNextShotReady`-associated routine at section `0x6144c` writes one through
the setter at `0x61484`, then follows a lazy-object initialization branch and
supplies `r1 = 0x01010006`, the preserved second argument as `r2`, and an object
pointer to section `0x602ac` via a tail branch at `0x614b0`. The event identifier
and ordering of these local calls are concrete instruction observations.
The implementation of `0x602ac`, serialization, packet layout, receiving-side
processing and delivery result have not been traced in this raw-image pass.
The numeric identifier is not assigned to an RTOS wire packet merely because a
Linux callback uses a related value.

The inspected producer and callers supply no proven ordering from successful
storage write/close or durability acknowledgement to readiness. A recovered flag
writer is therefore insufficient to claim that ready means the image is saved,
that SD traffic has finished, or that capture and transfer safely coexist.

## Scan limits and false-positive control

Direct little-endian byte searches for `0x85400000`, `0x85401c4d` and `0x00001c4d`
return zero matches in section 5. Nevertheless the producer above exists: ARM
immediate construction and selector/offset calls conceal those complete constants.
A failed direct-constant search must not be interpreted as an absent producer.

The full 12,075,648-byte section was scanned at 4-byte section alignment for ARM
MOVW/MOVT halves, ARM B/BL targets, and selected immediate PC-relative word loads.
Results are six MOV-half candidates, 23 branch candidates to three selected entries,
and five selected literal-load candidates. These counts describe encoding matches,
not six established functions or a complete executable map. The code-like
`MOVTHS r0,#0x1c4d` match at section `0x96fac8` is retained as unvalidated; a high
half with that value alone is not the `0x1c4d` offset-setting path. No executable
status is assigned to that region.

Literal words at section `0x614f0` (`0x806f34e8`) and `0x614f8` (`0x8056e6b0`)
are proven data operands of nearby PC-relative loads and point to exact strings.
Their bytes are not presented as instructions. Selected code windows stop before
these pools. The source retains 88 full printable matches covering readiness,
raw-capture and file-save/write/close names. File-related string hits remain leads;
no file-save completion function was inferred from their presence. Full string
listings and derived raw input stay ignored under `.work/run004/rtos/`.

Whole-program control flow, indirect references, Thumb regions, relocation,
concurrent Linux writers, cacheability, synchronization, boot timing and runtime
shared-memory visibility remain unresolved. This is a bounded positive producer
result, not a complete RTOS image analysis.
