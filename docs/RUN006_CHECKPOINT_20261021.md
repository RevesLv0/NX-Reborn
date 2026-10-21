# RUN006 checkpoint — paused for remaining usage

Historical checkpoint. Work resumed after the user clarified that a remaining
percentage was not a stop instruction. See `STATUS_20261022_RUN006.md` for the
subsequent primary-agent validation and actual sub-agent quota failures. The
counts and incomplete artifacts described below are checkpoint-time facts.

2026-10-21 KST. The user reported 3% usage remaining and requested a smaller
finishing scope, not immediate abandonment. Four sub-agents were interrupted to
conserve usage; the primary agent then completed the remaining kernel prefix
boundary below. This is a budget-bounded checkpoint, not a final RUN006 report.
Last published and CI-verified baseline: commit
`29234d7e510774a6aeac647160424e4378d1ffa0`, PR #1. Its counts remain 288 selected
completed functions / 49 reviewed ELF findings. RUN006 has not been added to them.

## Saved work and model requests

| Agent | Requested model / effort | Role |
|---|---|---|
| storage_errors_run006 | gpt-6-astra / high | Async storage errors, cancellation, queue ownership |
| app_error_consumers_run006 | gpt-6.1-sol / high | Wi-Fi/BT consumers, camera callback ingress, Linux bridge |
| rtos_transport_run006 | gpt-6-astra / high | RTOS observer, frame building, ring/MMIO transport |
| review_run006 | gpt-6.1-sol / high | Independent original-byte and interpretation review |

All used explicit requested settings and fork_turns=none. Independent runtime
model IDs are not exposed. Cumulative distinct agents: 24. Status: interrupted
for usage limit. Primary agent additionally followed smart-wifi/RVF outcomes.

All 17 discovered RUN006 Ghidra receipts are completed/return0; no project lock
remained at checkpoint. Exports still require final cumulative validation and
deduplication. No camera access, target execution or installation occurred.

## In-progress findings — final review still required

- Storage: conditional sync() also occurs in capture SIFListener case3 when its
  normal pending count decrements to zero, and in writeChunks' chunked loop under
  a memory-manager mode condition. RUN005's separate case4 sync description was
  incomplete; do not generalize it into no capture sync. Sync is not a checked
  per-file close-result or observed durability acknowledgement.
- writeChunks returns1 on cancellation state2 as well as its ordinary completion
  path; error/skip and callback meanings must stay distinct. Storage-condition API
  0x2f868 forwards0..3 into setCaptureException; condition2 sets worker skip.
  State API0x300b8 is logging-only in the inspected body. Follow remaining external
  async-error sources and queue mutation/ownership before any global bug claim.
- App raw mm-camera id0x3a converts to UI0x39. The literal name is
  CB_STL_SKIP_FILE_WRITE; idle trampoline0x21b868 reaches dispatcher0x218920 and
  File_Write_Done. It is an explicit skipped-write accounting entry.
- UI_WiFi_RVF_Shot_Result0x184c3c discards converted status; gated event1/non-null
  JPG path reaches DlnaRVFEvent(0x24,path). Root's fresh API decompilation
  (libdi-network-dlna-api originalVA0x110a0) routes case0x24 to imported
  RVFAppSendShotResultURLEvent and returns1 without checking its result. BT has
  separate queued path/metadata guards; downstream review is incomplete.
- RTOS observer registration: section0x58110/0x5821c subscribes object+8 to
  event0x01010006; vtable at inferredVA0x8056de04 slot+8 reaches thunk0x58efc
  (subtract8), then0x58ef8->0x58828. Event becomes ushort0x020a.
- Packet builder makes inner8 bytes 82 00 0a 02 00 00 00 00. Outer builder
  section0x37ac8 adds ff 7f 0a 00 00 03; ring write-index store0x37c4c precedes
  hook call0x37c68. Hook table0x8056aae0 slot+0xc points0x800383bc; code writes
  channel bit4 to address0x06001000. These are conditional static paths.
- Linux libcapture preserves incoming pointers through OnReceiveEvent0x8390c,
  OnReceived0x83950 and CCategoryHandleHolder::Run0x8e23c. libmulticore CFrame
  Receive0x5ccc -> CIPCCDriverIf Receive0x5158 -> libudd5 ipcc_read_pkt0x46168 ->
  ioctl0xc0107406. CFrame Handle0x5eac broadcasts the same pointer. Category
  getter0x5ea4 reads buffer+2; expected notify payload length is L-10. Exact
  prefix stripping must still be proved in the kernel, not assumed in userspace.
- Root smart-wifi state dispatch0x406c8 calls current-state vtable+8. Smartphone
  state's type0x13 branch is empty; inspected state+0xac stores set1. A bounded
  aligned scan is only candidate discovery, not global proof of absent writers.

## Finishing scope completed: packaged kernel prefix boundary

`analysis/evidence/kernel-prefix-run006.json` records original instructions from
hash-verified kernel2 at VA0xc02ced00..0xc02cee4c. `_ipcc_read_srj` first calls the
ring reader with length4 into the supplied destination, then calls that same
reader with the requested payload length and the SAME destination. On its normal
nonempty-ring path, the reader copies bytes and advances the shared read index
by the requested length modulo ring size. Thus the second read overwrites the
four-byte prefix and exposes the next bytes. For the RTOS frame reported above,
the delivered ten bytes are `00 03 82 00 0a 02 00 00 00 00`: category at+2 is
0x82, notification halfword+4 is0x020a, length halfword+6 is0. This supplies the
missing static pointer-origin correspondence to the userspace receiver.

The prefix condition is not a strict two-byte validation claim: its first-byte
equal branch can bypass the second-byte test. Only the normal framing path is
used here. Active boot selection, runtime ring visibility and acknowledgement
remain unverified. The broader agent artifacts still need final report/review.

## Highest-priority resumption

1. Independently review the newly completed kernel prefix evidence together with
   the agent's RTOS frame and userspace receive chain. Reuse
   `.work/run004/kernel/kernel-2-symbols.json` and KERNEL_HANDLERS_RUN004.md.
2. Complete independent review of storage sync/cancel paths, app registrations,
   Wi-Fi/BT downstream consumers and new RTOS evidence. Keep runtime/boot-role/
   queue concurrency/durability limits explicit.
3. Produce the unfinished RUN006 reports/manifests, validate all exports and
   update progress only after successful evidence association/deduplication.
   Preserve the eleven historical RUN004 exclusions.
4. Archive complete verified results and push the existing research branch under
   the user's standing authorization; update existing PR, keep draft/no merge.

Working directories: `.work/run006/storage`, `app-*`, `transfer`, and `rtos`.
Two new extractors and selected evidence exist in tools/firmware and
analysis/evidence. No RUN006 final architecture reports existed at interruption.
Restore prior source/tools from RUN002/RUN005 documentation; do not execute targets.
Intermediate research results should remain progress reports, not repeated requests
for the user to type 'continue'. The finishing scope was reduced due to usage.
