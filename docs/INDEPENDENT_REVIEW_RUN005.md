# Independent RUN005 review

Bounded offline static review of storage callback/error-queue, app conversion, and raw RTOS publication. No Ghidra database access or mutation, extracted target execution, camera/device I/O, commits, push, or upload.

## Inputs and inherited boundary

Read repository AGENTS.md and analysis/architecture/CAPTURE_COMPLETION_RUN004.md. Original firmware SHA-256 independently recomputed as f4c238e811970cf858b5d734119477ea191d35cd29d9f84b584157ecfc4ee997. RUN004 separates next-shot admission, worker callback, write result, and close/durability; those distinctions remain applicable.

## RTOS evidence checks

- Re-executed rtos_publish.py with original BIN and full-source-layout.json to .work/run005/review/rtos-publish-regenerated.json; result byte-for-byte JSON equal to tracked evidence.
- Independently read original BIN, checked all 8 region byte strings and hashes, reconstructed Capstone ARM rows, and checked all 229 instruction addresses/bytes/mnemonics/operands/file offsets.
- Checked all 31 recorded literal words directly in original BIN and all associated ASCII pointer targets.
- Selected section 5 SHA-256 is f8e417cb5b55768851ba7e2b8017d3a98dc0b0c8444cc0a5061265cc08dbbf7f, origin 0xef4301.
- Existing test_rtos_readiness.py: 3/3 fixtures pass.
- Static interpretation confirmed: 0x80061484 calls flag setter with one; event argument 0x01010006 and saved second argument flow to 0x800602ac. Gate at 0x80060308 branches around dispatch for a nonpositive helper result. Normal route adds publisher +4 (event byte 16..23 is one, not seven), tail-branches to 0x80096574, matches subscriber record +0, loads client +4, then calls vtable +8 with (client,event,param). Concrete virtual target is unresolved.
- Publication helper names and local register arguments do not prove a serialized wire frame, Linux receiver correspondence, delivery, or acknowledgment. Helper names enterCriticalSection/exitCriticalSection alone do not establish concurrency semantics.

## RTOS report and manifest

Reviewed final RTOS_PUBLISH_RUN005.md and rtos-publish-run005.json. All 3 artifact byte lengths and hashes pass. Selector byte, special events, exact/wildcard matching, subscriber +4 and vtable +8 argument path, discarded callback return, and entry/exit helper wording are supported by the bounded bytes. No correction requested. Raw findings are correctly separate from ELF coverage.

## ELF source and evidence checks

Original libsif, libmm-photo, and app full-file SHA-256 recomputations match the original filesystem inventory, including source/inode byte-match fields. App evidence regenerates identically after correction (SHA-256 0a38c982459903ce89548127c773f1706066ad8ec8a1c0eca8410b006350c2f5); storage evidence regenerates identically after correction (SHA-256 19acdfc6b2373dc34cdad7fdbc997a9af5124bd16643bf4400063536dbe98d45).

- Independently recomputed original ELF PT_LOAD file offsets and original Capstone rows for app 14 windows / 436 instructions and storage 35 windows / 770 instructions. All final windows fully decode requested lengths.
- Independently checked all emitted ELF relocation records: app 1, storage 17. Checked all four storage PC/literal/GOT arithmetic proofs against original words and their target relocations.
- Checked all twelve app conversion jump-table words and two-instruction return blocks; mappings 1..12 remain identity and unsigned out-of-range/default returns zero. Checked second-entry table index 0x39-1, raw destination 0x21b000, and its actual BL to 0x217cac.
- Reviewed original callback-store/copy/call instruction sequences: Notify type2 stores callback/parameters +0x24/+0x28/+0x2c; SaveExifImage and worker carry parameters to buffer +0x10/+0x14 and JpegDoneEx to sFileOp +0x10; worker callback uses (buffer,0,0); JpegDoneEx reloads two buffer words and calls current singleton callback. Both static binding and dynamic replacement caveat are supported.
- Reviewed normal queued zero before SaveExifImage, separate exception argument queue push, exception SIFListener(3,1,0), case3 idle scheduling, and captureSaveDone queued status/default consumption. Worker zero arguments are notification arguments, not a write result.
- App register r0-r3 path, spurious fifth Ghidra argument warning, dropped helper argument warning, status routing1..6, error latch/decrement ordering, UI-error mappings, and separate BT gates are accurately bounded.
- Read status numeric producer table against selected C and original byte windows: 0/1/2/5/6/8/12 are supported as stated. No unverified full enum or global queue mutation claim is made.
- Report correctly preserves separate SIFListener case4 sync() route and limits the no-write-result result to capture case3 chain.

## Corrections completed by owners

1. App counter entry requested160 bytes but linear decode stopped at88 before table data. Owner bounded it to88 and added decoded/undecoded fields plus linear-disassembly caveat. Final windows fully decode.
2. Storage report incorrectly said code VAs had identical file offsets. Owner replaced this with explicit PT_LOAD mappings, including 0x7cef0 -> file0x74ef0.
3. Four storage windows contained known post-return literal pools (and one next-function prefix) rendered as ARM rows. Owner clipped JpegDoneEx, destructor, status helper, and exception tail before those pools and added bounded linear-disassembly caveats. Actual sFileOp exception landing-pad instructions were retained.

## Manifest, export, and integration checks

Final app/storage/RTOS manifest artifact sizes/hashes all pass (3 artifacts each). All14 new ELF reviewed findings have actual evidence paths/hashes and required id/source SHA/location/method/limitations/unresolved-question fields; two raw RTOS findings remain separate from ELF denominator. App source inventory and paired-input manifest hashes pass.

Independently revalidated all41 final RUN005 schema-v2 export summaries/artifact row counts/identities with validate_export; 47/47 selected attempts completed. Saved results under .work/run005/review/exports-validated.json. Existing export validator fixtures pass5/5 in addition to readiness fixtures3/3. No new tests added for prose.

Read docs/STATUS_20261021_RUN005.md and docs/RUN005_REPRODUCTION.md. Status separates queued result and worker notification without asserting global false success; count zero is correctly insufficient to certify saving. Root was reminded that archive-completed wording requires actual upload/archive receipt; root owns packaging/upload scope.

## Verdict and limits

No unresolved substantive correction in the reviewed source-backed app/storage/RTOS reports. This is a bounded static review, not whole-feature validation, execution trace, queue concurrency proof, successful close/durability observation, transport-frame recovery, acknowledgment, or safe capture/transfer coexistence proof. Global/indirect queue mutations, asynchronous failures, callback replacement, concrete RTOS observer binding, and remote consumer semantics remain open. Did not touch Ghidra DBs or shared root documentation.
