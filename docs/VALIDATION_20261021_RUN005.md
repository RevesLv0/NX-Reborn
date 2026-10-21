# RUN005 validation — 2026-10-21 KST

**64 host fixture tests pass**, together with Python compileall and whitespace
checks. The work is offline source analysis; no target program, camera I/O or
firmware installation was performed. Source/extraction limitations remain those
of RUN002, including original opt xattr refcount and inherited outer-ZIP hash.

- Independent source-byte review covers **57 bounded windows / 1,435 instruction
  rows**: app 14/436, storage 35/770, RTOS 8/229. Complete original BIN/ELF hashes,
  original PT_LOAD mappings and section/BIN offsets match verified source inputs.
- App evidence includes the actual callback registration arguments, one imported
  relocation, twelve conversion table entries/return blocks, the second dispatch
  entry and error/counter/BT branches. Storage evidence includes seventeen
  relocations, four original literal/GOT calculations and concrete callback stores,
  copies and calls. RTOS evidence includes 31 literal words and string references.
- All **41 new schema-v2 export generations** validate by source identity, run ID,
  artifact SHA/length and row counts. All seven runner receipts completed with
  return zero. Selected decompilation attempts are **47/47 completed**; there are
  no new Ghidra failures, analyzer runs, imports or selection-budget omissions.
- The ledger deduplicates cumulative results to **288 completed selected functions**,
  **49 reviewed ELF findings** and **203 valid generations**, across the same
  41 loaded/exported ELF contents. Fourteen new ELF findings pass the evidence-path/
  SHA/location schema. Two raw RTOS findings are separate from the ELF denominator.
  Only eleven historical RUN004 incomplete-capture exclusions remain.

Review corrections stopped app disassembly before a jump table, replaced an
incorrect identical-VA/file-offset sentence with actual PT_LOAD offsets, and
clipped four storage windows before known literal pools/next-function data.
These corrections preserve the bounded callback/status conclusions and make
the evidence's decode extent explicit. A mistargeted standalone export-validator
invocation was corrected to the eight program subdirectories; it did not affect
the completed Ghidra runs. Both invocation history and corrected results remain.

Selected C is an interpretation, not recovered source or verified runtime ABI.
Callback replacement, queue concurrency/global mutations, asynchronous errors,
transport framing/acknowledgement and storage durability remain unproven. A
separate listener case calls `sync()`; no blanket no-synchronization claim is made.

See `INDEPENDENT_REVIEW_RUN005.md` for the full bounded review and
`SUBAGENT_USAGE_20261021.md` for roles and explicitly requested models. Full logs,
exports and unlocked snapshots are preserved as versioned Drive artifacts after
upload. Archive SHA-256 and ZIP CRC are verified again by full remote readback;
the final Drive artifact ledger records the actual verification results.
