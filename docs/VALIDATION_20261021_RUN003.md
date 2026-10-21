# RUN003 validation — 2026-10-21 KST

**55 host fixture tests passed**, Python compileall passed, and whitespace checks
passed. Actual firmware bytes were parsed or inspected; no target executable was
run and no camera I/O or firmware installation occurred.

- Source identity: every survey input matches the previously read-back original
  rootfs inode SHA. The symbol catalog newly checks all 1,895 unique ELF contents
  before parsing; zero parse/hash errors.
- Symbol fixtures: versioned definitions and required provider names, local versus
  undefined/dynamic symbols, SHA aliases, same-size source replacement, symlink
  rejection and stale completed-output invalidation.
- Progress fixtures: artifact/run-ID/hash mismatches, failed or incomplete receipts,
  source/input identity, duplicate generations and SHA/VA aliases, noanalysis versus
  import/analysis, timeout history and explicit reviewed-evidence fingerprints.
- Boot fixtures: whole input and bounds rejection, unaligned BIN string offsets,
  ARM literal pointers and Thumb PC alignment/addressing. Decoded kernel bytes are
  rechecked against exact source-section gzip streams.
- Ghidra: 20 new imports and all completed followup export generations validated
  by input SHA, run ID, artifact byte count/SHA and record counts. New automatic
  passes report no analyzer timeout. The original JPEG timeout and later response
  buffer failure remain historical failures despite the final successful retry.
- Ledger: 105 valid export generations, 41 distinct ELF contents with validated
  loaded-program exports, 46,539 mapped function locations and 183 unique selected
  functions with at least one completed decompilation. The failed historical run
  receipt is retained separately; no active/incomplete receipt or export validation
  error remains at final generation time.
- Explicit reviews: 24 bounded claims across 15 primary source ELFs. Direct
  Capstone review of systemd does not require a Ghidra import. No reviewed-function
  or whole-feature completion denominator is inferred.

An independent review agent reproduced the ledger and checked 2,427 selected
instruction-byte records against original BIN/ELF inputs without mismatch. Review
corrections addressed signed packet-length comparison wording, updater callsite
addresses, a bootloader callsite label, stale symbol refresh output and the JPEG
recovered-body limitation. These corrections are reflected in the final evidence.

The JPEG result has 28,272 recovered Ghidra body address bytes versus the ELF's
32,476-byte symbol; the difference is unreconciled. Successful decompilation is
not proof of complete function recovery, inferred types or ABI correctness.
Ghidra language selection is not a CPU measurement. Static pointer/address and
configuration results do not establish runtime mounts, core state, completion
acknowledgements or release of all hardware resources.

Full test logs, original run logs and validated snapshots are archived in the
RUN003 Drive bundles. Archives are created only after Ghidra locks disappear.
The source/fsck limitations from RUN002, including the original opt xattr reference
count discrepancy and skipped read-only journal recovery, remain unchanged.
