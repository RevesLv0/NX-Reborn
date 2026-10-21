# RUN004 validation — 2026-10-21 KST

**64 host fixture tests pass**, along with Python compileall and whitespace checks.
No target executable was run, and no camera/device I/O or firmware installation
occurred. Source extraction and read-only filesystem limitations remain those of
RUN002, including the original opt xattr reference-count discrepancy.

- Six kernel fixtures reject malformed counts, address arrays, markers, names,
  tokens, token indexes, mapping strings and input identities. The actual section-2
  table was independently recovered again: 37,167 entries and 4,795 matching
  export-name anchors, zero mismatches. Negative results in sections 0/3 are
  restricted to the documented layout/search profile.
- Three RTOS fixtures exercise signed ARM branch offsets, BLX exclusion,
  MOVW/MOVT halves, data-versus-code candidates and the unaligned BIN origin.
  The independent reviewer checked all sixteen selected region byte strings and
  hashes. A helper's equality predicate was initially described as inequality;
  the report and manifest were corrected. Setter call arguments remain unchanged.
- Capture review checks thirteen staged/source pairs, 2,152 retained original
  instruction rows, six complete explicit windows and 26 selected-C hashes.
  Transfer review checks 332 original instruction rows, 29 relocation words and
  eighteen selected-C hashes. Original PT_LOAD mappings, GOT/vtable calculations
  and source identities are distinct from inferred C types or runtime binding.
- Progress generation validates artifact hashes, run IDs, row counts and receipts,
  then deduplicates source SHA and original ELF VA. It reports 162 valid export
  generations, 257 distinct completed selected functions and 35 bounded reviewed
  ELF findings. Four RTOS and three raw-kernel reviewed findings are outside that
  ELF denominator. No semantic completion percentage is assigned.

An initial capture pass exported eleven programs but the runner expected thirteen,
so post-export association raised a missing-summary error. Its incomplete receipt,
original staged identities and eleven excluded generation records are retained.
A later eleven-input SURVEY pass and separate two-input photo passes succeeded.
Independent artifact validation of the first outputs does not turn its receipt
into a successful run. Selection-budget omissions in transfer passes are preserved.

The final fixture-log capture first omitted the documented `PYTHONPATH=.work/python`
setting and failed on missing pyelftools/Capstone dependencies. That invocation's
log is preserved; rerunning with the prescribed environment passed all 64 tests.
This was a host invocation error, not a target-program test failure.

Integration also corrected the capture review-ledger schema: finding prose belongs
in `claim`; `evidence` points to an existing file with a matching SHA, and questions
are arrays. Regeneration accepts all eleven new ELF findings. The only remaining
ledger validation exclusions are the eleven historical incomplete-capture outputs.

See `INDEPENDENT_REVIEW_RUN004.md` for the bounded review. Full logs, original
failed histories, catalogs, exports and unlocked database snapshots are preserved
in the versioned RUN004 Drive bundles. Each archive is checked locally, then fully
downloaded again to verify SHA-256 and ZIP CRC; the artifact ledger records actual
verification results after upload. Existing Drive files are preserved.
