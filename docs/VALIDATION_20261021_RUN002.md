# Run002 validation — 2026-10-21 KST

Host checks: **36 tests passed**, Python compileall passed, Git whitespace check passed.
Tests cover corrupted/reordered reconstruction inputs, section CRC/hash checks,
LZOP checksum/truncation/trailer handling, pre-existing partial files, native
directory/stat parsing, source/host same-size byte and symlink mutations, symlink
cycles, ordered dependency candidates and kernel header/data CRC corruption.

The tests use synthetic fixtures, not camera code. Full firmware validation was
also performed against newly downloaded real source bytes:

- All four archive/split-file sizes and SHA-256s match inherited source manifests.
- Full BIN and all ten sections match expected SHA-256/CRC values.
- All three LZOP streams match expected decoded size/SHA and exact stream consumption.
- Native reachable source directory enumeration is complete for both images;
  12 character devices are metadata-only on the host.
- All 14,760 ordinary file paths match independent source inode dump hashes;
  all 1,064 symlink targets match source metadata. Hardlink/source inode counts
  are distinguished from rdump host inodes.
- Source-tree JSON hashes chain into the full inventory receipt; inventory errors are zero.
- Read-only fsck returned rootfs 0 and opt 4; the recorded original opt xattr
  inconsistency and skipped journal recovery remain unresolved. Before/after
  image hashes prove no repair/change was applied.
- Kernel sections 0/2/3 have valid uImage header/payload CRCs and complete embedded
  Linux gzip streams. Boot slot roles remain unknown.
- New Ghidra survey exports are validated by input SHA, run ID, artifact SHA/size
  and row counts; exact bounded followup/failure details are in the expanded
  survey report and archived run receipts.

A separate review agent examined reconstruction, bounds, source inode comparison,
path/link handling and dependency limitations and reported no material correctness
issue. Suggested parser/failure-path tests were added and included above.

Both source-inode dump and rdump use native debugfs 1.47.2. This is an independent
readback path, not a second independent filesystem implementation. The original
outer ZIP was not re-downloaded. No target executable, camera connection or
firmware installation was used in these checks. Static resolution and automated
analysis are not whole-firmware semantic or runtime validation.
