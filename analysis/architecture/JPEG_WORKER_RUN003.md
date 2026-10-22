# JPEG worker bounded readback — run003

`DscJPEG::taskMain` now has a completed selected decompilation. The inspected
implementation contains conditional EXIF/MPF file-handler and callback routes,
and explicit assertions for several other numeric message modes. These findings
concern one worker; they do not establish the complete capture/JPEG pipeline.

Source: original rootfs `/usr/lib/libsif.so`, SHA-256
`9790fc02fe5b9793fc09da7eb5fd9453c730a55880654c84caf02dd3d1001109`.
Function original ELF VA/file offset: `0x3649c`. All addresses below use this
source and original ELF VAs; the selected executable file offsets equal those
VAs as independently mapped through `PT_LOAD`. Raw Ghidra addresses add `0x10000`.
No extracted program was executed and no camera was accessed.

## Conditional EXIF and MPF dispatch

The decompiled loop dequeues a message, reads a callback from message `+0x18`,
and switches on the first message word. In case three, it constructs a new
`tImage_buffer`, invokes `ExifEncoder::execute` at `0x38dfc` (PLT `0xec68`),
assigns its chunk vector to the new buffer, and destroys the local encoder.
Only when message field `+4` equals zero does it invoke
`DscFileHandler::operate` at `0x38e48` (PLT `0xee90`).

Case seven follows the corresponding MPF route: `MpfEncoder::execute` at
`0x3c730` (PLT `0xea88`), vector assignment, encoder destruction, and the
same `message +4 == 0` predicate before `operate` at `0x3c77c`.
Independent Capstone instruction windows reproduce both execute calls and
conditional file-handler branches. The encoder and file-handler implementations
were not followed here, so their results, filesystem operations, and durability
are not established by these callsites. Numeric mode meanings and callers remain
unresolved; C types and object layouts are inferred.

## Optional callback paths

Both cases check worker field `+0x1c`. If non-null, they call
`DscJPEG::copyChunkData` (`0x38e80` / `0x3c7c4`) before indirect callback calls
at `0x38eb0` / `0x3c7f4`. This callback occurs after `operate` is invoked on the
zero-mode branch; it is also reachable when that branch is skipped. No wait or
file-handler acknowledgement is shown in this selected caller sequence.

A separate common tail checks the callback previously taken from message `+0x18`
and invokes it indirectly at `0x3e2b0`. These callback targets and their ABI have
not been resolved. The decompiled common argument `uVar5` has multiple reaching
assignments, including logging/cleanup results, so it is not treated as a verified
success-status field. Callback presence alone does not establish capture or file
completion.

## Assertions are specific to selected message cases

The following callsites pass case-specific strings to the `__assert_fail` PLT
at original ELF `0xde7c`. Capstone confirms the call instructions and argument
setup; independent PC-relative literal resolution confirms each exact string.

| Decompiled case | Assert callsite / file offset | Exact condition string |
|---|---|---|
| 0 | `0x38574` | `0 && "do not jpeg encode here"` |
| 1 | `0x37da0` | `0 && "do not jpeg decode here"` |
| 6 | `0x3a80c` | `0 && "do not srw decode here"` |

These branches do not show whether callers submit those modes. They do not mean
JPEG encoding or SRW decoding is disabled across the camera, and do not locate
where those operations actually run.

## Reproduction and preserved failures

The original run001 selected attempt failed with `process: timeout`. The run003
retry using a 60-second timeout failed with `Response buffer size exceeded`.
The later run003 retry kept 60 seconds and raised the Ghidra decompiler response
cap to 256MB; it completed with 77,092 C characters, 2,115 C lines, and 7,068
exported instructions. Both failed results remain in the evidence and manifest;
they were not overwritten or counted as completed decompilations.

This readback launched no further Ghidra run. The two existing-program retry
runs used `--process --skip-analysis` in `NX500_FW112`; their four schema-v2
exports passed hash/schema validation. Two repeated ELFs do not count as new
imports or additional inventory coverage. Completion of this one decompilation
is not semantic completion of this worker or any camera feature.

The recovered Ghidra function body covers 28,272 address bytes, whereas the ELF
symbol declares 32,476 bytes. The difference has not been reconciled: literal
pools, embedded data or unresolved control flow can affect those measures. A
successful decompiler result therefore does not prove complete function recovery.

[Selected evidence](../evidence/jpeg-worker-run003.json) retains eight bounded
Capstone windows, selected C excerpts and three exact literal checks, with
source/artifact hashes. [Manifest](../../manifests/ghidra-jpeg-run003.json)
records the run receipts, output hashes, both historical failures, and three
reviewed findings. Further work should identify message producers and callback
registrations, then inspect the encoder and file-handler implementations.
