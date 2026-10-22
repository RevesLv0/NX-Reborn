# RUN004 independent offline review

Reviewer scope: original-byte/address consistency and substantive claims in capture completion, transfer binding, raw-kernel handlers, RTOS readiness, and root status/reproduction documents. Read `AGENTS.md`. No target firmware/program execution, device I/O, commits, uploads, or edits to another contributor's files.

## Findings

1. **RTOS predicate polarity — corrected by owner.** In section 5, offsets `0xcada8`–`0xcadbc` (`.work/full/NX500.bin` SHA-256 `f4c238e811970cf858b5d734119477ea191d35cd29d9f84b584157ecfc4ee997`, section SHA-256 `f8e417cb5b55768851ba7e2b8017d3a98dc0b0c8444cc0a5061265cc08dbbf7f`), `SUBS r3,r2,r0; RSBS r0,r3,#0; ADCS r0,r0,r3` returns 1 when the two object words are equal, and 0 otherwise. The RTOS report initially said "differ". Owner corrected this and refreshed the manifest. The reviewed setter arguments at `0x733ac` and `0xc9864` remain correctly zero: control reaches each setter only when the helper's current return in `r0` is zero.

## Reproduced checks

- Six kernel-symbol synthetic fixtures and three RTOS encoding fixtures pass.
- Recovered kallsyms again directly from each hash-verified decoded kernel input. Sections 0/3 have no accepted table in the documented profile; section 2 has one 37,167-entry complete table and all 4,795 exact export-string anchors agree with base `0xc0008000`.
- Checked all 9,610 capture evidence instruction byte records against original source ELF bytes and independently mapped each function through original `PT_LOAD` segments. Source SHA-256 and symbol-size checks pass.
- Checked all selected kernel handler evidence instruction bytes and decoded offsets against `.work/full/kernel-2.raw` SHA-256 `25bdca5cde4a5c10710d02dbaa904c62cd77b0b4562b8bf4d73c675f50bdb587`.
- Checked RTOS full BIN SHA-256, section SHA-256, all 16 bounded region byte strings, and per-region SHA-256 values.
- Checked transfer evidence's 332 original instruction records, 29 relocation stored words, both complete source ELF hashes against extracted originals, and all 18 completed selected decompiler artifact hashes. PT_LOAD mappings pass.
- Checked all 11 nested path/hash records in the kernel manifest and four RTOS artifact hashes at review time.
- Rechecked final bounded capture evidence after its deliberate size reduction: all 2,152 retained instruction records match original ELF bytes and all six explicit later-call windows decode completely. Checked all 13 capture staged/extracted pairs, 26 completed selected-C export hashes, 11 resolvable final capture manifest hashes, 50 resolvable transfer manifest hashes and five updated RTOS manifest hashes. Firmware-internal absolute paths were resolved beneath the extracted rootfs, not treated as host executables.

## Claim review

- Kernel report correctly distinguishes link VA from compressed source offsets, section 2 from active boot role, operation result record `+8` (IPCC) / `+0xd0` (HEVC) from the ioctl's own copy-accounting return, and nested HEVC pointer `+0xac` from output fields. Its signed `BGE` partial-copy caution matches the original instructions.
- Transfer constructor/vtable/GOT registration is supported by direct stores, relocation records and decoded callback callsites, including manager callback field `+0x10`, worker notifier field `+0x78`, shared `gSelectivePushCallback` GOT reference, and APP callback `0x5a368`. Report explicitly leaves actual runtime symbol resolution and final state consumption open.
- RTOS store producer agrees numerically with the Linux consumer address but does not prove shared runtime visibility, file completion, SD durability, notification acknowledgement, or safe capture/transfer coexistence. Report preserves those limits. Predicate polarity finding above is independent of this boundary conclusion.
- Root status/reproduction wording reviewed against available reports; no additional issue found so far.
- Final capture report distinguishes category-table index 2 / still index 10 (`0x020a`) from write-buffer index 7 (`0x0207`), and identifies the independent callback machinery without claiming the unresolved SIF callback slot is installed to `captureSaveDone`. Successful-write Boolean and discarded close result are correctly separated. Its 49/49 accounting explicitly includes repeated functions and preserves the initial post-export missing-summary error.

Final verdict: no unresolved material blocker found in the reviewed RUN004 claims. This is an independent bounded static review; it does not validate runtime ordering, firmware boot selection, hardware behavior, durability or whole-feature semantic completeness. Root must refresh any packaging/progress hashes after its own final edits.
