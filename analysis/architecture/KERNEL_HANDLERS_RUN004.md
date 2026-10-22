# RUN004: embedded Linux symbols and bounded IPCC / HEVC handlers

Newly reproduced offline static evidence, 2026-10-21 UTC. A complete embedded
ARM32 absolute-address kallsyms structure is recovered from **packaged kernel
section 2**. It supports a validated decoded-file / kernel-link-VA relationship
and original ARM instruction review of the two IPCC packet requests and HEVC
configuration request identified in RUN003 userspace. The active boot roles of
sections 0, 2 and 3 remain unknown. None of these results establishes which driver
is running on a camera.

## Inputs and reproduction

Source firmware `.work/full/NX500.bin` SHA-256:
`f4c238e811970cf858b5d734119477ea191d35cd29d9f84b584157ecfc4ee997`.
The collector checks each decoded kernel's complete length and SHA-256 against
[`kernel-headers.json`](../evidence/kernel-headers.json), whose prior bounded gzip,
source-section and uImage checks establish source provenance.

| Decoded input | Bytes | SHA-256 |
|---|---:|---|
| `.work/full/kernel-0.raw` | 9,201,060 | `942492550b303d203a5ab43614aafd46bc4644ae8afa474f3676db3b809a072b` |
| `.work/full/kernel-2.raw` | 7,474,108 | `25bdca5cde4a5c10710d02dbaa904c62cd77b0b4562b8bf4d73c675f50bdb587` |
| `.work/full/kernel-3.raw` | 9,201,060 | `fc38d13a10fdf4ae964f5100c0f043c7650f3e11385c90d7e07d58e9a3fecf9c` |

```sh
PYTHONPATH=.work/python python tools/firmware/kernel_symbols.py \
  --kernel-dir .work/full --headers analysis/evidence/kernel-headers.json \
  --raw-output-dir .work/run004/kernel \
  --output analysis/evidence/kernel-symbols-run004.json \
  --handler-output analysis/evidence/kernel-handlers-run004.json
python -m unittest discover -s tests -p test_kernel_symbols.py -v
```

Six synthetic tests pass: whole-table recovery across the second 256-name marker,
rejection of an address-like run without metadata, corrupted count/marker/token/index/
names, truncated index, unsorted addresses, exact export-string mapping checks and
input hash rejection. The tests use invented fixture symbols only; all reported
firmware symbols below come from the validated embedded metadata.

Selected evidence is in [`kernel-symbols-run004.json`](../evidence/kernel-symbols-run004.json)
and [`kernel-handlers-run004.json`](../evidence/kernel-handlers-run004.json).
The full 37,167-entry catalog, driver-string catalogs and bounded full linear ARM
listings stay ignored under `.work/run004/kernel/`. Their hashes and the reviewed
finding ledger are in [`kernel-run004.json`](../../manifests/kernel-run004.json).
These are ELF-independent raw-kernel metadata/review units; they add zero ELF
imports, auto-analysis completions or decompilation completions to ELF progress.

## K004-01: complete kallsyms and a checked link-address mapping

For kernel-2, every component agrees:

| Structure | Decoded-file offset | Validation |
|---|---:|---|
| 32-bit little-endian absolute address array | `0x5ac740` | 37,167 nondecreasing addresses |
| Symbol count | `0x5d0c00` | 37,167, matching the entire address run |
| Compressed names | `0x5d0c10`–`0x639eaf` exclusive | Exactly 37,167 nonempty names expand through the tokens |
| Markers | `0x639eb0` | All 146 entries equal measured offsets at every 256th name |
| Token table | `0x63a100`–`0x63a484` exclusive | Exactly 256 terminated printable tokens |
| Token index | `0x63a490` | All 256 little-endian 16-bit entries equal measured token starts |

The scan accepts only sufficiently long, nonconstant, bounded-span monotonic address
runs, a matching adjacent count, at most 15 zero alignment bytes between components,
complete compressed-name/marker/token/index agreement and printable expanded names.
An address-like sequence or plausible handful of names is insufficient.

Recovered `_text` and `stext` are `0xc0008000`; `_stext` is `0xc0008200`.
Taking decoded offset zero as `_text` gives
**kernel link VA = decoded-file offset + `0xc0008000`**. Independent confirmation is
especially strong: **all 4,795 recovered `__kstrtab_*` symbols point to the exact
matching embedded NUL-terminated export-name string at this mapping, with zero
mismatches**. For example `__kstrtab_kallsyms_lookup_name`, VA `0xc0690bcd`,
maps to exact string `kallsyms_lookup_name` at decoded offset `0x688bcd`.
The ARM windows below additionally resolve named direct-call targets and data pointers
consistently in this image.

This is a static image/link-address relationship, not an observed live mapping.
The uImage load/entry value `0x86008000` belongs to the separately packaged zImage;
it must not be substituted for this decoded link VA or treated as proof of a physical
mapping. Gzip means decoded offsets do not have a direct per-byte BIN offset. The
section-2 compressed stream begins at BIN `0x5f33c1` (6,239,169 decimal).

For sections 0 and 3, this scan finds no qualifying complete table. Its stated
profile is little-endian absolute ARM32 kallsyms, at least 1,024 symbols, addresses
in `[0x80000000,0xffff0000)`, at most `0x10000000` address span and bounded zero
padding. This is a negative search result for that profile; it does not establish
that symbols, functions or particular drivers are absent, nor does it prove a
kernel configuration option.

## K004-02: section-2 IPCC dispatch, record fields and separate results

All VAs in this section refer to kernel-2 with the SHA above; decoded offset is
VA minus `0xc0008000`. Recovered `ipcc_ioctl` starts at VA `0xc02cfa94`
(decoded `0x2c7a94`). Its original ARM dispatch constructs the exact request
constants with `MOVW`/`MOVT`, compares `r1`, and branches:

| Request | Compare / equal branch | Case | Named operation call |
|---|---|---|---|
| `0xc0107406` | `0xc02cfafc` / `0xc02cfb00` | `0xc02cfd28` | `0xc02cfd70` → `_ipcc_read_srj`, `0xc02cedc0` |
| `0xc0107407` | `0xc02cfb0c` / `0xc02cfb10` | `0xc02cfc9c` | `0xc02cfce0` → `_ipcc_write_srj`, `0xc02cf098` |

The handler saves userspace argument `r2` in `r4`, extracts request size into `r5`
(`UBFX` at `0xc02cfad4`) and copies the 16-byte request to stack `sp+0x48` through
recovered `__copy_from_user` (calls at `0xc02d05b0` / `0xc02d05e8`). Instructions
support this field-level interpretation for both cases:

| Record byte offset | Observed use |
|---:|---|
| `+0` | Loaded into `r0`, passed to recovered `_conv_coretoid` at `0xc02cecc4`; its return supplies operation argument 1 |
| `+4` | Loaded into `r2`; supplies operation argument 3, a length/count value used by the named packet helper |
| `+8` | Receives the named packet helper's `r0` result (`STR` at `0xc02cfd00` / `0xc02cfd8c`) |
| `+12` | Loaded into `r1`; supplies operation argument 2, the buffer address dereferenced/copied by the helpers |

**Field order is instruction-derived: the length is `+4`, and the buffer pointer
is `+12`.** No source C structure or RTOS message schema is asserted. The read
helper accesses its buffer as bytes and calls `__ipcc_read_srj`; the write helper
constructs a six-byte local prefix, copies payload bytes, updates indexed memory
and calls recovered `ipcc_send_interrupt`. That is a bounded static producer path,
not evidence of a peer consuming or acknowledging a packet.

Both cases copy the record back using `__copy_to_user` (write `0xc02d0638`, read
`0xc02d0684`). The handler's return comes through `r7` at `0xc02cfabc`, following
the copy-accounting path, while the packet helper result is stored in **record
`+8`**. A userspace `ioctl` return and the returned record word are separate
results. The copy-input branch uses signed `BGE` on the copy helper's result;
the selected instructions do not justify assuming every partial copy is rejected.
These observations do not supply a general error-handling or security assessment.

The recovered `ipcc_ops` data has the `ipcc_ioctl` pointer at `+0x20` (VA
`0xc05893c0`). Named `ipcc_miscdev` at VA `0xc071da7c` contains a pointer to exact
string `d5_ipcc` (VA `0xc0647160`) and `ipcc_ops`. The `ipcc_probe` path loads that
record pointer and calls recovered `misc_register` at `0xc02d0d08`, then tests its
return. This connects the packaged registration path, name and handler. Successful
registration and `/dev/d5_ipcc` availability on a running camera are unobserved.

## K004-03: section-2 HEVC request reaches a host/firmware boundary

Recovered `d5_hevc_ioctl` starts at VA `0xc02d5a58` (decoded `0x2cda58`).
`MOVW` / `MOVT` at `0xc02d5af8` / `0xc02d5afc` construct **`0xc10c7408`**;
comparison `0xc02d5b00` and equal branch `0xc02d5b04` reach case `0xc02d5e6c`.
The size extracted at `0xc02d5a8c` is `0x10c` for this request. A call to
`__copy_from_user` at `0xc02d6248` copies that record to `sp`.

The case loads a nested pointer from record **`+0xac`**. Four words at that nested
address (`+0`, `+4`, `+8`, `+12`) are tested; nonzero values are passed through
the recovered `d5_uservirt_to_phys` symbol and replaced with its result. The
helper name alone does not prove mapping validity or pinning. The original record
is then passed to recovered **`host_model_main`** at callsite `0xc02d5ed4`.
Its `r0` return is stored in record **`+0xd0`** at `0xc02d5ef8`; the record is
copied back through `__copy_to_user` at `0xc02d61dc`. As with IPCC, this operation
result word is separate from the ioctl handler's own return/copy accounting.

Bounded review of `host_model_main` (VA `0xc02d5490`) shows unsigned checks that
record fields `+0xbc` and `+0xc0` are at most 1. Its `+0xc0 == 0` path calls
`hevc_init` (`0xc02d5594`), `setHEVCEncOption` (`0xc02d55ac`),
`Send_HOST_to_FW(2,...)` (`0xc02d55d0`) and `Receive_FW_to_HOST(2,...)`
(`0xc02d55dc`). It writes words to record `+0xc4` and `+0xd4` before returning.
The function names are recovered metadata; their firmware protocol, message
meaning, timeouts, completion and actual encoding behavior are not reviewed here.
No frame-rate, dimensions, thermal limit or encoding capability follows.

Named `d5_hevc_ops` contains the handler pointer at `+0x20` (VA `0xc0589628`).
`d5_hevc_miscdev` at VA `0xc071e5ec` points to exact string `d5_hevc` (VA
`0xc0647618`) and that ops object. `d5_hevc_probe` loads the record pointer,
calls recovered `misc_register` at `0xc02d5864` and tests the result. This supplies
a static packaged counterpart to the RUN003 userspace `/dev/d5_hevc` open and
request, with boot-role and live-registration limits preserved.

## MICOM and remaining limits

Case-insensitive printable-string search finds zero `micom` hits in each decoded
image and zero such names in the complete recovered section-2 symbol table. Aligned
literal-word search finds neither `0x80044d00` nor `0x80044d05` in the three files.
It also finds none of the IPCC/HEVC request words, **despite their proven presence
as split MOVW/MOVT immediates in section 2**. Literal absence is therefore explicitly
insufficient to rule out a handler. MICOM's kernel implementation remains unresolved;
modules or another component may need separate inspection. No MICOM device semantics,
SOC units, battery freshness or power thresholds are established.

No extracted program or firmware was executed; no device I/O, camera access, flashing,
Ghidra import, decompilation, commit, push or upload was performed by this pass.
