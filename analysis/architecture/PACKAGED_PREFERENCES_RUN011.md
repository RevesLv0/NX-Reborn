# Packaged defaults and prefman command dispatch — RUN011

The packaged system-adjustment file contains the same seven temperature words
as RUN009's factory table: **4, 106, 110, 102, 105, 106, 110**. Its complete bytes
match the default bundle at `0x180000`, the same offset configured for group-4
NVD selector 1. This identifies a concrete packaged default source, without
proving the selected slot or live contents on a camera. The separate zero-filled
`pref_sys_default` table in libprefman remains a different source.

## Source identity and method

| Original partition/path | SHA-256 |
|---|---|
| rootfs `/usr/bin/prefman` | `b9c730df7890fb8c4cbb968e1990b510d7e861365992dd1c821ddd57a9dfca16` |
| opt `/pref/default/pref.bin` | `f96c3ecd54db98458bf337cd12a780d0fe59142ea3974b3fbe34820170122f9d` |
| opt `/pref/default/pref_adj_sys.bin` | `f520d39298ff0e455ff383e0209d5da3d3b3e319467d25d983a651db0e61136e` |

[Evidence](../evidence/packaged-preferences-run011.json) records the source SHA
of `/usr/bin/prefman.sh` and all eleven individual default files as well. The
collector checks them against the complete source-inode-verified inventory and
original extracted bytes. Shell assignments and `dd` lines are parsed as text;
neither the script, CLI, merge operation nor a device node is executed/opened.

The CLI's original ELF VAs equal its Ghidra VAs; file offsets are independently
mapped through PT_LOAD. Two completed exports select five C bodies. Two further
Thumb regions are manually decoded from original bytes and are explicitly not
selected-C completions. Their mode follows odd entry/function pointers, rather
than a guessed instruction set. Original trailing literal pools stay data.

## Default bundle correspondence

The script declares merge inputs under `/opt/pref` and uses `obs=512` with the
following seek values. Packaged files reside under `/opt/pref/default`; matching
their names/bytes does not prove a runtime copy into the script's input directory.

| Packaged file basename | Script sector | Bundle byte offset | Bytes |
|---|---:|---:|---:|
| `pref_app.bin` | 0 | `0x0` | 67,340 |
| `pref_app_restore.bin` | 768 | `0x60000` | 43,876 |
| `pref_line.bin` | 1,024 | `0x80000` | 2,560 |
| `pref_sysrw.bin` | 2,048 | `0x100000` | 1,616 |
| `pref_adj_sys.bin` | 3,072 | `0x180000` | 3,584 |
| `pref_adj_cap.bin` | 3,080 | `0x181000` | 3,584 |
| `pref_adj_iq.bin` | 3,088 | `0x182000` | 3,584 |
| `pref_adj_vfpn.bin` | 3,096 | `0x183000` | 24,064 |
| `pref_adj_cs.bin` | 3,144 | `0x189000` | 64,000 |
| `pref_adj_dpc.bin` | 3,272 | `0x199000` | 5,246,976 |
| `pref_adj_dpc2.bin` | 13,520 | `0x69a000` | 1,049,600 |

All eleven complete slices match their individual source file SHA-256 values.
Each header has magic `0x330033`, its exact file size at `+8`, and a CRC at `+4`
matching Python zlib CRC32 over bytes `0x200..end`. These are explicit checks of
the packaged bytes, not proof of successful firmware installation or NVD reads.

The system file's CRC is `0xd21d89c0`. At offsets `0x200 + lower_ID`, the words
are mode `0x91=4`, CIS warning/critical `0x95=106 / 0x99=110`, CPU
`0x9d=102 / 0xa1=105`, and ISP `0xa5=106 / 0xa9=110`. The mode/threshold names
are independently supplied by RUN009's factory descriptors. CPU/ISP intended
units are supplied by RUN010's TSU driver evidence; no extra CMOS calibration
is inferred from matching default words.

## Main, command table and the no-ID load path

The ARM entry at `0x8f9c` passes original word `0x8ef9` from literal `0x8fd0`
to `__libc_start_main`. Clearing its Thumb bit selects manual main region
`0x8ef8..0x8f8b`. Dynamic symbol `cmd_list` at `0x14214` contains eighteen
name/pointer pairs. Relevant odd pointers are `init → 0xa88d`,
`load → 0x9b8d`, `reset → 0x96fd`, and `addr → 0x9d5d`. The terminating `end`
record has a zero function pointer. Original table/name bytes accompany the
evidence.

After finding a nonnull command pointer, main's `0x8f62..0x8f66` passes
`argc-1` and `argv+1` to it. The original Thumb load handler
`0x9b8c..0x9ca7` compares that count against 2 at `0x9b90`; its signed
less-or-equal branch at `0x9b9a` goes to usage text at `0x9bc0`. The usage path
returns zero at `0x9c46..0x9c4b`. Its separate parsed-option path calls
`pref_load` at `0x9c8c`.

Consequently the script's `--start` sequence, `prefman init` followed by
`prefman load` with no extra arguments, reaches this inspected usage path for
the latter invocation. The script's help says “initialize and load all,” but
the recovered CLI branch does not establish such an all-ID reload. This is a
bounded static discrepancy; it does not prove that boot preferences are absent,
because the bootloader can preload memory through a separate path.

The init command at even code VA `0xa88c` iterates IDs 0–10, calls `pref_init`
and calls `pref_deinit` on its negative-result branches. RUN009 shows pref_init's
mapping/NVD-init calls; these are distinct from the load command. The selected
reset and addr bodies are retained for navigation and original-byte checking;
their entire command-line validation and failure semantics are not promoted to
reviewed claims in this pass.

## Reproduction and limits

```sh
PYTHONPATH=.work/python python tools/firmware/selected_elf_evidence.py \
  --root .work/run011 --subsystem prefinit \
  --output .work/run011/prefinit-selected.json --relocation-term pref_ \
  --string-term 'Usage:' --string-term prefman --string-term 'Load preference'
PYTHONPATH=.work/python python tools/firmware/packaged_preferences_evidence.py
PYTHONPATH=.work/python python tools/firmware/verify_selected_evidence.py \
  --evidence analysis/evidence/packaged-preferences-run011.json \
  --output manifests/evidence-verification-preferences-run011.json
```

The selected-evidence verifier audits seven code regions, 22 ELF data blocks and
19 strings; the preference collector separately rechecks all packaged file/slice
hashes, headers and CRCs. The source-correspondence finding is a non-ELF asset
unit, separate from ELF/function coverage. Live slot selection, persistent
calibration changes, boot preload order and actual CLI/script invocation require
their own evidence. No preference or temperature threshold was modified.
