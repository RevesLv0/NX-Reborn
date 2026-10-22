# RUN012 independent packaged-preference provenance review

Reviewed 2026-10-22. The packaged default slices, their temperature words and the selected CLI dispatch behavior are independently supported. These are packaged-file and original-code findings, not evidence that a camera loaded those bytes into its active preference mapping or chose a particular NVD slot.

## Inputs and reproduction

| Input | Bytes | Independently checked SHA-256 |
|---|---:|---|
| rootfs `/usr/bin/prefman` | See source-bound evidence | `b9c730df7890fb8c4cbb968e1990b510d7e861365992dd1c821ddd57a9dfca16` |
| rootfs `/usr/bin/prefman.sh` | See packaged-file evidence | `c07c36e92eedbe3e87e34b171554dd6a59e1d789445047a57e60367ccd84d115` |
| opt `/pref/default/pref.bin` | 7,971,840 | `f96c3ecd54db98458bf337cd12a780d0fe59142ea3974b3fbe34820170122f9d` |
| opt `/pref/default/pref_adj_sys.bin` | 3,584 | `f520d39298ff0e455ff383e0209d5da3d3b3e319467d25d983a651db0e61136e` |

The staged utility matches the original extracted rootfs file. All 13 packaged-file identities retained in [packaged-preferences-run011.json](../evidence/packaged-preferences-run011.json)—the script, bundle and eleven named component files—were independently SHA-checked. The collector [packaged_preferences_evidence.py](../../tools/firmware/packaged_preferences_evidence.py) was read and rerun with `--output .work/run012/review-prefs/reproduced.json`; this reproduced the completed evidence byte-for-byte, SHA-256 `caf51350001f6654f8f6ab7a15c0bdb9992f7555ec1516dff6c42adf103580b1`.

Independent pyelftools/Capstone checks reread all seven saved utility instruction windows and 22 data blocks from original `PT_LOAD` mappings. Main and load were manually decoded in Thumb mode from their odd original pointers. These windows are not new Ghidra function recoveries or completed C decompilations. No Ghidra project was accessed. The script/utility was not executed, and no preference file, mapped memory, NVD device or firmware was changed.

## Claim dispositions

| Finding | Independent disposition | Limit |
|---|---|---|
| Eleven component bins match the bundle at the script's sector offsets | Supported by complete byte comparison, sizes, magic and CRC checks below | Does not prove script execution, successful merging or deployment. |
| Packaged system temperature words match recovered factory defaults | Supported by original component bytes at `0x200+offset` | Distinct from libprefman's embedded zero defaults and from unobserved live preference memory. |
| Script `--start` invokes `prefman init` then `prefman load` without extra load arguments | Supported by original script bytes | Init/preload behavior and actual boot ordering are separate questions. |
| That no-argument `load` follows usage instead of its `pref_load` call | Supported by original main argument adjustment, command pointer and load branch | Does not mean all initialization or all utility invocations omit preference loading. |

## Packaged slices and CRCs

The script's merge lines use `obs=512 seek=N`. The independently compared components and bundle byte offsets are:

| Component under opt `/pref/default/` | Sector seek | Bundle offset | Bytes |
|---|---:|---:|---:|
| `pref_app.bin` | 0 | `0` | 67,340 |
| `pref_app_restore.bin` | 768 | `0x60000` | 43,876 |
| `pref_line.bin` | 1024 | `0x80000` | 2,560 |
| `pref_sysrw.bin` | 2048 | `0x100000` | 1,616 |
| `pref_adj_sys.bin` | 3072 | `0x180000` | 3,584 |
| `pref_adj_cap.bin` | 3080 | `0x181000` | 3,584 |
| `pref_adj_iq.bin` | 3088 | `0x182000` | 3,584 |
| `pref_adj_vfpn.bin` | 3096 | `0x183000` | 24,064 |
| `pref_adj_cs.bin` | 3144 | `0x189000` | 64,000 |
| `pref_adj_dpc.bin` | 3272 | `0x199000` | 5,246,976 |
| `pref_adj_dpc2.bin` | 13520 | `0x69a000` | 1,049,600 |

For each of the eleven named files, its complete bytes match the bundle slice, header word 0 is `0x330033`, header word +8 equals the actual file size, and header CRC word +4 matches host `zlib.crc32(component[0x200:])`. These checks establish packaged consistency; CRC agreement does not establish any active-device calibration or storage provenance beyond these files. Eleven named components are not necessarily eleven unique byte contents: the system and capture components here have the same hash.

The system component contains these unaligned little-endian signed words:

| Lower ID | Component offset | Word |
|---:|---:|---:|
| `0x91` | `0x291` | 4 |
| `0x95` | `0x295` | 106 |
| `0x99` | `0x299` | 110 |
| `0x9d` | `0x29d` | 102 |
| `0xa1` | `0x2a1` | 105 |
| `0xa5` | `0x2a5` | 106 |
| `0xa9` | `0x2a9` | 110 |

These reproduce the seven factory constants independently checked in [THERMAL_POLICY_REVIEW_RUN009.md](THERMAL_POLICY_REVIEW_RUN009.md). They do not replace the separate libprefman ELF zero table, determine the actual mapping's bytes or identify which NVD source was selected.

The script sets `IMG_PATH=/opt/pref`, whereas the packaged component files audited here reside under `/opt/pref/default`. Their matching offsets are a concrete packaging relationship, not proof that the script's runtime input paths existed or were populated by a copy step.

## Original main/load argument path

The original entry argument literal at utility VA `0x8fd0` is `0x8ef9`, selecting Thumb main code at even VA `0x8ef8` / file offset `0xef8`. Original dynamic symbol `cmd_list` is VA `0x14214`, size 144 bytes: 18 name/function pairs. Its `load` entry is index 3, pair VA `0x1422c`, and its original function pointer is `0x9b8d`, selecting Thumb code `0x9b8c` / file offset `0x1b8c`.

The decisive original instructions are:

```text
main 0x8f5c: d8f80430 ldr.w r3,[r8,#4]   # selected command function
main 0x8f62: 681e     subs r0,r5,#1       # original argc minus 1
main 0x8f64: 211d     adds r1,r4,#4       # original argv plus 1
main 0x8f66: 9847     blx r3

load 0x9b90: 0228     cmp r0,#2
load 0x9b9a: 11dd     ble 0x9bc0         # signed argc <= 2 -> usage
...
load 0x9c46: 0020     movs r0,#0
load 0x9c48: bde8f883 pop.w {...,pc}

load 0x9c88: 3946     mov r1,r7
load 0x9c8a: 4846     mov r0,sb
load 0x9c8c: fff7ece8 blx 0x8e68         # selected pref_load call
```

The `pref_load` call is bound by original type-22 relocation GOT `0x141c4`. For `/usr/bin/prefman load`, original argc is 2; main supplies load argc 1, which satisfies the signed `BLE` to usage at `0x9bc0`. That path returns zero at `0x9c46–0x9c48` without reaching `0x9c8c`.

The original script's usage text says `--start` initializes and loads all preferences, but its explicit commands are `prefman init` followed by `prefman load` without added arguments. The selected load command therefore does not perform its own `pref_load` call in that invocation. This does not inspect every behavior of `init`, boot-time preloading, other callers or other argument combinations.

Independent scratch artifacts are `.work/run012/review-prefs/{audit.py,audit.json,windows.txt,reproduced.json}`. This review establishes the bounded packaged-file and CLI facts while preserving the live NVD-selection and initialization-precedence questions.
