# RUN009 independent thermal-policy review

Reviewed 2026-10-22, offline. This is a second static review of original ELF instruction bytes, load segments, relocation entries and embedded data. Ghidra exports supplied names and candidate locations; the decisive checks below use the staged original files, whose SHA-256 values also match the corresponding extracted rootfs files. No target program was executed, camera accessed, threshold changed, or Ghidra project opened by this review.

## Verdict and necessary qualifications

The reviewed evidence supports a conditional application policy: the registered temperature callback can schedule an idle handler; level 2 in the appropriate UI state requests movie stop with reason 7; a reachable stop path invokes the commit wrapper, which calls `mmf_camcorder_commit` only for backend states 5 or 6. It does **not** prove that every critical temperature causes a completed, successful recording finalization.

The factory descriptor/default bindings, separate all-zero prefman defaults, mapped preference storage and NVD slot offsets independently agree with the parent RUN009 data evidence. The factory constants are embedded defaults, not observed runtime calibration. `0x85600000` is both the high half of the relevant adjustment IDs and the configured physical mapping base. The accessor selects a preference group from that value and returns a mapped base plus an offset; it does not directly dereference the 64-bit ID as a pointer.

Use these precise qualifications when describing the result:

- The callback accepts unsigned levels **0–2**, after an application gate returns zero. ARM `BHI` excludes negative bit patterns as well as positive levels greater than 2.
- The stop manager has a positive time/state guard; receiving stop reason 7 does not bypass it.
- The movie-enable check queries `sensorapi::get_value(2,"temp_level")`; it does not directly read the UI `0x83a` value written by the idle callback.
- The movie-enable function has an earlier delegated return. Its level-2 denial is therefore a reachable local policy branch, not a universal recording-start guarantee.
- A static path to an API named `commit`, and an error log for its result, do not establish successful media finalization on a device.

## Source identity and address convention

All addresses below are **original ELF virtual addresses**, not Ghidra rebased addresses. For the two shared libraries below, the exported Ghidra address is the original address plus `0x10000`. The app addresses do not have that extra Ghidra rebase.

| Label | Original rootfs path | SHA-256 |
|---|---|---|
| app | `/usr/apps/com.samsung.di-camera-app/bin/di-camera-app` | `55dcc78143724435a2e38b9e0d809960bd728668634bbcf7532ce137f882eb04` |
| factory | `/usr/lib/libfactory-mode.so` | `364075adfec81e43e416944541be0890649c24f20aebbe341add1eee510ab434` |
| prefman | `/usr/lib/libprefman.so` | `c44802d1983bd07eaf53f02761cf402143bce245b7e5d20499c62ce1164df18d` |

The staged copies are `.work/run009/{app,factory,pref}/inputs/<basename>`. SHA-256 was recomputed independently for staged and original extracted files. File offsets were recomputed through the file-backed `PT_LOAD` containing each window:

| ELF | `p_offset` | `p_vaddr` | `p_filesz` |
|---|---:|---:|---:|
| app | `0` | `0x8000` | `0x4384ac` |
| app | `0x4384ac` | `0x4484ac` | `0x54c04` |
| factory | `0` | `0` | `0x6a98ac` |
| factory | `0x6aa000` | `0x6b2000` | `0x1cb8` |
| prefman | `0` | `0` | `0x651d7c` |
| prefman | `0x652000` | `0x65a000` | `0x4d0` |

Thus, for example, app callback VA `0x271920` is file offset `0x269920`, while prefman's data pointer at VA `0x65a310` is file offset `0x652310`. Subtracting a global image base for every segment would be incorrect.

## Application policy: independent ARM checks

The following windows were independently decoded with Capstone in ARM mode. Identifiers and function names were cross-checked against ELF symbols and the existing Ghidra exports; external PLT targets were additionally resolved through the original ELF relocations.

| Window / instruction | Reproduced behavior | Limitation |
|---|---|---|
| app `0x271f6c–0x272010`; `0x271fc8–0x271fd4` | On the initializer's zero-argument branch, loads `r0=3`, `r1=0x271920`, calls `0x1d0a38` (`UI_Di_Sensor_Set_Callback`). | Registration itself is not evidence that this branch executed on a device. |
| app `0x271920–0x271a28` | Preserves callback `r1` in `r5`; calls `Ui_Check_Wifi_Or_Power_Off(2,6)` at `0x271934`; nonzero return exits at `0x271a24`. | Other application states can suppress this handler. |
| app `0x271a0c–0x271a20` | `cmp r5,#2; bhi 0x271a24`; loads `r0=0x271678`, `r1=r5`, calls PLT `0xae740`. | Unsigned levels 0–2 only; scheduling return is unused. |
| app `0x271750–0x271758` | Loads UI ID `0x83a`, passes preserved level as `r1`, calls `UI_Set_Value` at `0x1ffaec`. | This is a UI value update, not the source of the later sensor API query. |
| app `0x271774–0x271790` | Level must equal 2; `UI_Get_Value(0x27a)` must equal 6; then `r0=7`, `bl 0xe7284` (`UI_Manage_Movie_Stop`). | Does not prove the stop request progresses through all later guards. |
| app `0xe7284–0xe73bc` | Positive guard described below determines whether processing starts. | Reason 7 does not force processing. |
| app `0xe77a8–0xe77d4`, `0xe7820–0xe7840` | Reason-indexed jump table entry 7 is `0xe7820`; clears byte `0x44a368`, obtains helper result from `0xe2a7c`, calls `0xe2c00` with `r0=0`, `r1=helper result`. | Applies after the manager's earlier guard and flag branches. |
| app `0xe2c00–0xe2fb0`; `0xe2f8c–0xe2fa4` | Helper saves first argument in `r4`. At the final selection, `r4==1` calls `0x1d54f8`; otherwise calls `0x109890(0)` and `UI_Mm_Camcorder_Commit` at `0x1d5138`. | Additional helper side effects are not reviewed as a complete recording state machine. |
| app `0x1d5204–0x1d521c` | Subtracts 5 from backend state, unsigned-compares to 1, branches away when above; states 5 or 6 call PLT `0xac8c8` with handle from `0x4aa288`. | Invalid states do not call commit here. |
| app `0x1d52e0–0x1d53d4` | Tests returned commit result; nonzero result follows error formatting/logging. | No runtime result or finished output file was observed. |
| app `0xe5138–0xe5144`, `0xe4f50–0xe4f70` | Calls `UI_Di_Sensor_Get_Temp_Level`, compares result with 2, then level 2 branches to display parameters `(0xc,0xba,5,0,0)` and returns zero. | Only paths reaching this check are covered. |
| app `0x1d1224–0x1d1308`; `0x1d122c–0x1d1238` | Loads sensor ID 2 and string VA `0x3a02e4` (`temp_level`), calls sensorapi `get_value` PLT `0xadb28`, returns preserved result. | The getter can differ from an earlier queued callback/UI value. |
| app `0xe4d00–0xe4d14` | If UI value `0x2c0==1` on this earlier path, calls `UI_Check_K_Mount_Lens_Capture_And_Movie` (`0xf53c4`) and jumps directly to the return. | This bypasses the temperature branch; its callee's complete behavior is outside this review. |

The stop manager's guard is especially important. The independent instructions at `0xe729c–0xe72ec` admit processing at `0xe73bc` if either byte at `0x49e7c8` / `0x49e7c9` is nonzero, or if `UI_Get_Value(0x27a)==6` **and** signed `UI_Get_Value(0x2bc)>0`, or if stop reason is 0 or 5. Otherwise it logs the string `return : time:%d` (VA `0x37cd34`) and branches from `0xe73b8` to the epilogue at `0xe79e8`.

For the callback's reason 7 with both flags clear, UI state 6 alone is insufficient: the `0x2bc` value must be positive. An initial state check and a later API state check are separate conditions and cannot be collapsed into an unconditional stop.

Selected raw instruction checks, in on-disk byte order:

```text
app 0x271a0c: 020055e3  cmp r5,#2
app 0x271a10: 0300008a  bhi 0x271a24
app 0x27178c: 0700a0e3  mov r0,#7
app 0x271790: bbd6f9eb  bl 0xe7284
app 0xe72dc: 000050e3   cmp r0,#0
app 0xe72e0: 350000ca   bgt 0xe73bc
app 0x1d5204: 053045e2 sub r3,r5,#5
app 0x1d5208: 010053e3 cmp r3,#1
app 0x1d520c: 7100008a bhi 0x1d53d8
```

Original `R_ARM_JUMP_SLOT` (type 22) bindings independently resolve the important external calls:

| PLT VA | GOT relocation VA | Symbol |
|---|---:|---|
| app `0xae740` | `0x449b4c` | `g_idle_add` |
| app `0xac8c8` | `0x449124` | `mmf_camcorder_commit` |
| app `0xadb28` | `0x449744` | `_ZN9sensorapi9get_valueE9SENSOR_IDPKc` |

## Adjustment IDs, data binding and defaults

Factory `dfms_get_adjdata` at original VA `0xb8874` preserves incoming `r0` in `r6` and `r1` in `r7`. Instructions `0xb8a0c–0xb8a24` compare the high word with `0x85600000`, select `r0=4`, and call `pref_get_addr` PLT `0x9c78`. The original PLT resolves through GOT `0x6b2808`, type 22 relocation, to `pref_get_addr`. After a nonzero mapped address result, `0xb8ab4` adds `0x200` to the low ID word and `0xb8afc` adds that to the mapped result. A zero mapping branches to error handling.

Together with the adjacent `strd r6,r7` use for `%llx` formatting and the descriptor bytes below, this supports a 64-bit adjustment ID split across ARM `r0/r1`, with low offset and high group identifier. Do not mistake the decompiler's two 32-bit arguments for proof of an arbitrary pointer API.

The original dynamic symbol `dfms_adjdata_sys_info` is VA `0xcc070`, size `0xf00`. Each reviewed row is 96 bytes: an 80-byte name region, 32-bit low word at +80, high word at +84 and width at +88. All seven widths are 4 and all high words are `0x85600000`. The original dynamic symbol `dfms_adjdata_sys_default` is VA `0xccf70`, size `0x491`; values below are unaligned little-endian 32-bit reads from that base plus the low ID offset.

| Descriptor VA | Name | Low offset | Factory default VA | Embedded value | Prefman default VA / value |
|---|---|---:|---:|---:|---|
| `0xccc10` | `TEMP_SENSOR_SELECT` | `0x91` | `0xcd001` | 4 | `0x36465` / 0 |
| `0xccc70` | `TEMP_SENSOR_CIS_TH_WARNING` | `0x95` | `0xcd005` | 106 | `0x36469` / 0 |
| `0xcccd0` | `TEMP_SENSOR_CIS_TH_CRITICAL` | `0x99` | `0xcd009` | 110 | `0x3646d` / 0 |
| `0xccd30` | `TEMP_SENSOR_CPU_TH_WARNING` | `0x9d` | `0xcd00d` | 102 | `0x36471` / 0 |
| `0xccd90` | `TEMP_SENSOR_CPU_TH_CRITICAL` | `0xa1` | `0xcd011` | 105 | `0x36475` / 0 |
| `0xccdf0` | `TEMP_SENSOR_ISP_TH_WARNING` | `0xa5` | `0xcd015` | 106 | `0x36479` / 0 |
| `0xcce50` | `TEMP_SENSOR_ISP_TH_CRITICAL` | `0xa9` | `0xcd019` | 110 | `0x3647d` / 0 |

The separate prefman group-4 record at `0x65a2f8` contains name `adj_sys`, group ID 4 at +20 and size `0xe00` at +28. Its pointer field at `0x65a310` is zero in file bytes but has an **`R_ARM_ABS32` (type 2)** relocation to dynamic symbol `pref_sys_default`, original symbol VA `0x361d4`, addend zero. Under the normal ELF binding this is `load_bias + 0x361d4`, not a null default pointer. `pref_get_addr_default` at original `0x22ac` loads the +24 pointer and +28 size from the 36-byte group record. Its field addressing independently matches the record stride. The seven reviewed fields at `0x361d4+0x200+offset` are all zero; they must not be replaced in the report with the factory defaults above.

Prefman `pref_get_addr` (`0x2238`, Thumb) calls `pref_get_shm`; the independently decoded `pref_get_shm` window at `0x5594` returns the cached group mapping or calls `pref_create_shm`. `pref_create_shm` (`0x54e0`, Thumb) indexes 12-byte mapping records. Its group-4 record at VA `0x65a424` / file offset `0x652424` is `(0x85600000, 0xe00, 0)` before relocation/runtime changes. It opens string `/dev/mem` (computed VA `0x7038`) and maps with protection 3, flag 1, and that configured physical offset; the size-rounding instructions at `0x5510–0x551e` round `0xe00` up to `0x1000`. Original PLT bindings are `0x1ba4` → GOT `0x65a1c0` → `open`, and `0x1be0` → GOT `0x65a1d4` → `mmap`.

This establishes how runtime adjustment storage can be addressed. It does not provide the bytes resident in that physical memory, which initialization/reset path populated them, or whether ELF symbol interposition changes a binding at runtime.

## NVD slot cross-check

The original prefman NVD record at VA/file offset `0x6513f4`, 184-byte stride, contains `adj_sys` and three 48-byte path/offset slots after its initial 40 bytes. Independent bytes agree with the parent evidence:

| Slot selector | Path | Stored sector-offset word | Byte offset computed by code | Trailing word |
|---:|---|---:|---:|---:|
| 0 | `/dev/mmcblk0p1` | 0 | 0 | 8 |
| 1 | `/dev/mmcblk0p3` | `0xc00` | `0x180000` | 8 |
| 2 | `/dev/mmcblk0p5` | 0 | 0 | 8 |

Thumb `nvd_load` at `0x56b0` selects these slots from its fourth argument, multiplies the group by `0xb8`, loads the appropriate offset word, shifts it left by 9 (`0x571e`, `0x57a6`, `0x585c`) and passes that offset to `lseek` at `0x57ce`. Only these offsets were decoded; the units/meaning of the trailing word 8 remain unestablished by this review. No block-device contents were read and no slot was selected as the device's active/calibrated runtime source.

## Reproduction and evidence consistency

Independent local artifacts are `.work/run009/review/review_windows.py`, `original-elf-review.json`, `windows.txt`, `plt-relocations.json`, `compare_parent.py`, and `parent-comparison.json`. The decoder uses `PYTHONPATH=.work/python`, pyelftools and Capstone; it only reads original ELF bytes. Linear window decoding can display literal pools or jump-table words as instructions, so the table targets and literal bytes were interpreted as data where required.

The independently recomputed source hashes, `PT_LOAD` offsets and raw bytes match **all 53 windows** in [the parent userspace evidence](../evidence/thermal-policy-run009.json). All seven independently parsed descriptor names, IDs, widths, factory values and prefman zero fields match [the parent data evidence](../evidence/thermal-policy-data-run009.json). That data evidence contains zero instruction windows; the independent data conclusions here come from the explicit original table bytes and relocations, not from claiming an instruction-window comparison that was absent.

The parent evidence records a failed initial callback export and the later successful exports. This reviewer used completed exports as navigation only, ran no analyzer/decompiler jobs and encountered no decompiler timeout or truncation. One read-only shell attempt failed because the exec-server transport disconnected; the same read succeeded on retry. No quota exhaustion occurred during this review.

## Disposition of the parent architecture draft

Reviewed [THERMAL_POLICY_RUN009.md](THERMAL_POLICY_RUN009.md) after the independent byte/data work above. No correction is required to its bounded central conclusions.

| Parent claim family | Disposition |
|---|---|
| Registration of callback ID 3, application gate, unsigned 0–2 scheduling and conditional stop reason 7 | Independently reproduced from original app instructions. |
| Reason-7 early return, ordinary branch to helper, backend state 5/6 commit gate and absence of success proof | Independently reproduced; the draft correctly retains the positive-time guard and separates request from completion. |
| Sensor API temperature getter, local level-2 denial and earlier bypass | Independently reproduced; the draft correctly distinguishes the API query from UI `0x83a`. |
| Seven factory descriptors/defaults, prefman zero table and ABS32 binding | Independently reproduced from original table bytes, dynamic symbols and relocation record. |
| Physical mapping identity and NVD slot offsets, with trailing word 8 left without units | Independently reproduced from original prefman Thumb instructions and data. |
| Sensor callback-vector/mutex internals, test-temperature entry and stop-reason string mapper | Parent source windows pass independent byte/offset consistency checking; their complete semantic decoding was not repeated in this review. These claims are not upgraded to device observations. |
| `pref_load` validation, reset/save paths, and factory default export path | Parent source windows pass independent byte/offset consistency checking; complete semantic decoding was not repeated. The draft's conclusion that a reset name does not establish runtime factory-default adoption is appropriately bounded. |
| RUN008 mode-4 behavior and RUN010 units/conversion | Referenced separate research, not independently re-established here. |

Still unverified: actual runtime thresholds and units through the complete sensor pipeline, runtime preference initialization precedence, callback/idle timing, all recording entrypoints, backend commit completion, output-file integrity and device behavior. Separate kernel/unit research is outside this review's conclusions.
