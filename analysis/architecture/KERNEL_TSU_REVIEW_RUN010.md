# RUN010 independent Kernel2 TSU review

Reviewed 2026-10-22. The bounded conclusions in [KERNEL_TSU_RUN010.md](KERNEL_TSU_RUN010.md) agree with independently decoded original ARM bytes and data. No correction is required before integration. The evidence establishes intended units and local control flow; it does not establish active-kernel selection, physical accuracy, live resource failures, successful mutex acquisition or observed camera behavior.

## Inputs, method and reproduction

| Input | Size | Independently recomputed SHA-256 |
|---|---:|---|
| `.work/full/kernel-2.raw`, packaged decoded Kernel2 | 7,474,108 | `25bdca5cde4a5c10710d02dbaa904c62cd77b0b4562b8bf4d73c675f50bdb587` |
| `.work/run008/sensor/inputs/libdi-sensor.so`, original `/usr/lib/libdi-sensor.so` | 41,672 | `75541051bc8e6090ec32d75e1b1b921a965b5a1cad26bf9a0683f7feb93bed07` |

Kernel addresses below are original link VAs, with file offset `VA-0xc0008000`. The link base is the packaged-image convention used here, not a measured runtime mapping. Original ELF VAs were independently mapped through `PT_LOAD`; the reviewed sensor code addresses equal their file offsets. Decoding used Capstone ARM mode and pyelftools. Kernel function names came from the existing recovered symbol catalog as navigation; pointers, branch targets and arithmetic were checked from original bytes.

The collector [kernel_tsu_evidence.py](../../tools/firmware/kernel_tsu_evidence.py) was read and rerun with the original sources symlinked into an isolated working directory, `.work/run010/review-tsu/reproduce`. It reproduced [kernel-tsu-run010.json](../evidence/kernel-tsu-run010.json) byte-for-byte:

```text
SHA-256 9795a102c245fc0cd658ec7ba3bf0fb32de49137f621de055130f625f29c0c6f
9 code regions; 681 decoded instructions; 12 strings
```

All **37** recorded code/data/string/PLT blocks were independently reread from original inputs: offsets, bytes and per-block SHA-256 values agree. All **11** selected PLT addresses were independently evaluated from ARM immediate encodings and checked against original `SHT_REL` bindings. All three collector/evidence/report hashes and sizes in [the RUN010 manifest](../../manifests/kernel-tsu-run010.json) matched at review time.

The first reproduction command mistakenly used the repository working directory and rewrote the completed evidence with identical deterministic bytes; its SHA-256 remained exactly the existing manifest value. This timestamp-only rewrite was reported to the parent immediately, then reproduction was repeated in scratch. No parent content was changed. No target executable, device operation or Ghidra project was used, and no threshold was changed.

## Name, attribute, show and helper binding

Independent checks reproduce the complete selected binding chain:

| Original location | Original-byte finding |
|---|---|
| Kernel device `0xc07000a8` / file `0x6f80a8` | First word `0xc0647628` resolves to `d5_tsu`; next word is `0xffffffff` (device ID -1). |
| Kernel driver `0xc071ecd0` / file `0x716cd0` | First word is probe `0xc02e3d10`; name word at `0xc071ece4` is the same `d5_tsu` pointer. |
| Kernel `0xc02e3b9c–0xc02e3ba4` | Loads driver pointer `0xc071ecd0` and calls registration target `0xc0268c98`. |
| Kernel `0xc02e3e20–0xc02e3e44` | Three calls to `0xc0265018` use literal attribute pointers from `0xc02e3ee8/0xc02e3eec/0xc02e3ef0`; intervening code does not test creation return values. |
| Kernel resource `0xc0700190` | Start/end words `0x1040706c/0x10407087`, memory flag `0x200` at +12. The mapped data-register offset `0x10` corresponds to physical `0x1040707c` under this configuration. |

The three 16-byte attribute records independently decode as:

| Record VA / file offset | Name pointer / string | Mode | Show pointer | Store pointer |
|---|---|---:|---|---:|
| `0xc071ed20` / `0x716d20` | `0xc0673f5c` / `tem2803x` | `0x1b4` | `0xc02e3cb4` | 0 |
| `0xc071ed30` / `0x716d30` | `0xc06436a4` / `cpu` | `0x1b4` | `0xc02e3c68` | 0 |
| `0xc071ed40` / `0x716d40` | `0xc06454d4` / `isp` | `0x1b4` | `0xc02e3c1c` | 0 |

The CPU show loads selector 0 at `0xc02e3c6c`; ISP loads selector 1 at `0xc02e3c20`. Both call `0xc02e4060`. The combined show calls that same helper twice, with selectors 0 then 1 (`0xc02e3cb8–0xc02e3ccc`). This distinguishes the handlers' actual upper-byte helper from the separate low-byte helper at `0xc02e40d4`.

## Subtract-21 arithmetic and intended units

Kernel `0xc02e4060–0xc02e40d0` independently reproduces:

```text
mapped_base = *(g_tsu_info + 4)
clear control bit 4; set control bit 4; msleep(3)
word = *(mapped_base + 0x10)
selector 0 -> ((word >> 16) & 255) - 21
selector 1 -> (word >> 24) - 21
null mapped base or unsupported selector -> 255
```

Decisive original encodings include `5008e707` at `0xc02e40b0` (`ubfxeq r0,r0,#16,#8`), `200ca0e1` at `0xc02e40c8` (`lsr r0,r0,#24`), and `150040e2` at `0xc02e40cc` (`sub r0,r0,#21`). The helper dereferences the outer device pointer before testing its mapped base; a null outer pointer is not an explicitly handled error in this body.

Each ordinary byte result spans -21 through 234, so 255 is separate from that range. CPU and ISP shows compare the helper result against 255 before using `%d\n` at `0xc064f774`. Their error branch copies 16 bytes from `invalid value \n` at `0xc0673e1c` and returns 15. Combined show uses the same two numeric results with `%d degC, %d degC \n` at `0xc0673f28`; its format pointer is loaded at `0xc02e3d00–0xc02e3d04`.

**Disposition:** intended whole-degree Celsius representation is supported. The `degC` label belongs to these TSU results and does not independently calibrate the separate CMOS conversion. The report correctly avoids claiming millidegrees, measured accuracy, successful live sysfs creation or active boot selection.

The register-initialization body `0xc02e3f04–0xc02e3f50` loads `0x79`, inserts it at bits 24–31, inserts `0x1f` into the ten-bit field beginning at bit 12, and sets control bits. These setup constants do not by themselves prove a validated physical transfer curve.

## Kernel CMOS scaling and read return values

Independent decoding of kernel `0xc027b064–0xc027b37c` confirms ten channel-7 calls to `0xc001fb0c`. The raw helper at `0xc001fb0c–0xc001fb20` loads the channel register and returns it without masking or range checking. For each returned 32-bit word, the caller uses an ordinary low-32-bit multiply by 1000, an unsigned widening multiply by `0x399d336d`, then shifts the high half right by 9. Thus:

```text
p = (adc_word * 1000) mod 2^32
sample_word = (p * 0x399d336d) >> 41
```

The collector's exhaustive arithmetic assertion reran successfully for raw inputs 0 through `floor((2^32-1)/1000) = 4,294,967`, establishing equivalence to `floor(adc_word*1000/2275)` over that bounded interval. It does not establish the hardware's accepted input range or electrical units. The first-stage wrap must remain in any full-domain formula.

Kernel copy/return instructions are particularly decisive:

```text
0xc027b28c 0100a0e3 mov r0,#1
0xc027b290 3cd08de2 add sp,sp,#0x3c
0xc027b294 f08fbde8 pop {r4-r8,sb,sl,fp,pc}
0xc027b2a0 2820a0e3 mov r2,#40
0xc027b2a4 45d2fceb bl 0xc01afbc0
0xc027b2a8 000050e3 cmp r0,#0
0xc027b2ac 0b00a001 moveq r0,fp
0xc027b2b0 f6ffff0a beq 0xc027b290
0xc027b2b4 f4ffffea b 0xc027b28c
```

Here `fp` preserves the original requested count. The address-check failure also enters `0xc027b28c`; a nonzero copy result follows the same positive-1 return. The successful copy length is always 40, sourced through the literal pointer `0xc0753698` at `0xc027b380`. Request counts 39 or less and an initially null ADC client reach -1 returns instead.

**Disposition:** positive 1 on the selected kernel copy failure is a real original-byte result. It can pass this userspace caller's signed-negative-only check. Neither a completed 40-byte read nor an actual device copy failure was observed.

## Userspace conversion and failure control flow

The complete original update window is sensor ELF VA/file offset `0x4728–0x4a5b`. The following independent checks agree with the report:

| Original instructions | Finding and boundary |
|---|---|
| `0x4734–0x4750` | Clears 80 bytes at `sp+0x100` and 255 bytes at `sp`. |
| `0x4754–0x4768` | Calls lock veneer `0x3378`, then `read(fd,sp+0x100,40)`. Lock return is not inspected. |
| `0x4774–0x4778`, `0x4948–0x494c` | Signed `cmp r0,#0` / `blt` or `bge` tests only; zero and positive short reads proceed. |
| `0x4788–0x4790` | ISP open result becomes `r6`; negative result branches directly to `0x48e0`. |
| `0x47a0–0x47a8` | CPU open result becomes `r7`; negative result branches to the same `0x48e0`. |
| `0x48e0–0x48e8` | Sets return 0, restores stack and pops directly, with no unlock. CPU-open failure also passes no close of the already successful ISP descriptor. |
| `0x47bc–0x47cc`, `0x47e0–0x47f0` | Each TSU read result is unused before `strtol(sp,NULL,10)`. Shared buffer is not cleared between the two reads. |
| `0x47fc`, `0x4804`, `0x4914` | Normal path closes both TSU descriptors and calls unlock. |
| `0x4920–0x4938` | Retry open overwrites object descriptor `+0x54`; no prior-descriptor close occurs on that inspected path. |
| `0x4938→0x4a1c`, `0x4948–0x4960→0x4a2c`, `0x4a3c–0x4a48` | Retry failures converge on diagnostic, explicit unlock at `0x4a40`, return 0. |

The independent PLT calculations bind `open/read/close/strtol/sqrt` to their corresponding original type-22 relocation symbols. They also bind `0x3378` to defined lock wrapper `0x3838`, and `0x327c` to defined unlock wrapper `0x3840`. The wrappers add 4 to the object pointer and tail-branch to `pthread_mutex_lock` / `pthread_mutex_unlock` PLTs `0x3114` / `0x30cc`.

**Disposition:** the two sysfs negative-open branches omit the unlock **locally**, while retry failures explicitly unlock. A live locked mutex or stall remains conditional on successful acquisition, ordinary dynamic bindings and taking that branch. The report preserves those conditions. The same local interpretation applies to the descriptor cleanup omissions.

The conversion independently follows the nonzero-word accumulation loop at `0x4814–0x4828`, signed division at `0x4964`, constants -469 and `0x28d76c` at `0x4968–0x4978`, signed-integer-to-double conversion and square root at `0x483c–0x4844`, subtraction of binary64 1482.0 from original bytes at `0x4a60`, and truncating conversion at `0x4868`:

```text
Sensor = trunc_to_signed_int(sqrt(double(signed32(2676588 - 469*a))) - 1482.0)
```

This describes the normal finite, representable conversion; arithmetic uses the machine-width intermediate values. At `0x4848–0x4850`, self-comparison of the square root detects NaN and branches to the original `sqrt` veneer call at `0x4a50`; `0x4a58` rejoins the subtraction. The fallback is present despite the saved decompiler's unreachable-code presentation. Exceptional results are not assigned a valid temperature by this review.

For the precleared all-zero first ten words, the conversion yields 154. The following loop covers `sp+0x128..sp+0x14c`; ordinary bounded reads selected here do not populate that second ten-word area, and its zero-count branch assigns DSP value 153 at `0x4890`. These values do not establish measured Sensor/DSP temperatures.

## Incoming r8 and final disposition

The update prologue saves incoming `r8` at `0x4728`. The default branch at `0x48cc` jumps to `0x4900`; the preceding instructions in this body do not assign `r8`. Modes 1–4 assign `r8` after `get_level` calls at `0x49f0`, `0x48fc`, `0x49d8` and `0x49c0`. At `0x4904–0x4908`, the default path compares that incoming register and conditionally stores it to object field `+0x90`, subject to normal callee-saved-register behavior of called functions.

**Disposition:** the incoming-register fact is supported; a meaningful disabled-mode policy, random shutdown or observed device failure is not established. The report correctly leaves downstream thresholds, callbacks and camera shutdown conclusions separate.

Independent scratch artifacts are `.work/run010/review-tsu/{independent.py,independent.json,original-windows.txt,plt-independent.json}` and the isolated reproduced JSON under `reproduce/analysis/evidence/`. The review repeated the source/data and central semantic checks above; it did not rederive the whole kernel symbol catalog or the RUN008 miscdevice registration. Those inherited pieces remain identified as prior research.
