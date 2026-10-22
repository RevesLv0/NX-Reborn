# Packaged Kernel2 TSU producers and thermometer failure paths — RUN010

The packaged kernel binds `d5_tsu/cpu` and `d5_tsu/isp` to calibrated register-byte
readers. Their result is the selected byte minus 21, formatted as a signed integer;
the combined node explicitly labels the same values `degC`. This establishes the
firmware's intended whole-degree Celsius representation, without validating sensor
accuracy or proving that this kernel and these nodes are active on a camera.

The library's separate CMOS conversion is also reproduced. Its sysfs-open failure
paths omit the unlock call locally, whereas its thermister retry failures explicitly
unlock. These findings come from original ARM instructions, including the actual
branches and return epilogue, rather than inferred decompiler C.

## Sources and reproducibility

| Input | SHA-256 |
|---|---|
| `.work/full/kernel-2.raw` (decoded packaged Kernel2, 7,474,108 bytes) | `25bdca5cde4a5c10710d02dbaa904c62cd77b0b4562b8bf4d73c675f50bdb587` |
| `.work/run008/sensor/inputs/libdi-sensor.so` (original DSO) | `75541051bc8e6090ec32d75e1b1b921a965b5a1cad26bf9a0683f7feb93bed07` |

[Collector](../../tools/firmware/kernel_tsu_evidence.py) verifies both complete input
hashes before reading original bytes. [Evidence](../evidence/kernel-tsu-run010.json)
retains 681 ARM instructions in nine bounded regions, data and string bytes,
original file offsets, per-region hashes, ELF relocation entries and arithmetic
checks. Kernel link VA minus `0xc0008000` is the decoded file offset; it is not a
measured runtime mapping. ELF addresses are original link VAs, independently mapped
through PT_LOAD, and all selected ELF code VAs here equal file offsets. The recovered
symbol catalog is `.work/run004/kernel/kernel-2-symbols.json`, with its identity
recorded in the evidence. Existing RUN008 Ghidra output was a navigation aid; no
Ghidra project was changed and no decompiler output substitutes for these bytes.

```sh
PYTHONPATH=.work/python python tools/firmware/kernel_tsu_evidence.py
```

This is static offline analysis. There was no camera access, extracted-program
execution, firmware modification or flashing. The artifact manifest records the
collector and report identities separately from source firmware identities.

## TSU name → handler → register arithmetic

The platform device at `0xc07000a8` (offset `0x6f80a8`) and driver name field at
`0xc071ece4` both point to original string `d5_tsu` at `0xc0647628`. The platform
device ID is -1. Driver registration `0xc02e3b98` supplies `tsu_driver` at
`0xc071ecd0` to `platform_driver_register`; that structure starts with probe
`0xc02e3d10`. On the probe's successful initialization path, calls at
`0xc02e3e28/0xc02e3e38/0xc02e3e44` pass the three attribute records below to
`device_create_file`. Their return values are not checked in that path, so static
registration intent does not prove successful live creation.

| Original attribute record VA | Name | Show handler | Helper selector |
|---|---|---|---|
| `0xc071ed20` | `tem2803x` | `0xc02e3cb4` | CPU 0 then ISP 1 |
| `0xc071ed30` | `cpu` | `0xc02e3c68` | 0 |
| `0xc071ed40` | `isp` | `0xc02e3c1c` | 1 |

Each 16-byte record has a name pointer, mode `0x1b4` (octal 0664), its show pointer,
and zero store pointer. Probe literals at `0xc02e3ee8..0xc02e3ef3` retain the exact
record pointers; these words are treated as data, not ARM instructions.

`tsu_read_cal_value` at `0xc02e4060` (offset `0x2dc060`) uses mapped base from
`g_tsu_info` → `+4`. It clears then sets control-register bit 4, calls `msleep(3)`,
and loads the word at mapped offset `0x10`. It returns:

- CPU selector 0: `((word >> 16) & 255) - 21`.
- ISP selector 1: `(word >> 24) - 21`.
- Null mapped base or another selector: 255.

The stored platform memory resource is `0x1040706c..0x10407087`; the selected data
register would therefore be physical `0x1040707c` under this mapping. Hardware
behavior and effective resource availability are unobserved. The helper assumes
the outer device-information pointer is valid; its explicit null test is for the
mapped base.

The normal mathematical range is -21 through 234, so the 255 error return cannot
collide with a normal extracted-byte result. CPU/ISP handlers compare against 255;
normal values use original `"%d\n"` at `0xc064f774`, while 255 causes a 16-byte copy
of `"invalid value \n"` including NUL and returns text length 15. Combined show uses
`"%d degC, %d degC \n"` at `0xc0673f28`, which directly supports the intended unit.
There is no millidegree multiplier or divisor in this route. `_tsu_init` at
`0xc02e3f04` programs constants and control bits, including high byte `0x79` and
10-bit field at bit 12 with `0x1f`; these are register setup values, not proof of
an independently calibrated transfer curve.

The separately exported `tsu_read_value` at `0xc02e40d4` uses the low byte for CPU
and bits 8–15 for ISP, also subtracting 21. The inspected sysfs handlers call the
*calibrated* helper, selecting the upper register bytes. No extra calibration
lookup, per-device adjustment word or scale factor appears in that helper.

## CMOS words and conversion

RUN008 established the miscdevice/read binding to `drime5_thermister_read` at
`0xc027b064` (offset `0x273064`). Its original bytes are retained again here. For
an available ADC client and a sufficiently large request, it performs ten calls
to `drime5_adc_raw_read_hax(client,7)` and scales each returned word as follows:

```text
p = (adc_word * 1000) mod 2^32
sample_word = (p * 0x399d336d) >> 41
```

These are unsigned product operations. For every integer `adc_word` from 0 through
4,294,967, the collector exhaustively verifies equivalence to
`floor(adc_word * 1000 / 2275)`; above that range the first multiplication wraps.
The helper at `0xc001fb0c` loads the channel register with no mask or range check.
Thus neither a particular ADC bit width nor volts/millivolts is established. The
returned words have already been scaled; they are not unmodified ADC register
counts. The cached average uses the ten scaled words, a 32-bit sum, and unsigned
division-by-ten arithmetic. The normal copy is exactly 40 bytes from the ten
sample words, using the literal pointer `0xc0753698` at `0xc027b380`.

At entry, a null ADC-client field branches to a diagnostic and return -1;
requested count 39 or less also returns -1. The normal copy-success path returns
the original requested count, even though the copy length is fixed at 40. The
address-check/copy-failure paths at `0xc027b28c` return positive 1. Therefore a
copy failure can pass the caller's sign-only check as a positive short result.
The observed library request is exactly 40; behavior for other callers is not
established.

The userspace update at original `0x4728` clears 80 bytes at `sp+0x100` but asks
`read` for only 40. It averages the nonzero signed words among the first ten,
using signed integer division at `0x4964`. Its original arithmetic at
`0x4968..0x4978` supplies -469 and `0x28d76c` (2,676,588). The normal finite,
in-range conversion is:

```text
a = signed integer average of nonzero words, or 0 when all ten are zero
radicand = signed32(2676588 - 469*a)  # 32-bit multiplication/addition
Sensor = trunc_to_signed_int(sqrt(double(radicand)) - 1482.0)
```

The binary64 constant at `0x4a60` is exactly 1482.0. VFP conversion at `0x4868`
truncates to an integer. The code tests whether the hardware square root is NaN
and branches at `0x4850` to a real `sqrt` PLT call at `0x4a50`; it then rejoins the
subtraction/conversion. This fallback exists in original bytes even though the
saved Ghidra C reports an unreachable block. No valid temperature is assigned
here to negative-radicand or other exceptional floating-point outcomes. With no
32-bit overflow and a nonnegative average, the radicand becomes negative above
5,707. Sensor Celsius calibration is not independently demonstrated by the
selected CMOS instructions or the TSU unit label.

An all-zero first buffer produces integer 154, rather than an explicit invalid
marker. The subsequent loop reads the second ten words in the cleared 80-byte
area. With ordinary bounded `read` behavior, no selected call populates those
second ten words; this route stores DSP value 153 (`0x99`) in object field `+0x60`.
That does not establish a measured DSP temperature.

## Bounded failure-path audit

Original ELF relocations bind the selected `read/open/close/strtol/sqrt` veneers.
The lock/unlock veneers resolve to defined functions `0x3838/0x3840`; those add
4 to the object pointer and tail-call `pthread_mutex_lock/unlock`. This is subject
to ordinary runtime dynamic binding, which has not been observed.

| Trigger | Original-byte path and bounded result |
|---|---|
| Initial thermister read returns negative | `0x4778 → 0x4920`: reopens device and overwrites descriptor field `+0x54`. The inspected path contains no close of the previous descriptor. |
| Retry open or retry read returns negative | `0x4938 → 0x4a1c` or `0x4948..0x4960 → 0x4a2c`: prints diagnostic, calls unlock at `0x4a40`, returns 0. |
| Either thermister read returns zero or a positive short count | Only the sign is checked (`0x4774`, `0x4948`); processing continues without requiring 40 bytes. The precleared buffer can therefore contribute zero/partial sample words. |
| ISP sysfs open returns negative | `0x4790 → 0x48e0`: returns 0 through stack restore/pop at `0x48e4/0x48e8`, with no intervening unlock call. |
| CPU sysfs open returns negative after ISP open succeeded | `0x47a8 → 0x48e0`: same local unlock omission; also no close of the successful ISP descriptor on that path. |
| TSU read returns negative, zero or short count | Return values at `0x47bc/0x47e0` are unused; each immediately feeds the shared text buffer to `strtol(buffer,NULL,10)`. No length check, parse-end check or per-read buffer clear is present. |
| Both TSU opens and normal processing succeed | Closes at `0x47fc/0x4804`; unlock at `0x4914`; returns 1. |

The shared TSU buffer is cleared once at entry. Consequently, with ordinary libc
semantics, a first failed read leaving it untouched parses as zero; a later failed
CPU read leaving it untouched can parse the prior ISP text. The kernel's
`"invalid value \n"` contains no initial digits and therefore parses as zero,
without any explicit invalid-state handling in the selected caller. These are
conditional static consequences, not observed camera measurements. Normal
producer strings are much shorter than the requested 255-byte read; pathological
full-length/nonterminated inputs are not claimed as behavior of these handlers.

The sysfs-open branches demonstrably bypass the function's explicit unlock call.
If the mutex was acquired and the branch is taken with the normal bindings,
this leaves it locked locally; the CPU-open failure also leaves an opened ISP
descriptor locally unclosed. Whether this produces a live stall, and which callers
might recover resources, is not established. No runtime defect is inferred solely
from a C decompiler variable.

The default mode branch at `0x48cc` reaches `0x4900` without assigning `r8` in this
body; modes 1–4 assign `r8` from `get_level`. The prologue saves the incoming `r8`
and the default path compares/stores that incoming value. This bounded register
fact does not provide a meaningful disabled-mode policy or justify claiming an
observed random shutdown. Threshold values, active modes, callback consumers and
actual thermal stop/shutdown decisions remain separate investigations.
