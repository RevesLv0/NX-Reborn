# Temperature acquisition, level classification and power nodes — RUN008

The inspected app temperature display uses libdi-sensor's thermometer module,
which reads the CMOS thermister device and separate ISP/CPU TSU nodes. This is a
different path from the generic OEM thermistor wrappers discovered in RUN007.
The library classifies configured thresholds into levels 0/1/2 and filters level
changes across consecutive evaluations. Actual calibration values, physical
units and the final recording-stop/shutdown policy are not established here.

## Inputs and method

| Original source | SHA-256 |
|---|---|
| `/usr/apps/com.samsung.di-camera-app/bin/di-camera-app` | `55dcc78143724435a2e38b9e0d809960bd728668634bbcf7532ce137f882eb04` |
| `/usr/lib/libdi-sensor.so` | `75541051bc8e6090ec32d75e1b1b921a965b5a1cad26bf9a0683f7feb93bed07` |
| `/usr/lib/libslp_devman_plugin.so` | `a88cb8130ba246b45c077cf25f0c5944077e41b780eee20f5a5a675b35a15588` |
| Decoded packaged kernel 2 | `25bdca5cde4a5c10710d02dbaa904c62cd77b0b4562b8bf4d73c675f50bdb587` |

ELF addresses below are original link VAs; DSO Ghidra addresses add `0x10000`,
whereas app Ghidra addresses equal original VAs. Each file offset is mapped
independently through PT_LOAD. Saved TMode contexts select ARM versus Thumb.
Kernel link VA equals decoded offset plus `0xc0008000`, not a measured runtime
base. The packaged kernel's active boot role remains unverified.

[Userspace evidence](../evidence/thermal-userspace-run008.json) retains completed
receipts, source identities, selected C, original code windows and relocations.
[Kernel evidence](../evidence/thermal-kernel-run008.json) separates bounded code,
the read function's trailing literal pool, attribute/file-operation data and
original name strings. This is primary-agent static review; independent review
remains incomplete after the previously recorded actual quota failure. No
sensor measurement, sysfs access, target execution or power operation occurred.

## App display and sampling are separate operations

App `CAPPGUITopState::onEventDisplayTemperature` (`0x2b10dc`) removes its display
item for event data -1; otherwise it calls the three UI wrappers and formats
Sensor, CPU and ISP values into OSD item `0x867`.

| UI wrapper, original VA | libdi-sensor API request |
|---|---|
| `UI_Di_Sensor_Get_Temp_Sensor`, `0x1d1314` | `sensorapi::get_value(2,"sensor")` |
| `UI_Di_Sensor_Get_Temp_Cpu`, `0x1d14f4` | ID 2, key `cpu` |
| `UI_Di_Sensor_Get_Temp_Isp`, `0x1d1404` | ID 2, key `isp` |
| `UI_Di_Sensor_Get_Temp_Level`, `0x1d1224` | ID 2, key `temp_level` |

`sensorapi::initialize` (`0x514c`) constructs `csensor_thermometer(...,2)` and
stores it in module-list slot 2. Constructor `0x42b8` binds the vtable beginning
at original `0x118f8`. `R_ARM_ABS32` entries `0x11904` and `0x1190c` resolve its
update and get-value slots to `0x4728` and `0x41f8`. Thus the indirect API call
has a concrete class binding, conditional on initialization.

`sensorapi::get_value` (`0x6120`) returns zero before initialization. For the
inspected ID 2, its stop-flag branch invokes the update slot before fetching a
value; otherwise it uses the registered module. Thermometer getter `0x41f8`
locks its mutex and returns cached fields: sensor `+0x5c`, DSP `+0x60`, CPU
`+0x64`, ISP `+0x68`, or published level `+0x8c`, selected by case-insensitive
key comparison. Unknown keys return zero in that body.

The preview timer is separate UI behavior: `on_timer_temperature` (`0x35124c`)
toggles icon `0x816`; it does not read a sensor. `set_temperature` (`0x35f558`)
uses view/recording/UI guards and draws the red temperature icon for UI value
`0x83a` equal to 1 or 2. This does not independently bind that UI value to the
library callback or establish a recording-stop decision.

## Concrete acquisition endpoints

Thermometer initialize `0x43c8` opens `/dev/drime5-thermister` with code flag
`0x802`. Update `0x4728` requests `0x28` bytes from that descriptor, with an
open/read retry branch. It separately opens `/sys/devices/platform/d5_tsu/isp`
and `/sys/devices/platform/d5_tsu/cpu`, parses their text with `strtol`, and stores
the ISP/CPU cache fields. The sensor value is computed from the thermister data
using arithmetic including a square root. Numerical calibration, units and all
buffer/failure branches have not been validated as a physical measurement model.

In the packaged kernel, probe `0xc06d5d78` calls `misc_register` for the object
at `0xc071b290`, whose name string is `drime5-thermister` and whose file-operation
table is `thermister_fops` at `0xc0586110`. That table binds read handler
`0xc027b064`. The probe also calls `device_create_file` for attribute record
`0xc071b280`, named `cmos_thermister`, with show handler `0xc027b01c`.

The read body tests its ADC-client state and requested count, samples
`drime5_adc_raw_read_hax` on channel 7 ten times, maintains sample words and a
cached average, and copies `0x28` bytes to userspace on its normal copy path.
The attribute show body formats the cached word at global base `0xc075368c`
plus `0x34`; it does not perform a new ADC read in that body. These bytes establish
the intended device-name/read-size correspondence. The cached attribute word,
ADC words and app-converted Sensor value must not be treated as interchangeable
temperatures or assumed to share Celsius units.

## Threshold configuration and level-change filter

Initialize fetches words through `dfms_get_adjdata` with base argument
`0x85600000`. The selected IDs and destination fields are concrete:

| Setting | Adjustment ID | Thermometer object field |
|---|---|---|
| Mode selector | `0x91` | `+0x58` |
| Sensor lower / upper | `0x95` / `0x99` | `+0x6c` / `+0x7c` |
| CPU lower / upper | `0x9d` / `0xa1` | `+0x74` / `+0x84` |
| ISP lower / upper | `0xa5` / `0xa9` | `+0x78` / `+0x88` |

The actual words and their provenance/units are not read from a device or
reconstructed here. The diagnostic says recording limits are disabled when the
mode word is zero; this log does not prove all runtime behavior for that mode.

`get_level` (`0x46f8`) uses signed comparisons against fields
`+0x6c+4*type` and `+0x7c+4*type`: below lower returns 0; at/above lower but below
upper returns 1; at/above upper returns 2. In the inspected update body, defined
mode cases select Sensor (1), CPU (2), ISP (3), or the greater CPU/ISP classified
level (4). The disabled/default path and every error case remain separate review
questions; inferred uninitialized-register C is not assigned a fabricated meaning.

After a candidate is produced, a changed candidate updates `+0x90` first. Only
when a later evaluation matches `+0x90` and differs from published `+0x8c` does
the body update `+0x8c` and call `csensor_module::send_callback` with code 0 and
the level. This is a consecutive-evaluation filter. Polling cadence and callback
delivery are not established, so no debounce duration is inferred. The mutex
wrappers at `0x3838/0x3840` are real pthread lock/unlock calls; full failure-path
lock/resource lifecycle and partial reads still need review.

## Generic OEM wrappers and power setters

These separately selected plugin functions delegate to `sys_get_int`:

| Original code VA | Function/path |
|---|---|
| `0x5384` | temperature value: `/sys/devices/platform/sec-thermistor/temperature` |
| `0x5394` | temperature ADC: `/sys/devices/platform/sec-thermistor/temp-adc` |
| `0x5368` | battery temperature: `/sys/class/power_supply/battery/temp` |
| `0x55a0/0x55b0/0x55c0` | MICOM body battery volt/SOC/detect nodes |
| `0x5530` | `/sys/devices/platform/micom-ctrl/bat_event_flag` |
| `0x51a0/0x50b0` | `/sys/power/bootmode` and `/sys/power/wakeup_src` |

Their names and paths do not establish which nodes exist on the active kernel or
which caller uses them. In particular, the selected app thermometer path above
uses the thermister device and TSU nodes; it is not silently replaced with this
generic `sec-thermistor` route.

Plugin setters `0x57dc/0x57ec` delegate values to `sys_set_int` for
`/sys/devices/platform/d5-keys/shutdown` and `/sys/devices/platform/d5-keys/1shot`.
`sys_set_int` (`0x4a80`) formats an integer and calls its string-write helper.
This identifies a static request endpoint, without proving final power-off,
recording completion, filesystem persistence or the caller's checked result.

## Reproduction and remaining evidence

```sh
PYTHONPATH=.work/python python tools/firmware/selected_elf_evidence.py \
  --root .work/run008 --output analysis/evidence/thermal-userspace-run008.json \
  --relocation-term thermometer --relocation-term sensorapi \
  --relocation-term sys_get_int --relocation-term sys_set_int \
  --string-term /sys/ --string-term /dev/drime5 --string-term temp_level
PYTHONPATH=.work/python python tools/firmware/thermal_kernel_evidence.py
```

Remaining work is concrete: trace adjustment-data provenance and values, validate
temperature conversions and short/error reads, correlate callback registration
with UI state and recording-stop/shutdown consumers, establish polling/order,
and review lock/resource failure paths. Active kernel and sensor observations
would be separate evidence. No threshold, calibration or camera firmware was
modified.
