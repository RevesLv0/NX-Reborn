# Full-source Ghidra expansion — 2026-10-21

The newly reconstructed firmware makes eight additional ELF programs available for this
survey. They were imported into a separate `NX500_FULL_RUN002` project and statically
auto-analyzed with Ghidra 12.1.4 and JDK 21.0.12.1+1. The existing run001 projects were
preserved. No extracted program was executed and no camera was accessed.

Input chain: BIN SHA-256
`f4c238e811970cf858b5d734119477ea191d35cd29d9f84b584157ecfc4ee997` → rootfs SHA-256
`9c66f76f3124acb3b8d0c31374ca209d333fcb76267bb86ed9bc18c9e8ea73f7` → per-ELF hashes
and export artifact hashes in `manifests/ghidra-expanded-summary.json`.

## Scope and validation

| Original rootfs path | Function entries | Initial selected decompilation |
|---|---:|---:|
| `/usr/apps/com.samsung.smart-wifi-app/bin/smart-wifi-app` | 3,522 | 8/8 |
| `/usr/bin/allshare-svc` | 803 | 2/2 |
| `/usr/bin/allshare-dms` | 282 | 0/0 |
| `/usr/lib/libdi-network-dlna-api.so` | 1,426 | 7/7 |
| `/usr/lib/libdi-network-dlna-extlib.so` | 1,217 | 7/7 |
| `/usr/lib/libdi-network-dlna-stack.so` | 5,561 | 8/8 |
| `/usr/lib/libdeviced.so.0.1.0` | 161 | 3/3 |
| `/usr/lib/libdevice-node.so.0.1` | 309 | 2/2 |

Initial exports contain 13,281 function entries and 21,045 defined string entries. All
eight exports passed schema-v2 artifact hash, byte length, row count and run-ID checks.
Initial selected decompilation was 37/37 complete; two subsequent targeted exports added
six distinct smart-wifi functions, giving **43/43 selected decompilations**. No initial
auto-analyzer timed out at the 120-second per-file limit. The initial pattern matched
11 additional functions omitted by the eight-function per-file budget.

The counts include thunks, imported stubs, inferred functions and metadata strings. They
are not feature counts or a percentage of semantic coverage. The followups re-exported
the same eight programs with analysis disabled; their function/string counts must not
be added again. `allshare-dms` had no function matching the bounded selection pattern,
so its import and auto-analysis did not include selected decompilation.

Missing external DWARF and incomplete demangled vtable application were logged. A full
transitive dependency environment was not loaded. External/PLT names and direct call
edges do not establish runtime binding, indirect calls, ABI correctness or device behavior.

## Newly reproduced static findings

### SD/media paths depend on a runtime configuration value

Input `/usr/lib/libdeviced.so.0.1.0`, SHA-256
`df70b308f88d6c0eb038e2e67b69b4825ef12dec60230b6fd1c3dab942989f5d`.

`storage_get_path` starts at ELF VA/file offset `0x3a50` (772-byte symbol). At ELF
`0x3acc`, a `BL 0x1588` reaches the `vconf_get_int` PLT entry. Ghidra string references
at ELF `0x3ac0`/`0x3ac4` identify `db/deviced/mount_path_option`, whose string is at
ELF `0x9014`. The function branches using the returned value and requested storage
type, with references to `/opt/storage/sdcard`, `/mnt/mmc` and `/opt/media`.

Independent Capstone symbol disassembly agrees on the callsite; the complete listing is
in `.work/run002/storage-get-path-capstone.json`, with selected instructions and its hash
recorded in the tracked summary. Consequently, a hard-coded SD mount path cannot be
derived from this function alone. The actual NX500 configuration value remains unobserved.

### Selective push first submits an internal message

Input `/usr/apps/com.samsung.smart-wifi-app/bin/smart-wifi-app`, SHA-256
`1a3cd718c3554bc1f4ad53e6eb602176a7b3616a6d92699eea848309b3953b87`.

`CUSLNetworkSmartphoneLink::SelectivePushSendFile` starts at ELF VA `0x63e6c`, file
offset `0x5be6c`. At `0x63f24` it loads `r0 = 0x753`; at `0x63f28` it calls
`CSNetworkAPI::NetworkAPI` at ELF `0x59984`, passing the supplied pointer as the second
argument and zero for the third/fourth arguments. Capstone independently agrees with
the register setup and direct call.

Targeted decompilation plus corresponding instructions show these stages:

1. `NetworkAPI` (`0x59984`) dispatches directly through `handle` when its fourth argument
   is nonzero; the zero branch invokes `sendMsg` (`0x580d4`).
2. `sendMsg` calls `msgctl` and `msgsnd`, sending eight payload bytes with flag `0x800`.
   `NetworkAPI` returns zero for successful submission and two for a negative send result.
3. `getMsg` (`0x57f90`) uses `msgrcv`; the network task `t_Main` (`0x59bb8`) receives
   a message and calls `handle` (`0x597e8`).
4. `handle` routes the `0x700` command group to `handleSmartphoneLink` (`0x59068`),
   whose `0x753` branch calls the imported `DlnaSelectivePush_SendFile`.

Thus this initiating wrapper's success return describes the internal submission path;
it does not establish completed remote transfer, original-file bytes or camera resource
release. These numeric commands are internal program messages, not an identified network
wire protocol. Object layout and full source-level signatures remain inferred.

### Submission, scan cancellation and transfer stopping are distinct code routes

Input `/usr/lib/libdi-network-dlna-api.so`, SHA-256
`cdd6ffee8b95ab688fb4180ae473feca557317af1310447cc80869c2c737dac1`.

`DlnaSelectivePush_SendFile` starts at ELF `0x20dc0`. Its callsite `0x20ea8` invokes
the `SPTransferFile` PLT entry (`0xef58`); instruction `0x20eac` then sets `r0 = 1`
without inspecting a transfer result. The ELF also defines `SPTransferFile` at `0x583ac`,
whose body remains a next analysis target. This wrapper cannot prove completed transfer.

`DlnaDmsCancel` (`0x16270`) calls the imported
`DataBaseMgr::CancelInvalidateAllItems` and `DirectoryScanner::CancelScanDirectory`,
writes a flag, and returns one. The inspected function provides no completed-transfer
or resource-release acknowledgement.

In the same smart-wifi input identified above, `handleSmartphoneLink` (`0x59068`) has
separate command branches:

| Internal command | Called API |
|---|---|
| `0x705` | `DlnaDmsCancel` |
| `0x753` | `DlnaSelectivePush_SendFile` |
| `0x762` | `DlnaSelective_NPush_StartFileTransfer` |
| `0x763` | `DlnaSelective_NPush_StopFileTransfer` |

The static distinction prevents treating every function named “cancel” as equivalent.
The NPush start/stop implementation and any acknowledgement or quiescence condition
still need analysis; no resource-release behavior is asserted here.

## Reproduction and next work

The initial bounded command and all input/output hashes are in the tracked summary's
run receipt references. Local outputs are `.work/run002/outputs/ghidra`; targeted
outputs are `.work/run002/followup-recursive/outputs/ghidra` and
`.work/run002/message-route/outputs/ghidra`. The database is
`ghidra-projects/NX500_FULL_RUN002.{gpr,rep}` and may be archived only after analysis exits.

An initial single-basename `--process` attempt failed because the programs live under
the Ghidra `/inputs` folder. Its failure receipt remains in `.work/run002/followup/logs`.
Directory processing with `--process --skip-analysis` adds recursive lookup and succeeded.
The failure is not counted as a successful export or a decompiler failure.

Next inspect `SPTransferFile`, the NPush start/stop implementations and their callbacks,
then correlate caller state with capture/AF, SD writer and power management paths. The
present work maps static control flow; shutter/transfer coexistence and cancellation
completion remain device questions.
