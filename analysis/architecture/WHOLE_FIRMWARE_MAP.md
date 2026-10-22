# NX500 whole-firmware navigation map

Latest update: RUN010 retains the verified full BIN, sections and 17,394-path
filesystem inventory (1,956 ELF paths / 1,895 unique contents), and extends the
loaded-program survey to 43 contents. Selected C and bounded semantic review are
separate stages. See [current status](../../docs/STATUS_20261022_RUN010.md),
[boot/services](BOOT_SERVICES_20261021.md), and [expanded Ghidra survey](EXPANDED_GHIDRA_20261021.md).
The navigation entries below preserve the first-run evidence levels; their `Next retrieval`
items are now available locally and require semantic inspection. They must not be read
as current download blockers or runtime facts.

Status of the following baseline map: initial offline map, 2026-10-21 run001.

## Evidence contract and coverage

Every evidence statement below uses one of these labels:

- **[H: inherited-path hint]**: a path, symlink, or name in the inherited filesystem JSON listings. It identifies a retrieval candidate, not verified contents or active device behavior.
- **[D: verified dependency]**: `DT_NEEDED` recorded from a selected ELF whose measured SHA-256 matches its input manifest. This proves a declared library requirement, not runtime resolution, a function call, or a startup relationship. An unselected library's implementation remains unverified.
- **[S: actual static result]**: inspected configuration/script bytes, discovered symbols, direct-call export, or selected decompiled body from a completed Ghidra export. Symbol names and decompiled expressions are distinguished from understood behavior. None is device observation.

**[H]** `rootfs_tree.json` has 16,020 entries and `opt_tree.json` has 1,374 entries. These are inherited listings, not newly extracted files. Opt listing paths are partition-relative: e.g. opt `/pref/default/pref_sysrw.bin` must not be silently confused with rootfs `/pref`, whose listed symlink points to `/opt/pref`. The underlying firmware ZIP/BIN hashes in `docs/FIRMWARE_RESEARCH.md` remain inherited baseline values; this map does not promote them to independently verified full-firmware hashes.

**[D]** The current selected inventory contains 29 manifest-matching files, including 13 ARM32 little-endian ELFs; `dependency_edges.json` contains 251 declared edges. This is a small selected corpus, not 29 newly extracted files from a newly verified whole image. Source identifiers and hashes are recorded below.

**[S]** Only Ghidra directories containing `summary.json` were consulted. The source records identify Ghidra 12.1.4 / JDK 21 in the reproduction instructions. Exports are auto-analysis with bounded selected decompilation, not full semantic verification. Shared objects in this export use Ghidra base `0x10000` with original ELF base `0`; executables generally retain `0x8000`. Static code anchors below explicitly use **original ELF virtual addresses**, not file offsets. `nfc-manager-daemon` is another rebased object (see its summary). No overlay/OTHER-space string addresses are used; their derived ELF VAs are not reliable in the earlier exporter. No firmware program was executed for this map.

## Subsystem navigation

Grouping paths under a subsystem is a research filing choice; file naming alone does not establish their functional responsibilities.

### Boot, update and recovery

- **[H]** Rootfs lists `/sbin/init -> /usr/lib/systemd/systemd`, `/initrd/sbin/init`, `/etc/fstab`, `/etc/systemd/system/opt.mount`, `/etc/systemd/system/opt-usr.mount`, and `/usr/lib/systemd/system/tizen-init.target`. Rootfs `/boot` has no child file in this listing. The bootloader/kernel/partition layout must be recovered from the complete image separately; no boot sequence is established here.
- **[H]** Update candidates include `/usr/sbin/fw_upgrade`, `fw_upgrade_start`, `fw_upgrade_display`, `fw_upgrade_display.sh`, `/usr/lib/libfirmware-upgrade.so`, `/usr/lib/systemd/system/firmware-upgrade-display.service`, and `firmware-upgrade-display.path`.
- **[D]** Camera UI `E01` declares `libfirmware-upgrade.so` and `libsystem-tools.so`. Selected updater `E11` declares libc/pthread/runtime dependencies; selected recovery UI `E12` declares `libcairo.so.2`. These edges do not explain authorization, image verification, flash layout, or invocation conditions.
- **[S]** `E11` has discovered functions named `fw_emmc_flash_upgrader` at ELF VA `0xca74` and `fw_mtd_flash_upgrader` at `0xd224` (`functions.jsonl`). They are static navigation anchors only: no selected decompilation completed for this file.
- **[S]** Script `C01`, lines 7–29, searches `/sys/class/input` names for `gpio-keys` / `qpnp_pon`, constructs `/dev/input/event…` arguments, and invokes `/usr/bin/system-recovery`. This is script content, not proof that these names exist on NX500 hardware or that the script is reached. `E12` has a completed `main` decompilation at ELF VA `0x9760` with calls including `fb_set_info` and `fb_open`; the complete recovery/flash path remains pending.

**Next retrieval [H]**: `/initrd/sbin/init`, `/usr/lib/systemd/systemd`, `/etc/fstab`, `/etc/systemd/system/opt.mount`, `/etc/systemd/system/opt-usr.mount`, `/usr/sbin/fw_upgrade`, `/usr/sbin/fw_upgrade_start`, `/usr/sbin/fw_upgrade_display.sh`, `/usr/lib/libfirmware-upgrade.so`, and both firmware-upgrade-display units. Retrieve all firmware container section descriptors, boot/kernel/recovery sections, and partition metadata before claiming whole-image coverage.

### OS, services and IPC

- **[H]** Service/IPC candidates include `/usr/bin/starter`, `/usr/bin/dbus-daemon`, `/usr/bin/deviced`, `/usr/bin/resourced`, `/usr/lib/systemd/system/di-camera-app.service`, `starter.service`, `deviced.service`, `dbus.service`, `connman.service`, and `/etc/dbus-1/system.conf`. A listed symlink `/usr/lib/systemd/system/default.target.wants/di-camera-app.service -> ../di-camera-app.service` is an inherited enablement hint, not a reproduced startup graph.
- **[D]** `E01` declares D-Bus (`libdbus-1.so.3`, `libdbus-glib-1.so.2`, `libedbus.so.1`), `libvconf.so.0`, `libaul.so.0`, `libbundle.so.0`, `libss-client.so.1`, and device-node/device-service libraries. `E02` and `E04` also declare `libmulticore-bridge.so`; this identifies an important unexamined boundary without establishing its protocol or processor topology.
- **[S]** Selected NFC unit `C02`, lines 3–4, contains `After=system-server.service` and `Requires=system-server.service`; line 8 declares `/usr/bin/nfc-manager-daemon --daemon`. These are configured unit relationships only. The referenced system-server unit has not been verified; this is not evidence that the NFC service actually starts or that the dependency is satisfied.

**Next retrieval [H]**: the named service units and their drop-ins/target symlinks, `/usr/bin/starter`, `/usr/bin/deviced`, `/usr/lib/libmulticore-bridge.so`, `/usr/lib/libdiosal.so`, `/usr/lib/libdevice-node.so.0.1`, `/usr/lib/libdeviced.so.0.1.0`, `/etc/dbus-1/system.conf`, and `/etc/dbus-1/system.d/` contents. Then map socket names, D-Bus policy/activation, and IPC call sites with byte-level evidence.

### Capture, AF and lenses

- **[D]** UI `E01` declares capture library `libcapture-fw-prod.so`; capture `E02` declares `libuser-spec.so`, `libprefman.so`, `libface.so`, `libpalm.so`, `libdevice-node.so.0.1`, `libdiosal.so`, and `libmulticore-bridge.so`. Photo `E04` also declares the capture library. This establishes a selected dependency hub, not a capture state machine.
- **[S]** `E02` `CCapCmdExtIf::GetLensReady`, ELF VA `0x62fec`, reads `pref_rtos_get_ulong(0xd28)` and compares to `0x330033`; `GetLensAttach`, `0x63068`, compares the same preference result to `0x11223344`. `GetLensData`, `0x630e4`, requests `pref_rtos_get_bytes(0x20, destination, 0x40)` when the destination is non-null. These observed expressions do not identify preference storage, freshness, lens bus format, or valid caller contracts.
- **[S]** `E03` contains a completed decompilation named `sdic_fd_tracking_run_mainface` at `0x40270` and selected face-enrollment functions at `0x506d4`, `0x5094c`, `0x50e5c`. Names provide face-processing research anchors; AF policy, face-to-focus coupling, recognition behavior, and supported device features are not established.

**Next retrieval [H]**: `/usr/lib/libprefman.so`, `/usr/lib/libuser-spec.so`, `/usr/lib/libmulticore-bridge.so`, `/usr/lib/libdevice-node.so.0.1`, `/usr/lib/libpalm.so`, `/usr/lib/libdi-sensor.so`, `/usr/lib/libdiosal.so`, and opt `/pref/default/pref_sysrw.bin`. Next static work on existing `E02`: follow `ControlLens` (ELF VA `0x43db4`), preference consumers/writers, callback registration, and unresolved indirect calls before describing AF or lens commands.

### Still images, raw, JPEG and metadata

- **[D]** Photo `E04` declares `libsif.so`, `libudd5.so`, `libdi-alg-ipplatform.so`, `libredeye.so`, `libface.so`, `libmm-displayer.so`, capture/device/bridge libraries; SIF `E13` declares `libudd5.so`, `libmm-type.so`, and OS/logging libraries. This is the strongest currently selected still-image neighborhood.
- **[S]** `E04` `ImageGenerator::runFromCapture`, ELF VA `0x96684`, has exported direct calls to import stubs named `DscImage::Notify` (`0x2bef8`), `DscImage::SaveExifImage` (`0x2e694`), and named parser thunks `CaptureDataParser::convertRaw` (`0x2a878`) / `convertExif` (`0x2a350`). These are within-program edges to stubs/thunks, not a fully resolved cross-library dataflow. `DT_NEEDED(libsif.so)` and a same-named SIF function do not by themselves prove the runtime target.
- **[S]** `E13` `DscImage::Notify` at `0x89e00` writes callback/argument fields selected by an event switch; `DscImage::JpegDoneEx` at `0x7cef0` conditionally invokes a function pointer. `DscOsalFile::close` at `0x5ad4c` calls `fclose` when its stored handle is nonzero and clears that field. These narrow results show callback/file abstractions, not the complete JPEG/SRW encoder implementation.
- **[S]** `E13` `DscJPEG::taskMain` at `0x3649c` timed out during selected decompilation. Its absence from successful C output is a recorded analysis failure, not absence of code. Raw encoding/packing, calibration, sensor format, buffer ownership and completion ordering remain unresolved.

**Next retrieval [H]**: `/usr/lib/libudd5.so`, `/usr/lib/libdi-alg-ipplatform.so`, `/usr/lib/libmm-type.so`, `/usr/lib/libredeye.so`, `/usr/lib/libjpeg.so.8.0.2`, `/usr/lib/libturbojpeg.so`, and `/usr/lib/libmmutil_jpeg.so.0.0.0`. Next work on existing inputs: finish SIF JPEG worker with bounded decompiler limits and disassembly; resolve photo import relocations to SIF exports; trace raw parse/metadata/file-write functions separately.

### Video, audio and display

- **[D]** UI `E01` declares `libmmf-camcorder.so`, `libmmfcore.so`, `libmmf_player.so`, `libmm-displayer.so`, `libmmfsound.so.0`, `libavsysaudio.so.0`, `libpulse.so.0`, `libasound.so.2`, `libdrm.so.2`, `libtbm.so.1`, and `libhdmi-cec.so`. Selected camcorder `E05` declares `libmmfcore.so` plus C/runtime libraries. Its summary reports zero selected decompilations; its semantic role is not recovered.
- **[H]** Rootfs lists `/usr/lib/libmmfmodules.so`, `/usr/lib/libmmfosal.so`, `/usr/lib/gstreamer-0.10/libgstdrime5sink.so`, `/usr/lib/gstreamer-0.10/libgstencodebin.so`, `/usr/lib/gstreamer-0.10/libgstisomp4.so`, `/usr/lib/libavcodec.so.54.59.100`, `/usr/lib/systemd/system/pulseaudio.service`, and `sound-server.service`. Their presence does not prove a particular recording pipeline, codec, frame rate, resolution, bit rate, or HDMI behavior.
- **[H]** Camcorder INIs are listed under rootfs `/usr/etc/` and opt `/etc/`. Their effective precedence and plugin loading still need independent analysis.

**Next retrieval [H]**: `/usr/lib/libmmfcore.so`, `/usr/lib/libmmfmodules.so`, `/usr/lib/libmmfosal.so`, `/usr/lib/libmm-displayer.so`, `/usr/lib/libmmf_player.so`, the listed DRIME5/encodebin/MP4 plugins, `/usr/lib/libavsysaudio.so.0` (resolve its listed symlink before retrieval), and pulse/sound units. Compare selected `/usr/etc/mmfw_camcorder*.ini` to newly retrieved opt `/etc/mmfw_camcorder*.ini`; do not assume which copy is consumed.

### Storage, filesystem and media databases

- **[H]** Rootfs lists `/sdcard -> /mnt/mmc`, `/usr/bin/media-server`, `/usr/bin/media-scanner`, `/usr/bin/mediadb-update`, `/etc/deviced/mmc.conf`, `/usr/lib/libfilelist-manager.so`, `/usr/lib/libmedia-service.so.1.0.0`, and media-server/media-scanner units. Opt lists `/dbspace -> /tmp/dbspace`, `/_dbspace/.app_info.db`, and other database files. These entries do not establish mount success, database schemas, journaling policy or update ownership.
- **[D]** UI `E01` declares `libfilelist-manager.so`, `libcapi-content-media-content.so.0`, `libsqlite3.so.0`, and `libSLP-db-util.so.0`; SAP `E08` also declares SQLite/db-util. This identifies overlapping storage dependencies, not a common database or join relationship.
- **[S]** `E01` `UI_Dynamic_Calculate_Remain`, ELF VA `0xd2bb0`, calls `UI_Mm_Camera_Get_Predicted_FreeCardSpace` and `ui_get_image_file_size`, then an integer division helper. The names and arithmetic are static observations; remaining-shot accuracy, reservation policy, and card-error handling need callers and device tests.

**Next retrieval [H]**: `/etc/fstab`, `/etc/deviced/mmc.conf`, `/usr/lib/libfilelist-manager.so`, `/usr/lib/libcapi-content-media-content.so.0.2.108`, `/usr/lib/libmedia-service.so.1.0.0`, media-server/scanner binaries and units, plus opt `/_dbspace/` schema-bearing databases and associated journals as coherent snapshots. Inspect schemas read-only without assuming factory data describes a live device.

### Connectivity: Wi-Fi, Bluetooth, NFC, USB and DLNA

- **[D]** UI `E01` declares Wi-Fi/direct/tethering/NFC libraries, `libdi-network-dlna-api.so`, and BT app `E07`. RVF `E06` declares DLNA stack/extlib/dmsui/api libraries; BT `E07` declares `libcapi-network-bluetooth.so.0`, `libsap-api.so.1`, `libsap-client-stub-api.so.1`; SAP `E08` declares Bluetooth and package/app-framework libraries. This is a navigation graph, not evidence of remotely callable camera controls.
- **[S]** `E06` `RVFAppStart`, ELF VA `0x31f10`, contains a call named `SMPDMSStart`; `RVFCDSActionRequest`, `0x31b10`, obtains `UPnPAppCDS::GetInstance` and invokes a function pointer named `HandleCDSActionRequest`. Accepted actions, request parsing, network binding, authorization and capture behavior remain untraced. RVF naming is not proof of a remote-shutter API.
- **[D]** NFC daemon `E10` declares `libnfc-common-lib.so.1`, `libdl.so.2`, GIO/app-framework/Bluetooth libraries. MTP responder `E09` declares vconf/GLib/thread/runtime libraries. Neither dependency list establishes USB descriptors, endpoints, enabled modes or NFC payload behavior.
- **[H]** Rootfs lists `/usr/sbin/connmand`, `/usr/sbin/wpa_supplicant`, `/usr/sbin/p2p_supplicant`, `/usr/sbin/bluetoothd`, `/lib/modules/bt8887.ko`, `mlan.ko`, `sd8xxx.ko`, `/usr/etc/bluetooth/MRVL_8887.bin`, `/etc/connman/main.conf`, `/usr/etc/wifi-direct/p2p_supp.conf`, and `/usr/apps/com.samsung.smart-wifi-app/bin/smart-wifi-app`. Listing names do not establish active radio support or runtime driver selection.
- **[H]** Precise already-selected configuration entry points are `/usr/share/deviced/usb-configurations/usb-configurations.xml`, `/usr/lib/nfc/nfctag.info`, `/etc/bluetooth/main.conf`, and `/etc/allshare/config/{UPnPConfig.xml,DMS/xml/DeviceDescription.xml,DMS/xml/ContentDirectory_1.xml,DMS/xml/ConnectionManager_1.xml}`. Effective lookup/override behavior remains unverified.

**Next retrieval [H]**: `/usr/lib/libdi-network-dlna-stack.so`, `libdi-network-dlna-api.so`, `libdi-network-dlna-extlib.so`, `libdi-network-dlna-dmsui.so`, `/usr/lib/libsap-client-stub-api.so.1` (retrieve resolved target), `/usr/lib/libcapi-network-bluetooth.so.0.1.61`, `/usr/lib/libnfc-common-lib.so.1` (retrieve resolved target), the listed smart-wifi binary, connman/wpa/BT daemons and configs, and `/usr/lib/systemd/system/allshare-dms.service`. Trace server registration and parser dispatch before documenting any externally usable protocol.

### UI, settings and persistent preferences

- **[D]** UI `E01` declares EFL (`libelementary.so.1`, `libevas.so.1`, `libedje.so.1`, Ecore), X11, `libgui.so`, `libdi-elementary.so`, `libprefman.so`, `libuser-spec.so`, and `libvconf.so.0`. This establishes declared framework/settings dependencies only.
- **[S]** `E01` `UI_Set_Efs_Value_Power_Off`, ELF VA `0xd7270`, reads `UI_Get_Value(0x133)` and `User_Spec_Get_DB_Value(0xa6e0)`, sets UI value `0x1f0`, then calls `User_Spec_Set_DB_Value(0xa6e0, first_value)`. The underlying persistence backend and identifiers' meanings are not established by this function's name.
- **[H]** Adjacent applications are `/usr/apps/com.samsung.di-thumbnail/bin/di-thumbnail`, `/usr/apps/com.samsung.ap-setting-app/bin/ap-setting-app`, and `/usr/apps/com.samsung.app-selector/bin/app-selector`; opt `/pref/default/pref_sysrw.bin` is a settings candidate. Resource names and database defaults do not prove enabled menus or supported settings.

**Next retrieval [H]**: `di-thumbnail`, `ap-setting-app`, `app-selector`, `/usr/lib/libgui.so`, `/usr/lib/libdi-elementary.so`, `/usr/lib/libprefman.so`, `/usr/lib/libuser-spec.so`, opt default preferences, plus selected UI app metadata and Edje resources. Map numeric settings through readers/writers and default tables before naming them.

### Power, hibernation and thermal control

- **[D]** UI `E01` declares `libhibernation.so`, `libsysman.so.0`, `libmicom-node.so.0.1`, `libdevice-node.so.0.1` and `libdeviced.so.0.1.0`. Capture `E02` also declares device/bridge libraries. Actual ownership of shutdown, sensor power, battery monitoring and thermal limits is unresolved.
- **[H]** Rootfs lists `/usr/bin/hibernation.sh`, `/usr/bin/hib_tool`, `/usr/bin/hib_exjob`, `/usr/bin/micom_updater`, `/etc/micom.hex`, `/usr/lib/systemd/system/hibernation.service`, `hib_tmp.service`, `hib_post.service`, `/usr/bin/resourced`, and `/usr/lib/systemd/system/resourced.service`. Listed vconf-like paths include `/var/run/memory/sysman/body_battery_soc` and `battery_status_low`. These are candidates, not live measurements or proven shutdown policies.
- **[S]** UI has selected decompilation `UI_Reset_Power_Timer_Capture_Mode_By_Event` at ELF VA `0xd3c00` with branches on UI values and calls to other UI helpers. It is a timer-policy navigation anchor; no timeout values, temperature thresholds, safe limits or MCU protocol are established.

**Next retrieval [H]**: `/usr/lib/libsysman.so.0.2.0`, `/usr/lib/libhibernation.so`, `/usr/lib/libmicom-node.so.0.1`, `/usr/bin/deviced`, `/usr/bin/hibernation.sh`, `/usr/bin/hib_tool`, `/usr/bin/micom_updater`, `/etc/micom.hex`, hibernation units, `/usr/bin/resourced`, and its unit/configuration. Thermal control remains an explicit coverage gap: identify sysfs/ioctl strings and driver handlers in these bytes and the kernel rather than inventing a dedicated thermal daemon.

## Evidence index

Paths below are original rootfs paths unless marked opt. Input hashes identify selected original bytes, not generated Ghidra databases. For **D**, method is Python/pyelftools 0.32 ELF dynamic-section parsing by `tools/firmware/inventory.py`; no code address applies to a dynamic-section dependency claim. For **S**, consult the matching completed `.work/outputs/ghidra/<basename>-<first12sha>/` file (`summary.json`, `functions.jsonl`, `calls.jsonl`, `decompiled.jsonl`) and the original ELF VAs stated above. Script/config observations use line numbers instead of code addresses. Generated output paths may change on rerun; SHA + binary path + address is the stable locator.

| ID | Original path | SHA-256 |
|---|---|---|
| E01 | `/usr/apps/com.samsung.di-camera-app/bin/di-camera-app` | `55dcc78143724435a2e38b9e0d809960bd728668634bbcf7532ce137f882eb04` |
| E02 | `/usr/lib/libcapture-fw-prod.so` | `a07867292610ac6376e29e3cd64bc79a274452412387fb7853c5a3fb3f96bba5` |
| E03 | `/usr/lib/libface.so` | `f2936a156173d48b1a54a6647da6d169f3bd8276c3d8448eca1f784ddd29047f` |
| E04 | `/usr/lib/libmm-photo.so` | `ea4ae65608a6f9ea0761e35c18764401cf7b876652f7949c322e880fa9f68ca9` |
| E05 | `/usr/lib/libmmf-camcorder.so` | `49f89956d0a09de51656e4427cc960c10d01f4971c39a1b85d19554431c03c78` |
| E06 | `/usr/lib/libdi-network-dlna-rvf.so` | `a7c8f03e4fdcc035762f83a2168efbbb4a4d93ac34802d1d4e097eb74404f567` |
| E07 | `/usr/lib/libdi-network-bt-app.so` | `94a8f7ae05298d9a143d89c3b67cb1141ef3aea7c2cdc0004ef9799cda261eae` |
| E08 | `/usr/lib/libsap-api.so.1.0.0` | `f130d83a9313710104c9c972e4ac3285e7c2b6cd8e7ee40cbce0a77142a96ac0` |
| E09 | `/usr/bin/mtp-responder` | `630d4f6c8beb4008973c2bf3646fa032768e5810d5aa6b673b472330e983409b` |
| E10 | `/usr/bin/nfc-manager-daemon` | `4f71b292ced7180280eb53c87bb52f7e6e188278cfee84ad2b106b45ee219ddf` |
| E11 | `/usr/sbin/fw_upgrade_recovery` | `7bf571fa83ce39f417b0759c024942311e4b1aa6487b46eda9562ae339aef3ff` |
| E12 | `/usr/bin/system-recovery` | `161f5656f5d9e2df53b835dda648ce0c173696dbae5b8a56c61130b7f1f541cb` |
| E13 | `/usr/lib/libsif.so` | `9790fc02fe5b9793fc09da7eb5fd9453c730a55880654c84caf02dd3d1001109` |
| C01 | `/usr/bin/run-system-recovery` | `6e11c6ab41a37856cc0400271b77dd4cf735e34248d8c79d6cf26ae0abf9ab84` |
| C02 | `/usr/lib/systemd/system/nfc-manager.service` | `2bc098524e97bff6dabbe94b99242ed6632646df18c8fd0b9c74311783000162` |

**[H] Inherited listing input hashes** (hash of the listing itself, not proof of its underlying filesystem):

- `.work/legacy/rootfs_tree.json` SHA-256 `8fc8d281b63f1c28f9e956fec8e2968450ea439246b7a692921fc4531edb611a`.
- `.work/legacy/opt_tree.json` SHA-256 `48662e826c378ee888bb641916478ec6e5e41279c577871d4115925779dff1ee`.

**[D] Selected inventory receipts**:

- `.work/outputs/inventory/selected_inventory.json` SHA-256 `e3a2dcad105b90b02c4e1aff9a2089d51b2f5f4eb3d30285e6389a631854a079`.
- `.work/outputs/inventory/dependency_edges.json` SHA-256 `ebc99e5091a010d0242694cb4b0e32d456ac24859624f6ae69ecd5592ebcf25a`.

## Work boundary and next decision

The next high-value retrieval set is the init/mount/service configuration, the capture preference/bridge boundary, `libudd5.so`, the multimedia core/modules, and the DLNA stack/API libraries. These close distinct blind spots: startup configuration, cross-core/device control, still-image implementation, video pipeline construction, and network dispatch. Verify each newly retrieved file against a source receipt before promoting path hints to byte-backed evidence.

No claim here establishes real startup order, on-device successful loading, complete image coverage, sensor/AF algorithms, SRW bit layout, video capabilities, remote API support, security properties, or thermal safety. Those require additional static tracing and, where appropriate, separately authorized device observations. No camera I/O, installation, upload or firmware execution was performed for this map.
