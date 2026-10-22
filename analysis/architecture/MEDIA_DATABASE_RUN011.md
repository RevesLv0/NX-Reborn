# Media registration and DCF ownership — RUN011

The camera's DCF file list and the platform media database have separate owners.
`libfilelist-manager.so` builds and mutates a directory-backed DCF index;
`libcapi-content-media-content` and `libmedia-service` implement media-row
registration, refresh, deletion and notification. A filename reservation or a
database notification is not a checked capture-write result.

## Sources and evidence boundary

| Original rootfs source | SHA-256 |
| --- | --- |
| `/usr/lib/libfilelist-manager.so` | `112671b699b07e58b4221d8b654ea6f35b48a43059091bab4f69923484c8e357` |
| `/usr/lib/libmedia-service.so.1.0.0` | `11a07486570485e865050c82ee743e5528e366e0e45d70191a4149f76e8f0214` |
| `/usr/lib/libcapi-content-media-content.so.0.2.108` | `a626848eb85966888ebc9b54c42197b07c3fd78b276328603b7cf0e0bf67b1ce` |
| `/usr/apps/com.samsung.di-camera-app/bin/di-camera-app` | `55dcc78143724435a2e38b9e0d809960bd728668634bbcf7532ce137f882eb04` |

Each source is checked against the complete filesystem inventory's independently
dumped source SHA and the original extracted bytes. The three libraries add
vendor implementation coverage; the camera application supplies linked caller
evidence. Ghidra projects and exports remain under the exclusive
`NX500_RUN011_MEDIA` project and ignored `.work/run011/media` workspace.
All code addresses below are **original ELF VAs**. DSO selected C uses Ghidra
addresses with `0x10000` added; original instruction records and PT_LOAD file
offsets in [the evidence](../evidence/media-database-run011.json) remove that
rebasing. Thumb function pointers retain bit zero in ELF relocations; code
addresses clear it. No target binary was executed or device accessed.

Eight exports validate against their source SHA and exact run IDs, with 68/68
selected attempts completed, no selected decompiler failure or budget omission,
and 11,409 original instruction records with no decoder failure. Three library
imports completed analysis without timeout. The application import reached its
explicit 180-second analysis limit; its seven selected bodies still completed.
Later named-program reexports used `--process --recursive-process
--skip-analysis`; their disabled analysis is not a recovery of the timed-out
application analysis. Six completed runner receipts retain this distinction.
All runs used one CPU, 1024M Java heap and at most one owned headless process.

## DCF list: filesystem enumeration and local item state

`CSFileList::Listup` (`0x10e18`) constructs a `CSDCFList`, supplies its base URI
and series/non-DCF settings, calls its `Listup`, saves the resulting count and
sets its local readiness word `+0x234` to one. Its filesystem adapter
`PCSDCFFSIO::Open` (`0x130e4`) calls `scandir64`, with separate filters for the
flag and a path containing `Camera`; `Read` (`0x1318c`) returns directory-entry
names and consumes the allocated entries. The linked implementation uses DCF
items and C++ deque/vector state. This is actual directory/list code, and its
declared dependencies do not include SQLite.

`CSFileList::GetNewFileName` (`0x1208c`) selects `JPG`, `SRW`, `MPO`, `MP4` or
`AVI` for the reviewed numerical type branches, chooses naming components and
delegates to `CSDCFList::GetNewFileName`. It then updates its cached count.
`CSDCFList::AddPhotoMetadata` (`0xc080`) finds directory/file indexes and calls
`CSDCFDir::setPhotoData`; this is a DCF item metadata update, not SQL insertion.

The item is added **during filename allocation**. `CSDCFList::GetNewFileName`
(`0xdd6c`) checks the 100,000-item bound, gets the next index and calls
`GetNewFileIndex_SetInfo` (`0xa55c`). That helper formats the name, obtains a
timestamp, calls `CSDCFDir::AddHead` (`0x7bc0`), formats the full pathname and
increments the list's count at `+0x98`. `AddHead` constructs a `DCFItem` and
pushes it to the directory deque. The caller subsequently backs up the series
value and selects the current file. This sequence does not await a file-write
completion. The constructor (`0x12480`) supplies `/mnt/mmc`, `PHOTO` and `SAM_`
defaults and installs the `CSFileList` vtable; defaults do not prove mounted or
writable storage.

App wrapper `UI_Filelist_Management_Get_New_Photofile_Name` (`0x1ce9cc`)
selects virtual `+0x5c` for its new-file branch and `+0x60` for its latest-name
branch. It maps the supplied photo type to the library's numerical type.
`UI_Filelist_Add_PhotoMeta` (`0x1d0498`) copies selected image-info fields into
a local record and calls virtual `+0xb8`. Thus filename allocation and metadata
addition have separate concrete app/library boundaries. App
`UI_State_Common_Filelist_Get_New_Photofile_Name` (`0x121670`) also has alternate
temporary/sample-image branches, including `/tmp/RAMDISK.JPG` and
`/tmp/DEMO.JPG`; the DCF path is conditional, not universal.

The app's installation sequence is concrete. `UI_State_Common_Filelist_Init`
(`0x120434`), when its no-card check permits, calls management Create and
Get_File_List; the latter stores `CBIFileListManager::GetFileList()` into
`gDcfList`. Library `CBIFileListManager::Create` (`0x6480`) constructs the
`CSFileList` object described above. App initialization then registers photo
metadata reading, lists the directory and installs
`UI_State_Common_Filelist_Get_New_Photofile_Name` through
`UI_Mm_Photo_Register_Get_File_Name` (`0x1dc294`) and imported
`mm_photo_register_get_file_name`. Separate wrapper
`UI_Mm_Photo_Register_Add_Key_Info` (`0x1dc2a0`) supplies concrete
`UI_Filelist_Add_PhotoMeta` (`0x1d0498`) to imported
`mm_photo_register_add_image_metadata`. The no-card branch still installs
those two callbacks. The app PLT relocations preserve both import bindings.

The original `R_ARM_ABS32` relocations establish a concrete interface table at
`_ZTV10CSFileList` (`0x1d670`, address point `0x1d678`). Relevant slots are:

| Offset from address point | Intended ELF target |
| --- | --- |
| `+0x10` | `CSFileList::Listup`, Thumb pointer `0x10e19` |
| `+0x18` | `CSFileList::Delete`, Thumb pointer `0x11485` |
| `+0x5c` | `CSFileList::GetNewFileName`, Thumb pointer `0x1208d` |
| `+0xb0` | `CSFileList::RegisterPhotoMetadataCB`, Thumb pointer `0xe9b9` |
| `+0xb8` | `CSFileList::AddPhotoMetadata`, Thumb pointer `0xe9a1` |

The raw on-disk table words are zero before relocation. The relocation symbol
and value, rather than those raw zeros or demangled names alone, establish these
bindings. Runtime loader interposition and replacement of the app's object
pointer are not observed.

## Delete results and file-list state can diverge

The reviewed `CSDCFList::Delete(char*)` (`0xc23c`) skips a protected item;
otherwise it requests removal of the item and optional companion object,
removes the item from its in-memory directory and optionally removes an empty
directory. The removal calls' results are not tested before the list mutation.
`PCSDCFFSIO::RemoveFile` (`0x13278`) calls `unlink`; only a result of `-1`
causes a fallback `remove`. `CSFileList::Delete` (`0x11484`) subsequently refreshes
its count and calls `sync`. This describes index/delete control flow, not proof
that a particular physical deletion completed. The same distinction applies to
selected/all-item deletion paths and their later `sync` calls.

## Platform database registration and error boundaries

`media_content_scan_file` (`0x1bca4`) validates the path and calls
`g_file_test(path,0x10)`. The absent-path branch calls
`media_svc_delete_item_by_path`. A regular-file branch checks ignored-directory
and storage-type rules, checks database membership, then refreshes an existing
item or immediately inserts one when the existence query returns `-0x6c`.
It converts the service result through `_content_error_capi`. An insert result
`-0x6d` is logged as an already-inserted case and changed to zero locally.
This branch does not encode a proof of the originating capture's outcome.

`media_info_insert_to_db` (`0xb260`) has the same membership/insertion split and
then retrieves a media-info object from the DB. `media_info_delete_from_db`
(`0xb6ac`) maps a media UUID to a pathname using the exact query
`SELECT path FROM media WHERE media_uuid='%q'`, then delegates to the service.

`media_svc_insert_item_immediately` (`0x4b90`) builds media information,
extracts image/media metadata, obtains a folder ID, optionally requests a
thumbnail and calls `_media_svc_insert_item_with_data` (`0x8688`). Only a zero
local insertion result reaches the diagnostic `Insertion is successful` and
`_media_svc_publish_noti`. The insertion helper constructs `INSERT INTO media`
with explicit UUID, pathname, filename, size/time, folder, metadata and other
columns, then either submits SQL or appends it to a query list. The selected
query is evidence for the **`media` table**, not a claim that a row exists in
the extracted factory image or on a running camera.

`_media_svc_create_media_table` (`0xa854`) supplies the literal table name
`media` to a `CREATE TABLE IF NOT EXISTS` template with primary-key
`media_uuid`, unique nonnull `path`, nonnull `file_name` and `folder_uuid`, plus
metadata/size/time/validity fields. `_media_svc_sql_query` (`0x9d40`) forwards
the SQL text to imported `media_db_request_update_db` and converts the result.
The per-process notification helper (`0x105f0`) passes `getpid()`, operation,
path and metadata to imported `media_db_update_send`; it distinguishes that
send's local zero/nonzero result. The immediate-insert caller does not replace
its insertion result with that notification-send result.

`_media_svc_delete_item_by_path` (`0x7ba4`) constructs
`DELETE FROM media WHERE path='%q'`. Its outer service function (`0x5e38`)
retrieves type/thumbnail/notification information, checks the DB-deletion
result and publishes a deletion notification only on its zero branch. It can
then remove a nondefault thumbnail. This DB deletion function does not remove
the original media pathname in the reviewed body; physical DCF deletion has a
separate implementation above.

The library contains `/opt/usr/dbspace/.media.db` at original VA `0x189a0`.
Its selected consumer `_media_svc_personal_data_backup` (`0xb824`) formats
`ATTACH DATABASE '%s' AS mediadb` with that pathname, then copies
`mediadb.media` rows restricted to `/opt/storage/PersonalStorage%` into another
connection's `main.media`. This establishes a concrete DB filename and table
use in the personal-storage backup operation. It does not establish the normal
connection implementation: `media_svc_connect` (`0x4094`) delegates to external
`media_db_connect` in the media-utils neighborhood. Effective runtime DB
placement and connection/transaction service ownership need that dependency's
body. The full source inventory contains no regular file with `.media.db` in
its pathname, so no factory media-row snapshot is asserted.

## Asynchronous scan completion and configured services

`media_content_scan_folder` (`0x1c09c`) allocates an eight-byte callback/context
record, stores the supplied callback and data, and passes its concrete wrapper
`_media_content_scan_cb` (`0x183c8`) to the imported
`media_directory_scanning_async`. The wrapper forwards the result word at
request object `+4` to the installed callback with its saved user data and frees
the record. This result is an asynchronous scanner boundary, independent of the
photo file-save callback. The selected request function converts immediate
submission errors; the lower transport and all cancellation paths remain open.

DB-update subscription has its own concrete registration:
`media_content_set_db_updated_cb` (`0x1c230`) stores callback/context in a
two-word record and calls imported `media_db_update_subscribe` with
`_media_content_db_update_noti_cb` (`0x18384`). That wrapper forwards fields
to the installed callback with a literal leading zero and saved user data.
Its inferred signature requires ABI care; the zero must not be renamed
successful-capture status. This update subscription and asynchronous folder
scanning use different wrappers and records.

Source-verified configuration names `libmedia-content-plugin.so` in
`/usr/etc/media-server-plugin`. The media-server unit requests
`/usr/bin/media-server`, requires/starts after `icd.service` and specifies
restart behavior; media-scanner's unit requests `/usr/bin/media-scanner`.
The selected CAPI and service libraries do not establish that these services
started, which plugin was loaded at runtime, or the complete request protocol.

## Capture completion remains a separate contract

The [RUN006 storage](STORAGE_ERRORS_RUN006.md) and
[app consumer](APP_ERROR_CONSUMERS_RUN006.md) reports retain the verified
worker/callback boundary: local skipped/failed writes and cancellation can
converge on the same file-worker callback, while the app has a separate
mm-camera skipped-write accounting entrance. No DCF item or media-row evidence
changes that conclusion. Pending worker count zero, delivered app callback,
list metadata, DB registration and successful persistence remain distinct
facts requiring their own evidence.

The newly selected app photo completion and `UI_Capture_File_Write_Done`
bodies do not directly undo the filename reservation. This is a bounded caller
observation: it does not prove that no other callback, relist or cancellation
path can rebuild or alter the list. Complete rollback ownership and correlation
between a specific reserved item, skipped-write notification and SIF completion
remain unresolved.

Reproduce with
`PYTHONPATH=.work/python python tools/firmware/media_database_evidence.py`.
[The run manifest](../../manifests/ghidra-media-run011.json) preserves commands,
input records, receipts, validated summaries and output hashes;
[the bounded review](../../manifests/review-media-run011.json) identifies the
reviewed claims and remaining limits. No SQL statements were executed against
an original or copied database in this task.
