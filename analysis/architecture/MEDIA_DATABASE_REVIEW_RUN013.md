# Independent media database / DCF review — RUN013

The nine bounded claims in `manifests/review-media-run011.json` are supported by the independently checked original bytes. Filename allocation mutates the DCF list before a capture-write completion; the app's callback and virtual-table bindings are concrete ELF bindings; platform media-row operations and their notifications have separate code and callback records. These findings do not establish successful capture, durable storage, a runtime database row, or complete cancellation rollback. No substantive correction to `MEDIA_DATABASE_RUN011.md` is required within this review's scope.

## Inputs and method

| Original rootfs source | SHA-256 | Review alias |
| --- | --- | --- |
| `/usr/lib/libfilelist-manager.so` | `112671b699b07e58b4221d8b654ea6f35b48a43059091bab4f69923484c8e357` | F |
| `/usr/lib/libmedia-service.so.1.0.0` | `11a07486570485e865050c82ee743e5528e366e0e45d70191a4149f76e8f0214` | S |
| `/usr/lib/libcapi-content-media-content.so.0.2.108` | `a626848eb85966888ebc9b54c42197b07c3fd78b276328603b7cf0e0bf67b1ce` | C |
| `/usr/apps/com.samsung.di-camera-app/bin/di-camera-app` | `55dcc78143724435a2e38b9e0d809960bd728668634bbcf7532ce137f882eb04` | A |

The files were read directly beneath `.work/full/extracted/rootfs`, rather than read back from Ghidra. All addresses below are original ELF virtual addresses. Each checked byte range was translated through its original file-backed `PT_LOAD`: `file_offset = p_offset + VA - p_vaddr`, constrained by `p_filesz`. Independent Python/pyelftools and Capstone decoding used ARM mode for selected application bodies and the recorded ARM/Thumb mode for the libraries. Thumb code addresses clear bit zero; ELF function-pointer values preserve it. The decompiled C was navigation material, with instruction/register flow and original relocation records governing the findings.

The scratch reviewer `.work/run013/review-media/audit.py` checked all 68 selected bodies' 11,409 instruction records against original bytes and file offsets and independently decoded each record. These are instruction records, not a claim of 68 contiguous windows: a selected body can include a recovered veneer outside its main range. The reviewer also checked all 183 selected relocations (53 F, 87 S, 37 C, 6 A), including relocation type, symbol, symbol value and original four-byte words; all 103 selected strings; and all three packaged configuration files' hashes and text. Original ARM PLT-veneer arithmetic, including Thumb entry stubs, resolved 1,014 direct call sites to their relocation symbols, counting repeated sites. This broader byte audit does not confer semantic review on every exported function or descendant.

Additional independent PC-relative literal evaluation is saved in `.work/run013/review-media/literals.{py,json}`. Per-body independent disassemblies, copied C navigation text, resolved calls and `audit.json` remain in the same ignored scratch directory. Reproduce these host-only checks from the repository with:

```sh
PYTHONPATH=.work/python python .work/run013/review-media/audit.py
PYTHONPATH=.work/python python .work/run013/review-media/literals.py
```

The parent evidence SHA-256 remains `8b992b69afe7953d2a3eee11f7640b3d0eaeaf0b8ec31b596494eebdcea7e825`; the architecture report, Ghidra manifest and collector hashes also match the four artifact hashes recorded in the review manifest. The parent collector and Ghidra analysis were not rerun. Its recorded application analysis timeout remains a limitation even though the selected bodies completed. No Ghidra project was opened and no extracted program, SQL statement, device operation or target filesystem write was executed.

## Claim dispositions

The source aliases in this table bind each address to the exact path and SHA above.

| Claim | Disposition and original-byte support | Boundaries |
| --- | --- | --- |
| M01: directory enumeration and constructor defaults | Supported. F `0x130e4` calls `scandir64` on its separate filter branches; `0x1318c` consumes directory-entry names. DCF/list traversal at `0xdf08` and `0x7e68` belongs to local directory/item state. Constructor `0x12480` installs the vtable and copies `/mnt/mmc`, `PHOTO`, `SAM_` from independently resolved literals. | Constructor defaults do not establish actual mounted media, writable storage or effective runtime settings. |
| M02: filename allocation adds an item before storage completion | Supported. F `0xdd6c` calls `GetNewFileIndex_SetInfo` at `0xa55c`; that helper calls `AddHead` at `0xa5be`, then increments object `+0x98` at `0xa620–0xa628`. F `0x7bc0` constructs/copies a DCF item into its deque. A `0x1ce9cc` invokes virtual `+0x5c` on its new-name branch; `0x121670` supplies the conditional DCF callback path. | A reservation is local list state. Alternate app temporary/sample names bypass that DCF branch, and no actual capture ordering was observed. |
| M03: intended app object, callbacks and vtable bindings | Supported. A `0x1ce6b4` stores the imported GetFileList result at `0x4aa018`; F Create `0x6480` constructs CSFileList via its constructor import. A init `0x120434` supplies callback `0x121670` through `0x1dc294`; wrapper `0x1dc2a0` supplies metadata callback `0x1d0498`. F constructor GOT and ABS32 vtable rows bind the virtual calls as detailed below. | Intended ELF binding does not prove runtime object identity, callback execution, loader interposition or allocation success. The no-card init branch also registers the callbacks. |
| M04: physical-delete results do not gate selected list removal | Supported. F `0xc23c` skips protected items; otherwise physical removal calls at `0xc2e0` and optional `0xc300` are followed by `RemoveItem` at `0xc320` without testing their results. F `0x13278` calls unlink and falls back to remove only for `-1`. F `0x11484` refreshes the count and calls sync. | This is the reviewed pathname-deletion control flow, not proof that physical deletion succeeded, or exhaustive review of every deletion entry. |
| M05: CAPI exists/refresh/insert/delete/error split | Supported. C `0x1bca4` tests path existence, regular-file/ignored-directory/storage rules and database membership; `0x1bd94` branches zero to refresh, `0x1bd98` compares `-0x6c` for insert. Insert `-0x6d` is changed to local zero before conversion. C `0xb260`, `0xb6ac`, `0x18a5c` implement related insert/delete/error conversion boundaries. | Numeric local outcomes do not prove the originating capture succeeded or that a row persisted. |
| M06: media SQL, insertion and notification results are distinct | Supported. S `0xa854` formats a `media` schema; `0x8688` constructs its INSERT; `0x9d40` delegates SQL to `media_db_request_update_db`. S `0x4b90` retains the local insertion result and notifies only on its zero branch; `0x105f0` delegates to `media_db_update_send`. S deletion `0x5e38` checks SQL deletion from helper `0x7ba4` before notifying. | SQL construction/submission, insertion result and notification result are distinct observations; lower IPC, transaction persistence and notification receipt are outside this review. |
| M07: concrete .media.db path is a backup consumer | Supported. S `0xb842–0xb84a` resolves format at `0x18980` and pathname at `0x189a0`, then calls sqlite3_mprintf for ATTACH. S `0x4094`, call `0x40cc`, delegates normal connection to external `media_db_connect`. | The pathname proves the selected backup attachment, not the normal database connection implementation or live path. Inventory absence is not runtime absence. |
| M08: folder-scan and DB-update callbacks are separate | Supported. C `0x1c09c` installs wrapper `0x183c8` with an eight-byte callback/context record via `media_directory_scanning_async`. C `0x1c230` installs wrapper `0x18384` and its own record via `media_db_update_subscribe`. Original register/stack flow distinguishes their callback arguments and ownership. | Neither wrapper is the photo write completion. The DB wrapper's leading zero cannot establish successful capture. Full lower transport, cancellation and concurrency semantics remain open. |
| M09: selected app completion bodies have no direct DCF rollback | Supported as bounded. The original instructions and resolved direct call targets of A `0x217cac` and `0x21b978` show no explicit/direct DCF reservation deletion or undo in these selected bodies. They update app state/accounting and invoke other helpers, including the file-write-done entrance. | Descendants, unresolved/indirect calls, relisting, global cancellation and other callbacks were not exhaustively followed. This does not prove that reservation rollback is globally absent. |

## Concrete allocation and binding checks

At F `0xdd84`, `movw/movt` constructs 99,999; the comparison and signed greater-than branch reject counts above that value. Thus the parent report's 100,000-item bound means the selected allocation path accepts a current count at most 99,999. The GetNewFileIndex result has its own negative-error branch. The successful SetInfo path formats the filename, obtains time, calls AddHead, formats the complete pathname and increments `+0x98`; only afterward does its caller back up the series and set the current file. No capture-completion callback or platform media-registration call gates this local item addition.

The constructor's literal calculations independently yield F `0x148fc` (`/mnt/mmc`), `0x13a40` (`PHOTO`) and `0x144a0` (`SAM_`). Its original `0x12496` load uses GOT entry `0x1dc14`, whose `R_ARM_GLOB_DAT` relocation targets `_ZTV10CSFileList` at `0x1d670`; `0x1249c` adds eight and `0x124a2` stores address point `0x1d678`. The following original `R_ARM_ABS32` rows resolve otherwise-zero on-disk table words:

| Original vtable row | Slot from `0x1d678` | Relocated intended pointer |
| --- | --- | --- |
| F `0x1d688` | `+0x10` | `0x10e19`, Listup |
| F `0x1d690` | `+0x18` | `0x11485`, Delete |
| F `0x1d6d4` | `+0x5c` | `0x1208d`, GetNewFileName |
| F `0x1d728` | `+0xb0` | `0xe9b9`, RegisterPhotoMetadataCB |
| F `0x1d730` | `+0xb8` | `0xe9a1`, AddPhotoMetadata |

A `0x1cea08/0x1cea10` loads/calls virtual `+0x5c`; its other branch `0x1cea28/0x1cea3c` uses `+0x60`. Metadata callback A `0x1d0498` loads virtual `+0xb8` at `0x1d0574` and calls it at `0x1d0580`. App wrapper `0x1dc298` resolves through GOT `0x449700` to `mm_photo_register_get_file_name`; wrapper `0x1dc2ac` resolves through GOT `0x448e28` to `mm_photo_register_add_image_metadata`, after constructing literal callback `0x1d0498` in r0. Init's ordinary branch obtains/lists the object and registers these callbacks; its no-card branch still installs both. These checks establish the relevant object and callback bridges without assuming that every photo uses the DCF naming branch.

## Database and callback boundaries checked in instructions

C `0x1bcfa` supplies test flag `0x10` to `g_file_test`; a false result reaches service deletion at `0x1bd2e`. The present-path branch tests regular-file flag one. Membership zero reaches refresh call `0x1bef0`; `cmn r0,#0x6c` at `0x1bd98` reaches immediate insertion call `0x1bf46`. `cmn r6,#0x6d` at `0x1bf54` reaches the already-inserted branch, where `0x1bff4` moves the zero-valued r5 into r6 before the shared `_content_error_capi` call at `0x1bf96`. Other service-error branches retain their own values for conversion. This is a local error mapping, not a complete validator of file contents or write completion.

S immediate insertion saves its helper's return in r4 at `0x4cbc`; the zero comparison at `0x4cbe` gates the success/notification branch. `_media_svc_publish_noti` is called at `0x4d94`, but its r0 return does not replace that saved insertion result. SQL wrapper `0x9d6e–0x9d7a` passes the SQL text to external `media_db_request_update_db` and tail-calls conversion; an inferred decompiler `void` signature does not override this original return flow. Notification helper `0x10624` calls external `media_db_update_send` and tests that call's local result. In the delete service, `0x5f0e` calls the SQL delete helper, `0x5f16–0x5f1a` saves/tests its result, and only zero reaches notification at `0x5f44`. The later physical remove call uses the separately obtained nondefault thumbnail pathname, not the original media pathname supplied in r5.

Independent S backup literal evaluation gives `ATTACH DATABASE '%s' AS mediadb` at `0x18980` and `/opt/usr/dbspace/.media.db` at `0x189a0`. Its selected SQL copies personal-storage rows from the attached media table into another connection's `main.media`. The parent inventory has no regular-file record containing `.media.db` in its pathname; that bounds what the packaged inventory supplies and does not establish a live database's absence.

C folder wrapper `0x183c8` loads the request result at object `+4`, calls the installed callback with that value and saved context (`0x18406–0x1840c`), then frees its record. DB-update wrapper `0x18384` instead assembles its distinct callback ABI, sets r0 to literal zero at `0x183a6` and calls the installed callback at `0x183b6`. Its context comes from the independent subscription record. The selected wrapper does not itself free that subscription record. These instructions support separate boundaries without interpreting the literal zero as a photo result.

The packaged media-server plugin selector and service-unit contents were source-hash checked. Configuration and declared dependencies do not establish running services or the active implementation. Lower media-utils connection/write handling, scanner/plugin dispatch, end-to-end callback correlation, successful physical writes and rollback ownership remain unresolved. This independent review changes no parent evidence, manifest or prior report.
