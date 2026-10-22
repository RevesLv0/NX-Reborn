# Measured offline analysis progress

The filesystem corpus contains **1,895 unique ELF contents across 1,956 paths**. Content coverage uses SHA-256, so duplicate paths and followup exports never increase the denominator or numerator.

**Semantic completion percentage is unknown.** Import, automated analysis, export, selected decompilation and reviewed static findings are separate stages. These counts do not prove feature behavior on a camera.

| Stage | Unique ELF numerator / denominator | Content coverage |
|---|---:|---:|
| source verified | 1895 / 1895 | 100.0% |
| imported with success receipt | 32 / 1895 | 1.689% |
| loaded program export validated | 43 / 1895 | 2.269% |
| auto analysis completed with success receipt | 32 / 1895 | 1.689% |
| selected decompilation completed | 34 / 1895 | 1.794% |
| reviewed static findings | 23 / 1895 | 1.214% |

Validated export generations: 556; rejected generations: 11. Deduplicated mapped nonexternal function entries: 47,799. Selected function attempts: 639; completed: 639. There is no whole-corpus function denominator. ABI-unverified mapped entries: 47,799.

Successful `-import` receipts count only when their input manifest SHA and firmware path agree with the source inventory. Restored `-process -noanalysis` exports establish a loaded program and valid export; they do not establish a newly measured import or completed auto-analysis. Artifact bytes, SHA-256, row counts, run IDs and receipt exit state are checked on every rebuild. Failed runs and stale exports remain visible as errors and do not count as coverage.

11 exported contents lack a matching successful auto-analysis export generation in the scanned records. The restored run001 exports were generated with `-process -noanalysis` from previously documented analyzed programs. This conservative stage count does not mean those programs were never analyzed, and it does not erase earlier work; the matching current-generation evidence is simply an export receipt, not an auto-analysis receipt. Earlier narrative/log history is distinct from the validated-generation numerator.

Function counts deduplicate source SHA-256 plus original ELF virtual address. External/unmapped entries are reported per generation separately. Analyzer timeouts, decompiler failures/errors, budget omissions, signatures with unverified ABI, and explicit reviewed-unit unresolved questions remain in the JSON ledger. Repeated failures are attempt history, not additional analyzed functions.

The JSON contains a reproducible per-SHA backlog, pending work units and overlapping filename-based subsystem hints. Its ranking is only a navigation heuristic; it assigns no semantic subsystem ownership or completeness. Source verification uses debugfs extraction and source-inode dumps from the same implementation; it is not an independent filesystem parser or runtime observation. Non-ELF firmware sections, kernel images, resources and configuration require separate denominators.

Reproduce from the repository root:

```sh
python tools/firmware/analysis_progress.py \
  --inventory .work/full/inventory/full_filesystem_inventory.json \
  --run-root .work/restored-run001 --run-root .work/run002 --run-root .work/run003 --run-root .work/run004 --run-root .work/run005 --run-root .work/run006 --run-root .work/run007 --run-root .work/run008 --run-root .work/run009 --run-root .work/run010/af --run-root .work/run010/transfer --run-root .work/run010/transfer-budget-attempts \
  --review-ledger manifests/ghidra-capture-run003.json \
  --review-ledger manifests/ghidra-video-power-run003.json \
  --review-ledger manifests/ghidra-transfer-run003.json \
  --review-ledger manifests/ghidra-jpeg-run003.json \
  --review-ledger manifests/boot-review-run003.json \
  --review-ledger manifests/ghidra-capture-run004.json \
  --review-ledger manifests/ghidra-transfer-run004.json \
  --review-ledger manifests/ghidra-storage-run005.json \
  --review-ledger manifests/ghidra-app-storage-run005.json \
  --review-ledger manifests/review-run006.json \
  --review-ledger manifests/review-run007.json \
  --review-ledger manifests/review-run008.json \
  --review-ledger manifests/review-run009.json \
  --review-ledger manifests/review-af-run010.json \
  --review-ledger manifests/review-transfer-run010.json \
  --review-ledger manifests/review-tsu-run010.json \
  --output manifests/analysis-progress.json --markdown docs/ANALYSIS_PROGRESS.md
```

Review counts are unmeasured unless explicit `--review-ledger` inputs are provided. Review inputs accept a list or a manifest containing `reviewed_findings`. Each reviewed unit must record a stable ID, inventory source SHA, original ELF VA or file offset, existing evidence path, method, limitations and unresolved questions. Prose reports and generated pseudocode are never silently classified as reviewed findings.

Registered reviewed static units: 95. Review content coverage counts primary source SHA associations only; extra source anchors stay attached to each unit. It does not measure the fraction of semantics understood.

Inventory SHA-256: `c874bc1a39049f8f6afb508aa34e9fb0b4aacd1480e7603afade30a4613d461f`. All source SHA, original paths, export artifact hashes, receipt locations and per-SHA work units are preserved in [the ledger](../manifests/analysis-progress.json).

Validation errors at generation time:

- `.work/run004/capture/initial/outputs/ghidra/di-camera-app-55dcc7814372/summary.json`: Run receipt is incomplete or failed; not coverage
- `.work/run004/capture/initial/outputs/ghidra/fw_upgrade_recovery-7bf571fa83ce/summary.json`: Run receipt is incomplete or failed; not coverage
- `.work/run004/capture/initial/outputs/ghidra/libcapture-fw-prod.so-a07867292610/summary.json`: Run receipt is incomplete or failed; not coverage
- `.work/run004/capture/initial/outputs/ghidra/libdi-network-bt-app.so-94a8f7ae0529/summary.json`: Run receipt is incomplete or failed; not coverage
- `.work/run004/capture/initial/outputs/ghidra/libdi-network-dlna-rvf.so-a7c8f03e4fdc/summary.json`: Run receipt is incomplete or failed; not coverage
- `.work/run004/capture/initial/outputs/ghidra/libface.so-f2936a156173/summary.json`: Run receipt is incomplete or failed; not coverage
- `.work/run004/capture/initial/outputs/ghidra/libmmf-camcorder.so-49f89956d0a0/summary.json`: Run receipt is incomplete or failed; not coverage
- `.work/run004/capture/initial/outputs/ghidra/libsap-api.so.1.0.0-f130d83a9313/summary.json`: Run receipt is incomplete or failed; not coverage
- `.work/run004/capture/initial/outputs/ghidra/mtp-responder-630d4f6c8beb/summary.json`: Run receipt is incomplete or failed; not coverage
- `.work/run004/capture/initial/outputs/ghidra/nfc-manager-daemon-4f71b292ced7/summary.json`: Run receipt is incomplete or failed; not coverage
- `.work/run004/capture/initial/outputs/ghidra/system-recovery-161f5656f5d9/summary.json`: Run receipt is incomplete or failed; not coverage
