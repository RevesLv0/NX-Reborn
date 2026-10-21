# Measured offline analysis progress

The filesystem corpus contains **1,895 unique ELF contents across 1,956 paths**. Content coverage uses SHA-256, so duplicate paths and followup exports never increase the denominator or numerator.

**Semantic completion percentage is unknown.** Import, automated analysis, export, selected decompilation and reviewed static findings are separate stages. These counts do not prove feature behavior on a camera.

| Stage | Unique ELF numerator / denominator | Content coverage |
|---|---:|---:|
| source verified | 1895 / 1895 | 100.0% |
| imported with success receipt | 28 / 1895 | 1.478% |
| loaded program export validated | 41 / 1895 | 2.164% |
| auto analysis completed with success receipt | 28 / 1895 | 1.478% |
| selected decompilation completed | 30 / 1895 | 1.583% |
| reviewed static findings | 15 / 1895 | 0.792% |

Validated export generations: 105; rejected generations: 0. Deduplicated mapped nonexternal function entries: 46,539. Selected function attempts: 183; completed: 183. There is no whole-corpus function denominator. ABI-unverified mapped entries: 46,539.

Successful `-import` receipts count only when their input manifest SHA and firmware path agree with the source inventory. Restored `-process -noanalysis` exports establish a loaded program and valid export; they do not establish a newly measured import or completed auto-analysis. Artifact bytes, SHA-256, row counts, run IDs and receipt exit state are checked on every rebuild. Failed runs and stale exports remain visible as errors and do not count as coverage.

13 exported contents lack a matching successful auto-analysis export generation in the scanned records. The restored run001 exports were generated with `-process -noanalysis` from previously documented analyzed programs. This conservative stage count does not mean those programs were never analyzed, and it does not erase earlier work; the matching current-generation evidence is simply an export receipt, not an auto-analysis receipt. Earlier narrative/log history is distinct from the validated-generation numerator.

Function counts deduplicate source SHA-256 plus original ELF virtual address. External/unmapped entries are reported per generation separately. Analyzer timeouts, decompiler failures/errors, budget omissions, signatures with unverified ABI, and explicit reviewed-unit unresolved questions remain in the JSON ledger. Repeated failures are attempt history, not additional analyzed functions.

The JSON contains a reproducible per-SHA backlog, pending work units and overlapping filename-based subsystem hints. Its ranking is only a navigation heuristic; it assigns no semantic subsystem ownership or completeness. Source verification uses debugfs extraction and source-inode dumps from the same implementation; it is not an independent filesystem parser or runtime observation. Non-ELF firmware sections, kernel images, resources and configuration require separate denominators.

Reproduce from the repository root:

```sh
python tools/firmware/analysis_progress.py \
  --inventory .work/full/inventory/full_filesystem_inventory.json \
  --run-root .work/restored-run001 --run-root .work/run002 --run-root .work/run003 \
  --review-ledger manifests/ghidra-capture-run003.json \
  --review-ledger manifests/ghidra-video-power-run003.json \
  --review-ledger manifests/ghidra-transfer-run003.json \
  --review-ledger manifests/ghidra-jpeg-run003.json \
  --review-ledger manifests/boot-review-run003.json \
  --output manifests/analysis-progress.json --markdown docs/ANALYSIS_PROGRESS.md
```

Review counts are unmeasured unless explicit `--review-ledger` inputs are provided. Review inputs accept a list or a manifest containing `reviewed_findings`. Each reviewed unit must record a stable ID, inventory source SHA, original ELF VA or file offset, existing evidence path, method, limitations and unresolved questions. Prose reports and generated pseudocode are never silently classified as reviewed findings.

Registered reviewed static units: 24. Review content coverage counts primary source SHA associations only; extra source anchors stay attached to each unit. It does not measure the fraction of semantics understood.

Inventory SHA-256: `c874bc1a39049f8f6afb508aa34e9fb0b4aacd1480e7603afade30a4613d461f`. All source SHA, original paths, export artifact hashes, receipt locations and per-SHA work units are preserved in [the ledger](../manifests/analysis-progress.json).
