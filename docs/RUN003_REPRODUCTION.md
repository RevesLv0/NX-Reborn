# Reproduce RUN003 catalogs and followup surveys

Start with `FULL_REPRODUCTION_RUN002.md` to restore the verified firmware corpus,
pinned Ghidra/JDK and Python packages. All commands run host analysis tools only.
Run from the repository root. Firmware executables are never invoked.

## Global metadata catalog

```sh
PYTHONPATH=.work/python python tools/firmware/symbol_catalog.py \
  --inventory .work/full/inventory/full_filesystem_inventory.json \
  --rootfs .work/full/extracted/rootfs --opt .work/full/extracted/opt \
  --output .work/run003/symbols
```

The JSONL records raw symbol names, binding, visibility, source SHA, section index,
original value, Thumb-bit handling and GNU version requirements/definitions. Imported
undefined symbols and dynamic export candidates are distinct. Named table entries
and declared function locations are not a total-function or semantic denominator.
The tool checks the selected original bytes against their inventory SHA before
parsing, rejects source symlinks and invalidates stale output before a refresh.
Full JSONL and per-program metadata are archived in the symbol/progress bundle;
the small receipt is `manifests/symbol-catalog-run003.json`.

## Static boot and selected evidence

See `tools/firmware/boot_sections.py --help` and the boot report for exact source
section and decoded-kernel address conventions. Byte-offset evidence distinguishes
absolute BIN offsets, section offsets, inferred link bases and decoded-stream offsets.

```sh
PYTHONPATH=.work/python python tools/firmware/video_power_evidence.py \
  --work .work/run003/video-power --rootfs .work/full/extracted/rootfs \
  --opt .work/full/extracted/opt --output analysis/evidence/video-power-run003.json
```

The capture evidence extractor is preserved as
`analysis/evidence/capture-ipc-run003-extract.py`; its exact output/source hashes
are in the capture manifest. Selected report evidence remains in Git, complete
decompiler outputs and instruction listings remain in the Drive snapshots.

## Ghidra resource controls and large worker retry

`tools/ghidra/run_headless.py` now accepts `--max-memory`, `--max-cpu`,
`--decompile-timeout` and `--decompile-payload-mb`. Heap and CPU limits bound the
host batch; decompiler timeout and response size are separately recorded. A zero
payload override preserves the installed provider default. Exporter version
`2026-10-21.3` records the effective response cap. Earlier generation hashes and
exporter versions remain intact.

Capture used one new eight-file project and video/power one new twelve-file
project. Transfer followups process the existing `NX500_FULL_RUN002` project
recursively with analysis disabled. Exact regex budgets and manifests are recorded
in `ghidra-capture-run003.json`, `ghidra-video-power-run003.json` and
`ghidra-transfer-run003.json`.

The previous JPEG worker timeout was retried at 60 seconds; the first retry hit
the response buffer limit. The following bounded retry completed. Use both
`libsif.so` and `libmm-photo.so` copied into the paired input directory so both
processed program summaries can be checked by the runner:

```sh
python tools/ghidra/run_headless.py \
  --ghidra .work/tools/ghidra_12.1.4_PUBLIC --jdk .work/tools/jdk-21.0.12.1+1 \
  --input .work/run003/jpeg/inputs --work .work/run003/jpeg-expanded \
  --project NX500_FW112 --process --skip-analysis \
  --pattern '^DscJPEG::taskMain$' --decompile-budget 1 --decompile-timeout 60 \
  --decompile-payload-mb 256 --max-memory 2G --max-cpu 1
```

Use a new output work directory for another generation. Do not overwrite historical
failed export generations. Snapshot projects only after the processes exit and
their database locks disappear.

## Stage coverage

`docs/ANALYSIS_PROGRESS.md` contains the exact ledger command, including explicit
review manifest arguments. It validates successful receipts, source identity and
artifact hashes, then deduplicates source SHA plus original ELF VA. Restored
analysis-disabled exports are not silently counted as new imports or automatic
analysis. Reviewed claims are explicit bounded evidence units, not declarations
that whole functions/features have been understood. Non-ELF code is outside the
ELF percentage denominator.
