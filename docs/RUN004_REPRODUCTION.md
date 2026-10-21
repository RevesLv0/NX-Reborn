# Reproduce RUN004 boundary traces

Restore the verified corpus and pinned tools using `FULL_REPRODUCTION_RUN002.md`
and `RUN003_REPRODUCTION.md`. Run from the repository root; execute host analysis
tools only. Target ELF binaries are inputs, never host commands.

```sh
PYTHONPATH=.work/python python tools/firmware/rtos_readiness.py \
  --bin .work/full/NX500.bin --manifest manifests/full-source-layout.json \
  --output analysis/evidence/rtos-readiness-run004.json \
  --raw-output-dir .work/run004/rtos
```

```sh
PYTHONPATH=.work/python python tools/firmware/kernel_symbols.py \
  --kernel-dir .work/full --headers analysis/evidence/kernel-headers.json \
  --raw-output-dir .work/run004/kernel \
  --output analysis/evidence/kernel-symbols-run004.json \
  --handler-output analysis/evidence/kernel-handlers-run004.json
PYTHONPATH=.work/python python tools/firmware/capture_completion_evidence.py \
  --root .work/full/extracted/rootfs \
  --output analysis/evidence/capture-completion-run004-capstone.json
```

Input identities and selected handler extraction are recorded
in `manifests/kernel-run004.json` and the kernel report. The extractor accepts
only the supported absolute ARM32 kallsyms layout after checking the complete
name/marker/token structure. Failure to recover another layout is not proof that
symbols or functions are absent.

Ghidra followups use the existing SURVEY, photo and RUN002 projects with
`-process -noanalysis`; they do not add imports or new automatic analysis.
Exact commands, input pairing, budgets and artifact identities are in the capture
and transfer run manifests. Preserve the failed initial capture receipt and its
original 13-file input set: SURVEY actually contains 11 programs. The successful
retry uses the paired 11-file set, and photo processing uses its own 2-program
project. Do not replace an old failed receipt with a later successful result.

The progress document contains the complete regeneration command. Fixture tests:

```sh
PYTHONPATH=.work/python python -m unittest discover -s tests -v
python -m compileall -q tools tests
git diff --check
```

Full instruction listings, symbol catalogs, decompiler exports, logs, original
failed history and unlocked database snapshots belong in the versioned Drive
bundles; only selected evidence and small manifests belong in Git.
