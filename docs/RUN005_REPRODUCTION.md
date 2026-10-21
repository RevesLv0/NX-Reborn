# Reproduce RUN005 storage and observer traces

Restore the verified corpus and tools using `FULL_REPRODUCTION_RUN002.md` and
`RUN003_REPRODUCTION.md`. Start commands from the repository root. Firmware
programs are data inputs; none is executed on the host.

The storage and app reports/manifests preserve exact selected Ghidra commands,
input pairing, budgets, receipts and export hashes. The storage project is
`NX500_FW112` with exactly two inputs (libsif/photo); the app project is
`NX500_FW112_SURVEY` with exactly eleven. Do not mix the two source sets.
Each fresh generation uses `-process -noanalysis`, bounded 30-second selected
decompilation, 1536M heap and one CPU. Repeated exports are not new imports.

```sh
PYTHONPATH=.work/python python tools/firmware/app_storage_evidence.py
PYTHONPATH=.work/python python tools/firmware/storage_producer_evidence.py \
  --root .work/full/extracted/rootfs \
  --output analysis/evidence/storage-producer-run005.json
PYTHONPATH=.work/python python tools/firmware/rtos_publish.py \
  --bin .work/full/NX500.bin --manifest manifests/full-source-layout.json \
  --output analysis/evidence/rtos-publish-run005.json
```

Further source/run details are in `manifests/ghidra-storage-run005.json` and
`STORAGE_PRODUCER_RUN005.md`. Original PT_LOAD mapping and relocation checks
corroborate selected C; inferred Ghidra types alone do not establish an ABI.
RTOS section offsets and inferred link VAs remain distinct from actual BIN offsets.

`ANALYSIS_PROGRESS.md` contains the complete cumulative regeneration command.
Retain the eleven historical RUN004 exclusions and their incomplete receipt;
they must not be erased when adding successful RUN005 generations.

```sh
PYTHONPATH=.work/python python -m unittest discover -s tests -v
python -m compileall -q tools tests
git diff --check
```

Full exports, input identities, original logs, symbol references and unlocked
project snapshots are archived under Drive Codex as versioned RUN005 files.
The underlying source identities and read-only filesystem limitations remain
those of the RUN002 baseline. Existing Drive files are preserved.
