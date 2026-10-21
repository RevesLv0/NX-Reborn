# NX500 firmware research

## Scope and storage

The complete final official NX500 firmware is the research scope: boot/update/recovery,
OS/services/IPC, capture/AF/lenses, JPEG/SRW/image processing, video/audio/display,
storage/media databases, Wi-Fi/Bluetooth/NFC/USB, UI/configuration and power/thermal control.
Inventory every partition and file; progressively analyze executable code and dependencies.

Drive project: https://drive.google.com/drive/folders/1XKdCmvj9g_XqLKnyrlAmJk52oRDI2SHu

- Existing `1차 시도`: reference archive, preserved and reused.
- Active `Codex`: https://drive.google.com/drive/folders/1Xr8YHrtXuPudHGPC_fUl9zBoFxhhSZGJ
- `00_관리_및_진행현황`: index, scope, status and links.
- `01_원본_및_무결성`: input/tool hashes and provenance, new source receipts.
- `02_추출_및_전체인덱스`: section/filesystem/ELF/dependency inventories.
- `03_Ghidra_프로젝트_및_출력`: reproducible database snapshots, decompilation, logs.
- `04_구조_및_기능분석`: architecture, subsystem maps and evidence.
- `05_검증_및_보고서`: verification results, limitations, device-only questions.

Firmware bytes live in Drive and ignored `.work/` locally. Ghidra databases use ignored
`ghidra-projects/` because Ghidra rejects dot-prefixed project path components.
Git tracks tools, manifests, selected evidence and current conclusions. Do not duplicate
source firmware in the new folder solely to change its filing location; reference the
preserved source by Drive ID and SHA-256. Do not commit signed download URLs.

## Evidence levels

1. **Inherited**: a prior report/listing says this; bytes not independently re-extracted yet.
2. **Byte-verified**: available input size/hash agrees with the source manifest.
3. **Static reproduced**: instruction, relocation, symbol, configuration or call relationship independently checked.
4. **Inferred**: interpretation with explicit premises and unresolved indirect/hardware dependencies.
5. **Device-observed**: actual device and test conditions recorded separately.

Record binary SHA-256, original path, virtual address/file offset distinction, tool version,
evidence references and limitations. Import and auto-analysis are not semantic completion.
Decompiler output is an aid, not recovered original source. Record timeouts and failed exports.

## Baseline

Samsung support pages currently list v1.12 (2016-05-16):
https://www.samsung.com/uk/support/model.EV-NX500ZBMJDE/
https://www.samsung.com/es/support/model/EV-NX500ZBMIES/

Preserved original Drive ID: `1aRDIHiq_6HEoHIunxXmDuYmld5w67-sY`.
Inherited ZIP SHA-256: `bceabae2bfef9faf90fe0bef0782f6458605ce4dc187bad39497ab7ec3305af1`.
Inherited BIN SHA-256: `f4c238e811970cf858b5d734119477ea191d35cd29d9f84b584157ecfc4ee997`.
These are prior baseline values until a new complete download is independently verified.

## Reproduction

Use a full JDK 21 and Ghidra 12.1.4, both isolated in `.work/tools/`.
Python dependencies are pinned in `tools/requirements-research.txt`.

On Linux x86_64 with Python 3.12, run `python tools/bootstrap_research.py --work .work`
to restore the pinned tools, or append `--check-only` to verify an existing installation.

```sh
PYTHONPATH=.work/python python tools/firmware/inventory.py \
  --input .work/inputs/selected --legacy .work/legacy \
  --additional-manifest manifests/additional-inputs.json --output .work/outputs/inventory
python tools/ghidra/run_headless.py \
  --ghidra .work/tools/ghidra_12.1.4_PUBLIC --jdk .work/tools/jdk-21.0.12.1+1 \
  --input .work/inputs/selected/rootfs/usr/lib/libmm-photo.so --work .work
```

The headless exporter writes complete discovered function and direct call listings, defined
string references, and a bounded selection of decompiled functions with disassembly. Pass
`--pattern` and `--decompile-budget` for subsystem-specific analysis. Unresolved indirect
calls and all unselected functions remain pending. Cross-program edges must be resolved
against ELF imports/exports; same-named functions alone are not proof of a call.

## Work completion and next-session handoff

Upload new artifacts into their matching Codex child folder and read back metadata/content.
Record source hashes, tool versions, completed stages, failed stages, and next commands.
Save a Ghidra snapshot only after the analyzer releases its database lock. Preserve working
code in Git; use a reviewable branch/PR for changes. Camera I/O and firmware installation
are separate from this offline research.
