# RUN003 environment and tooling changes

2026-10-21 KST. Reused the existing verified firmware extraction and pinned
Ghidra 12.1.4/JDK/Python toolchain. The managed environment reports current
unrestricted/enforced HTTP policy. No environment configuration, credential
binding, route, system package or original firmware byte was changed.

The executor has an 8 GiB memory limit and a two-core CPU quota. Added explicit
headless heap/CPU controls and per-function decompiler timeout/response-size options
to the existing runner. The capture and video/power batches each used a 1536M
heap and one analysis CPU. Transfer followups used a 768M heap with analysis
disabled. The final JPEG retry used a 2G heap, one CPU, a 60-second timeout and
256 MB response cap. These are host analysis resource settings, not camera
firmware parameters.

Exporter version `2026-10-21.3` records the effective decompiler response cap.
Earlier exporter hashes and failure receipts remain in their original run
directories. Two new projects, `NX500_RUN003_CAPTURE` and
`NX500_RUN003_VIDEO_POWER`, isolate new imports. The existing
`NX500_FULL_RUN002` and `NX500_FW112` projects were reopened for bounded
analysis-disabled followups, then closed before snapshotting.

Added a source-SHA symbol catalog, explicit stage-progress ledger, raw boot/ELF
evidence extraction and regression fixtures. Catalogs, raw derived strings and
complete exports stay ignored under `.work/run003`; source firmware remains in
the existing preserved Drive archive. Git tracks tools, small selected evidence,
survey manifests and the per-SHA progress/backlog ledger.

New Drive results are separate RUN003 artifacts under the existing Codex folders.
Previously saved Drive files are preserved. `manifests/drive-artifacts-run003.json`
records exact artifact URLs, hashes and readback checks. PR #1 remains the working
draft; no merge or camera deployment is performed.
