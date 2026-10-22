# Run002 environment and repository changes

2026-10-21 KST. The managed environment now reports current observations with
`unrestricted` HTTP policy in `enforced` state. GitHub and its API returned HTTP
200; authenticated Drive streams for the 68 MB prior Ghidra snapshot and all four
full-firmware slices succeeded. The previous task's 403 policy block is resolved.
No environment configuration, proxy route or credential binding was changed here.
Shell network commands use the supported additional network permission path.
The Samsung support page refresh itself returned HTTP 403; this does not undo
the separately verified GitHub/Drive connectivity results.

The workspace started with only the main README. The existing research branch
was fetched, its AGENTS.md read, and PR #1 attached to this chat. Changes continue
on that branch and preserve the draft PR; no merge is performed.

Ghidra 12.1.4 and Temurin JDK 21.0.12.1+1 were restored with the existing pinned
bootstrap; the prior 68,264,385-byte Ghidra ZIP matched SHA-256
`e2af81f29c7cbf933748c35a19d6b18c8badf3dc333365ec74f4af495b2df3f2`.
The eight-file survey uses a separate Ghidra project. Existing run001 databases
and exports remain intact; restored old exports are in `.work/restored-run001/`.

The base Debian image had no usable liblzo2/debugfs tools or apt package index.
Five Debian amd64 packages were materialized under `.work/tools/native/` with
package SHA-256 checks; no global installation was made. Exact URLs, sizes and
hashes are in `manifests/native-tools.json`; `tools/bootstrap_native.py` reproduces
this installation. The selected native packages are e2fsprogs/libext2fs/libcom_err/
libss 1.47.2-3+b12 and liblzo2 2.10-3+b1.

New source reconstruction, LZOP, source inode readback, whole ELF inventory,
boot metadata and kernel tools are tracked with tests. Full inventories, native
source trees, read-only fsck logs, Ghidra databases and complete exports are
archived under the existing Codex folder; original firmware slices stay in the
preserved `1차 시도` archive. Signed URLs, raw firmware and target shared libraries
are excluded from Git. Source/derived archive links and measured hashes are
recorded in `manifests/drive-artifacts-run002.json`.
