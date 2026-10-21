# NX Reborn firmware research

- Current scope: complete NX500 firmware inventory and progressive offline reverse engineering.
- Preserve the Drive `1차 시도` archive. New Drive deliverables belong under the existing `Codex` folder.
- Keep firmware bytes, extracted files and temporary downloads in ignored `.work/`; never stage them. Ghidra databases use ignored `ghidra-projects/` because Ghidra rejects dot-prefixed project path components.
- Track scripts, tool/source manifests, selected evidence and conclusions in Git.
- Every conclusion must identify input SHA-256, binary path, virtual address or file offset, method, and limitations.
- Distinguish inherited reports, newly reproduced static evidence, inferred behavior and device observations.
- Import, automated analysis and decompilation are separate stages; none alone means a feature is understood.
- Do not execute extracted camera programs on the host. This research does not include camera access or firmware installation.
- Prefer reproducible batch tools. Record analyzer timeouts, failures and decompiler truncation explicitly.
