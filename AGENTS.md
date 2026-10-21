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
- When delegating, tell the user each sub-agent's role and model setting (explicit requested ID or parent inheritance), then summarize its results. Record the rationale, known reasoning effort, artifacts and unresolved work in the sub-agent usage log.
- Keep requested model settings distinct from verified runtime model identity. Never guess unavailable historical or inherited model IDs. See `docs/SUBAGENT_USAGE_20261021.md` for the reconstructed history and reporting format.
- Continue authorized offline reverse engineering through dependent next steps without ending the turn merely because an intermediate report or batch finished. Use progress messages for intermediate results; ask for user input only when a concrete decision, missing input or device action is needed.
- Routine research commits and pushes to the existing research branch/PR are authorized by the user. If automatic review cannot verify that authorization, check the actual prior instruction and payload/destination scope before retrying; never bypass a rejection or silently broaden publication scope.
- A reported remaining-usage percentage alone is not a stop instruction. Continue authorized work and save checkpoints regularly; the user will handle quota resets after actual exhaustion. Record actual quota failures and do not repeatedly retry unavailable agents.
