# RUN012 independent review of RUN010 AF/lens boundaries

Reviewed 2026-10-22. The nine bounded claims in [review-af-run010.json](../../manifests/review-af-run010.json) agree with independent original-byte and relocation checks. No central correction is required. In particular, the named app removal path does not clear the selected capture listener, and the AF handler's stored value 1 must remain distinct from the setter's 12-byte copy. Neither finding establishes a live failure or a memory-safety vulnerability.

This was offline read-only firmware analysis. No target executable, device I/O, Ghidra project access/mutation, firmware change, commit or push occurred. The active RUN012 AF project was not opened. Existing reports and manifests were not rewritten.

## Sources, addressing and audit scope

| Original rootfs input | Independently recomputed SHA-256 |
|---|---|
| `/usr/apps/com.samsung.di-camera-app/bin/di-camera-app` | `55dcc78143724435a2e38b9e0d809960bd728668634bbcf7532ce137f882eb04` |
| `/usr/lib/libcapture-fw-prod.so` | `a07867292610ac6376e29e3cd64bc79a274452412387fb7853c5a3fb3f96bba5` |
| `/usr/lib/libmulticore-bridge.so` | `f14a12e4d9172989d73c8dff0fd59580c65ccd1972264c9d94c8d1a736820390` |
| `/usr/lib/libuser-spec.so` | `2d04ab487cc9980cb87e513b25ff09011839203756d28857eedfd50a9cc730ec` |

The four staged files under `.work/run010/af/core/inputs` match their original extracted rootfs counterparts. All addresses below are original ELF link VAs. Original instruction/data bytes were independently mapped through each containing file-backed `PT_LOAD`, then decoded in ARM mode with Capstone. For example, app `0x12dbd4` is file offset `0x125bd4`, app `0x220038` is file offset `0x218038`; the selected DSO code VAs equal their file offsets. Ghidra's extra `0x10000` DSO rebase is not applied to these addresses.

Every saved original-code window in [af-lens-run010.json](../evidence/af-lens-run010.json) matches: **68 code windows, four data blocks and 434 relocation records**. The audit recomputed source identities, offsets and raw bytes; relocation types, names and symbol values were independently checked against original ELF sections. In addition, **603 direct call/branch sites** in those windows were resolved by evaluating original ARM PLT immediate encodings and matching the computed GOT address to its relocation; this count includes repeated calls to the same binding.

The semantic checks below cover the nine bounded findings. They do not mean every instruction in the much larger ioctl windows, every registered handler, the entire bridge framing ABI or all command meanings were reviewed. Saved C was navigation; decisive evidence here is original instructions, table bytes and relocation binding. No analyzer/decompiler job was run by this reviewer.

## Nine-claim disposition

| Claim | Disposition and independent original locations | Limit preserved |
|---|---|---|
| `AF010-REGISTER` | Supported: app `0x12dbd4–0x12dbdc`, wrapper `0x1e3f64–0x1e3f88`; capture translator `0x30b60–0x30bbc`, selected case `0x30f04–0x30f10`; ioctl internal argument branch `0x2bd38–0x2bd48` | A selected static registration site does not prove boot execution or initialization success. |
| `AF010-LISTENER` | Supported: capture `0x853a0`, `0x85400`, `0x85478`; app removal `0x1e4480–0x1e44a0`; `ControlLens` null check `0x44714–0x44738` | No claim about concurrent lifetime, runtime ownership or actual shutdown sequencing. |
| `AF010-TRANSPORT` | Supported for selected edges/branches: capture `0x83e14`; bridge `0x66c8`, `0x6700`, `0x73fc`, `0x7898–0x7970` | No proof of complete packing semantics, queue lifetime, successful delivery or RTOS handling. |
| `AF010-DISPATCH` | Supported: capture subscription `0x85688`; holder mapper `0x8e2f8`; constructor `0x8dfa4`; virtual dispatch `0x8e23c`; notify constructor `0x8a524`; Run `0x8a628` | Conditional on subscriptions, expected construction and ordinary dynamic binding. |
| `AF010-LENS-EVENT` | Supported: category ABS32 `0xb1f7c`, lens ABS32 `0xb227c`, category/subcategory `0x8dacc/0x8db54`, handler `0x8d28c` | Stored field 8 and two integer extractions do not establish complete message bounds or physical completion. |
| `AF010-AF-SCAN` | Supported: liveview ABS32 `0xb20d4`, handler `0x8bf5c`, setter `0x8855c`, getter `0x91c64` | Stored field 1 is not independently established as a one-byte backing allocation; 12-byte copy remains a distinct fact. |
| `AF010-UI-QUEUE` | Supported: app `0x220038`, mask call path `0x2205a0`, scheduling `0x220674–0x2206c8`, common idle helper `0x223db0` | Queueing is not a displayed transition; downstream `0x221d64` is not semantically reviewed here. |
| `AF010-COMMAND` | Supported for the reported selected numeric encodings: capture `0x43db4`; app CAF `0x1e7240`, AF lock `0x1e5b3c`; translator `0x30b30`; 3A cases `0x42fe8` and `0x43bcc` | Code expressions/opcodes do not establish focus, motor behavior, convergence or hardware success. |
| `AF010-PREFERENCES` | Supported: user-spec `0x3e10`, `0x1df74`, `0x1df84` | Wrapper lengths do not establish freshness, shared-layout coherence, writers or RTOS ownership. |

## Registration, listener storage and the removal boundary

Three original app instructions bind the callback parameter at the selected callsite:

```text
0x12dbd4 380000e3 movw r0,#0x38
0x12dbd8 220040e3 movt r0,#0x22
0x12dbdc ded802eb bl 0x1e3f5c
```

The resulting pointer is `0x220038`. Wrapper `0x1e3f64` moves it into `r2`, loads the camera handle into `r0`, sets request `r1=0x13`, size `r3=4` and zero stack arguments, then calls `0xae704` at `0x1e3f88`. Original type-22 GOT relocation `0x449b38` binds that veneer to `mm_camera_ioctl`.

Capture's request translator subtracts 1 before its indexed branch table. Request `0x13` therefore uses original branch instruction `0x30bbc`, targeting `0x30f04`, which writes `0x1050007`. The ioctl branch at `0x2bd38–0x2bd48` forwards the public pointer with internal size 4 through PLT `0x26724`, GOT `0xb0b04`, bound to `ControlLens` (`0x43db4`). Its registration jump-table entry leads to `0x44714`; a null pointer branches directly to the existing result path, while a nonnull pointer reaches registration at `0x4472c` through PLT `0x269dc`, GOT `0xb0bec`.

The registration method `0x853a0` initializes result -1, requires a nonzero pointer, writes it once to a global slot and changes the result to zero (`0x853c0–0x853e0`). GOT `0xb1668` has `R_ARM_GLOB_DAT` binding to `m_pLensEventListener`, original symbol VA `0xb33d4`. The original method contains no list append or iteration. Unregister at `0x85400` requires a nonnull pointer equal to the stored pointer before writing zero (`0x85420–0x85458`). Notify at `0x85478` checks this same slot, then supplies the saved three arguments in `r0/r1/r2` to `blx r3` at `0x854c4`.

App removal sets request `0x13`, pointer `r2=0`, public size `r3=0` at `0x1e448c–0x1e44a0`. The selected ioctl path still uses internal size 4; the null check in `ControlLens` skips registration. Its validated result remains zero and it does not call unregister or clear the listener. The report's distinction between a removal name/zero result and actual pointer removal is therefore supported.

## Category 0x82 and message 0x519

The holder mapper at `0x8e318–0x8e37c` maps receive category `0x82` to index 2. Holder Run computes object address `this + 4 + index*4`, loads its vptr, then calls virtual slot +8 (`0x8e28c–0x8e2dc`). Holder construction stores its newly constructed `CNotifyHandler` at `this+0xc`, exactly that index's slot.

The notify constructor loads `_ZTV14CNotifyHandler` through original `R_ARM_GLOB_DAT` relocation `0xb1590`, symbol VA `0xb02b8`, adds 8 and stores the vptr (`0x8a54c–0x8a558`). Its virtual Run pointer at original `0xb02c8` has `R_ARM_ABS32` relocation to `CNotifyHandler::Run`, original `0x8a628`. This independently supplies the class binding for the holder's indirect dispatch.

Notify Run stores the incoming message pointer at object +8 and supplied integer field at +4; a null pointer instead clears both. `notifyCategory` loads the message halfword at +4, shifts right by 8 and maps special high byte `0xaa` to slot 10; other values above 9 map to 0 (`0x8db08–0x8db3c`). `subCategory` retains the low byte (`0x8db78–0x8db7c`). The receive category and message category are separate fields.

For message halfword `0x519`, high byte 5 selects category-table slot 5. Table `0xb1f54` has an `R_ARM_ABS32` relocation at `0xb1f7c` (`base + 5*8`) to `execLensNotify` (`0x8ab8c`). Low byte 25 selects lens-table record `0xb227c` (`0xb21b4 + 25*8`), relocated to `onLensEvent` (`0x8d28c`). The original stored words are zero with zero member-adjustment words; treating those file bytes alone as null runtime methods would ignore their relocations.

`onLensEvent` checks object +4 against 8 at `0x8d2a8–0x8d2b0`. On equality it calls `getParam<int>` for message +8 and +12 (`0x8d2c8`, `0x8d2e0`), then calls `NotifyLensEvent(first,second,0)` at `0x8d2f8`. Original PLT `0x260d0` resolves GOT `0xb08e8` to `_Z8getParamIiET_PKS0_`; `0x25698` resolves GOT `0xb0580` to Notify. The accepted branch stores result zero; the mismatch branch stores -2.

Use **stored count/length field** when describing the value 8: this local code checks the supplied integer field, while message backing bounds and the complete frame ABI remain outside this review. The two integer extractions establish the selected delivery expression, not an independently measured allocation or hardware event meaning.

## AF scan: stored value 1 versus 12 copied bytes

Liveview table base `0xb20ac`, slot 5, has original ABS32 relocation at `0xb20d4` to `onAFScanDone` (`0x8bf5c`). The same high/low-byte selection makes message `0x305` category 3/subcategory 5.

The independent original handler sequence is:

- `0x8bf78–0x8bf80`: load object +4, compare with 1, branch to -2 on mismatch.
- `0x8bf88–0x8bf94`: derive message +8 and call `SetFocusScanResult` through GOT `0xb0aa4`.
- `0x8bfa4–0x8bfb4`: derive message +8 again and call byte `getParam<unsigned char>` through GOT `0xb1168`.
- `0x8bfc0–0x8bfd0`: pass callback ID `0x1040001`, that byte and zero to `SendAppCallback` through GOT `0xb0ef8`.

The setter's actual copy at `0x88598–0x885a4` is `ldr r0,[r2]; ldr r1,[r2,#4]; ldr r2,[r2,#8]; stm r3!,{r0,r1,r2}`: **three words / 12 bytes**. Getter `0x91ca0–0x91cac` supplies category `0x81`, opcode `0x365` and size 12 to its send call.

These are two independently established facts: the handler tests a stored integer equal to 1; its setter reads 12 bytes from the payload pointer. The meaning and units of the stored integer, buffer allocation and framing relationship remain unresolved. The report correctly avoids deriving a one-byte allocation, out-of-bounds access or vulnerability from this comparison alone. Callback naming likewise does not establish focus convergence or the meaning of every status bit.

## Transport and UI scheduling boundaries

Capture `SendCommand` loads category `0x83` at `0x83e38`, preserves opcode/size/payload and calls imported `CMulticoreBridge::Send` through original GOT `0xb0a40`. Bridge wrapper `0x6700` forwards into lowercase send at `0x66c8`; that function obtains `_mySender` through GOT `0x1244c`, then calls `CSender::Send` through GOT `0x124f4`.

`CSender::createFrame` stores first byte 2, second byte zero and the supplied halfwords at stack header offsets +2/+4/+6 (`0x7440–0x7454`) before its build call. `CSender::Send` first creates a frame, then checks category `0x10` and a destination-alive global; the destination-not-alive route calls `CFrameQueue::Push` at `0x7968` and returns -1. The other route attempts sending under its selected lock and has additional result/error cleanup branches. These facts support the bounded transport claim; they do not prove delivery or settle full frame packing, errors or lifetime.

The app lens callback saves ID/status in `r4/r6`. Its initial selected gate at `0x220080`, later state paths and event-mask call at `0x2205a4` can prevent queueing. Some preliminary UI-value updates occur before that gate; the review does not treat the function as side-effect-free when it exits early.

Accepted ID `0x12` with positive status queues `0x223dec` at `0x220690`; ID `0x1a` queues `0x223dd0` at `0x2206ac`; ordinary IDs queue `0x223db0` at `0x2206c8`. ID `0xd` first sets the status register to zero. The ordinary packing instruction is `orr r1,r6,r4,lsl #16` (`0x2206c4`), without an independently established input-range guarantee. GLib veneer `0xae740` resolves GOT `0x449b4c` to `g_idle_add`.

Common idle helper `0x223db0` obtains high half with logical shift right 16 and low half with `UXTH`, then calls `0x221d64` with a zero third argument. This verifies queue/unpack expressions, not eventual display behavior or downstream event semantics.

## Concrete command and preference checks

The original `ControlLens` jump table indexes commands relative to `0x1050001` (`0x43dfc–0x43e58`) after validation. Independent selected payload and send instructions agree with the reported table:

| Commands | Transport opcodes | Decisive original instruction ranges |
|---|---|---|
| `0x1050002/4/b` | `0x501/502/504` | Low-word byte truncation/decrement and byte store; sends at `0x44254/0x442ac/0x447d4`. |
| `0x1050005` | `0x503` | Word comparison to 1 and byte selection `0x442d4–0x442ec`; send `0x4430c`. |
| `0x1050006/8` | `0x307/308` | Low-byte / low-byte-minus-one branches, sends `0x44704/0x44364`. |
| `0x1050009/a` | `0x505/507` | Zero size/payload at sends `0x44754/0x4477c`. |
| `0x105000d/f` | `0x509/506` | Pointer forwarded with size 8, sends `0x44810/0x4484c`. |
| `0x1050010/11` | `0x508/50a` | Zero size/payload to sync send `0x44874`; one byte forwarded to ordinary send `0x448b0`. |

App CAF places the incoming boolean byte in a 16-byte public payload and uses request 5 at `0x1e7310–0x1e731c`. Translator request 5 targets `0x30e50`, writing `0x1040005`. Its selected 3A jump-table branch targets `0x42fe8`; `0x43000–0x43018` maps input byte zero to 1 and any nonzero byte to 0, then the accepted branch sends one byte with opcode `0x206` at `0x4345c–0x43464`.

App AF lock similarly uses public request 9 at `0x1e5c1c–0x1e5c28`, translated through `0x30ea0` to `0x1040009`. Its 3A branch `0x43bcc` starts a byte at 2, retains 2 only for input byte 1, otherwise ORs `0x10`, and sends `0x204` at `0x43c24–0x43c2c`. These numeric operations are supported; they do not independently establish physical AF lock, continuous AF behavior or motor protocol.

User-spec wrappers independently load `(offset,size)` as `(0x120,0x6c)` at `0x1df78–0x1df80` and `(0x20,0x38)` at `0x1df88–0x1df90`. Both tail-branch to PLT `0x35b8`, GOT `0x3721c`, binding `pref_rtos_get_bytes`. The readiness wrapper reads four bytes at `0xd28` (`0x3e18–0x3e2c`) and compares against `0x330033` / `0x11223344` (`0x3e34–0x3e4c`). The associated diagnostics identify source intent; return freshness, authorship and coherence remain unverified. Another wrapper's 0x40-byte request at offset 0x20 is not collapsed into these interface sizes.

## Reproduction artifacts and unresolved work

Independent artifacts are `.work/run012/review-af/audit.py`, `audit.json`, per-source/per-VA original instruction dumps, `calls.py`, and `calls.json`. They only read original ELF data. The completed parent evidence was not regenerated or modified.

This review closes the nine listed independent-semantic-review units to the bounded extent stated. It does not review subsequent RUN012 AF work, downstream app dispatcher `0x221d64`, full receive-frame provenance, RTOS algorithms, physical focus/motor success, listener concurrency, or the stored-count/backing-buffer relationship. Those remain separate evidence tasks.
