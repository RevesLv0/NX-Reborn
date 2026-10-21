# Initial firmware findings — 2026-10-21

## Reproduced evidence

- The selected 28-file archive and a separately preserved `libsif.so` match their inherited
  SHA-256/size expectations. This verifies those available bytes, not a new extraction of the
  full original firmware. Source receipts are in `manifests/`.
- ELF `DT_NEEDED` metadata links `di-camera-app` to capture, photo, camcorder, display,
  networking, media DB, update and device/power libraries. This is a loader dependency map,
  not proof that each function is called during a particular camera mode.
- Byte-verified rootfs/opt `ContentDirectory_1.xml` each declare 12 actions, including Browse,
  Search, GetSystemUpdateID and transfer-related actions. Device descriptions contain the
  template name `Redwood`, model number `0.765`, and empty UDN. These are configuration
  declarations, not an observed NX500 service identity or usable endpoint.
- Ghidra recovered a `DscImage::Notify(..., 2, ..., 3, 0)` registration in
  `ImageGenerator::runFromCapture` (entry ELF VA `0x96684`, registration callsite `0x9677c`), and an idle callback in
  `ImageGenerator::SIFListener` (ELF VA `0x9f080`). The callback route values alone do not
  encode a verified successful file close.

## Important refinement to prior close-result claims

Input: `/usr/lib/libsif.so`, SHA-256
`9790fc02fe5b9793fc09da7eb5fd9453c730a55880654c84caf02dd3d1001109`.

`DscOsalFile::close()` is an 80-byte function at ELF VA `0x5ad4c`.
Independent Capstone disassembly and Ghidra agree that it conditionally calls the fclose PLT
entry (`BL` at `0x5ad7c`, target `0xdad4`), then clears the stored stream pointer. ELF relocation
metadata associates `fclose` with GOT `0xa6420`. See `evidence/libsif-close-capstone.json` and
the Ghidra output in Drive.

No branch in this wrapper checks the return value after that call. However, the subsequent
instructions leave `r0` unchanged through the return. Therefore, it is **not established that
all callers discard the close result**. A caller might inspect the register, depending on its
actual ABI and call path. The no-open-stream branch also has a different register history.
Ghidra inferred a pointer return type here; that type is not source-level proof. Caller and
vtable analysis remains necessary. Preserve this distinction instead of repeating a global
"return value lost" conclusion.

`DscJPEG::taskMain` did not decompile within the initial 20-second per-function budget.
Its successful import/disassembly is not a successful decompilation or semantic verification.

## Address convention

For the shared libraries examined here, Ghidra selected image base `0x10000`, whereas the
original ELF image base is zero. Ghidra `va` and addresses printed in C/disassembly therefore
have a `+0x10000` shift relative to original ELF VAs. Exports include explicit `elf_va` fields
and both bases. For example, Ghidra `0x6ad4c` maps to ELF `0x5ad4c`. File offsets are a separate
quantity and must be calculated from PT_LOAD mappings.

The Ghidra language ID `ARM:LE:32:v8` identifies the decoder selected by the tool, not a
measurement that NX500 uses an ARMv8 CPU.

## Remaining work

Obtain the complete preserved source or its split sections; independently reconstruct its
section/filesystem manifests; analyze startup units, DBus/configuration and all ELF dependencies;
then follow capture/AF, image/video processing, storage, connectivity, power and recovery paths.
Do not elevate inherited file listings or automated call graphs into device-observed facts.
