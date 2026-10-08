# ARCHITECTURE_GAPS

These are measured gaps; absence is reported as UNKNOWN rather than treated as completion.

- Lifecycle callbacks: `269/846` have a function link.
- Unresolved edges: `0`.
- Failed/error analysis runs: `4`.
- Candidate evidence: `1`; unknown evidence: `6285`.

Still UNKNOWN until direct evidence is imported: runtime validation of CFG edges, complete JNI/Java method registration, OSAL queue producer/consumer resolution, semantic names for generated functions, and hardware/ioctl parameter layouts.

## Recorded blockers

- `python_elf_index` `<private-firmware-path>/live-libInfraDlnaControl.so`: `Reading section 0 at offset 524852 past EOF 518212`
- `python_elf_index` `<private-firmware-path>/live-dlna-parts/part-0.bin`: `Reading section 0 at offset 524852 past EOF 30001`
- `elf_linkage` `<private-firmware-path>/live-libInfraDlnaControl.so`: `Reading section 0 at offset 524852 past EOF 518212`
- `elf_linkage` `<private-firmware-path>/live-dlna-parts/part-0.bin`: `Reading section 0 at offset 524852 past EOF 30001`