# Phase 4.51 — Missing `dmode` on the unpacked image does not prevent multi-stage fallback

## Inputs and provenance

1. User ran **CMD**:
   ```cmd
   dir /s /b ".\firmware-analysis\official-3.21-dat\firmware.tar_unpacked\*dmode*"
   ```
   and observed **`File Not Found`**. This is a pathname-search result *only* for that offline directory. It is not a read of a live mounted `/setting` partition.
2. This phase independently re-read and SHA-256 verified the original user-supplied **`bootin_fw321.elf`** (ELF32 LE ARM Thumb ET_EXEC, 13,384 bytes, SHA256 `d2bc0c51d4523052170520607fb60709020e48811e5d5ad65843f5e97ffaa983`), checked the file-backed `.data` bytes and re-examined the Thumb branch instructions. No execution, camera connection, disassembler artifact or Sony binary was committed.
3. Existing Phase 4.50 established two **distinct** conditional architectures: mode-based combined multi-stage `im.elf s g r u l i a ...` launched by main's `system()`, and event-based individual stage `im.elf i &` / `im.elf a &` shell launches. This phase proves how *missing or empty mode-file reads* affect the former path.

## 1. Exact missing-file fallback branch

Original `bootin.elf`, function `0x9460`, contains NUL string `/setting/mode/dmode` at **0x9ef1**. PC-relative `0x9678` points to it. `0x948c` writes this pointer into its configuration+0x08, then calls `open(path,0)` at **0x948e** (PLT `open@GLIBC_2.4`, 0x8ba0):

```asm
0x948e  blx   0x8ba0       ; open(path, O_RDONLY)
0x9492  subs  r6, r0, #0  ; save returned fd
0x9494  blt   0x950e       ; NEGATIVE fd: skip file-data parse
0x9496  mov   r1, r7
0x9498  movs  r2, #0x1e
0x949a  blx   0x8c88       ; read(fd, buffer, 30 bytes)
0x949e  ldr   r1, [r5,#0xc] ; LOAD PREEXISTING MODE POINTER
...
0x9506  str   r1, [r4,#0xc] ; store result ONLY on opened-fd path
0x9508  str   r3, [r4]     ; store parsed flags
0x950a  blx   0x8d08       ; close(fd)
0x950e  movs  r6, #1       ; negative-open path, first optional argv index
0x9510  b     0x9728
```

Consequences:

- **On `open` failure**, branch **0x9494→0x950e→0x9728** does *not* write config+0x0c, preserving its file-initialized pointer **until any optional command-line parse or mode selector**.
- **On `read` returning zero or a negative value**, the preexisting config+0x0c pointer is loaded at **0x949e**, no scan-loop body is entered because **0x9500** compares index zero to the read length and **0x9502** branches to **0x94a6** only for `0 < read_len`; the original pointer is stored again at **0x9506**.
- **On a positive read**, `0x94a6..0x94fc` examines the read bytes and changes the selected pointer when it encounters one of digits **0,1,2,3**. It also accepts option letters that modify flags. This is not proof of the file content in a live rootfs.

## 2. Actual compiled default survives missing-file branch

By parsing the *original ELF's real file offsets*, not an assumed address:

- `.data` VMA **0x12a8c** has file offset **0x2a8c**. Configuration structure base is **0x12a94**.
- Configuration+0x0c at **VMA 0x12aa0 / file offset 0x2aa0** contains exact LE bytes **`95 a6 00 00`**, pointer **0x0000a695**.
- Original `.rodata` VMA **0x9ddc** has file offset **0x1ddc**; at **0xa695 / offset 0x2695**, exact string bytes **`33 20 00`** = **`"3 "\0`**.
- Original config flags at **VMA 0x12a94** are **zero** in the file. Runtime flags may be changed by startup parsing, so only the file image default is known.

If no optional argv or bypass changes the result, **0x9738** loads config+0x0c, **0x973a** loads its first byte **'3'**, **0x9754** loads case-3 stage-string pointer from `0x97b8` = **0xa4fa**, and **0x975a** writes that pointer back into config+0x0c. At **0xa4fa** is exact **`"s g r u l i a "\0`**. The stage selector's **bit0x1** guard at **0x9732..0x9736** can bypass this selection; and optional CLI args at **0x9728..0x972a** may change config. Neither is assumed absent in real camera startup.

## 3. Reachability, not executed-state evidence

The original executable `_start` passes Thumb `main=0x9c65` to `__libc_start_main` and the real main calls parse at **0x9c7a → 0x97d0 → 0x9460**. On its normal conditional path, main calls composed launcher **0x9ca2→0x9914**, whose stage-string append **0x99c2..0x99c6** consumes the same mode field. The shell call occurs **0x9a54→system@GLIBC_2.4**. Hence the *no-file/default* branch can reach a one-process multi-stage command, provided its other flags, args, and calls allow it.

The user's `dir` output plus this native fallback means **an absent filename in the update image would not, by itself, disprove the combined stage startup path**. Nor does it prove the device cold boots with `dmode=3`, lacks persistent settings, successfully executes the shell command, or loads any given plugin. All of these remain **UNKNOWN**.

## 4. Implications for Camera Core API reconstruction

The Phase4.49 separate-child `i` and `a` startup commands still do not share `RTLD_GLOBAL`. But in the preserved compiled-default Phase4.50/4.51 combined startup, `i` and `a` CLI tokens can belong to a **single process**, making same-process libObj `dlopen("/usr/lib/libObj.so",0x101)` and later `dlopen(NULL)` / `dlsym("Application_System_Init")` a *conditional candidate*.

Still missing: actual launch argv, successful mode/IMDB gate traversal, prior same-process `libObj.so` load, `Application_System_Init` dynamic resolution, ModelCamera ID11 module mapping, and the actor sending stage 0x940036/037 to bootin's fixed inbox 0x94020a.

Original Camera Core graph **unchanged**: 74 primary static + 5 inferred + 5 unresolved = 84 tracked; runtime verified APIs=0, safe to invoke APIs=0. Machine-code and file-offset witnesses in `sdk/bootin_dmode_fallback_3_21.json`.

## Next offline line of investigation

For Phase 4.52, the best next *new* proof is to trace the actual `im.elf` same-process IMDB stage flag iteration around event/queue callbacks and `Application_System_Init` symbol scope, rather than rescanning for a `dmode` filename. Further directory search may help establish settings mount provenance, but current uploaded sources do not contain the live file.
