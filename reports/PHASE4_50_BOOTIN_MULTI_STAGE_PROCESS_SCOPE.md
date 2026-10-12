# Phase 4.50 — A second bootin launch architecture: **one multi-stage im.elf process**

**Source:** read-only, independently SHA-pinned original Sony A6000 Firmware 3.21 `bootin_fw321.elf` (13,384 bytes, SHA-256 **`d2bc0c51d4523052170520607fb60709020e48811e5d5ad65843f5e97ffaa983`**), cross-checked with original `im-vendor-original.elf` (SHA-256 **`f0f181426af4add55a8510c5441ff86c3121678fd1f7e0467152070e870d803a`**). All ARM Thumb VMA addresses below refer to original file mappings, not executed device state.

## Major correction to Phase 4.49

Phase 4.49 correctly established `bootin.elf` can react to fixed-inbox (`0x94020a`) event words 0x940031..0x940037 by calling `system("im.elf s &")` etc., including separate `system("im.elf i &")` and `system("im.elf a &")` branches. **That conditional event path indeed launches separate child processes and does not share glibc dynamic linker's RTLD_GLOBAL namespace across children.**

However, another **real, distinct bootin control-flow path** had not yet been examined. It constructs **one** shell command using a selected *multi-stage* argument string, and runs the accumulated command through one `system()` call. Thus **"i and a stages always run as separate im processes" was too broad**. The new mode-dependent single-process path changes how we evaluate whether earlier `libObj.so` loads may make `Application_System_Init` visible later in the *same* process.

## 1. Direct stage-mode selector and original rodata

Inside bootin at **0x9738..0x975a**, the code loads the first byte of a mode-string pointer in its global state and compares it with ASCII digits `'0'`, `'1'`, `'2'`, `'3'`. The branches select literal pointers and store the selected stage-argument string at **0x975a**.

| Mode byte | Branch | Pointer literal | Selected string's ELF VMA | Exact bounded original string |
|---|---|---|---|---|
| `'0'` (or unmatched) | 0x973c → 0x9758 | 0x97bc | **0xa5af** | `s ` |
| `'1'` | 0x9740..0x9746 | 0x97b0 | **0xa4e6** | `s g r u ` |
| `'2'` | 0x9748..0x974e | 0x97b4 | **0xa4ef** | `s g r u l ` |
| **`'3'`** | **0x9750..0x9756** | **0x97b8** | **0xa4fa** | **`s g r u l i a `** |

Source selection depends on other bootin parsing conditions; **we have not observed the selected mode on the actual camera**. These strings are *not* merely an unreferenced unused static catalog: the instruction `0x975a: str r2,[r3,#0xc]` stores the chosen pointer into state used by the command builder.

## 2. The command builder uses the mode selection

The alternative builder at **0x9930..0x9a54** has a writable command buffer pointed to by PC-relative literal **0x9abc = 0x00012ab8**:

- At **0x9974..0x997c**, `r1=[r4+0x18]` and `r0=0x12ab8` lead to `strncpy` (PLT `0x8c20`) with length **0x400**.
- It then assembles the command through helper **0x9260**, whose branch target **0x8cdc** is the relocations-verified `strncat` PLT; the length remaining is tracked against a 0x400-byte bound.
- The launch prefix is selected from original strings **`im.elf ` at 0xa57d** and **`gdb --args im.elf ` at 0xa572**, depending on option bits. Other command fragments come from state fields and literals.
- Critically, **0x99c2** loads **`r1=[r4+0x0c]`**, the same *selected stage-string pointer* written at 0x975a, and at **0x99c6** invokes append helper **0x9260**.
- At **0x9a54**, `bootin.elf` loads the built command buffer as `r0` and calls **`system@GLIBC_2.4` through PLT 0x8c30** (independent `R_ARM_JUMP_SLOT` at GOT **0x12a04**).

This is direct machine-code dataflow from mode selector → stage arguments → command string → OS launcher. When the selected mode is `'3'`, its *one* assembled shell-command invocation includes **`s g r u l i a`** as consecutive options to one `im.elf` invocation, subject to its other options and to successful execution.

## 3. The original im.elf supports multi-selector arguments

The separately uploaded original im executable parses its argument vector in the main call at **0x9af2 → 0xa628**. It individually recognizes `i` and `a` and ORs flags in the *same* config word:

- Token `i`: Thumb OR **`0x200000`** at **0xa760**.
- Token `a`: Thumb OR **`0x400000`** at **0xa77e**.
- Multiple tokens are traversed in an argument loop, so when both are provided their flag bits can coexist. The broader token family **s/g/r/u/l/i/a** is checked by the same argument parser (note: the `boot=` prefix parser separately treats some character branches; direct single-token comparisons must be distinguished).

Main directly delegates several early stages through its guarded IMDB iterator **0x9b7e..0x9c1e** and conditionally constructs phase event messages at **0x9d04..0x9d88**. This establishes the **ability for one invocation to carry multiple stage flags**, *not* complete observed execution of stage 5→7 or stage 7→8 record traversal. The OSAL delivery and state callback bridge remain unproven.

## 4. Precise correction to libObj dynamic symbol binding

Earlier phases found a conditional loader path: for 31 possible IMDB records of types 0x20000001..03 with packed high-half set, `im.elf` uses **`dlopen("/usr/lib/libObj.so",0x101)`** rather than the logical row name, and for the row99 `appFw.so` initialization record, it uses **`dlopen(NULL)`** followed by `dlsym(...,"Application_System_Init")` and a guarded initializer call.

**If** a matching earlier record is actually selected and successfully loaded into the *same* `im.elf` process with glibc's `RTLD_GLOBAL` flag, a later same-process lookup from `dlopen(NULL)` **may** find `Application_System_Init`, which the independently verified original `libObj.so` exports. This is now a plausible control architecture for `bootin` mode `'3'`, not just a mistaken assumption that globals flow across separate children.

**Still not demonstrated:** that a real camera selects mode `'3'`, that the earlier gated IMDB records and appFw row99 actually run in the same process, that `dlopen` succeeds, that symbol visibility/binding works with the actual loader state, or that the camera invokes the function. **No API is promoted to runtime-verified**.

A separate literal ` LD_PRELOAD=/usr/tool/LeakTracer.so ` at bootin `0xa459` is selected by a debug option at `0x9774..0x9786`; it is **not** evidence that normal startup preloads libObj.so. This string is not an actual `libObj.so` preload path.

## 5. Summary and next proof target

Two conditional executable bootin architectures are now separately proved:

1. **Per-event dispatch:** fixed inbox `0x94020a`, event `0x940036/037`, distinct background-launched `im.elf i &` and `im.elf a &` processes; no interprocess loader namespace reuse.
2. **Mode-composed startup:** mode `'3'` selects `s g r u l i a `, builder appends that string to one constructed command, one `system()` launch; multiple stage bits **can** belong to one im process.

Next: identify the actual offline bootin mode input (file/boot args) and prove whether its selected flags result in both the generic libObj candidate loader and row99 initialization within the same process, or instead the event stage path dominates. In parallel, find the real producer for stage 0x940036/37 to bootin's 0x94020a inbox. Neither is a runtime-observed claim.

**Original Camera Core metrics unchanged:** 74 directly verified static, 5 inferred, 5 unresolved, 84 tracked; five end-to-end blockers open; runtime-verified APIs and safe-to-invoke APIs both zero. Structured witnesses: `sdk/bootin_multistage_launch_3_21.json`. Firmware ELFs are not uploaded to GitHub.


## 6. Direct file-origin proof for bootin's mode byte

The original `bootin.elf` includes NUL-terminated **`/setting/mode/dmode`** at ELF rodata **0x9ef1**, loaded through PC-relative literal **0x9678**. Inside function **0x9460**, **0x9486** loads this path, **0x948e** calls relocation-resolved `open@GLIBC_2.4` (PLT **0x8ba0**), and **0x949a** calls `read@GLIBC_2.4` (PLT **0x8c88**) into a bounded stack buffer of length **0x1e**. The byte loop from **0x94a6..0x9506** recognizes ASCII digit bytes **0/1/2/3** and stores a selected string pointer in bootin's configuration state.

This establishes a **concrete, code-backed source** of the bootin mode selection. The later comparison at 0x9738 reads that state and chooses the stage bundle. Importantly the contents of `/setting/mode/dmode` were **not supplied** by the user's unpacked directory, and `open/read` can fail. Hence this report does NOT claim a particular mode is the default or selected on the actual camera.

Next efficient safe offline evidence: check whether `0700_part_image/dev/nflasha15_unpacked_unpacked/setting/mode/dmode` or a differently mounted overlay path exists in the unpacked image. Listing/copying or inspecting that file is read-only and does not require camera connection. Its offline bytes (if present) could be compared with the bootin mode parser, with care not to equate an update-image default with live camera state.
