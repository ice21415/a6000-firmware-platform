# Phase 4.49 — Original bootin.elf proves seven-stage event-to-process launcher; corrects process-global loader inference

## SHA-pinned source and method

The original, user-uploaded **`bootin_fw321.elf`** was independently checked:
- Size: **13,384 bytes**.
- SHA-256: **`d2bc0c51d4523052170520607fb60709020e48811e5d5ad65843f5e97ffaa983`**.
- ELF32 ARM EABI5 **ET_EXEC**, little-endian, original entry **0x8dc1**, stripped.
- Read-only analysis: `readelf -hW -SW -rW -dW`, ARM Thumb `llvm-objdump -d --triple=thumbv7-none-eabi`, exact ELF section/file-offset literal checks. No device interaction or firmware execution.

The independent firmware-original `im-vendor-original.elf` has SHA-256 `f0f181426af4add55a8510c5441ff86c3121678fd1f7e0467152070e870d803a`. All instruction addresses below are original file **virtual addresses**, never claims about runtime loader addresses.

## 1. Decisive result: 0x940036 and 0x940037 in bootin are **receive-side comparisons**

`bootin.elf` has a message dispatcher at **0x9b20**. At **0x9b28**, it reads the first word of the received message into **r1**. The immediately following equality chain compares that word to literal entries `0x9c00..0x9c30`, and on match selects a literal **shell command string**. All seven match branches converge on **0x9b3a**, a PLT-linked **`system@GLIBC_2.4`** call (PLT **0x8c30**, `R_ARM_JUMP_SLOT` GOT **0x12a04**).

| Incoming event | Literal | Branch compare | Command pointer slot | Exact ELF rodata command |
| --- | --- | --- | --- | --- |
| `0x00940031` | 0x9c00 | 0x9b2a | 0x9c04 | **`im.elf s &`** at 0xa60e |
| `0x00940032` | 0x9c08 | 0x9b34 | 0x9c0c | **`im.elf g &`** at 0xa619 |
| `0x00940033` | 0x9c10 | 0x9b44 | 0x9c14 | **`im.elf r &`** at 0xa624 |
| `0x00940034` | 0x9c18 | 0x9b4e | 0x9c1c | **`im.elf u &`** at 0xa62f |
| `0x00940035` | 0x9c20 | 0x9b58 | 0x9c24 | **`im.elf l &`** at 0xa63a |
| **`0x00940036`** | **0x9c28** | **0x9b62** | **0x9c2c** | **`im.elf i &`** at **0xa645** |
| **`0x00940037`** | **0x9c30** | **0x9b6c** | **0x9c34** | **`im.elf a &`** at **0xa650** |

`0x9b3e` returns zero after the shell call; it **does not validate that the child initialized correctly**. The `&` is part of every command string, so the requested program is background-launched by the shell. Each such successful launch creates a **separate process**, not another dynamic-linker load into a previous `im.elf` process.

**Correction to Phase 4.48**: the literal/import ranking correctly found `bootin.elf`, but its 0x940036/037 literals are demonstrated **receive-side** switch conditions, not proof that `bootin.elf` sends these stage words.

## 2. bootin has a separate fixed UIPC stage-event inbox ID 0x94020a

At **0x9c64..0x9d04**, the main event loop loads literal **`0x0094020a`** from **0x9d18** as the first argument to **`osal_rcv_msg_tmo`**, at call **0x9cd0** (PLT 0x8c94, GOT R_ARM_JUMP_SLOT 0x12a24). On successful receive status (zero) it loads the message pointer at **0x9cde** and calls the seven-stage dispatcher **0x9b20** at **0x9ce0**. It then frees the message at **0x9cf0**, and repeats until its internal stop-state condition.

Earlier **0x9816** registers an OSAL callback by calling `osal_reg_sync_msg_queue_cb` (PLT 0x8c14), passing literal **`0x94020a`** from 0x9834; its callback address literal is Thumb **0x8e41** from 0x983c. The `osal_rcv_msg_tmo` first argument is the fixed ID **0x94020a**, **not** the old im.elf dynamic receiver ID. Actual queue ownership/registration and delivery remain runtime-conditional.

The three known numeric addresses are distinct:

- **`0x0094020a`**: bootin stage inbox.
- **`0x0094016a`**: earlier verified im.elf fixed `osal_snd_msg` destination. bootin also has a branch that sends other, non-stage messages there (below).
- **`0x00946000..0x00946fff`**: the possible successfully allocated im.elf dynamic receive queue range (Phase 4.46).

This eliminates another false equivalence: **receiving 0x940036 in bootin on 0x94020a is not evidence that im.elf received that event on its dynamic queue**.

## 3. Proven bidirectional-looking control cases, not proven stage forwarding

In the same `0x9b20` dispatcher, other non-stage IDs reach helper **0x8f08**:

- Incoming **0x940002** is mapped at `0x9b88..0x9b92` to a helper call with destination **0x94020a** and message code **0x940001**.
- Incoming **0x9400f3** or **0x9400f4** matches `0x9b94..0x9ba0` and calls the helper with destination **0x94016a**.
- Helper **0x8f08** allocates an OSAL message at `0x8f1a`, stores caller-supplied message code at **0x8f26**, then calls relocations-resolved **`osal_snd_msg` at 0x8f34** (PLT 0x8cc4; GOT 0x12a34).

Thus bootin has an **actual conditional outbound control-message path** to the im.elf fixed queue ID **0x94016a**, but the events sent on this observed branch are **0x9400f3/f4**, *not 0x940036/37*. Do not call this a proven fixed-to-dynamic forwarding route.

## 4. Independent im.elf argument semantics match bootin strings

Original `im.elf` parser entry **0xa628** compares each argument with the `boot=` prefix at 0xa640, **and on mismatch continues through exact `strcmp` tokens** (e.g. `"i"` at 0xc3a9, `"a"` at 0xc36f, `"s"` at 0xc056). The code sets:

- Single argument **`"i"`**: `0xa75c..0xa760` ORs stage flag **0x200000**.
- Single argument **`"a"`**: `0xa77a..0xa77e` ORs stage flag **0x400000**.
- Subsequent `im.elf` main conditional event producer sites **0x9d72** (0x940036) and **0x9d88** (0x940037) send via OSAL wrapper, with destination **0x94016a**.

So a *conditional static cross-process path* exists: **a message arriving at bootin's 0x94020a receiver with code 0x940036/37 -> bootin shell-launches a separate im.elf process with token i/a -> that process's parser selects the corresponding stage bit -> its own code may issue an OSAL stage message to 0x94016a**.

This does **not** show the original producer to bootin's 0x94020a inbox, any successful child launch, sender return status, or any later delivery into the im main 0x946xxx receive loop.

## 5. Architectural correction to earlier cross-stage libObj theory

Phase 4.41/4.42 noted that 31 possible `dlopen("/usr/lib/libObj.so",0x101)` record candidates are array-ordered before appFw row99, and 30 belong to stage 5→7 while row99 belongs to stage 7→8. **Stage order in the IMDB table must not be equated to linker-global scope across `im.elf i` and `im.elf a` processes.** The bootin launcher explicitly backgrounds each requested stage via `system("im.elf <letter> &")`, which is a new **separate OS process invocation**. A shared object loaded `RTLD_GLOBAL` in one such process is **not automatically made globally visible to another process's `dlopen(NULL)`/ `dlsym`**.

Neither `im.elf` nor directly linked `libIMDB.so` has `libObj.so` in its `DT_NEEDED` list. Other bootstrap conditions or a same-process prior load could still resolve it; **we have not ruled out** a valid initialization. But **preceding earlier-stage process loads alone are inadequate** to prove row99's `Application_System_Init` symbol binding in a distinct `im.elf a` process.

This is a stronger *correction of a potential over-inference* than simply counting more literals. The exact unresolved target becomes **symbol source and setup within the same `im.elf a` process**, plus stage-inbox producer of 0x940036/37 at **0x94020a**.

## Scope and accounting

All findings are static verified ARM instructions, .rodata words, .rel.plt, and independently examined sources. No code was executed, no firmware image/kernel module was altered, and no device was accessed.

Original Camera Core graph remains **74 primary static / 5 inferred / 5 unresolved = 84 tracked**, and both runtime-verified and safe-to-invoke API counts remain **0**. This cross-ELF startup architecture is recorded separately in `sdk/bootin_stage_launcher_3_21.json`.
