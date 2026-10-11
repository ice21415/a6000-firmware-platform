# Phase 4.45 — `libosal_uipc.so` resolves im.elf's IPC operations to the kernel UIPC driver

## Provenance and scope

Original user-uploaded Sony A6000 firmware 3.21 `libosal_uipc_fw321.so`: **26,636 bytes**, SHA-256 **`0c6b87a012eb757dbe0a5b9b7b19fb91fc27c1dafc0e78facb126114416cf1ef`**, ELF32 little-endian ARM EABI5, `DT_SONAME=libosal_uipc.so`. It was inspected read-only using `readelf`, `llvm-objdump` and literal bytes; no execution, upload back to GitHub, firmware writing or camera communication. It exports `osal_snd_msg`, `osal_rcv_msg_tmo`, `osal_reg_sync_msg_queue_cb`, `osal_dynamic_id`, and corresponding `u_osal_*` kernel IPC delegates.

All addresses below are ELF VMAs of **this** `libosal_uipc.so`, not `im.elf`. Original `im.elf` is SHA256 `f0f181426af4add55a8510c5441ff86c3121678fd1f7e0467152070e870d803a`.

## 1. All three IPC frontends branch on endpoint ID bit 0x8000

| Public API | Entry | Predicate | If bit 0x8000 clear | If bit 0x8000 set |
|---|---|---|---|---|
| `osal_snd_msg` | 0x421c | **0x4220** `tst.w r0,#0x8000` | **0x423e** tail-branch to `u_osal_snd_msg` PLT | local endpoint logic from 0x4260 |
| `osal_rcv_msg_tmo` | 0x3b68 | **0x3b78** `tst.w r3,#0x8000` | **0x3b7e** `BLX u_osal_rcv_msg_tmo` PLT | local receive queue lookup from 0x3bb8 |
| `osal_reg_sync_msg_queue_cb` | 0x3914 | **0x3928** `tst.w r5,#0x8000` | **0x3932** tail-branch to `u_osal_reg_sync_msg_queue_cb` PLT | local registration from 0x3944 |

The record `im.elf` repeatedly uses destination **0x0094016a**, whose low 16 bits are **0x016a** and `0x0094016a & 0x8000 = 0`. Thus **its sender and sync callback registration are in the UIPC/kerneldriver delegated branch**. This is direct static instruction proof of *which code path would be invoked*, not successful OSAL call results.

## 2. UIPC delegates use distinct ioctl request values

`libosal_uipc.so` contains exact ASCII literal **`/dev/uipc`** at 0x51e4. Initialization function `do_init` at 0x1f84 loads that path and calls `open(...,2)` (read/write) at **0x1f94**. The `ioctl@GLIBC_2.4` PLT is 0x1740, resolved using `.rel.plt` `R_ARM_JUMP_SLOT` at GOT 0xe1c4.

| Internal wrapper | Thumb entry | `ioctl` at | Request (r1) |
|---|---|---|---|
| `u_osal_snd_msg` | 0x2430 | **0x2450** | **0x80000004** |
| `u_osal_rcv_msg_tmo` | 0x256c | **0x2594** | **0x80000007** |
| `u_osal_reg_sync_msg_queue_cb` | 0x2624 | **0x2650** | **0x80000008** |
| `u_osal_dynamic_id` | 0x278c | **0x27b8** | **0x8000000c** |

Each wrapper prepares a distinct stack-based argument structure and invokes `ioctl(fd,request,pointer)`. These requests tell us the **userspace IPC interface boundaries**; only the unseen kernel implementation can establish the destination mapping, queue behaviors, or guaranteed processing order. Do not equate calling `ioctl` to a successful send.

## 3. Important cross-ELF result: the *main receiver* also requests remote UIPC ID allocation

The original `im.elf` main at **0x9e30–0x9e34** requests `osal_dynamic_id` via helper 0x92bc with **r0=0x2a**, **r1=0x94**, r2=output pointer. In the OSAL library:

- **0x4720** computes `r3 = r0 & 0x2`; for `0x2a` this is nonzero.
- **0x4740–0x4742** takes the nonzero branch to **0x489c**, which delegates to `u_osal_dynamic_id`.
- That delegate uses `ioctl` request **0x8000000c** to request an identifier from the kernel.
- The resulting ID is saved in `im.elf` via **0x9e3a→0xa570** to global `0x15410`; its getter at 0xa580 feeds `osal_rcv_msg_tmo` at **0x9eaa**.

Thus the `im.elf` event sender, sync callback registration, and dynamic main message receiver all pass through the same **UIPC abstraction and /dev/uipc driver interface**. The receiver ID **itself is runtime-generated** (not statically resolved here), so do **not** equate it with fixed sender destination `0x94016a` without explicit driver routing logic.

The registered sync callback is **0x95b1** in `im.elf`, distinct from stage handler **0xa06d**. The sync callback's inspected direct message ID comparisons do not explicitly match 0x940036 or 0x940037. Phase 4.44 already proved a *separate* variable callback path through `0x9eaa osal_rcv_msg_tmo → 0x9eb2 BLX r5` if the selected callback remains a06d. The kernel **may** connect these flows, but the source uploaded to date **does not establish such a mapping**.

## 4. Remaining evidence boundary

Static UIPC frontend/delegate paths are now proven. **Still unresolved**: whether boot flags emit both stage events, OSAL ioctl calls succeed, whether the kernel maps 0x94016a to the dynamically allocated receive ID or bridges callbacks, whether messages are processed in emitted order, and successful earlier `libObj.so` load/visibility before `Application_System_Init`.

**Next offline target:** original same-firmware kernel driver's `/dev/uipc` implementation (or its kernel image/module) and startup argv. Avoid claiming a fully confirmed sender→handler chain from this userspace library alone. No need to use actual camera or alter firmware.

Project evidence: `sdk/osal_uipc_routing_3_21.json`. Original Camera Core graph stays **74 primary + 5 inferred + 5 unresolved = 84**; all five end-to-end blockers remain. Runtime verified APIs=0; safe to invoke APIs=0.
